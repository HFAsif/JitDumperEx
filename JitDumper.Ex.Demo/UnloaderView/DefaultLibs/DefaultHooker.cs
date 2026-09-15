using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Hooks ICorJitCompiler::compileMethod.")]
    internal sealed unsafe class DefaultHooker : IHooker
    {
        private const uint MemCommit = 0x1000;
        private const uint MemReserve = 0x2000;
        private const uint PageReadWrite = 0x04;
        private const uint PageExecuteRead = 0x20;
        private const uint PageExecuteReadWrite = 0x40;
        private const int X86TrampolineSize = 7;
        private const int X64TrampolineSize = 12;

        private static readonly object InitializeLock = new();
        private static readonly object HookLock = new();

        private static CompileMethodDelegate? _originalDelegate;
        private static CompileMethodDelegate? _handlerDelegate;
        private static nint _hookPosition;
        private static nint _originalCompileMethod;
        private static NativeMethods.SafeVirtualMemoryHandle? _trampoline;
        private static volatile bool _initialized;

        [ThreadStatic]
        private static bool _insideHook;

        private volatile JitMethodCallback? _callback;
        private bool _disposed;

        public bool IsHooked { get; private set; }

        private static string JitModuleName => ThisStaticClass.IsNet4 ? "clrjit.dll" : "mscorjit.dll";

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [SuppressUnmanagedCodeSecurity]
        private delegate nint* GetJitDelegate();

        // The Desktop CLR/SSCLI ICorJitCompiler contract explicitly declares
        // compileMethod as __stdcall.  The managed delegate therefore keeps the
        // native this pointer as its explicit first argument instead of treating
        // this JIT ABI as an ordinary C++ __thiscall.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [SuppressUnmanagedCodeSecurity]
        private delegate uint CompileMethodDelegate(nint self, void* comp, StructureViews.CORINFO_METHOD_INFO* info, uint flags, byte** nativeEntry, uint* nativeSizeOfCode);

        [HelperClass.SomeElementsInfos("Builds the JIT hook trampoline.")]
        public static void Initialize()
        {
            if (_initialized)
                return;

            lock (InitializeLock)
            {
                if (_initialized)
                    return;

                nint jit = NativeMethods.GetModuleHandle(JitModuleName);
                if (jit == IntPtr.Zero)
                    jit = NativeMethods.LoadLibrary(JitModuleName);

                if (jit == IntPtr.Zero)
                    throw new InvalidOperationException($"Unable to load JIT module '{JitModuleName}'. Win32Error={Marshal.GetLastWin32Error()}");

                nint getJitAddress = NativeMethods.GetProcAddress(jit, "getJit");
                if (getJitAddress == IntPtr.Zero)
                    throw new MissingMethodException(JitModuleName, "getJit");

                GetJitDelegate getJit = Marshal.GetDelegateForFunctionPointer<GetJitDelegate>(getJitAddress);
                nint* compiler = getJit();
                if (compiler == null || *compiler == IntPtr.Zero)
                    throw new InvalidOperationException("getJit returned a null ICorJitCompiler/vtable pointer.");

                nint hookPosition = *compiler;
                nint originalCompileMethod = *(nint*)hookPosition;
                if (originalCompileMethod == IntPtr.Zero)
                    throw new InvalidOperationException("ICorJitCompiler::compileMethod pointer is null.");

                NativeMethods.SafeVirtualMemoryHandle trampoline = CreateTrampoline(originalCompileMethod);
                try
                {
                    CompileMethodDelegate originalDelegate = Marshal.GetDelegateForFunctionPointer<CompileMethodDelegate>(trampoline.DangerousGetHandle());
                    CompileMethodDelegate handlerDelegate = HookHandler;




                    RuntimeHelpers.PrepareDelegate(originalDelegate);
                    RuntimeHelpers.PrepareDelegate(handlerDelegate);

                    _hookPosition = hookPosition;
                    _originalCompileMethod = originalCompileMethod;
                    _trampoline = trampoline;
                    _originalDelegate = originalDelegate;
                    _handlerDelegate = handlerDelegate;
                    _initialized = true;
                }
                catch
                {
                    trampoline.Dispose();
                    throw;
                }

                ThisStaticClass.Logger.LogInformation("[JIT-HOOK] Initialized {Module}; compileMethod=0x{CompileMethod:X}", JitModuleName, StaticMethods.NativeAddressValue(_originalCompileMethod));
            }
        }

        public void Hook() => HookCore(null);

        public void Hook(JitMethodCallback callback)
        {
            ArgumentNullException.ThrowIfNull(callback);
            HookCore(callback);
        }

        private void HookCore(JitMethodCallback? callback)
        {
            Initialize();

            lock (HookLock)
            {
                ThrowIfDisposed();

                if (_activeInstance is not null && !ReferenceEquals(_activeInstance, this))
                    throw new InvalidOperationException("Another DefaultHooker instance already owns the process-global JIT hook.");

                if (IsHooked)
                {
                    _callback = callback;
                    return;
                }

                _callback = callback;
                _activeInstance = this;
                try
                {
                    CompileMethodDelegate handler = _handlerDelegate ?? throw new InvalidOperationException("JIT hook handler was not initialized.");
                    WriteHookPointer(Marshal.GetFunctionPointerForDelegate(handler));
                    IsHooked = true;
                }
                catch
                {
                    _activeInstance = null;
                    _callback = null;
                    throw;
                }
            }
        }

        public void UnHook()
        {
            lock (HookLock)
                UnHookCore();
        }

        private void UnHookCore()
        {
            if (!IsHooked)
                return;

            if (!ReferenceEquals(_activeInstance, this))
                throw new InvalidOperationException("This DefaultHooker instance does not own the active JIT hook.");

            WriteHookPointer(_originalCompileMethod);
            IsHooked = false;
            _callback = null;
            _activeInstance = null;
        }




        [MethodImpl(MethodImplOptions.NoInlining)]
        [HelperClass.SomeElementsInfos("Captures IL around the real JIT call.")]
        private static uint HookHandler(nint self, void* comp, StructureViews.CORINFO_METHOD_INFO* info, uint flags, byte** nativeEntry, uint* nativeSizeOfCode)
        {
            CompileMethodDelegate original = _originalDelegate ?? throw new InvalidOperationException("Original JIT compileMethod is not initialized.");

            if (_insideHook || info == null)
                return original(self, comp, info, flags, nativeEntry, nativeSizeOfCode);

            _insideHook = true;
            JitMethodCallback? callback = CurrentCallback;
            try
            {
                nint methodHandle;
                ImmutableArray<byte> il;
                uint maxStack;
                uint ehCount;
                uint options;
                JitExceptionRegion[] exceptionRegions;
                bool exceptionRegionsFromJit;

                try
                {
                    methodHandle = (nint)info->ftn;
                    il = SnapshotIL(info);
                    maxStack = StructureViews.GetMaxStack(info);
                    ehCount = StructureViews.GetEHCount(info);
                    options = StructureViews.GetOptions(info);
                    exceptionRegionsFromJit = TryCaptureExceptionRegions(ehCount, out exceptionRegions);
                }
                catch (Exception ex)
                {
                    uint fallbackResult = original(self, comp, info, flags, nativeEntry, nativeSizeOfCode);
                    try { ThisStaticClass.Logger.LogWarning(ex, "[JIT-HOOK] Capture failed; original compileMethod completed without custom processing."); }
                    catch { }
                    return fallbackResult;
                }


                uint jitResult = original(self, comp, info, flags, nativeEntry, nativeSizeOfCode);

                nint nativeCode = nativeEntry == null ? IntPtr.Zero : (nint)(*nativeEntry);
                uint nativeSize = nativeSizeOfCode == null ? 0 : *nativeSizeOfCode;
                JitMethodContext context = new(methodHandle, il, maxStack, ehCount, options, exceptionRegions, exceptionRegionsFromJit, nativeCode, nativeSize, jitResult);

                try
                {
                    callback?.Invoke(in context);
                }
                catch (Exception ex)
                {


                    try
                    {
                        ThisStaticClass.Logger.LogError(ex, "[JIT-HOOK] Per-method callback failed for MethodHandle=0x{MethodHandle:X}", StaticMethods.NativeAddressValue(context.MethodHandle));
                    }
                    catch
                    {
                    }
                }

                return jitResult;
            }
            finally
            {
                _insideHook = false;
            }
        }




        private static JitMethodCallback? CurrentCallback => _activeInstance?._callback;

        private static volatile DefaultHooker? _activeInstance;

        private void WriteHookPointer(nint value)
        {
            if (_hookPosition == IntPtr.Zero)
                throw new InvalidOperationException("JIT hook position is not initialized.");

            uint oldProtect = 0;
            bool protectionChanged = false;




            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(_hookPosition, (nuint)IntPtr.Size, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException($"VirtualProtect failed while updating JIT hook. Win32Error={Marshal.GetLastWin32Error()}");

                protectionChanged = true;
                Marshal.WriteIntPtr(_hookPosition, value);
            }
            finally
            {
                if (protectionChanged && !NativeMethods.VirtualProtect(_hookPosition, (nuint)IntPtr.Size, oldProtect, out _))
                {
                    try
                    {
                        ThisStaticClass.Logger.LogCritical("[JIT-HOOK] Failed to restore vtable page protection. Win32Error={Win32Error}", Marshal.GetLastWin32Error());
                    }
                    catch
                    {
                    }
                }
            }
        }

        private static bool TryCaptureExceptionRegions(uint ehCount, out JitExceptionRegion[] regions)
        {
            if (ehCount == 0)
            {
                regions = [];
                return true;
            }






            regions = [];
            return false;
        }

        private static ImmutableArray<byte> SnapshotIL(StructureViews.CORINFO_METHOD_INFO* info)
        {
            if (info->ILCode == null || info->ILCodeSize == 0)
                return ImmutableArray<byte>.Empty;

            int length = checked((int)info->ILCodeSize);
            byte[] bytes = new byte[length];
            new ReadOnlySpan<byte>(info->ILCode, length).CopyTo(bytes);




            return ImmutableCollectionsMarshal.AsImmutableArray(bytes);
        }

        private static NativeMethods.SafeVirtualMemoryHandle CreateTrampoline(nint target)
        {
            int size = IntPtr.Size == 8 ? X64TrampolineSize : X86TrampolineSize;
            NativeMethods.SafeVirtualMemoryHandle memoryHandle = NativeMethods.VirtualAlloc(IntPtr.Zero, (nuint)size, MemCommit | MemReserve, PageReadWrite);
            if (memoryHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                memoryHandle.Dispose();
                throw new OutOfMemoryException($"VirtualAlloc failed for JIT trampoline. Win32Error={error}");
            }

            nint memory = memoryHandle.DangerousGetHandle();
            byte* p = (byte*)memory;

            if (IntPtr.Size == 8)
            {

                p[0] = 0x48;
                p[1] = 0xB8;
                Unsafe.WriteUnaligned(p + 2, unchecked((ulong)(long)target));
                p[10] = 0xFF;
                p[11] = 0xE0;
            }
            else
            {

                p[0] = 0xB8;
                Unsafe.WriteUnaligned(p + 1, unchecked((uint)(int)target));
                p[5] = 0xFF;
                p[6] = 0xE0;
            }

            if (!NativeMethods.VirtualProtect(memory, (nuint)size, PageExecuteRead, out _))
            {
                int error = Marshal.GetLastWin32Error();
                memoryHandle.Dispose();
                throw new InvalidOperationException($"VirtualProtect failed for JIT trampoline. Win32Error={error}");
            }

            if (!NativeMethods.FlushInstructionCache(NativeMethods.GetCurrentProcess(), memory, (nuint)size))
            {
                int error = Marshal.GetLastWin32Error();
                memoryHandle.Dispose();
                throw new InvalidOperationException($"FlushInstructionCache failed for JIT trampoline. Win32Error={error}");
            }

            return memoryHandle;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(DefaultHooker));
        }

        public void Dispose()
        {
            lock (HookLock)
            {
                if (_disposed)
                    return;

                UnHookCore();
                _disposed = true;
            }

            GC.SuppressFinalize(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return default;
        }

    }
}
