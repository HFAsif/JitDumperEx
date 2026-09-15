using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Native CLR and JIT ABI layouts.")]
    internal static unsafe class StructureViews
    {
        // Common prefix of the CLR2/CLR4 CORINFO_METHOD_INFO layouts.
        // CLR2 stores maxStack/EHcount as ushort immediately after this prefix;
        // CLR4 stores them as uint. Keep the shared prefix exact and read the
        // version-specific tail through the helpers below.
        [StructLayout(LayoutKind.Sequential)]
        internal struct CORINFO_METHOD_INFO
        {
            public IntPtr ftn;
            public IntPtr scope;
            public byte* ILCode;
            public uint ILCodeSize;
        }





#if NET40
        [MethodImpl((MethodImplOptions)256)]
#endif
        private static byte* GetMethodInfoTail(CORINFO_METHOD_INFO* info)
            => (byte*)&info->ILCodeSize + sizeof(uint);

#if NET40
        [MethodImpl((MethodImplOptions)256)]
#endif
        internal static uint GetMaxStack(CORINFO_METHOD_INFO* info)
        {
            byte* tail = GetMethodInfoTail(info);
            return ThisStaticClass.IsNet4 ? Unsafe.ReadUnaligned<uint>(tail) : Unsafe.ReadUnaligned<ushort>(tail);
        }

#if NET40
        [MethodImpl((MethodImplOptions)256)]
#endif
        internal static uint GetEHCount(CORINFO_METHOD_INFO* info)
        {
            byte* tail = GetMethodInfoTail(info);
            return ThisStaticClass.IsNet4 ? Unsafe.ReadUnaligned<uint>(tail + sizeof(uint)) : Unsafe.ReadUnaligned<ushort>(tail + sizeof(ushort));
        }

#if NET40
        [MethodImpl((MethodImplOptions)256)]
#endif
        internal static uint GetOptions(CORINFO_METHOD_INFO* info)
        {
            byte* tail = GetMethodInfoTail(info);
            return ThisStaticClass.IsNet4 ? Unsafe.ReadUnaligned<uint>(tail + (sizeof(uint) * 2)) : Unsafe.ReadUnaligned<uint>(tail + (sizeof(ushort) * 2));
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Win32Point
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Win32Message
        {
            public IntPtr hwnd;
            public uint message;
            public nuint wParam;
            public IntPtr lParam;
            public uint time;
            public Win32Point pt;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ExeContext
        {
            // Do not replace this metadata delegate with delegate* unmanaged[Fastcall].
            // HFDotnetEx CLR4 x86 prewarm discovers this exact FastCall metadata shape
            // and patches the CLR-generated interop stub before first invocation.
            [UnmanagedFunctionPointer(CallingConvention.FastCall)]
            [SuppressUnmanagedCodeSecurity]
            private delegate int ExecuteEXEDelegateClr4X86(IntPtr hInst);

            public required IntPtr lib;
            public required IntPtr func;

            public void ExecuteExe()
            {
                if (IntPtr.Size == 4 && Environment.Version.Major == 4)
                {
                    ExecuteEXEDelegateClr4X86 execute = Marshal.GetDelegateForFunctionPointer<ExecuteEXEDelegateClr4X86>(func);
                    _ = execute(lib);
                    return;
                }

                delegate* unmanaged[Stdcall]<IntPtr, int> executeStdCall = (delegate* unmanaged[Stdcall]<IntPtr, int>)func.ToPointer();
                _ = executeStdCall(lib);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct DllContext
        {
            [UnmanagedFunctionPointer(CallingConvention.FastCall)]
            [SuppressUnmanagedCodeSecurity]
            private delegate int ExecuteDLLDelegateClr4X86(IntPtr hInst, uint dwReason, IntPtr lpReserved, int fFromThunk);

            public required IntPtr lib;
            public required IntPtr func;
            public required uint dwReason;
            IntPtr lpReserved;
            public required int fFromThunk;

            public void ExecuteDll()
            {
                if (IntPtr.Size == 4 && Environment.Version.Major == 4)
                {
                    ExecuteDLLDelegateClr4X86 executeDll = Marshal.GetDelegateForFunctionPointer<ExecuteDLLDelegateClr4X86>(func);

                    _ = executeDll(lib, dwReason, lpReserved, fFromThunk);
                    return;
                }

                // ExecuteDLLForAttach is proven StdCall in LoaderExDemo runtime testing.
                // Keep this convention independent from the CLR4 x86 EXE FastCall path.
                delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, int, int> execute =
                    (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, int, int>)func.ToPointer();

                _ = execute(lib, dwReason, lpReserved, fFromThunk);
            }
        }

        internal struct MemOperand
        {
            public int BaseRegister;
            public bool HasBase;
            public long Displacement;
            public int BytesUsed;
        }

    }
}
