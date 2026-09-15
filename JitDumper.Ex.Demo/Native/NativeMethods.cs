using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace LoaderExDemo
{
    // LoaderExDemo is a full-trust native/JIT diagnostic tool.  Suppressing the
    // legacy unmanaged-code permission stack walk on these internal P/Invokes
    // matches the pattern used by the Framework's own interop hot paths.
    [SuppressUnmanagedCodeSecurity]
    [HelperClass.SomeElementsInfos("Win32 and CLR native interop surface.")]
    internal static class NativeMethods
    {
        private const string Kernel32 = "kernel32.dll";
        private const string User32 = "user32.dll";
        private const uint MemRelease = 0x8000;

        [DllImport(Kernel32, ExactSpelling = true)]
        public static extern void DebugBreak();

        [DllImport(Kernel32, ExactSpelling = true, CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr lib, string proc);

        [DllImport(Kernel32, EntryPoint = "LoadLibraryW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryNative(string lib);

        [DllImport(Kernel32, EntryPoint = "GetModuleHandleW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string moduleName);





        internal static IntPtr LoadLibrary(string lib)
        {
            if (string.IsNullOrWhiteSpace(lib))
                throw new ArgumentException("Module name/path is required.", nameof(lib));
            IntPtr loaded = GetModuleHandle(lib);
            return loaded != IntPtr.Zero ? loaded : LoadLibraryNative(lib);
        }

        [DllImport(Kernel32, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool VirtualProtect(IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport(Kernel32, ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport(Kernel32, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, nuint dwSize);

        [DllImport(Kernel32, ExactSpelling = true, SetLastError = true)]
        internal static extern SafeVirtualMemoryHandle VirtualAlloc(IntPtr lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

        [DllImport(Kernel32, ExactSpelling = true, SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr lpAddress, nuint dwSize, uint dwFreeType);

        [DllImport(User32, EntryPoint = "PeekMessageW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PeekMessage(out StructureViews.Win32Message lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport(User32, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TranslateMessage(ref StructureViews.Win32Message lpMsg);

        [DllImport(User32, EntryPoint = "DispatchMessageW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr DispatchMessage(ref StructureViews.Win32Message lpMsg);

        [DllImport(Kernel32, ExactSpelling = true)]
        internal static extern IntPtr RtlLookupFunctionEntry(ulong ControlPc, out ulong ImageBase, IntPtr HistoryTable);

        // VirtualAlloc ownership is real ownership, so keep it behind SafeHandle
        // rather than a naked IntPtr. SafeHandle brings the Framework's critical
        // finalization/reference-counting policy to the JIT trampoline allocation.
        [SuppressUnmanagedCodeSecurity]
        internal sealed class SafeVirtualMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
        {



            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            internal SafeVirtualMemoryHandle()
                : base(ownsHandle: true)
            {
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            protected override bool ReleaseHandle() => VirtualFree(handle, UIntPtr.Zero, MemRelease);
        }
    }
}
