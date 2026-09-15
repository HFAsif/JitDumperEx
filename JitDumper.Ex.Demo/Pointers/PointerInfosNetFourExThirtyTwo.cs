using System.Runtime.CompilerServices;

namespace LoaderExDemo
{
    /// <summary>
    /// CLR 4.x x86 pointer resolver.
    ///
    /// Resolves:
    ///   _CorDllMain -> ExecuteDLL -> ExecuteDLLForAttach
    ///   _CorExeMain -> _CorExeMainInternal -> ExecuteEXE
    ///
    /// PDB-free, RVA-free.
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR4 x86 execution pointers.")]
    internal static unsafe class PointerInfosNetFourExThirtyTwo
    {
        private const int MaxScan = 0x400;
        internal static bool Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
#if !NET40_OR_GREATER
            throw new NotSupportedException("This resolver is for .NET Framework 4.x.");
#else
            if (IntPtr.Size != 4 || Environment.Version.Major != 4)
                throw new NotSupportedException("This resolver is for CLR 4.x x86 only.");

            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (clr == IntPtr.Zero)
                return false;

            bool dllOk = ResolveDllPointers(ptrs, clr);
            bool exeOk = ResolveExePointers(ptrs, clr);

            return dllOk && exeOk;
#endif
        }

        internal static bool ResolveDllPointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            return clr != IntPtr.Zero && ResolveDllPointers(ptrs, clr);
        }

        internal static bool ResolveExePointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            return clr != IntPtr.Zero && ResolveExePointers(ptrs, clr);
        }

        private static bool ResolveDllPointers(PointerInfosBase ptrs, IntPtr clr)
        {
            ptrs.CorDllMain = NativeMethods.GetProcAddress(clr, "_CorDllMain");
            if (ptrs.CorDllMain == IntPtr.Zero)
                return false;

            byte* executeDllCall = FindExecuteDllCall((byte*)ptrs.CorDllMain.ToPointer());

            if (executeDllCall == null)
                return false;

            ptrs.ExecuteDLLCall = (IntPtr)executeDllCall;
            ptrs.ExecuteDLL = PointerHelpers.ResolveRel32Call(executeDllCall);
            if (ptrs.ExecuteDLL == IntPtr.Zero)
                return false;

            byte* attachCall = FindExecuteDllForAttachCall((byte*)ptrs.ExecuteDLL.ToPointer());

            if (attachCall == null)
                return false;

            ptrs.ExecuteDLLForAttachCall = (IntPtr)attachCall;
            ptrs.ExecuteDLLForAttach = PointerHelpers.ResolveRel32Call(attachCall);

            return ptrs.ExecuteDLLForAttach != IntPtr.Zero;
        }

        private static bool ResolveExePointers(PointerInfosBase ptrs, IntPtr clr)
        {

            ptrs.CorExeMain = NativeMethods.GetProcAddress(clr, "_CorExeMain");
            if (ptrs.CorExeMain == IntPtr.Zero)
                return false;

            byte* internalCall = FindCorExeMainInternalCall((byte*)ptrs.CorExeMain.ToPointer());

            if (internalCall == null)
                return false;

            ptrs.CorExeMainInternalCall = (IntPtr)internalCall;
            ptrs.CorExeMainInternal = PointerHelpers.ResolveRel32Call(internalCall);

            if (ptrs.CorExeMainInternal == IntPtr.Zero)
                return false;

            byte* executeExeCall = FindExecuteExeCall((byte*)ptrs.CorExeMainInternal.ToPointer());

            if (executeExeCall == null)
                return false;

            ptrs.ExecuteEXECall = (IntPtr)executeExeCall;
            ptrs.ExecuteEXE = PointerHelpers.ResolveRel32Call(executeExeCall);

            return ptrs.ExecuteEXE != IntPtr.Zero;
        }





        private static byte* FindExecuteDllCall(byte* start)
        {
            for (int i = 16; i < MaxScan - 8; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;



                if (!PointerHelpers.Is5x(p[-1]) || !PointerHelpers.Is5x(p[-2]))
                    continue;

                if (p[5] != 0x89)
                    continue;

                if (p[6] != 0x45 && p[6] != 0x85)
                    continue;

                return p;
            }

            return null;
        }





        private static byte* FindExecuteDllForAttachCall(byte* start)
        {
            for (int i = 16; i < MaxScan - 8; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;

                if (IsFourPushLayout(p) || IsLongLocalArgumentLayout(p) || IsShortLocalArgumentLayout(p) || IsLegacyFallbackLayout(p))
                {
                    return p;
                }
            }

            return null;
        }

        private static bool IsFourPushLayout(byte* p)
        {
            return PointerHelpers.Is5x(p[-1]) &&
                   p[-4] == 0xFF &&
                   p[-7] == 0xFF &&
                   p[-10] == 0xFF;
        }

        private static bool IsLongLocalArgumentLayout(byte* p)
        {


            return p[-6] == 0x8B &&
                   p[-5] == 0x8D;
        }

        private static bool IsShortLocalArgumentLayout(byte* p)
        {


            return p[-3] == 0x8B &&
                   p[-2] == 0x4D;
        }

        private static bool IsLegacyFallbackLayout(byte* p)
        {
            return p[-12] == 0x8B &&
                   p[-1] == 0x95 &&
                   p[5] == 0x8B &&
                   p[6] == 0xF0;
        }





        private static byte* FindCorExeMainInternalCall(byte* start)
        {
            for (int i = 16; i < MaxScan - 12; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;



                bool beforeShort = p[-3] == 0x89 &&
                    p[-2] == 0x45 &&
                    p[-1] == 0xFC;

                bool beforeLong = p[-6] == 0x89 &&
                    p[-5] == 0x85 &&
                    Unsafe.ReadUnaligned<int>(p - 4) == -4;

                bool afterShort = p[5] == 0xC7 &&
                    p[6] == 0x45 &&
                    p[7] == 0xFC;

                bool afterLong = p[5] == 0xC7 &&
                    p[6] == 0x85 &&
                    Unsafe.ReadUnaligned<int>(p + 7) == -4;

                if ((beforeShort || beforeLong) && (afterShort || afterLong))
                {
                    return p;
                }
            }

            return null;
        }





        private static byte* FindExecuteExeCall(byte* start)
        {
            for (int i = 8; i < MaxScan - 8; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;






                bool oldLayout = p[-1] == 0x50 &&
                    p[5] == 0x3B &&
                    p[6] == 0xC3 &&
                    p[7] == 0x0F;






                bool newLayout = p[-2] == 0x8B &&
                    p[-1] == 0xC8 &&
                    p[5] == 0x85 &&
                    p[6] == 0xC0 &&
                    p[7] == 0x0F;

                if (oldLayout || newLayout)
                    return p;
            }

            return null;
        }




    }
}
