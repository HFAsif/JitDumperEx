using System.Runtime.CompilerServices;

namespace LoaderExDemo
{
    /// <summary>
    /// CLR 4.x x64 pointer resolver.
    ///
    /// Resolves:
    ///   _CorDllMain -> ExecuteDLL -> ExecuteDLLForAttach
    ///   _CorExeMain -> _CorExeMainInternal -> ExecuteEXE
    ///
    /// No PDB, no fixed RVA, no CLR build-number table.
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR4 x64 execution pointers.")]
    internal static unsafe class PointerInfosNetFourExSixtyFour
    {
        private const int CorMainScan = 0x500;
        private const int ExecuteDllScan = 0x1800;
        private const int CorExeMainInternalScan = 0x2000;
        internal static bool Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
#if !NET40_OR_GREATER
            throw new NotSupportedException("This resolver is for .NET Framework 4.x.");
#else
            if (IntPtr.Size != 8 || Environment.Version.Major != 4)
                throw new NotSupportedException("This resolver is for CLR 4.x x64 only.");

            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (clr == IntPtr.Zero)
                return false;

            byte* clrBase = (byte*)clr.ToPointer();
            int clrSize = PointerHelpers.GetImageSize(clrBase);

            if (clrSize <= 0)
                return false;

            bool dllOk = ResolveDllPointers(ptrs, clr, clrBase, clrSize);
            bool exeOk = ResolveExePointers(ptrs, clr, clrBase, clrSize);

            return dllOk && exeOk;
#endif
        }

        internal static bool ResolveDllPointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (clr == IntPtr.Zero)
                return false;

            byte* clrBase = (byte*)clr.ToPointer();
            int clrSize = PointerHelpers.GetImageSize(clrBase);

            return clrSize > 0 &&
                   ResolveDllPointers(ptrs, clr, clrBase, clrSize);
        }

        internal static bool ResolveExePointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (clr == IntPtr.Zero)
                return false;

            byte* clrBase = (byte*)clr.ToPointer();
            int clrSize = PointerHelpers.GetImageSize(clrBase);

            return clrSize > 0 &&
                   ResolveExePointers(ptrs, clr, clrBase, clrSize);
        }

        private static bool ResolveDllPointers(PointerInfosBase ptrs, IntPtr clr, byte* clrBase, int clrSize)
        {
            ptrs.CorDllMain = NativeMethods.GetProcAddress(clr, "_CorDllMain");

            if (ptrs.CorDllMain == IntPtr.Zero)
                return false;

            byte* executeDllCall = FindExecuteDllCall((byte*)ptrs.CorDllMain.ToPointer(), clrBase, clrSize);

            if (executeDllCall == null)
                return false;

            ptrs.ExecuteDLLCall = (IntPtr)executeDllCall;
            ptrs.ExecuteDLL = PointerHelpers.ResolveRel32Call(executeDllCall);

            if (ptrs.ExecuteDLL == IntPtr.Zero)
                return false;

            byte* attachCall = FindExecuteDllForAttachCall((byte*)ptrs.ExecuteDLL.ToPointer(), clrBase, clrSize);

            if (attachCall == null)
                return false;

            ptrs.ExecuteDLLForAttachCall = (IntPtr)attachCall;
            ptrs.ExecuteDLLForAttach = PointerHelpers.ResolveRel32Call(attachCall);

            return ptrs.ExecuteDLLForAttach != IntPtr.Zero;
        }

        private static bool ResolveExePointers(PointerInfosBase ptrs, IntPtr clr, byte* clrBase, int clrSize)
        {

            ptrs.CorExeMain = NativeMethods.GetProcAddress(clr, "_CorExeMain");

            if (ptrs.CorExeMain == IntPtr.Zero)
                return false;

            byte* internalCall = FindCorExeMainInternalCall((byte*)ptrs.CorExeMain.ToPointer(), clrBase, clrSize);

            if (internalCall == null)
                return false;

            ptrs.CorExeMainInternalCall = (IntPtr)internalCall;
            ptrs.CorExeMainInternal = PointerHelpers.ResolveRel32Call(internalCall);

            if (ptrs.CorExeMainInternal == IntPtr.Zero)
                return false;

            byte* executeExeCall = FindExecuteExeCall((byte*)ptrs.CorExeMainInternal.ToPointer(), clrBase, clrSize);

            if (executeExeCall == null)
                return false;

            ptrs.ExecuteEXECall = (IntPtr)executeExeCall;
            ptrs.ExecuteEXE = PointerHelpers.ResolveRel32Call(executeExeCall);

            return ptrs.ExecuteEXE != IntPtr.Zero;
        }





        private static byte* FindExecuteDllCall(byte* start, byte* clrBase, int clrSize)
        {
            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < CorMainScan - 5; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);

                if (target == IntPtr.Zero || !PointerHelpers.InsideModule((byte*)target.ToPointer(), clrBase, clrSize))
                {
                    continue;
                }

                int score = 0;


                if (HasZeroR9D(p - 32, p))
                    score += 100;

                if (HasWriteToRCX(p - 48, p)) score += 12;
                if (HasWriteToEDX(p - 48, p)) score += 12;
                if (HasWriteToR8 (p - 48, p)) score += 12;

                if (LooksLikeResultUse(p + 5))
                    score += 25;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 100 ? best : null;
        }





        private static byte* FindExecuteDllForAttachCall(byte* start, byte* clrBase, int clrSize)
        {
            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < ExecuteDllScan - 5; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);

                if (target == IntPtr.Zero || !PointerHelpers.InsideModule((byte*)target.ToPointer(), clrBase, clrSize))
                {
                    continue;
                }

                bool rcx = HasWriteToRCX(p - 64, p);
                bool edx = HasWriteToEDX(p - 64, p);
                bool r8  = HasWriteToR8 (p - 64, p);
                bool r9  = HasWriteToR9 (p - 64, p);

                int score = 0;

                if (rcx) score += 30;
                if (edx) score += 30;
                if (r8)  score += 30;
                if (r9)  score += 30;

                if (rcx && edx && r8 && r9)
                    score += 100;

                if (LooksLikeResultUse(p + 5))
                    score += 35;

                if (HasWriteToRCX(p - 24, p)) score += 8;
                if (HasWriteToEDX(p - 24, p)) score += 8;
                if (HasWriteToR8 (p - 24, p)) score += 8;
                if (HasWriteToR9 (p - 24, p)) score += 8;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 220 ? best : null;
        }





        private static byte* FindCorExeMainInternalCall(byte* start, byte* clrBase, int clrSize)
        {
            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < CorMainScan - 8; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);

                if (target == IntPtr.Zero || !PointerHelpers.InsideModule((byte*)target.ToPointer(), clrBase, clrSize))
                {
                    continue;
                }

                int score = 0;







                if (HasSubRsp(p - 40, p))
                    score += 25;

                if (HasZeroStackLocal(p - 40, p))
                    score += 60;

                if (p[5] == 0xEB || p[5] == 0xE9)
                    score += 100;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 160 ? best : null;
        }





        private static byte* FindExecuteExeCall(byte* start, byte* clrBase, int clrSize)
        {
            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < CorExeMainInternalScan - 8; i++)
            {
                byte* p = start + i;

                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);

                if (target == IntPtr.Zero || !PointerHelpers.InsideModule((byte*)target.ToPointer(), clrBase, clrSize))
                {
                    continue;
                }

                int score = 0;






                if (p[-3] == 0x48 && p[-2] == 0x8B && p[-1] == 0xC8)
                {
                    score += 140;
                }

                if (p[5] == 0x85 && p[6] == 0xC0)
                {
                    score += 80;
                }

                if (p[7] == 0x0F)
                    score += 20;



                if (HasWriteToRCX(p - 20, p))
                    score += 30;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 220 ? best : null;
        }





        private static bool HasZeroR9D(byte* start, byte* end)
        {
            for (byte* p = start; p < end; p++)
            {
                if (p + 3 <= end && p[0] == 0x45 && (p[1] == 0x33 || p[1] == 0x31) && p[2] == 0xC9)
                {
                    return true;
                }

                if (p + 6 <= end && p[0] == 0x41 && p[1] == 0xB9 && Unsafe.ReadUnaligned<int>(p + 2) == 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasWriteToRCX(byte* start, byte* end)
        {
            for (byte* p = start; p < end; p++)
            {
                if (p + 3 <= end && p[0] == 0x48 && p[1] == 0x8B && ((p[2] >> 3) & 7) == 1)
                {
                    return true;
                }

                if (p + 2 <= end && p[0] == 0x8B && ((p[1] >> 3) & 7) == 1)
                {
                    return true;
                }

                if (p + 3 <= end && p[0] == 0x48 && p[1] == 0x8D && ((p[2] >> 3) & 7) == 1)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasWriteToEDX(byte* start, byte* end)
        {
            for (byte* p = start; p < end; p++)
            {
                if (p + 2 <= end && p[0] == 0x8B && ((p[1] >> 3) & 7) == 2)
                {
                    return true;
                }

                if (p + 3 <= end && (p[0] & 0xF0) == 0x40 && p[1] == 0x8B && ((p[2] >> 3) & 7) == 2)
                {
                    return true;
                }

                if (p + 5 <= end && p[0] == 0xBA)
                    return true;
            }

            return false;
        }

        private static bool HasWriteToR8(byte* start, byte* end)
        {
            for (byte* p = start; p < end; p++)
            {
                if (p + 3 <= end && (p[0] & 0xF4) == 0x44 && p[1] == 0x8B)
                {
                    int reg = ((p[2] >> 3) & 7) +
                        (((p[0] & 0x04) != 0) ? 8 : 0);

                    if (reg == 8)
                        return true;
                }

                if (p + 6 <= end && p[0] == 0x41 && p[1] == 0xB8)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasWriteToR9(byte* start, byte* end)
        {
            for (byte* p = start; p < end; p++)
            {
                if (p + 3 <= end && p[0] == 0x45 && (p[1] == 0x33 || p[1] == 0x31) && p[2] == 0xC9)
                {
                    return true;
                }

                if (p + 3 <= end && p[0] == 0x45 && p[1] == 0x8B && ((p[2] >> 3) & 7) == 1)
                {
                    return true;
                }

                if (p + 3 <= end && (p[0] & 0xF4) == 0x44 && p[1] == 0x8B)
                {
                    int reg = ((p[2] >> 3) & 7) +
                        (((p[0] & 0x04) != 0) ? 8 : 0);

                    if (reg == 9)
                        return true;
                }

                if (p + 6 <= end && p[0] == 0x41 && p[1] == 0xB9)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasSubRsp(byte* start, byte* end)
        {
            for (byte* p = start; p + 4 <= end; p++)
            {

                if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC)
                {
                    return true;
                }


                if (p + 7 <= end && p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasZeroStackLocal(byte* start, byte* end)
        {
            for (byte* p = start; p + 6 <= end; p++)
            {

                if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0x64 && p[3] == 0x24 && p[5] == 0x00)
                {
                    return true;
                }


                if (p[0] == 0x83 && p[1] == 0x64 && p[2] == 0x24 && p[4] == 0x00)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool LooksLikeResultUse(byte* p)
        {
            if (p[0] == 0x8B && (p[1] & 0x07) == 0)
                return true;

            if (p[0] == 0x89 && ((p[1] >> 3) & 7) == 0)
            {
                return true;
            }

            if (p[0] == 0x85 && p[1] == 0xC0)
                return true;

            if (p[0] == 0x3D || (p[0] == 0x83 && ((p[1] >> 3) & 7) == 7))
            {
                return true;
            }

            return false;
        }




    }
}
