using HelperClass.Unsafe.JitTools;
using Microsoft.Extensions.Logging;
using System.Runtime.CompilerServices;

namespace LoaderExDemo
{
    /// <summary>
    /// CLR 2.x / 3.5 x64 primary execution-pointer resolver (mscorwks.dll).
    ///
    /// Existing resolver logic is preserved; only storage/dispatch is centralized.
    ///
    /// Resolves the NET2 equivalents of the primary NET4 execution chain:
    ///   _CorDllMain -> ExecuteDLL -> ExecuteDLLForAttach
    ///   _CorExeMain -> [_CorExeMainInternal when present] -> ExecuteEXE
    ///
    /// No fixed RVAs are used.
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR2 x64 execution pointers.")]
    internal static unsafe class PointerInfosNetTwoExSixtyFour
    {
        private const int CorMainScan = 0x900;
        private const int InternalScan = 0x3000;
        internal static bool Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            if (IntPtr.Size != 8 || Environment.Version.Major != 2)
                throw new NotSupportedException("This resolver is for CLR 2.x x64 only.");

            IntPtr mscorwks = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (mscorwks == IntPtr.Zero)
                return false;

            byte* moduleBase = (byte*)mscorwks.ToPointer();
            int moduleSize = PointerHelpers.GetImageSize(moduleBase);
            if (moduleSize <= 0)
                return false;

            bool dllOk = ResolveDllPointers(ptrs, mscorwks, moduleBase, moduleSize);
            bool exeOk = ResolveExePointers(ptrs, mscorwks, moduleBase, moduleSize);

            return dllOk && exeOk;
        }

        internal static bool ResolveDllPointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr mscorwks = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (mscorwks == IntPtr.Zero)
                return false;

            byte* moduleBase = (byte*)mscorwks.ToPointer();
            int moduleSize = PointerHelpers.GetImageSize(moduleBase);

            return moduleSize > 0 && ResolveDllPointers(ptrs, mscorwks, moduleBase, moduleSize);
        }

        internal static bool ResolveExePointers(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            IntPtr mscorwks = NativeMethods.LoadLibrary(MemoryView._clrLib);
            if (mscorwks == IntPtr.Zero)
                return false;

            byte* moduleBase = (byte*)mscorwks.ToPointer();
            int moduleSize = PointerHelpers.GetImageSize(moduleBase);

            return moduleSize > 0 && ResolveExePointers(ptrs, mscorwks, moduleBase, moduleSize);
        }





        private static bool ResolveDllPointers(PointerInfosBase ptrs, IntPtr mscorwks, byte* moduleBase, int moduleSize)
        {
            ptrs.CorDllMain = NativeMethods.GetProcAddress(mscorwks, "_CorDllMain");
            if (ptrs.CorDllMain == IntPtr.Zero)
                return false;

            byte* executeDllCall = FindExecuteDllCall((byte*)ptrs.CorDllMain.ToPointer(), moduleBase, moduleSize);

            if (executeDllCall == null)
                return false;

            ptrs.ExecuteDLLCall = (IntPtr)executeDllCall;
            ptrs.ExecuteDLL = PointerHelpers.ResolveRel32Call(executeDllCall);

            if (!PointerHelpers.InsideModule(ptrs.ExecuteDLL, moduleBase, moduleSize))
                return false;

            byte* attachCall = FindExecuteDllForAttachCall((byte*)ptrs.ExecuteDLL.ToPointer(), moduleBase, moduleSize);

            if (attachCall == null)
                return false;

            ptrs.ExecuteDLLForAttachCall = (IntPtr)attachCall;
            ptrs.ExecuteDLLForAttach = PointerHelpers.ResolveRel32Call(attachCall);

            return PointerHelpers.InsideModule(ptrs.ExecuteDLLForAttach, moduleBase, moduleSize);
        }

        private static byte* FindExecuteDllCall(byte* start, byte* moduleBase, int moduleSize)
        {
            byte* best = null;
            int bestScore = 0;
            int max = PointerHelpers.ClampScan(start, CorMainScan, moduleBase, moduleSize);

            for (int i = 0; i < max - 5; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);
                if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                    continue;

                int score = 0;


                if (HasZeroR9D(PointerHelpers.ClampBackward(p, 64, moduleBase), p)) score += 180;
                if (HasWriteToRCX(PointerHelpers.ClampBackward(p, 64, moduleBase), p)) score += 35;
                if (HasWriteToEDX(PointerHelpers.ClampBackward(p, 64, moduleBase), p)) score += 35;
                if (HasWriteToR8(PointerHelpers.ClampBackward(p, 64, moduleBase), p)) score += 35;
                if (LooksLikeResultUse(p + 5, moduleBase, moduleSize)) score += 45;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 260 ? best : null;
        }

        private static byte* FindExecuteDllForAttachCall(byte* start, byte* moduleBase, int moduleSize)
        {



            var calls = PointerHelpers.GetReachableRel32Calls(start, moduleBase, moduleSize, true, 4096, 160000);

            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < calls.Count; i++)
            {
                byte* p = (byte*)calls[i].ToPointer();
                int score = ScoreExecuteDllForAttachCall(p, moduleBase, moduleSize, true);

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            if (best != null && bestScore >= 430)
                return best;







            ThisStaticClass.Logger.LogInformation("[NET2:X64:DLL] Reachable CFG did not prove ExecuteDLLForAttach; using executable-section semantic fallback.");

            byte* fallback = FindExecuteDllForAttachCallInExecutableSections(moduleBase, moduleSize);

            if (fallback != null)
            {
                IntPtr target = PointerHelpers.ResolveRel32Call(fallback);
                ThisStaticClass.Logger.LogInformation("[NET2:X64:DLL] Semantic fallback selected CALL=0x{CallSite:X16} TARGET=0x{Target:X16}", ((IntPtr)fallback).ToInt64(), target.ToInt64());
            }

            return fallback;
        }

        private static int ScoreExecuteDllForAttachCall(byte* p, byte* moduleBase, int moduleSize, bool reachableFromExecuteDll)
        {
            if (p == null || p[0] != 0xE8)
                return 0;

            IntPtr target = PointerHelpers.ResolveRel32Call(p);
            if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                return 0;

            byte* before96 = PointerHelpers.ClampBackward(p, 96, moduleBase);
            byte* before40 = PointerHelpers.ClampBackward(p, 40, moduleBase);

            bool rcxWide = HasWriteToRCX(before96, p);
            bool edxWide = HasWriteToEDX(before96, p);
            bool r8Wide = HasWriteToR8(before96, p);
            bool r9Wide = HasWriteToR9(before96, p);

            int nearArgs = 0;
            if (HasWriteToRCX(before40, p)) nearArgs++;
            if (HasWriteToEDX(before40, p)) nearArgs++;
            if (HasWriteToR8(before40, p)) nearArgs++;
            if (HasWriteToR9(before40, p)) nearArgs++;

            int score = 0;

            if (reachableFromExecuteDll)
                score += 80;

            if (rcxWide) score += 30;
            if (edxWide) score += 30;
            if (r8Wide) score += 30;
            if (r9Wide) score += 30;

            if (rcxWide && edxWide && r8Wide && r9Wide)
                score += 110;

            score += nearArgs * 35;
            if (nearArgs == 4)
                score += 100;

            if (LooksLikeResultUse(p + 5, moduleBase, moduleSize))
                score += 80;



            if (p - moduleBase >= 17 && moduleBase + moduleSize - p >= 8 && IsKnownClr2X64AttachLayout(p))
            {
                score += 180;
            }

            int bodyScore = ScoreExecuteDllForAttachBody((byte*)target.ToPointer(), moduleBase, moduleSize);




            score += bodyScore;

            return score;
        }

        private static byte* FindExecuteDllForAttachCallInExecutableSections(byte* moduleBase, int moduleSize)
        {
            if (moduleBase == null || moduleSize <= 0)
                return null;

            int e_lfanew = Unsafe.ReadUnaligned<int>(moduleBase + 0x3C);
            if (e_lfanew <= 0 || e_lfanew >= moduleSize - 0x100)
                return null;

            byte* nt = moduleBase + e_lfanew;
            if (Unsafe.ReadUnaligned<uint>(nt) != 0x00004550)
                return null;

            ushort numberOfSections = Unsafe.ReadUnaligned<ushort>(nt + 6);
            ushort optionalHeaderSize = Unsafe.ReadUnaligned<ushort>(nt + 20);
            byte* section = nt + 24 + optionalHeaderSize;

            byte* best = null;
            int bestScore = 0;

            const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

            for (int s = 0; s < numberOfSections; s++, section += 40)
            {
                uint virtualSize = Unsafe.ReadUnaligned<uint>(section + 8);
                uint virtualAddress = Unsafe.ReadUnaligned<uint>(section + 12);
                uint rawSize = Unsafe.ReadUnaligned<uint>(section + 16);
                uint characteristics = Unsafe.ReadUnaligned<uint>(section + 36);

                if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                    continue;

                uint sectionSize = virtualSize > rawSize ? virtualSize : rawSize;
                if (sectionSize < 8 || virtualAddress >= (uint)moduleSize)
                    continue;

                ulong remaining = (ulong)moduleSize - virtualAddress;
                if ((ulong)sectionSize > remaining)
                    sectionSize = (uint)remaining;

                byte* begin = moduleBase + (int)virtualAddress;
                byte* end = begin + (int)sectionSize;

                for (byte* p = begin; p + 8 < end; p++)
                {
                    if (p[0] != 0xE8)
                        continue;

                    IntPtr target = PointerHelpers.ResolveRel32Call(p);
                    if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                        continue;


                    byte* before48 = PointerHelpers.ClampBackward(p, 48, moduleBase);
                    int argWrites = 0;
                    if (HasWriteToRCX(before48, p)) argWrites++;
                    if (HasWriteToEDX(before48, p)) argWrites++;
                    if (HasWriteToR8(before48, p)) argWrites++;
                    if (HasWriteToR9(before48, p)) argWrites++;

                    if (argWrites < 3)
                        continue;

                    int bodyScore = ScoreExecuteDllForAttachBody((byte*)target.ToPointer(), moduleBase, moduleSize);



                    if (bodyScore < 360)
                        continue;

                    int score = ScoreExecuteDllForAttachCall(p, moduleBase, moduleSize, false);

                    if (score > bestScore)
                    {
                        bestScore = score;
                        best = p;
                    }
                }
            }

            return bestScore >= 560 ? best : null;
        }

        private static int ScoreExecuteDllForAttachBody(byte* start, byte* moduleBase, int moduleSize)
        {
            if (!PointerHelpers.InsideModule(start, moduleBase, moduleSize))
                return 0;

            int max = PointerHelpers.ClampScan(start, 0x320, moduleBase, moduleSize);
            if (max < 32)
                return 0;

            LdasmWWh ldasm = new();
            byte* p = start;
            byte* end = start + max;
            int instructions = 0;
            int directCalls = 0;
            int gatedCalls = 0;
            int firstGatedOffset = -1;

            while (p < end && instructions < 180)
            {
                uint length;
                try
                {
                    length = ldasm.Disassemble(p, true);
                }
                catch
                {
                    break;
                }

                if (length == 0 || length > 15 || p + (int)length > end)
                    break;

                if (p[0] == 0xE8 && length == 5)
                {
                    IntPtr target = PointerHelpers.ResolveRel32Call(p);
                    if (PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                    {
                        directCalls++;

                        if (HasEaxResultGateAfterCall(p + 5, end, moduleBase, moduleSize))
                        {
                            gatedCalls++;
                            if (firstGatedOffset < 0)
                                firstGatedOffset = (int)(p - start);
                        }
                    }
                }





                if (p[0] == 0xC3 || p[0] == 0xC2 || p[0] == 0xCC)
                    break;

                p += (int)length;
                instructions++;
            }

            int score = 0;

            if (directCalls >= 3) score += 80;
            else if (directCalls >= 2) score += 30;

            if (gatedCalls >= 1) score += 110;
            if (gatedCalls >= 2) score += 300;
            if (gatedCalls >= 3) score += 80;

            if (firstGatedOffset >= 0 && firstGatedOffset <= 0x120)
                score += 50;

            return score;
        }

        private static bool HasEaxResultGateAfterCall(byte* start, byte* hardEnd, byte* moduleBase, int moduleSize)
        {
            if (!PointerHelpers.InsideModule(start, moduleBase, moduleSize))
                return false;

            byte* end = start + 48;
            if (end > hardEnd)
                end = hardEnd;
            if (end > moduleBase + moduleSize)
                end = moduleBase + moduleSize;

            LdasmWWh ldasm = new();
            byte* p = start;
            bool sawEaxCondition = false;
            int instructions = 0;

            while (p < end && instructions < 10)
            {
                uint length;
                try
                {
                    length = ldasm.Disassemble(p, true);
                }
                catch
                {
                    return false;
                }

                if (length == 0 || length > 15 || p + (int)length > end)
                    return false;

                if (IsEaxConditionInstruction(p, (int)length))
                {
                    sawEaxCondition = true;
                }
                else if (sawEaxCondition && IsConditionalBranchInstruction(p, (int)length))
                {
                    return true;
                }
                else if (p[0] == 0xE8 || p[0] == 0xC3 || p[0] == 0xC2)
                {


                    return false;
                }

                p += (int)length;
                instructions++;
            }

            return false;
        }

        private static bool IsEaxConditionInstruction(byte* p, int length)
        {
            if (p == null || length <= 0)
                return false;

            byte* q = p;
            int remaining = length;



            if (remaining > 1 && q[0] >= 0x40 && q[0] <= 0x4F)
            {
                q++;
                remaining--;
            }

            if (remaining >= 2)
            {
                byte op = q[0];
                byte modrm = q[1];


                if (op == 0x85 && modrm == 0xC0)
                    return true;


                if ((op == 0x0B || op == 0x09) && modrm == 0xC0)
                    return true;


                if (op == 0x3B && (modrm & 0xC0) == 0xC0 && ((modrm >> 3) & 7) == 0)
                {
                    return true;
                }


                if (op == 0x39 && (modrm & 0xC0) == 0xC0 && (modrm & 7) == 0)
                {
                    return true;
                }


                if (remaining >= 3 && op == 0x83 && modrm == 0xF8)
                    return true;
            }


            if (remaining >= 5 && q[0] == 0x3D)
                return true;

            return false;
        }

        private static bool IsConditionalBranchInstruction(byte* p, int length)
        {
            if (p == null || length <= 0)
                return false;

            if (p[0] >= 0x70 && p[0] <= 0x7F)
                return true;

            return length >= 2 &&
                   p[0] == 0x0F &&
                   p[1] >= 0x80 && p[1] <= 0x8F;
        }

        private static bool IsKnownClr2X64AttachLayout(byte* p)
        {
            if (p == null)
                return false;








            return p[-17] == 0x44 && p[-16] == 0x8B && p[-15] == 0xCE &&
                   p[-14] == 0x4C && p[-13] == 0x8B && p[-12] == 0x84 && p[-11] == 0x24 &&
                   p[-6] == 0x41 && p[-5] == 0x8B && p[-4] == 0xD5 &&
                   p[-3] == 0x49 && p[-2] == 0x8B && p[-1] == 0xCF &&
                   p[5] == 0x44 && p[6] == 0x8B && p[7] == 0xE0;
        }





        private static bool ResolveExePointers(PointerInfosBase ptrs, IntPtr mscorwks, byte* moduleBase, int moduleSize)
        {
            ptrs.CorExeMain = NativeMethods.GetProcAddress(mscorwks, "_CorExeMain");
            if (ptrs.CorExeMain == IntPtr.Zero)
                return false;

            byte* corExe = (byte*)ptrs.CorExeMain.ToPointer();


            byte* directExecute = FindExecuteExeCall(corExe, CorMainScan, moduleBase, moduleSize);

            if (directExecute != null)
            {
                ptrs.CorExeMainInternalCall = IntPtr.Zero;
                ptrs.CorExeMainInternal = ptrs.CorExeMain;

                ptrs.ExecuteEXECall = (IntPtr)directExecute;
                ptrs.ExecuteEXE = PointerHelpers.ResolveRel32Call(directExecute);

                return PointerHelpers.InsideModule(ptrs.ExecuteEXE, moduleBase, moduleSize);
            }



            byte* bestInternalCall = null;
            byte* bestExecuteCall = null;
            int bestScore = 0;

            int max = PointerHelpers.ClampScan(corExe, CorMainScan, moduleBase, moduleSize);

            for (int i = 0; i < max - 5; i++)
            {
                byte* p = corExe + i;
                if (p[0] != 0xE8)
                    continue;

                IntPtr wrapper = PointerHelpers.ResolveRel32Call(p);
                if (!PointerHelpers.InsideModule(wrapper, moduleBase, moduleSize))
                    continue;

                byte* executeCall = FindExecuteExeCall((byte*)wrapper.ToPointer(), InternalScan, moduleBase, moduleSize);

                if (executeCall == null)
                    continue;

                int score = 220;

                if (HasSubRsp(PointerHelpers.ClampBackward(p, 40, moduleBase), p))
                    score += 25;

                if (HasZeroStackLocal(PointerHelpers.ClampBackward(p, 40, moduleBase), p))
                    score += 55;

                if (p[5] == 0xEB || p[5] == 0xE9)
                    score += 60;

                if (score > bestScore)
                {
                    bestScore = score;
                    bestInternalCall = p;
                    bestExecuteCall = executeCall;
                }
            }

            if (bestInternalCall == null || bestExecuteCall == null)
                return false;

            ptrs.CorExeMainInternalCall = (IntPtr)bestInternalCall;
            ptrs.CorExeMainInternal = PointerHelpers.ResolveRel32Call(bestInternalCall);

            ptrs.ExecuteEXECall = (IntPtr)bestExecuteCall;
            ptrs.ExecuteEXE = PointerHelpers.ResolveRel32Call(bestExecuteCall);

            return PointerHelpers.InsideModule(ptrs.CorExeMainInternal, moduleBase, moduleSize) &&
                   PointerHelpers.InsideModule(ptrs.ExecuteEXE, moduleBase, moduleSize);
        }

        private static byte* FindExecuteExeCall(byte* start, int requestedScan, byte* moduleBase, int moduleSize)
        {
            byte* best = null;
            int bestScore = 0;
            int max = PointerHelpers.ClampScan(start, requestedScan, moduleBase, moduleSize);

            for (int i = 0; i < max - 8; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;

                IntPtr target = PointerHelpers.ResolveRel32Call(p);
                if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                    continue;

                int score = 0;








                if (p - moduleBase >= 12 && p[-3] == 0x48 && p[-2] == 0x0B && p[-1] == 0xC0 && p[5] == 0x85 && p[6] == 0xC0)
                {
                    score += 210;
                }





                if (p - moduleBase >= 3 && p[-3] == 0x48 && p[-2] == 0x8B && p[-1] == 0xC8)
                {
                    score += 150;
                }

                if (p[5] == 0x85 && p[6] == 0xC0)
                    score += 85;

                if (HasWriteToRCX(PointerHelpers.ClampBackward(p, 28, moduleBase), p))
                    score += 45;


                byte* before = PointerHelpers.ClampBackward(p, 48, moduleBase);
                if (HasZeroR9D(before, p) && HasWriteToEDX(before, p) && HasWriteToR8(before, p))
                {
                    score -= 130;
                }

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
                    return true;

                if (p + 6 <= end && p[0] == 0x41 && p[1] == 0xB9 && Unsafe.ReadUnaligned<int>(p + 2) == 0)
                    return true;
            }

            return false;
        }

        private static bool HasWriteToRCX(byte* start, byte* end)
        {
            return HasWriteToRegister(start, end, 1);
        }

        private static bool HasWriteToEDX(byte* start, byte* end)
        {
            return HasWriteToRegister(start, end, 2);
        }

        private static bool HasWriteToR8(byte* start, byte* end)
        {
            return HasWriteToRegister(start, end, 8);
        }

        private static bool HasWriteToR9(byte* start, byte* end)
        {
            return HasWriteToRegister(start, end, 9);
        }

        private static bool HasWriteToRegister(byte* start, byte* end, int targetRegister)
        {
            if (start == null || end == null || start >= end)
                return false;

            for (byte* p = start; p < end; p++)
            {
                byte* q = p;
                byte rex = 0;

                if (q[0] >= 0x40 && q[0] <= 0x4F)
                {
                    rex = q[0];
                    q++;
                    if (q >= end)
                        continue;
                }

                byte op = q[0];


                if ((op == 0x8B || op == 0x8D) && q + 1 < end)
                {
                    byte modrm = q[1];
                    int reg = (modrm >> 3) & 7;
                    if ((rex & 0x04) != 0)
                        reg += 8;

                    if (reg == targetRegister)
                        return true;
                }



                if ((op == 0x31 || op == 0x33) && q + 1 < end)
                {
                    byte modrm = q[1];
                    if ((modrm & 0xC0) == 0xC0)
                    {
                        int regField = (modrm >> 3) & 7;
                        int rmField = modrm & 7;

                        if ((rex & 0x04) != 0) regField += 8;
                        if ((rex & 0x01) != 0) rmField += 8;

                        if (regField == rmField && regField == targetRegister)
                            return true;
                    }
                }


                if (op >= 0xB8 && op <= 0xBF)
                {
                    int reg = op - 0xB8;
                    if ((rex & 0x01) != 0)
                        reg += 8;

                    if (reg == targetRegister)
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
                    return true;

                if (p + 7 <= end && p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC)
                    return true;
            }

            return false;
        }

        private static bool HasZeroStackLocal(byte* start, byte* end)
        {
            for (byte* p = start; p + 5 <= end; p++)
            {

                if (p[0] == 0x83 && p[1] == 0x64 && p[2] == 0x24 && p[4] == 0x00)
                    return true;


                if (p + 6 <= end && p[0] == 0x48 && p[1] == 0x83 && p[2] == 0x64 && p[3] == 0x24 && p[5] == 0x00)
                    return true;
            }

            return false;
        }

        private static bool HasEarlyBoolGate(byte* start, byte* moduleBase, int moduleSize)
        {
            int max = PointerHelpers.ClampScan(start, 0x200, moduleBase, moduleSize);

            for (int i = 0; i < max - 16; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;

                for (int j = 5; j <= 18 && i + j + 4 < max; j++)
                {
                    byte* q = p + j;

                    if (q[0] == 0x85 && q[1] == 0xC0)
                    {
                        byte op = q[2];
                        if ((op >= 0x70 && op <= 0x7F) || op == 0x0F)
                            return true;
                    }







                    if (j >= 7)
                    {
                        byte* z = q - 2;
                        if ((z[0] == 0x33 || z[0] == 0x31) && (z[1] & 0xC0) == 0xC0 && q[0] == 0x3B && (q[1] & 0xF8) == 0xC0)
                        {
                            byte op = q[2];
                            if ((op >= 0x70 && op <= 0x7F) || op == 0x0F)
                                return true;
                        }
                    }
                }
            }

            return false;
        }

        private static bool LooksLikeResultUse(byte* p, byte* moduleBase, int moduleSize)
        {
            if (p == null || p < moduleBase || p >= moduleBase + moduleSize)
                return false;

            if (p[0] == 0x85 && p[1] == 0xC0) return true;
            if (p[0] == 0x89) return true;
            if (p[0] == 0x8B) return true;
            if (p[0] == 0x3B) return true;



            if (p[0] >= 0x40 && p[0] <= 0x4F && p[1] == 0x8B && (p[2] & 0xC7) == 0xC0)
            {
                return true;
            }

            if (p[0] == 0xEB || p[0] == 0xE9) return true;

            return false;
        }




    }
}
