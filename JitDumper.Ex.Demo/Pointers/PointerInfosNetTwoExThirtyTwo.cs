namespace LoaderExDemo
{
    /// <summary>
    /// CLR 2.x / 3.5 x86 primary execution-pointer resolver (mscorwks.dll).
    ///
    /// Existing resolver logic is preserved; only storage/dispatch is centralized.
    ///
    /// Resolves the NET2 equivalents of the primary NET4 execution chain:
    ///   _CorDllMain -> ExecuteDLL -> ExecuteDLLForAttach
    ///   _CorExeMain -> [_CorExeMainInternal when present] -> ExecuteEXE
    ///
    /// On CLR2 x86 some builds place ExecuteEXE directly in _CorExeMain.
    /// In that collapsed layout CorExeMainInternal is set to CorExeMain and
    /// CorExeMainInternalCall remains IntPtr.Zero (there is no separate callsite).
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR2 x86 execution pointers.")]
    internal static unsafe class PointerInfosNetTwoExThirtyTwo
    {
        private const int CorMainScan = 0x500;
        private const int InternalScan = 0x1800;
        internal static bool Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            if (IntPtr.Size != 4 || Environment.Version.Major != 2)
                throw new NotSupportedException("This resolver is for CLR 2.x x86 only.");

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

            byte* executeDllCall = FindExecuteDllCall((byte*)ptrs.CorDllMain.ToPointer());
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

        private static byte* FindExecuteDllCall(byte* start)
        {
            if (start == null)
                return null;







            for (int i = 16; i < CorMainScan - 8; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;

                if (IsKnownExecuteDllLayout(p))
                    return p;
            }


            for (int i = 16; i < CorMainScan - 8; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;

                if (p[-3] == 0xFF && p[-6] == 0xFF && p[-9] == 0xFF)
                {
                    return p;
                }
            }

            return null;
        }

        private static bool IsKnownExecuteDllLayout(byte* p)
        {
            bool registerPush = (p[-10] & 0xF8) == 0x50;

            return registerPush &&
                   p[-9] == 0xFF && p[-8] == 0x75 && p[-7] == 0x10 &&
                   p[-6] == 0xFF && p[-5] == 0x75 && p[-4] == 0x0C &&
                   p[-3] == 0xFF && p[-2] == 0x75 && p[-1] == 0x08;
        }

        private static byte* FindExecuteDllForAttachCall(byte* start, byte* moduleBase, int moduleSize)
        {




            var calls = PointerHelpers.GetReachableRel32Calls(start, moduleBase, moduleSize, false, 1024, 50000);

            byte* best = null;
            int bestScore = 0;

            for (int i = 0; i < calls.Count; i++)
            {
                byte* p = (byte*)calls[i].ToPointer();
                IntPtr target = PointerHelpers.ResolveRel32Call(p);

                if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                    continue;

                int score = 0;








                if (IsClr2ForwardedAttachLayout(p))
                    score += 500;



                if (IsFourPushLayout(p))             score += 120;
                if (IsLongLocalArgumentLayout(p))    score += 80;
                if (IsShortLocalArgumentLayout(p))   score += 70;
                if (IsLegacyAttachFallbackLayout(p)) score += 60;

                if (LooksLikeResultUse(p + 5))
                    score += 70;

                if (p[5] == 0x89 && p[6] == 0x45)
                    score += 90;

                if (HasEarlyBoolGate((byte*)target.ToPointer(), moduleBase, moduleSize))
                    score += 100;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = p;
                }
            }

            return bestScore >= 300 ? best : null;
        }

        private static bool IsClr2ForwardedAttachLayout(byte* p)
        {
            if (p == null)
                return false;

            return p[-10] == 0xFF && p[-9] == 0x75 && p[-8] == 0x14 &&
                   p[-7]  == 0xFF && p[-6] == 0x75 && p[-5] == 0x10 &&
                   p[-4]  == 0xFF && p[-3] == 0x75 && p[-2] == 0x0C &&
                   PointerHelpers.Is5x(p[-1]);
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
            return p[-6] == 0x8B && p[-5] == 0x8D;
        }

        private static bool IsShortLocalArgumentLayout(byte* p)
        {
            return p[-3] == 0x8B && p[-2] == 0x4D;
        }

        private static bool IsLegacyAttachFallbackLayout(byte* p)
        {
            return p[-12] == 0x8B &&
                   p[-1] == 0x95 &&
                   p[5] == 0x8B &&
                   p[6] == 0xF0;
        }





        private static bool ResolveExePointers(PointerInfosBase ptrs, IntPtr mscorwks, byte* moduleBase, int moduleSize)
        {
            ptrs.CorExeMain = NativeMethods.GetProcAddress(mscorwks, "_CorExeMain");
            if (ptrs.CorExeMain == IntPtr.Zero)
                return false;

            byte* corExe = (byte*)ptrs.CorExeMain.ToPointer();




            byte* directExecute = FindExecuteExeCall(corExe, CorMainScan);
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

                IntPtr target = PointerHelpers.ResolveRel32Call(p);
                if (!PointerHelpers.InsideModule(target, moduleBase, moduleSize))
                    continue;

                byte* executeCall = FindExecuteExeCall((byte*)target.ToPointer(), InternalScan);

                if (executeCall == null)
                    continue;

                int score = 200;



                if (p[5] == 0xEB || p[5] == 0xE9)
                    score += 30;

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

        private static byte* FindExecuteExeCall(byte* start, int requestedScan)
        {
            if (start == null)
                return null;

            for (int i = 8; i < requestedScan - 8; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;





                bool oldLayout = p[-1] == 0x50 &&
                    p[5] == 0x3B &&
                    p[6] == 0xC3;





                bool newerLayout = p[-2] == 0x8B &&
                    p[-1] == 0xC8 &&
                    p[5] == 0x85 &&
                    p[6] == 0xC0;

                if (oldLayout || newerLayout)
                    return p;
            }

            return null;
        }





        private static bool HasEarlyBoolGate(byte* start, byte* moduleBase, int moduleSize)
        {
            int max = PointerHelpers.ClampScan(start, 0x180, moduleBase, moduleSize);

            for (int i = 0; i < max - 12; i++)
            {
                byte* p = start + i;
                if (p[0] != 0xE8)
                    continue;


                for (int j = 5; j <= 14 && i + j + 4 < max; j++)
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

        private static bool LooksLikeResultUse(byte* p)
        {
            if (p == null)
                return false;

            if (p[0] == 0x8B && p[1] == 0xF0) return true;
            if (p[0] == 0x85 && p[1] == 0xC0) return true;
            if (p[0] == 0x89 && (p[1] == 0x45 || p[1] == 0x85)) return true;
            if (p[0] == 0x3B && p[1] == 0xC3) return true;

            return false;
        }
    }
}
