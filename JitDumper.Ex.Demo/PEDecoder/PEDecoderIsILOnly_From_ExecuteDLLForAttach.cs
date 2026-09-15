using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LoaderExDemo
{
        /// <summary>
        /// Common PEDecoder::IsILOnly resolver without Iced.
        ///
        /// Anchor:
        ///     existing _ExecuteDLLForAttach_Call
        ///
        /// No PDB.
        /// No fixed CLR RVA/version table.
        /// No whole clr.dll scan.
        /// No external disassembler dependency.
        ///
        /// The resolver scans only a small ExecuteDLLForAttach window for direct
        /// CALL rel32 instructions. Every target is then validated against the
        /// real PEDecoder::IsILOnly semantic:
        ///
        ///     GetCorHeader()->Flags & COMIMAGE_FLAGS_ILONLY
        ///
        /// IMAGE_COR20_HEADER.Flags = +0x10
        /// COMIMAGE_FLAGS_ILONLY    = 1
        ///
        /// Supports x86 and x64.
        /// </summary>
        [HelperClass.SomeElementsInfos("Finds IsILOnly from ExecuteDLLForAttach.")]
        internal static unsafe class PEDecoderIsILOnlyFromAttach
        {
            private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

            private const int ATTACH_SCAN_BYTES = 0x700;
            private const int TARGET_SCAN_BYTES = 0x120;

            private const long COR20_FLAGS_OFFSET = 0x10;
            private const ulong COMIMAGE_FLAGS_ILONLY = 1;

            private static readonly SearchValues<byte> PaddingBytes =
                SearchValues.Create((byte)0x90, (byte)0xCC);

            public static IntPtr ExecuteDLLForAttach { get; private set; }
            public static IntPtr IsILOnlyCallSite { get; private set; }
            public static IntPtr PEDecoderIsILOnly { get; private set; }
            public static IntPtr ResultCheck { get; private set; }
            public static IntPtr ResultJcc { get; private set; }

            public static int CallsChecked { get; private set; }
            public static int Candidates { get; private set; }
            public static int BestScore { get; private set; }

            private readonly struct Section(ulong start, ulong end)
            {
                public ulong Start { get; } = start;
                public ulong End { get; } = end;
            }

            private readonly struct Candidate(ulong anchor, ulong callSite, ulong target, int score)
            {
                public ulong Anchor { get; } = anchor;
                public ulong CallSite { get; } = callSite;
                public ulong Target { get; } = target;
                public int Score { get; } = score;
            }

            /// <summary>
            /// Stack-only view over the bounded native-code snapshot used by the
            /// semantic decoder. Keeping the reader ref-like prevents the scan
            /// window from escaping into heap state while centralizing bounds and
            /// little-endian scalar reads.
            /// </summary>
            private readonly ref struct CodeReader(ReadOnlySpan<byte> code)
            {
                private readonly ReadOnlySpan<byte> _code = code;

                public int Length => _code.Length;

                public byte this[int index] => _code[index];

                public bool Has(int offset, int length)
                {
                    return offset >= 0 &&
                           length >= 0 &&
                           offset <= _code.Length - length;
                }

                public int ReadInt32(int offset)
                {
                    return BinaryPrimitives.ReadInt32LittleEndian(_code.Slice(offset, sizeof(int)));
                }

                public uint ReadUInt32(int offset)
                {
                    return BinaryPrimitives.ReadUInt32LittleEndian(_code.Slice(offset, sizeof(uint)));
                }
            }















            [HelperClass.SomeElementsInfos("Scores and resolves the IsILOnly target.")]
            public static IntPtr Resolve(IntPtr executeDLLForAttachCall)
            {
                Reset();

                if (executeDLLForAttachCall == IntPtr.Zero)
                    return IntPtr.Zero;

                IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);

                if (clr == IntPtr.Zero)
                    return IntPtr.Zero;

                bool is64;
                ImmutableArray<Section> sections;

                if (!ReadExecutableSections(clr, out is64, out sections))
                {
                    return IntPtr.Zero;
                }

                if ((IntPtr.Size == 8) != is64)
                    return IntPtr.Zero;

                ulong input = PtrToUInt64(executeDLLForAttachCall);

                if (!IsExecutable(sections, input))
                {
                    return IntPtr.Zero;
                }

                List<ulong> anchors = [];


                AddAnchor(anchors, input, sections);


                TryAddCallTarget(anchors, input, sections);


                if (input > 0)
                {
                    TryAddCallTarget(anchors, input - 1, sections);
                }


                if (input >= 5)
                {
                    TryAddCallTarget(anchors, input - 5, sections);
                }


                if (!is64)
                {
                    ulong x86Start = FindLikelyX86FunctionStart(input, sections);

                    AddAnchor(anchors, x86Start, sections);
                }

                List<Candidate> found = [];

                for (int i = 0; i < anchors.Count; i++)
                {
                    ScanAttach(anchors[i], sections, is64, found);
                }

                if (found.Count == 0)
                    return IntPtr.Zero;


                Dictionary<ulong, Candidate> unique = [];

                for (int i = 0; i < found.Count; i++)
                {
                    Candidate c = found[i];
                    Candidate old;

                    if (!unique.TryGetValue(c.Target, out old) || c.Score > old.Score)
                    {
                        unique[c.Target] = c;
                    }
                }

                List<Candidate> list = new List<Candidate>(unique.Values);

                Candidates = list.Count;

                list.Sort(delegate (Candidate a, Candidate b) { return b.Score.CompareTo(a.Score); });

                Candidate best = list[0];


                if (best.Score < 180)
                    return IntPtr.Zero;


                if (list.Count > 1 && list[1].Score >= best.Score - 12)
                {
                    return IntPtr.Zero;
                }

                ExecuteDLLForAttach = ToIntPtr(best.Anchor);

                PEDecoderIsILOnly = ToIntPtr(best.Target);





                ulong boundedCallSite = FindCallSiteInsideAttachAnchors(anchors, best.Target, sections);

                IsILOnlyCallSite = boundedCallSite != 0 ? ToIntPtr(boundedCallSite) : ToIntPtr(best.CallSite);











                ulong resultCheck;
                ulong resultJcc;

                if (FindBoolResultGateInsideAttachAnchors(anchors, PtrToUInt64(IsILOnlyCallSite), sections, out resultCheck, out resultJcc))
                {
                    ResultCheck = ToIntPtr(resultCheck);
                    ResultJcc = ToIntPtr(resultJcc);
                }

                BestScore = best.Score;

                return PEDecoderIsILOnly;
            }

            private static void Reset()
            {
                ExecuteDLLForAttach = IntPtr.Zero;
                IsILOnlyCallSite = IntPtr.Zero;
                PEDecoderIsILOnly = IntPtr.Zero;
                ResultCheck = IntPtr.Zero;
                ResultJcc = IntPtr.Zero;

                CallsChecked = 0;
                Candidates = 0;
                BestScore = 0;
            }





            private static void ScanAttach(ulong anchor, ImmutableArray<Section> sections, bool is64, List<Candidate> output)
            {
                Section section;

                if (!TryGetContainingSection(sections, anchor, out section))
                {
                    return;
                }

                int count = checked((int)Math.Min((ulong)ATTACH_SCAN_BYTES, section.End - anchor));

                if (count < 5)
                    return;

                byte[] rented = ArrayPool<byte>.Shared.Rent(count);
                try
                {
                    Marshal.Copy(ToIntPtr(anchor), rented, 0, count);
                    ReadOnlySpan<byte> bytes = rented.AsSpan(0, count);




                    for (int i = 0; i <= bytes.Length - 5; i++)
                    {
                        if (bytes[i] != 0xE8)
                            continue;

                        ulong callSite = anchor + (uint)i;
                        int rel = ReadInt32LittleEndian(bytes, i + 1);
                        ulong target = AddSigned(callSite + 5, rel);

                        if (!IsExecutable(sections, target))
                            continue;

                        target = FollowJumpThunk(target, sections, is64);
                        if (!IsExecutable(sections, target))
                            continue;

                        CallsChecked++;
                        int score = ValidateIsILOnlyBody(target, sections, is64);
                        if (score <= 0)
                            continue;



                        score += ScoreCallResultContext(bytes, i + 5);
                        output.Add(new Candidate(anchor, callSite, target, score));
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            private static int ScoreCallResultContext(ReadOnlySpan<byte> bytes, int offset)
            {
                int checkOffset;
                int jccOffset;

                if (!TryFindBoolResultGate(bytes, offset, Math.Min(bytes.Length, offset + 24), out checkOffset, out jccOffset))
                {
                    return 0;
                }

                int score = 35;


                int distance = checkOffset - offset;
                if (distance <= 2)
                    score += 25;
                else if (distance <= 8)
                    score += 18;
                else
                    score += 8;

                if (jccOffset >= 0)
                    score += 20;

                return score;
            }













            private static bool TryFindBoolResultGate(ReadOnlySpan<byte> bytes, int start, int end, out int checkOffset, out int jccOffset)
            {
                checkOffset = -1;
                jccOffset = -1;

                if (start < 0 || start >= bytes.Length)
                    return false;

                if (end > bytes.Length)
                    end = bytes.Length;

                int p = SkipPadding(bytes, start, end);






                if (p + 4 <= end && (bytes[p] == 0x31 || bytes[p] == 0x33))
                {
                    byte xorModRm = bytes[p + 1];
                    int mod = (xorModRm >> 6) & 3;
                    int reg = (xorModRm >> 3) & 7;
                    int rm = xorModRm & 7;

                    if (mod == 3 && reg == rm)
                    {
                        int q = p + 2;

                        if (q + 2 <= end && bytes[q] == 0x3B)
                        {
                            byte cmpModRm = bytes[q + 1];
                            int cmpMod = (cmpModRm >> 6) & 3;
                            int cmpDst = (cmpModRm >> 3) & 7;
                            int cmpSrc = cmpModRm & 7;

                            if (cmpMod == 3 && cmpDst == 0 && cmpSrc == reg)
                            {
                                checkOffset = q;
                                q += 2;

                                if (TryFindImmediateJcc(bytes, q, end, out jccOffset))
                                    return true;

                                return true;
                            }
                        }
                    }
                }


                int limit = Math.Min(end, p + 12);

                for (int i = p; i < limit; i++)
                {
                    int used = 0;


                    if (i + 2 <= end && bytes[i] == 0x85 && bytes[i + 1] == 0xC0)
                    {
                        used = 2;
                    }

                    else if (i + 2 <= end && bytes[i] == 0x84 && bytes[i + 1] == 0xC0)
                    {
                        used = 2;
                    }

                    else if (i + 2 <= end && (bytes[i] == 0x09 || bytes[i] == 0x0B) && bytes[i + 1] == 0xC0)
                    {
                        used = 2;
                    }

                    else if (i + 3 <= end && bytes[i] == 0x83 && bytes[i + 1] == 0xF8 && bytes[i + 2] == 0x00)
                    {
                        used = 3;
                    }

                    else if (i + 5 <= end && bytes[i] == 0x3D && ReadInt32LittleEndian(bytes, i + 1) == 0)
                    {
                        used = 5;
                    }

                    if (used == 0)
                        continue;

                    checkOffset = i;
                    TryFindImmediateJcc(bytes, i + used, end, out jccOffset);
                    return true;
                }

                return false;
            }

            private static bool TryFindImmediateJcc(ReadOnlySpan<byte> bytes, int offset, int end, out int jccOffset)
            {
                jccOffset = -1;
                offset = SkipPadding(bytes, offset, end);

                if (offset >= end)
                    return false;


                if (bytes[offset] == 0x74 || bytes[offset] == 0x75)
                {
                    jccOffset = offset;
                    return true;
                }


                if (offset + 2 <= end && bytes[offset] == 0x0F && (bytes[offset + 1] == 0x84 || bytes[offset + 1] == 0x85))
                {
                    jccOffset = offset;
                    return true;
                }

                return false;
            }

            private static int SkipPadding(ReadOnlySpan<byte> bytes, int start, int end)
            {
                if (start < 0)
                    return start;

                if (end > bytes.Length)
                    end = bytes.Length;

                if (start >= end)
                    return start;

                int relative = bytes.Slice(start, end - start).IndexOfAnyExcept(PaddingBytes);
                return relative < 0 ? end : start + relative;
            }

            private static bool FindBoolResultGateInsideAttachAnchors(List<ulong> anchors, ulong callSite, ImmutableArray<Section> sections, out ulong resultCheck, out ulong resultJcc)
            {
                resultCheck = 0;
                resultJcc = 0;

                if (callSite == 0)
                    return false;

                for (int a = 0; a < anchors.Count; a++)
                {
                    ulong anchor = anchors[a];
                    Section section;

                    if (!TryGetContainingSection(sections, anchor, out section))
                        continue;

                    int count = checked((int)Math.Min((ulong)ATTACH_SCAN_BYTES, section.End - anchor));

                    if (count < 8)
                        continue;

                    if (callSite < anchor || callSite + 5 >= anchor + (ulong)count)
                        continue;

                    byte[] rented = ArrayPool<byte>.Shared.Rent(count);
                    try
                    {
                        Marshal.Copy(ToIntPtr(anchor), rented, 0, count);
                        ReadOnlySpan<byte> bytes = rented.AsSpan(0, count);

                        int afterCall = checked((int)(callSite - anchor)) + 5;
                        int checkOffset;
                        int jccOffset;

                        if (!TryFindBoolResultGate(bytes, afterCall, Math.Min(bytes.Length, afterCall + 24), out checkOffset, out jccOffset))
                            continue;

                        if (checkOffset >= 0)
                            resultCheck = anchor + (uint)checkOffset;

                        if (jccOffset >= 0)
                            resultJcc = anchor + (uint)jccOffset;

                        return resultCheck != 0;
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(rented);
                    }
                }

                return false;
            }










            public static IntPtr GetCallSiteInsideExecuteDLLForAttach(IntPtr executeDLLForAttachCall, IntPtr isILOnly)
            {
                if (executeDLLForAttachCall == IntPtr.Zero || isILOnly == IntPtr.Zero)
                {
                    return IntPtr.Zero;
                }

                IntPtr clr = NativeMethods.LoadLibrary(MemoryView._clrLib);

                if (clr == IntPtr.Zero)
                    return IntPtr.Zero;

                bool is64;
                ImmutableArray<Section> sections;

                if (!ReadExecutableSections(clr, out is64, out sections))
                {
                    return IntPtr.Zero;
                }

                ulong input = PtrToUInt64(executeDLLForAttachCall);

                ulong target = PtrToUInt64(isILOnly);

                if (!IsExecutable(sections, input) || !IsExecutable(sections, target))
                {
                    return IntPtr.Zero;
                }

                List<ulong> anchors = [];

                AddAnchor(anchors, input, sections);

                TryAddCallTarget(anchors, input, sections);

                if (input > 0)
                {
                    TryAddCallTarget(anchors, input - 1, sections);
                }

                if (input >= 5)
                {
                    TryAddCallTarget(anchors, input - 5, sections);
                }

                if (!is64)
                {
                    ulong x86Start = FindLikelyX86FunctionStart(input, sections);

                    AddAnchor(anchors, x86Start, sections);
                }

                ulong callSite = FindCallSiteInsideAttachAnchors(anchors, target, sections);

                return callSite == 0
                    ? IntPtr.Zero
                    : ToIntPtr(callSite);
            }

            private static ulong FindCallSiteInsideAttachAnchors(List<ulong> anchors, ulong target, ImmutableArray<Section> sections)
            {
                ulong bestSite = 0;
                int bestContextScore = int.MinValue;

                for (int a = 0; a < anchors.Count; a++)
                {
                    ulong anchor = anchors[a];

                    Section section;

                    if (!TryGetContainingSection(sections, anchor, out section))
                    {
                        continue;
                    }

                    int count = checked((int)Math.Min((ulong)ATTACH_SCAN_BYTES, section.End - anchor));

                    if (count < 5)
                        continue;

                    byte[] rented = ArrayPool<byte>.Shared.Rent(count);
                    try
                    {
                        Marshal.Copy(ToIntPtr(anchor), rented, 0, count);
                        ReadOnlySpan<byte> bytes = rented.AsSpan(0, count);

                        for (int i = 0; i <= bytes.Length - 5; i++)
                        {
                            if (bytes[i] != 0xE8)
                                continue;

                            int rel = ReadInt32LittleEndian(bytes, i + 1);
                            ulong destination = AddSigned(anchor + (uint)i + 5, rel);
                            if (destination != target)
                                continue;

                            int contextScore = ScoreCallResultContext(bytes, i + 5);


                            if (contextScore > bestContextScore)
                            {
                                bestContextScore = contextScore;
                                bestSite = anchor + (uint)i;
                            }
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(rented);
                    }
                }

                return bestSite;
            }





            private static int ValidateIsILOnlyBody(ulong target, ImmutableArray<Section> sections, bool is64)
            {
                Section section;

                if (!TryGetContainingSection(sections, target, out section))
                {
                    return 0;
                }

                int count = checked((int)Math.Min((ulong)TARGET_SCAN_BYTES, section.End - target));

                if (count <= 0)
                    return 0;

                byte[] rented = ArrayPool<byte>.Shared.Rent(count);
                try
                {
                    Marshal.Copy(ToIntPtr(target), rented, 0, count);
                    CodeReader code = new(rented.AsSpan(0, count));

                    int best = 0;


                    int semanticLimit = Math.Min(code.Length, 0x70);

                    for (int i = 0; i < semanticLimit; i++)
                    {
                        int baseReg;
                        int used;






                        if (TryMatchTestFlagsOne(code, i, is64, out baseReg, out used))
                        {
                            int score = 100;

                            if (baseReg == 0)
                                score += 65;

                            if (HasNearbyCallBefore(code, i, 0x28))
                                score += 45;

                            if (i <= 0x20)
                                score += 25;
                            else if (i <= 0x40)
                                score += 10;

                            if (HasReturnSoon(code, i + used, 0x70))
                                score += 10;

                            if (score > best)
                                best = score;
                        }






                        int movReg;
                        int movBase;
                        int movUsed;

                        if (TryMatchMovFlags(code, i, is64, out movReg, out movBase, out movUsed))
                        {
                            int andUsed;

                            if (TryMatchAndRegOne(code, i + movUsed, is64, movReg, out andUsed))
                            {
                                int score = 100;

                                if (movBase == 0)
                                    score += 50;

                                if (HasNearbyCallBefore(code, i, 0x28))
                                    score += 35;

                                if (i <= 0x28)
                                    score += 20;

                                if (HasReturnSoon(code, i + movUsed + andUsed, 0x70))
                                    score += 10;

                                if (score > best)
                                    best = score;
                            }
                        }
                    }

                    return best;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }










            private static bool TryMatchTestFlagsOne(CodeReader code, int offset, bool is64, out int baseRegister, out int bytesUsed)
            {
                baseRegister = -1;
                bytesUsed = 0;

                int p = offset;
                byte rex;

                SkipPrefixes(code, ref p, is64, out rex);

                if (p >= code.Length)
                    return false;

                byte opcode = code[p++];

                if (opcode != 0xF6 && opcode != 0xF7)
                {
                    return false;
                }

                if (p >= code.Length)
                    return false;

                byte modrm = code[p];

                int group = (modrm >> 3) & 7;

                if (group != 0)
                    return false;

                StructureViews.MemOperand mem;

                if (!TryParseMemoryOperand(code, p, is64, rex, out mem))
                {
                    return false;
                }

                if (!mem.HasBase || IsStackOrFrameRegister(mem.BaseRegister) || mem.Displacement != COR20_FLAGS_OFFSET)
                {
                    return false;
                }

                p += mem.BytesUsed;

                if (opcode == 0xF6)
                {
                    if (p >= code.Length || code[p] != 1)
                    {
                        return false;
                    }

                    p++;
                }
                else
                {
                    if (!code.Has(p, sizeof(uint)))
                        return false;

                    uint imm = code.ReadUInt32(p);

                    if (imm != COMIMAGE_FLAGS_ILONLY)
                    {
                        return false;
                    }

                    p += 4;
                }

                baseRegister = mem.BaseRegister;

                bytesUsed = p - offset;

                return true;
            }


            private static bool TryMatchMovFlags(CodeReader code, int offset, bool is64, out int destinationRegister, out int baseRegister, out int bytesUsed)
            {
                destinationRegister = -1;
                baseRegister = -1;
                bytesUsed = 0;

                int p = offset;
                byte rex;

                SkipPrefixes(code, ref p, is64, out rex);

                if (p >= code.Length || code[p++] != 0x8B)
                {
                    return false;
                }

                if (p >= code.Length)
                    return false;

                byte modrm = code[p];

                int mod = (modrm >> 6) & 3;

                if (mod == 3)
                    return false;

                int reg = (modrm >> 3) & 7;

                if (is64 && (rex & 0x04) != 0)
                {
                    reg += 8;
                }

                StructureViews.MemOperand mem;

                if (!TryParseMemoryOperand(code, p, is64, rex, out mem))
                {
                    return false;
                }

                if (!mem.HasBase || IsStackOrFrameRegister(mem.BaseRegister) || mem.Displacement != COR20_FLAGS_OFFSET)
                {
                    return false;
                }

                destinationRegister = reg;
                baseRegister = mem.BaseRegister;
                bytesUsed = (p - offset) +
                    mem.BytesUsed;

                return true;
            }




            private static bool TryMatchAndRegOne(CodeReader code, int offset, bool is64, int expectedRegister, out int bytesUsed)
            {
                bytesUsed = 0;

                int p = offset;
                byte rex;

                SkipPrefixes(code, ref p, is64, out rex);

                if (p >= code.Length)
                    return false;

                byte opcode = code[p++];

                if (opcode != 0x83 && opcode != 0x81)
                {
                    return false;
                }

                if (p >= code.Length)
                    return false;

                byte modrm = code[p++];

                int mod = (modrm >> 6) & 3;

                int group = (modrm >> 3) & 7;

                int rm = modrm & 7;

                if (mod != 3 || group != 4)
                {
                    return false;
                }

                if (is64 && (rex & 0x01) != 0)
                {
                    rm += 8;
                }

                if (rm != expectedRegister)
                    return false;

                if (opcode == 0x83)
                {
                    if (p >= code.Length || code[p] != 1)
                    {
                        return false;
                    }

                    p++;
                }
                else
                {
                    if (!code.Has(p, sizeof(uint)))
                        return false;

                    uint imm = code.ReadUInt32(p);

                    if (imm != 1)
                        return false;

                    p += 4;
                }

                bytesUsed = p - offset;

                return true;
            }



            private static bool TryParseMemoryOperand(CodeReader code, int modrmOffset, bool is64, byte rex, out StructureViews.MemOperand result)
            {
                result = default(StructureViews.MemOperand);

                if (modrmOffset >= code.Length)
                    return false;

                int p = modrmOffset;

                byte modrm = code[p++];

                int mod = (modrm >> 6) & 3;

                int rm = modrm & 7;

                if (mod == 3)
                    return false;

                int baseReg = -1;
                bool hasBase = true;

                if (rm == 4)
                {

                    if (p >= code.Length)
                        return false;

                    byte sib = code[p++];

                    int baseBits = sib & 7;

                    if (mod == 0 && baseBits == 5)
                    {
                        hasBase = false;
                    }
                    else
                    {
                        baseReg = baseBits;

                        if (is64 && (rex & 0x01) != 0)
                        {
                            baseReg += 8;
                        }
                    }
                }
                else
                {
                    if (mod == 0 && rm == 5)
                    {

                        hasBase = false;
                    }
                    else
                    {
                        baseReg = rm;

                        if (is64 && (rex & 0x01) != 0)
                        {
                            baseReg += 8;
                        }
                    }
                }

                long displacement = 0;

                if (mod == 1)
                {
                    if (p >= code.Length)
                        return false;

                    displacement = unchecked((sbyte)code[p]);

                    p++;
                }
                else if (mod == 2 || (mod == 0 && !hasBase))
                {
                    if (!code.Has(p, sizeof(int)))
                        return false;

                    displacement = code.ReadInt32(p);

                    p += 4;
                }

                result.BaseRegister = baseReg;

                result.HasBase = hasBase;

                result.Displacement = displacement;

                result.BytesUsed = p - modrmOffset;

                return true;
            }

            private static void SkipPrefixes(CodeReader code, ref int p, bool is64, out byte rex)
            {
                rex = 0;

                int prefixCount = 0;

                while (p < code.Length && prefixCount < 8)
                {
                    byte b = code[p];

                    if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65)
                    {
                        p++;
                        prefixCount++;
                        continue;
                    }

                    if (is64 && b >= 0x40 && b <= 0x4F)
                    {
                        rex = b;
                        p++;
                        prefixCount++;
                        continue;
                    }

                    break;
                }
            }

            private static bool IsStackOrFrameRegister(int register)
            {



                return register == 4 ||
                       register == 5;
            }

            private static bool HasNearbyCallBefore(CodeReader body, int position, int maxDistance)
            {
                int min = Math.Max(0, position - maxDistance);

                for (int i = position - 5; i >= min; i--)
                {
                    if (i < 0)
                        break;

                    if (body[i] != 0xE8)
                        continue;


                    if (i + 5 <= position)
                        return true;
                }

                return false;
            }

            private static bool HasReturnSoon(CodeReader body, int start, int distance)
            {
                int end = Math.Min(body.Length, start + distance);

                for (int i = start; i < end; i++)
                {

                    if (body[i] == 0xC3 || body[i] == 0xC2)
                    {
                        return true;
                    }
                }

                return false;
            }





            private static void AddAnchor(List<ulong> anchors, ulong address, ImmutableArray<Section> sections)
            {
                if (address == 0 || !IsExecutable(sections, address))
                {
                    return;
                }

                for (int i = 0; i < anchors.Count; i++)
                {
                    if (anchors[i] == address)
                        return;
                }

                anchors.Add(address);
            }

            private static void TryAddCallTarget(List<ulong> anchors, ulong callSite, ImmutableArray<Section> sections)
            {
                if (!IsExecutable(sections, callSite))
                {
                    return;
                }

                byte* p = (byte*)ToIntPtr(callSite).ToPointer();

                if (p[0] != 0xE8)
                    return;

                int rel = Unsafe.ReadUnaligned<int>(p + 1);

                ulong target = AddSigned(callSite + 5, rel);

                if (!IsExecutable(sections, target))
                {
                    return;
                }


                target = FollowJumpThunkSimple(target, sections);

                AddAnchor(anchors, target, sections);
            }

            private static ulong FollowJumpThunk(ulong address, ImmutableArray<Section> sections, bool is64)
            {
                ulong current = address;

                for (int depth = 0; depth < 4; depth++)
                {
                    if (!IsExecutable(sections, current))
                    {
                        break;
                    }

                    byte* p = (byte*)ToIntPtr(current).ToPointer();


                    if (p[0] == 0xE9)
                    {
                        int rel = Unsafe.ReadUnaligned<int>(p + 1);

                        ulong next = AddSigned(current + 5, rel);

                        if (next == current || !IsExecutable(sections, next))
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }


                    if (p[0] == 0xEB)
                    {
                        sbyte rel = unchecked((sbyte)p[1]);

                        ulong next = AddSigned(current + 2, rel);

                        if (next == current || !IsExecutable(sections, next))
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }



                    if (is64 && p[0] == 0xFF && p[1] == 0x25)
                    {
                        int disp = Unsafe.ReadUnaligned<int>(p + 2);

                        ulong slot = AddSigned(current + 6, disp);

                        IntPtr slotPtr = ToIntPtr(slot);

                        ulong next = unchecked((ulong)Unsafe.ReadUnaligned<long>(slotPtr.ToPointer()));

                        if (next == current || !IsExecutable(sections, next))
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }

                    break;
                }

                return current;
            }

            private static ulong FollowJumpThunkSimple(ulong address, ImmutableArray<Section> sections)
            {
                ulong current = address;

                for (int depth = 0; depth < 3; depth++)
                {
                    if (!IsExecutable(sections, current))
                    {
                        break;
                    }

                    byte* p = (byte*)ToIntPtr(current).ToPointer();

                    if (p[0] == 0xE9)
                    {
                        int rel = Unsafe.ReadUnaligned<int>(p + 1);

                        ulong next = AddSigned(current + 5, rel);

                        if (next == current || !IsExecutable(sections, next))
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }

                    if (p[0] == 0xEB)
                    {
                        sbyte rel = unchecked((sbyte)p[1]);

                        ulong next = AddSigned(current + 2, rel);

                        if (next == current || !IsExecutable(sections, next))
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }

                    break;
                }

                return current;
            }



            private static ulong FindLikelyX86FunctionStart(ulong address, ImmutableArray<Section> sections)
            {
                Section section;

                if (!TryGetContainingSection(sections, address, out section))
                {
                    return 0;
                }

                ulong min = address > 0x180 ? address - 0x180 : section.Start;

                if (min < section.Start)
                    min = section.Start;

                for (ulong p = address; p >= min + 5; p--)
                {
                    byte* q = (byte*)ToIntPtr(p).ToPointer();


                    if (q[0] == 0x8B && q[1] == 0xFF && q[2] == 0x55 && q[3] == 0x8B && q[4] == 0xEC)
                    {
                        return p;
                    }


                    if (q[0] == 0x55 && q[1] == 0x8B && q[2] == 0xEC)
                    {
                        return p;
                    }

                    if (p == min + 5)
                        break;
                }


                for (ulong p = address; p > min; p--)
                {
                    byte previous = Unsafe.ReadUnaligned<byte>((byte*)ToIntPtr(p - 1).ToPointer());

                    if (previous != 0xCC && previous != 0x90)
                    {
                        continue;
                    }

                    byte current = Unsafe.ReadUnaligned<byte>((byte*)ToIntPtr(p).ToPointer());

                    if (current != 0xCC && current != 0x90)
                    {
                        return p;
                    }
                }

                return 0;
            }





            private static bool ReadExecutableSections(IntPtr module, out bool is64, out ImmutableArray<Section> sections)
            {
                is64 = false;
                sections = ImmutableArray<Section>.Empty;

                byte* p = (byte*)module.ToPointer();

                if (p == null || Unsafe.ReadUnaligned<ushort>(p) != 0x5A4D)
                {
                    return false;
                }

                int e_lfanew = Unsafe.ReadUnaligned<int>(p + 0x3C);

                if (e_lfanew <= 0)
                    return false;

                byte* nt = p + e_lfanew;

                if (Unsafe.ReadUnaligned<uint>(nt) != 0x00004550)
                    return false;

                byte* fileHeader = nt + 4;

                ushort sectionCount = Unsafe.ReadUnaligned<ushort>(fileHeader + 2);

                ushort optionalSize = Unsafe.ReadUnaligned<ushort>(fileHeader + 16);

                byte* optional = fileHeader + 20;

                ushort magic = Unsafe.ReadUnaligned<ushort>(optional);

                if (magic == 0x20B)
                    is64 = true;
                else if (magic == 0x10B)
                    is64 = false;
                else
                    return false;

                int sizeOfImage = Unsafe.ReadUnaligned<int>(optional + 0x38);

                if (sizeOfImage <= 0)
                    return false;

                ulong moduleBase = PtrToUInt64(module);

                byte* sectionTable = optional + optionalSize;

                ImmutableArray<Section>.Builder builder = ImmutableArray.CreateBuilder<Section>(sectionCount);

                for (int i = 0; i < sectionCount; i++)
                {
                    byte* sh = sectionTable +
                        i * 40;

                    int virtualSize = Unsafe.ReadUnaligned<int>(sh + 8);

                    int virtualAddress = Unsafe.ReadUnaligned<int>(sh + 12);

                    int rawSize = Unsafe.ReadUnaligned<int>(sh + 16);

                    uint characteristics = Unsafe.ReadUnaligned<uint>(sh + 36);

                    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                    {
                        continue;
                    }

                    int size = virtualSize > 0 ? virtualSize : rawSize;

                    if (size <= 0 || virtualAddress < 0 || virtualAddress >= sizeOfImage)
                    {
                        continue;
                    }

                    if (virtualAddress + size > sizeOfImage)
                    {
                        size = sizeOfImage -
                            virtualAddress;
                    }

                    ulong start = moduleBase +
                        (uint)virtualAddress;

                    builder.Add(new Section(start, start + (uint)size));
                }

                sections = builder.ToImmutable();

                return !sections.IsDefaultOrEmpty;
            }

            private static bool TryGetContainingSection(ImmutableArray<Section> sections, ulong address, out Section section)
            {
                for (int i = 0; i < sections.Length; i++)
                {
                    Section s = sections[i];

                    if (address >= s.Start && address < s.End)
                    {
                        section = s;
                        return true;
                    }
                }

                section = default;
                return false;
            }

            private static bool IsExecutable(ImmutableArray<Section> sections, ulong address)
            {
                Section unused;

                return TryGetContainingSection(sections, address, out unused);
            }

            private static int ReadInt32LittleEndian(ReadOnlySpan<byte> source, int offset)
            {
                return BinaryPrimitives.ReadInt32LittleEndian(source.Slice(offset, sizeof(int)));
            }






            private static ulong PtrToUInt64(IntPtr value)
            {
                if (IntPtr.Size == 4)
                {
                    return unchecked((uint)value.ToInt32());
                }

                return unchecked((ulong)value.ToInt64());
            }

            private static IntPtr ToIntPtr(ulong value)
            {
                if (IntPtr.Size == 4)
                {
                    return new IntPtr(unchecked((int)(uint)value));
                }

                return new IntPtr(unchecked((long)value));
            }

            private static ulong AddSigned(ulong value, long displacement)
            {
                return unchecked((ulong)((long)value + displacement));
            }

            public static void Print()
            {
                ILogger logger = ThisStaticClass.Logger;
                if (!logger.IsEnabled(LogLevel.Information))
                    return;

                logger.LogInformation("PEDecoder::IsILOnly / common attach resolver / no Iced");

                logger.LogInformation("Attach resolver: ExecuteDLLForAttach=0x{ExecuteDLLForAttach:X}, " + "IsILOnlyCallSite=0x{IsILOnlyCallSite:X}, PEDecoderIsILOnly=0x{PEDecoderIsILOnly:X}, " + "ResultCheck=0x{ResultCheck:X}, ResultJcc=0x{ResultJcc:X}", ExecuteDLLForAttach.ToInt64(), IsILOnlyCallSite.ToInt64(), PEDecoderIsILOnly.ToInt64(), ResultCheck.ToInt64(), ResultJcc.ToInt64());

                logger.LogInformation("Attach resolver summary: CallsChecked={CallsChecked}, Candidates={Candidates}, Score={Score}", CallsChecked, Candidates, BestScore);
            }
        }
    }
