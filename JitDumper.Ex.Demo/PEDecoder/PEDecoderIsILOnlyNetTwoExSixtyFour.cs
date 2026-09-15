using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace LoaderExDemo
{
    /// <summary>
    /// CLR 2.x / .NET 2.0-3.5 x64 resolver for the standalone
    /// PEDecoder::IsILOnly call used by ExecuteDLLForAttach.
    ///
    /// Verified semantic layout (addresses vary with ASLR):
    ///
    ///     lea  rcx,[rsp+pedecoderLocal]
    ///     call PEDecoder::PEDecoder
    ///     lea  rcx,[rsp+pedecoderLocal]
    ///     call PEDecoder::IsILOnly
    ///     xor  zeroReg,zeroReg
    ///     cmp  eax,zeroReg
    ///     je   ContinueAttach
    ///       ... early S_OK/false-return path ...
    /// ContinueAttach:
    ///     lea  rcx,[rsp+pedecoderLocal]
    ///     call PEDecoder::HasManagedEntryPoint
    ///
    /// The final resolver is PDB-free and does not validate the internals of
    /// PEDecoder::IsILOnly.  Instead it identifies the call by its unique
    /// ExecuteDLLForAttach caller semantics.  This is important on CLR2 x64,
    /// where the old generic target-body validator rejects the real function.
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR2 x64 ILOnly call gate.")]
    internal static unsafe class PEDecoderIsILOnlyNetTwoExSixtyFour
    {
        private const int ScanBytes = 0x180;
        private static readonly SearchValues<byte> PaddingBytes = SearchValues.Create((byte)0x90, (byte)0xCC);

        internal sealed class Result
        {
            public IntPtr ExecuteDLLForAttach;
            public IntPtr IsILOnlyCallSite;
            public IntPtr IsILOnly;
            public IntPtr ResultCheck;
            public IntPtr ResultJcc;
            public int CallsChecked;
            public int Candidates;
            public int Score;
        }

        private readonly struct LeaInfo(int offset, int length, int displacement)
        {
            public int Offset { get; } = offset;
            public int Length { get; } = length;
            public int Displacement { get; } = displacement;
        }

        internal static Result? Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));

            if (IntPtr.Size != 8 || Environment.Version.Major != 2)
                return null;




            IntPtr executeDLLForAttach = ptrs.ExecuteDLLForAttach;
            if (executeDLLForAttach == IntPtr.Zero)
                return null;

            byte[] rented = ArrayPool<byte>.Shared.Rent(ScanBytes);
            try
            {
                try
                {
                    Marshal.Copy(executeDLLForAttach, rented, 0, ScanBytes);
                }
                catch
                {
                    return null;
                }

                ReadOnlySpan<byte> bytes = rented.AsSpan(0, ScanBytes);
                Result? best = null;
                int callsChecked = 0;
                int candidates = 0;

                for (int callOffset = 0; callOffset <= bytes.Length - 5; callOffset++)
                {
                    if (bytes[callOffset] != 0xE8)
                        continue;

                    callsChecked++;



                    if (!TryGetLeaRcxRspImmediatelyBeforeCall(bytes, callOffset, out LeaInfo isIlOnlyLea))
                        continue;

                    int constructorCallOffset = FindPreviousDirectCallEndingBefore(bytes, isIlOnlyLea.Offset, 12);
                    if (constructorCallOffset < 0)
                        continue;

                    if (!TryGetLeaRcxRspImmediatelyBeforeCall(bytes, constructorCallOffset, out LeaInfo constructorLea))
                        continue;

                    if (constructorLea.Displacement != isIlOnlyLea.Displacement)
                        continue;

                    if (!TryFindBoolZeroGateAfterCall(bytes, callOffset + 5, out int checkOffset, out int jccOffset, out int continueOffset, out int zeroRegister))
                        continue;

                    if ((uint)continueOffset >= (uint)bytes.Length)
                        continue;

                    int score = 230;



                    if (TryValidateContinueAttach(bytes, continueOffset, isIlOnlyLea.Displacement, zeroRegister, out _))
                        score += 70;



                    if (callOffset <= 0x80)
                        score += 25;
                    else if (callOffset <= 0xC0)
                        score += 10;

                    candidates++;

                    int rel = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(callOffset + 1, sizeof(int)));
                    long callAddress = executeDLLForAttach.ToInt64() + callOffset;
                    long targetAddress = callAddress + 5L + rel;

                    Result current = new()
                    {
                        ExecuteDLLForAttach = executeDLLForAttach,
                        IsILOnlyCallSite = new IntPtr(callAddress),
                        IsILOnly = new IntPtr(targetAddress),
                        ResultCheck = IntPtr.Add(executeDLLForAttach, checkOffset),
                        ResultJcc = IntPtr.Add(executeDLLForAttach, jccOffset),
                        CallsChecked = callsChecked,
                        Candidates = candidates,
                        Score = score
                    };

                    if (best is null || current.Score > best.Score)
                        best = current;
                }

                if (best is not { Score: >= 250 })
                    return null;



                best.CallsChecked = callsChecked;
                best.Candidates = candidates;
                return best;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        private static bool TryGetLeaRcxRspImmediatelyBeforeCall(ReadOnlySpan<byte> bytes, int callOffset, out LeaInfo info)
        {
            info = default;



            int p = callOffset - 5;
            if (p >= 0 && bytes[p] == 0x48 && bytes[p + 1] == 0x8D && bytes[p + 2] == 0x4C && bytes[p + 3] == 0x24)
            {
                info = new LeaInfo(p, 5, unchecked((sbyte)bytes[p + 4]));
                return true;
            }



            p = callOffset - 8;
            if (p >= 0 && bytes[p] == 0x48 && bytes[p + 1] == 0x8D && bytes[p + 2] == 0x8C && bytes[p + 3] == 0x24)
            {
                info = new LeaInfo(p, 8, BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(p + 4, sizeof(int))));
                return true;
            }

            return false;
        }

        private static int FindPreviousDirectCallEndingBefore(ReadOnlySpan<byte> bytes, int beforeOffset, int maxGap)
        {
            int min = Math.Max(0, beforeOffset - maxGap - 5);

            for (int i = beforeOffset - 5; i >= min; i--)
            {
                if (bytes[i] != 0xE8)
                    continue;



                ReadOnlySpan<byte> padding = bytes.Slice(i + 5, beforeOffset - (i + 5));
                if (padding.IndexOfAnyExcept(PaddingBytes) < 0)
                    return i;
            }

            return -1;
        }

        private static bool TryFindBoolZeroGateAfterCall(ReadOnlySpan<byte> bytes, int start, out int checkOffset, out int jccOffset, out int continueOffset, out int zeroRegister)
        {
            checkOffset = -1;
            jccOffset = -1;
            continueOffset = -1;
            zeroRegister = -1;

            int end = Math.Min(bytes.Length, start + 14);
            int p = start;

            p = SkipPadding(bytes, p, end);





            if (p + 5 < bytes.Length && TryMatchXorSame32(bytes, p, out zeroRegister))
            {
                int xorLength = 2;
                int cmp = p + xorLength;

                if (TryMatchCmpEaxRegister(bytes, cmp, zeroRegister))
                {
                    checkOffset = cmp;
                    int afterCmp = cmp + 2;

                    if (TryReadJeTarget(bytes, afterCmp, out jccOffset, out continueOffset))
                    {
                        return true;
                    }
                }
            }




            if (p + 3 < bytes.Length && bytes[p] == 0x85 && bytes[p + 1] == 0xC0)
            {
                zeroRegister = 0;
                checkOffset = p;

                if (TryReadJeTarget(bytes, p + 2, out jccOffset, out continueOffset))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryMatchXorSame32(ReadOnlySpan<byte> bytes, int offset, out int register)
        {
            register = -1;

            if (offset + 1 >= bytes.Length)
                return false;


            if (bytes[offset] != 0x33 && bytes[offset] != 0x31)
                return false;

            byte modrm = bytes[offset + 1];
            if ((modrm & 0xC0) != 0xC0)
                return false;

            int reg = (modrm >> 3) & 7;
            int rm = modrm & 7;
            if (reg != rm)
                return false;

            register = reg;
            return true;
        }

        private static bool TryMatchCmpEaxRegister(ReadOnlySpan<byte> bytes, int offset, int register)
        {
            if (offset + 1 >= bytes.Length)
                return false;


            if (bytes[offset] == 0x3B)
            {
                byte modrm = bytes[offset + 1];
                if ((modrm & 0xC0) == 0xC0 && ((modrm >> 3) & 7) == 0 && (modrm & 7) == register)
                {
                    return true;
                }
            }


            if (bytes[offset] == 0x39)
            {
                byte modrm = bytes[offset + 1];
                if ((modrm & 0xC0) == 0xC0 && ((modrm >> 3) & 7) == 0 && (modrm & 7) == register)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryReadJeTarget(ReadOnlySpan<byte> bytes, int offset, out int jccOffset, out int targetOffset)
        {
            jccOffset = -1;
            targetOffset = -1;

            int p = offset;
            int end = Math.Min(bytes.Length, offset + 4);

            p = SkipPadding(bytes, p, end);


            if (p + 1 < bytes.Length && bytes[p] == 0x74)
            {
                sbyte rel = unchecked((sbyte)bytes[p + 1]);
                jccOffset = p;
                targetOffset = p + 2 + rel;
                return true;
            }


            if (p + 5 < bytes.Length && bytes[p] == 0x0F && bytes[p + 1] == 0x84)
            {
                int rel = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(p + 2, sizeof(int)));
                jccOffset = p;
                targetOffset = p + 6 + rel;
                return true;
            }

            return false;
        }

        private static bool TryValidateContinueAttach(ReadOnlySpan<byte> bytes, int continueOffset, int pedecoderDisp, int zeroRegister, out int nextCallOffset)
        {
            nextCallOffset = -1;


            LeaInfo continueLea;
            if (!TryReadLeaRcxRspAt(bytes, continueOffset, out continueLea))
                return false;

            if (continueLea.Displacement != pedecoderDisp)
                return false;

            int callOffset = continueOffset + continueLea.Length;
            if (callOffset + 4 >= bytes.Length || bytes[callOffset] != 0xE8)
                return false;

            nextCallOffset = callOffset;

            int afterCall = callOffset + 5;


            if (TryMatchCmpEaxRegister(bytes, afterCall, zeroRegister))
                return true;


            if (afterCall + 1 < bytes.Length && bytes[afterCall] == 0x85 && bytes[afterCall + 1] == 0xC0)
            {
                return true;
            }

            return false;
        }

        private static bool TryReadLeaRcxRspAt(ReadOnlySpan<byte> bytes, int offset, out LeaInfo info)
        {
            info = default;

            int p = offset;
            int end = Math.Min(bytes.Length, offset + 4);
            p = SkipPadding(bytes, p, end);

            if (p + 4 < bytes.Length && bytes[p] == 0x48 && bytes[p + 1] == 0x8D && bytes[p + 2] == 0x4C && bytes[p + 3] == 0x24)
            {
                info = new LeaInfo(p, 5, unchecked((sbyte)bytes[p + 4]));
                return true;
            }

            if (p + 7 < bytes.Length && bytes[p] == 0x48 && bytes[p + 1] == 0x8D && bytes[p + 2] == 0x8C && bytes[p + 3] == 0x24)
            {
                info = new LeaInfo(p, 8, BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(p + 4, sizeof(int))));
                return true;
            }

            return false;
        }
        private static int SkipPadding(ReadOnlySpan<byte> bytes, int start, int end)
        {
            if ((uint)start >= (uint)end || start < 0 || end > bytes.Length)
                return start;

            int relative = bytes.Slice(start, end - start).IndexOfAnyExcept(PaddingBytes);
            return relative < 0 ? end : start + relative;
        }

    }
}
