using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace LoaderExDemo
{
    /// <summary>
    /// CLR 2.x / .NET 2.0-3.5 x86 resolver for the ILONLY gate inside
    /// ExecuteDLLForAttach.
    ///
    /// On the verified x86 CLR2 build, PEDecoder::IsILOnly is inlined in
    /// ExecuteDLLForAttach.  The native sequence is semantically:
    ///
    ///     call PEDecoder::GetCorHeader
    ///     test byte ptr [eax+10h], 1
    ///     je   ContinueAttach
    ///
    /// followed at ContinueAttach by the HasManagedEntryPoint path.
    ///
    /// This resolver therefore does not invent a standalone
    /// PEDecoder::IsILOnly pointer.  It resolves the real inline gate:
    /// GetCorHeader call-site/target, Flags test, and the JE that must be
    /// forced to continue.
    /// </summary>
    [HelperClass.SomeElementsInfos("Resolves CLR2 x86 inline ILOnly logic.")]
    internal static unsafe class PEDecoderIsILOnlyNetTwoExThirtyTwo
    {
        private const int ScanBytes = 0x180;
        private static readonly SearchValues<byte> PaddingBytes = SearchValues.Create((byte)0x90, (byte)0xCC);
        private const int ContinueValidationBytes = 0x28;

        internal sealed class Result
        {
            public IntPtr ExecuteDLLForAttach;
            public IntPtr GetCorHeaderCallSite;
            public IntPtr GetCorHeader;
            public IntPtr ResultCheck;
            public IntPtr ResultJcc;
            public int Score;
        }

        internal static Result? Resolve(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));

            if (IntPtr.Size != 4 || Environment.Version.Major != 2)
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

                for (int callOffset = 0; callOffset <= bytes.Length - 5; callOffset++)
                {
                    if (bytes[callOffset] != 0xE8)
                        continue;

                    if (!TryFindInlineIlOnlyTestAfterCall(bytes, callOffset + 5, out int testOffset, out int testLength))
                        continue;

                    if (!TryGetContinueJe(bytes, testOffset + testLength, out int jccOffset, out _, out int continueOffset))
                        continue;

                    if ((uint)continueOffset >= (uint)bytes.Length)
                        continue;

                    int score = 100;



                    bool hasLeaBeforeCall = TryFindLeaEcxEbpBeforeCall(bytes, callOffset, out int leaBeforeCallOffset, out int leaBeforeCallDisp);
                    if (hasLeaBeforeCall)
                        score += 35;


                    if (TryValidateContinuePath(bytes, continueOffset, out _, out int leaContinueDisp))
                    {
                        score += 55;



                        if (hasLeaBeforeCall && leaBeforeCallOffset >= 0 && leaBeforeCallDisp == leaContinueDisp)
                            score += 35;
                    }


                    if (testOffset <= 0x60)
                        score += 20;
                    else if (testOffset <= 0xA0)
                        score += 10;

                    if (best is null || score > best.Score)
                    {
                        int rel = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(callOffset + 1, sizeof(int)));
                        long callAddress = executeDLLForAttach.ToInt64() + callOffset;
                        long targetAddress = callAddress + 5L + rel;

                        best = new Result
                        {
                            ExecuteDLLForAttach = executeDLLForAttach,
                            GetCorHeaderCallSite = new IntPtr(callAddress),
                            GetCorHeader = new IntPtr(targetAddress),
                            ResultCheck = IntPtr.Add(executeDLLForAttach, testOffset),
                            ResultJcc = IntPtr.Add(executeDLLForAttach, jccOffset),
                            Score = score
                        };
                    }
                }




                return best is { Score: >= 190 } ? best : null;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        private static bool TryFindInlineIlOnlyTestAfterCall(ReadOnlySpan<byte> bytes, int start, out int testOffset, out int testLength)
        {
            testOffset = -1;
            testLength = 0;

            int end = Math.Min(bytes.Length, start + 8);

            for (int i = start; i < end; i++)
            {

                if (i != start && bytes[i - 1] != 0x90 && bytes[i - 1] != 0xCC)
                    break;



                if (i + 3 < bytes.Length && bytes[i] == 0xF6 && bytes[i + 1] == 0x40 && bytes[i + 2] == 0x10 && bytes[i + 3] == 0x01)
                {
                    testOffset = i;
                    testLength = 4;
                    return true;
                }



                if (i + 6 < bytes.Length && bytes[i] == 0xF7 && bytes[i + 1] == 0x40 && bytes[i + 2] == 0x10 && bytes[i + 3] == 0x01 && bytes[i + 4] == 0x00 && bytes[i + 5] == 0x00 && bytes[i + 6] == 0x00)
                {
                    testOffset = i;
                    testLength = 7;
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetContinueJe(ReadOnlySpan<byte> bytes, int start, out int jccOffset, out int jccLength, out int continueOffset)
        {
            jccOffset = -1;
            jccLength = 0;
            continueOffset = -1;

            int i = start;
            int end = Math.Min(bytes.Length, start + 4);

            i = SkipPadding(bytes, i, end);


            if (i + 1 < bytes.Length && bytes[i] == 0x74)
            {
                sbyte rel = unchecked((sbyte)bytes[i + 1]);
                jccOffset = i;
                jccLength = 2;
                continueOffset = i + 2 + rel;
                return true;
            }


            if (i + 5 < bytes.Length && bytes[i] == 0x0F && bytes[i + 1] == 0x84)
            {
                int rel = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(i + 2, sizeof(int)));
                jccOffset = i;
                jccLength = 6;
                continueOffset = i + 6 + rel;
                return true;
            }

            return false;
        }

        private static bool TryFindLeaEcxEbpBeforeCall(ReadOnlySpan<byte> bytes, int callOffset, out int leaOffset, out int displacement)
        {
            leaOffset = -1;
            displacement = 0;

            int start = Math.Max(0, callOffset - 12);

            for (int i = callOffset - 1; i >= start; i--)
            {

                if (i + 5 < callOffset && bytes[i] == 0x8D && bytes[i + 1] == 0x8D)
                {
                    leaOffset = i;
                    displacement = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(i + 2, sizeof(int)));
                    return true;
                }


                if (i + 2 < callOffset && bytes[i] == 0x8D && bytes[i + 1] == 0x4D)
                {
                    leaOffset = i;
                    displacement = unchecked((sbyte)bytes[i + 2]);
                    return true;
                }
            }

            return false;
        }

        private static bool TryValidateContinuePath(ReadOnlySpan<byte> bytes, int continueOffset, out int callOffset, out int leaDisplacement)
        {
            callOffset = -1;
            leaDisplacement = 0;

            int end = Math.Min(bytes.Length, continueOffset + ContinueValidationBytes);

            for (int i = continueOffset; i < end; i++)
            {
                int leaLength = 0;
                int displacement = 0;

                if (i + 5 < end && bytes[i] == 0x8D && bytes[i + 1] == 0x8D)
                {
                    displacement = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(i + 2, sizeof(int)));
                    leaLength = 6;
                }
                else if (i + 2 < end && bytes[i] == 0x8D && bytes[i + 1] == 0x4D)
                {
                    displacement = unchecked((sbyte)bytes[i + 2]);
                    leaLength = 3;
                }
                else
                {
                    continue;
                }

                int p = i + leaLength;

                p = SkipPadding(bytes, p, end);

                if (p + 4 >= end || bytes[p] != 0xE8)
                    continue;

                int afterCall = p + 5;
                if (!HasBoolResultTestAndJcc(bytes, afterCall, end))
                    continue;

                callOffset = p;
                leaDisplacement = displacement;
                return true;
            }

            return false;
        }

        private static bool HasBoolResultTestAndJcc(ReadOnlySpan<byte> bytes, int offset, int end)
        {
            offset = SkipPadding(bytes, offset, end);

            int testLength;

            if (offset + 1 < end && bytes[offset] == 0x85 && bytes[offset + 1] == 0xC0)
            {
                testLength = 2;
            }
            else if (offset + 1 < end && bytes[offset] == 0x84 && bytes[offset + 1] == 0xC0)
            {
                testLength = 2;
            }
            else
            {
                return false;
            }

            offset += testLength;

            if (offset >= end)
                return false;

            if (bytes[offset] == 0x74 || bytes[offset] == 0x75)
                return true;

            return offset + 1 < end &&
                   bytes[offset] == 0x0F &&
                   (bytes[offset + 1] == 0x84 || bytes[offset + 1] == 0x85);
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
