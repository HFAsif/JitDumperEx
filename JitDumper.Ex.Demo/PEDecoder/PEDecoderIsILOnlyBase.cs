using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    /// <summary>
    /// Instance state for the resolved ILONLY gate used by ExecuteDLLForAttach.
    ///
    /// CLR2 x86 is special: PEDecoder::IsILOnly is inlined, so there is no
    /// standalone IsILOnly function pointer/call-site on that path.  In that
    /// mode ResultCheck and ResultJcc are the authoritative values.
    /// </summary>
    internal abstract class PEDecoderIsILOnlyBase
    {
        public nint ExecuteDLLForAttach { get; protected set; }

        public bool IsInline { get; protected set; }


        public nint IsILOnlyCallSite { get; protected set; }
        public nint IsILOnly { get; protected set; }


        public nint GetCorHeaderCallSite { get; protected set; }
        public nint GetCorHeader { get; protected set; }



        public nint ResultCheck { get; protected set; }
        public nint ResultJcc { get; protected set; }

        public int CallsChecked { get; protected set; }
        public int Candidates { get; protected set; }
        public int BestScore { get; protected set; }

        public bool IsResolved
        {
            get
            {
                if (ExecuteDLLForAttach == IntPtr.Zero)
                    return false;

                if (IsInline)
                {
                    return ResultCheck != IntPtr.Zero &&
                           ResultJcc != IntPtr.Zero &&
                           GetCorHeaderCallSite != IntPtr.Zero &&
                           GetCorHeader != IntPtr.Zero;
                }

                return IsILOnlyCallSite != IntPtr.Zero &&
                       IsILOnly != IntPtr.Zero &&
                       ResultCheck != IntPtr.Zero &&
                       ResultJcc != IntPtr.Zero;
            }
        }

        public abstract nint Resolve(PointerInfosBase ptrs);

        protected void Clear()
        {
            ExecuteDLLForAttach = IntPtr.Zero;
            IsInline = false;

            IsILOnlyCallSite = IntPtr.Zero;
            IsILOnly = IntPtr.Zero;

            GetCorHeaderCallSite = IntPtr.Zero;
            GetCorHeader = IntPtr.Zero;

            ResultCheck = IntPtr.Zero;
            ResultJcc = IntPtr.Zero;

            CallsChecked = 0;
            Candidates = 0;
            BestScore = 0;
        }

        protected nint ResolveNetTwoX86Inline(PointerInfosBase ptrs)
        {
            PEDecoderIsILOnlyNetTwoExThirtyTwo.Result? result = PEDecoderIsILOnlyNetTwoExThirtyTwo.Resolve(ptrs);

            if (result == null)
                return IntPtr.Zero;

            ExecuteDLLForAttach = result.ExecuteDLLForAttach;
            IsInline = true;

            GetCorHeaderCallSite = result.GetCorHeaderCallSite;
            GetCorHeader = result.GetCorHeader;
            ResultCheck = result.ResultCheck;
            ResultJcc = result.ResultJcc;



            IsILOnlyCallSite = IntPtr.Zero;
            IsILOnly = IntPtr.Zero;

            CallsChecked = 1;
            Candidates = 1;
            BestScore = result.Score;



            return ResultCheck;
        }

        protected nint ResolveNetTwoX64Call(PointerInfosBase ptrs)
        {
            PEDecoderIsILOnlyNetTwoExSixtyFour.Result? result = PEDecoderIsILOnlyNetTwoExSixtyFour.Resolve(ptrs);

            if (result == null)
                return IntPtr.Zero;

            ExecuteDLLForAttach = result.ExecuteDLLForAttach;
            IsInline = false;

            IsILOnlyCallSite = result.IsILOnlyCallSite;
            IsILOnly = result.IsILOnly;
            ResultCheck = result.ResultCheck;
            ResultJcc = result.ResultJcc;

            CallsChecked = result.CallsChecked;
            Candidates = result.Candidates;
            BestScore = result.Score;

            return IsILOnly;
        }

        protected nint ResolveNetFourX86(PointerInfosBase ptrs)
        {
            return ResolveNetFourCallGate(ptrs);
        }

        protected nint ResolveNetFourX64(PointerInfosBase ptrs)
        {
            return ResolveNetFourCallGate(ptrs);
        }


















        private nint ResolveNetFourCallGate(PointerInfosBase ptrs)
        {
            nint resolved = ResolveFromAttach(ptrs);

            if (resolved == IntPtr.Zero || IsILOnlyCallSite == IntPtr.Zero || IsILOnly == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            ResultCheck = StaticMethods.FindTestEaxAfterCall(IsILOnlyCallSite);

            if (ResultCheck == IntPtr.Zero)
                return IntPtr.Zero;

            ResultJcc = StaticMethods.GetJccAfterTestEax(ResultCheck);

            if (ResultJcc == IntPtr.Zero)
                return IntPtr.Zero;

            return resolved;
        }





        protected nint ResolveFromAttach(PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));

            nint anchor = ptrs.ExecuteDLLForAttachCall;

            if (anchor == IntPtr.Zero)
                anchor = ptrs.ExecuteDLLForAttach;

            if (anchor == IntPtr.Zero)
                return IntPtr.Zero;

            nint resolved = PEDecoderIsILOnlyFromAttach.Resolve(anchor);

            ExecuteDLLForAttach = PEDecoderIsILOnlyFromAttach.ExecuteDLLForAttach;

            IsILOnlyCallSite = PEDecoderIsILOnlyFromAttach.IsILOnlyCallSite;

            IsILOnly = PEDecoderIsILOnlyFromAttach.PEDecoderIsILOnly;

            CallsChecked = PEDecoderIsILOnlyFromAttach.CallsChecked;

            Candidates = PEDecoderIsILOnlyFromAttach.Candidates;

            BestScore = PEDecoderIsILOnlyFromAttach.BestScore;

            return resolved;
        }

        public void Print()
        {
            ILogger logger = ThisStaticClass.Logger;
            if (!logger.IsEnabled(LogLevel.Information))
                return;

            logger.LogInformation("[PEDecoderIsILOnly RuntimeKey={RuntimeKey}]", (IntPtr.Size * 10) + Environment.Version.Major);

            logger.LogInformation("ExecuteDLLForAttach = {ExecuteDLLForAttach}", FormatPointer(ExecuteDLLForAttach));

            logger.LogInformation("Mode = {Mode}", IsInline ? "INLINE-ILONLY" : "CALL-ILONLY");

            if (IsInline)
            {
                logger.LogInformation("GetCorHeader call = {GetCorHeaderCallSite}", FormatPointer(GetCorHeaderCallSite));

                logger.LogInformation("PEDecoder::GetCorHeader = {GetCorHeader}", FormatPointer(GetCorHeader));

                logger.LogInformation("ILOnly flags test = {ResultCheck}", FormatPointer(ResultCheck));

                logger.LogInformation("ILOnly continue JCC = {ResultJcc}", FormatPointer(ResultJcc));

                logger.LogInformation("PEDecoder::IsILOnly = {Mode}", "<inlined on CLR2 x86>");
            }
            else
            {
                logger.LogInformation("IsILOnly call-site = {IsILOnlyCallSite}", FormatPointer(IsILOnlyCallSite));

                logger.LogInformation("PEDecoder::IsILOnly = {IsILOnly}", FormatPointer(IsILOnly));

                if (ResultCheck != IntPtr.Zero)
                {
                    logger.LogInformation("ILOnly result check = {ResultCheck}", FormatPointer(ResultCheck));
                }

                if (ResultJcc != IntPtr.Zero)
                {
                    logger.LogInformation("ILOnly continue JCC = {ResultJcc}", FormatPointer(ResultJcc));
                }
            }

            logger.LogInformation("Resolver summary: CallsChecked={CallsChecked}, Candidates={Candidates}, Score={Score}", CallsChecked, Candidates, BestScore);
        }

        private static string FormatPointer(nint pointer) => IntPtr.Size == 8 ? "0x" + unchecked((ulong)(long)pointer).ToString("X16") : "0x" + unchecked((uint)(int)pointer).ToString("X8");
    }
}
