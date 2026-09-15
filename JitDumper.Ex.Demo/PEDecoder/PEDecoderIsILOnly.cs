namespace LoaderExDemo
{
    /// <summary>
    /// Single PEDecoder::IsILOnly entry point for all supported CLR/architecture
    /// combinations.
    ///
    /// RuntimeKey:
    ///     42 = CLR2 x86
    ///     44 = CLR4 x86
    ///     82 = CLR2 x64
    ///     84 = CLR4 x64
    /// </summary>
    [HelperClass.SomeElementsInfos("Selects runtime ILOnly gate resolver.")]
    internal sealed class PEDecoderIsILOnly : PEDecoderIsILOnlyBase
    {
        public int RuntimeKey => (IntPtr.Size * 10) + Environment.Version.Major;

        [HelperClass.SomeElementsInfos("Resolves the active CLR ILOnly gate.")]
        public override nint Resolve(PointerInfosBase ptrs)
        {
            Clear();

            return RuntimeKey switch
            {


                42 => ResolveNetTwoX86Inline(ptrs),


                44 => ResolveNetFourX86(ptrs),



                82 => ResolveNetTwoX64Call(ptrs),

                84 => ResolveNetFourX64(ptrs),

                _ => throw new NotSupportedException($"Unsupported CLR/architecture combination. RuntimeKey={RuntimeKey}")
            };
        }
    }
}
