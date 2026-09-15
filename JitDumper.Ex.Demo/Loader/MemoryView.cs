namespace LoaderExDemo
{
    /// <summary>
    /// Runtime module names shared by the semantic pointer/PEDecoder locators.
    ///
    /// The old Net4 x86 ExecuteDLL/ExecuteDLLForAttach resolver that previously
    /// lived here had no remaining call sites; the authoritative resolution now
    /// lives under Pointers/ and PEDecoder/. Keep this type only as the central
    /// runtime-module-name owner used by those active resolvers.
    /// </summary>
    internal static class MemoryView
    {
#if NET35 || NET20
        public const string _clrLib = "mscorwks.dll";
#elif NET40_OR_GREATER
        public const string _clrLib = "clr.dll";
#endif
    }
}
