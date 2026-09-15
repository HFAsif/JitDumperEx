namespace LoaderExDemo
{
    internal abstract class PointerInfosBase
    {
        public IntPtr CorDllMain { get; internal set; }

        public IntPtr ExecuteDLL { get; internal set; }
        public IntPtr ExecuteDLLCall { get; internal set; }

        public IntPtr ExecuteDLLForAttach { get; internal set; }
        public IntPtr ExecuteDLLForAttachCall { get; internal set; }

        public IntPtr CorExeMain { get; internal set; }

        public IntPtr CorExeMainInternal { get; internal set; }
        public IntPtr CorExeMainInternalCall { get; internal set; }

        public IntPtr ExecuteEXE { get; internal set; }
        public IntPtr ExecuteEXECall { get; internal set; }

        public int RuntimeKey => ThisStaticClass.RuntimeKeyStatic;

        protected void ClearPointers()
        {
            CorDllMain = IntPtr.Zero;

            ExecuteDLL = IntPtr.Zero;
            ExecuteDLLCall = IntPtr.Zero;
            ExecuteDLLForAttach = IntPtr.Zero;
            ExecuteDLLForAttachCall = IntPtr.Zero;

            CorExeMain = IntPtr.Zero;
            CorExeMainInternal = IntPtr.Zero;
            CorExeMainInternalCall = IntPtr.Zero;

            ExecuteEXE = IntPtr.Zero;
            ExecuteEXECall = IntPtr.Zero;
        }
    }
}
