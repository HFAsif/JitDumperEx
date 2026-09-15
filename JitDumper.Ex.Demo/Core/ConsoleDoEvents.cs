namespace LoaderExDemo
{
    internal static class ConsoleDoEvents
    {
        private const uint PM_REMOVE = 0x0001;

        public static void DoEvents()
        {
            while (NativeMethods.PeekMessage(out StructureViews.Win32Message msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                NativeMethods.TranslateMessage(ref msg);
                NativeMethods.DispatchMessage(ref msg);
            }
        }
    }
}
