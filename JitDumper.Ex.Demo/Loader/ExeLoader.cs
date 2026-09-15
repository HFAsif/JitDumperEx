using System.Diagnostics;
using System.Reflection.PortableExecutable;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Invokes CLR EXE or DLL entrypoints.")]
    internal static class ExeLoader
    {
        public static bool ExecuteExe(string path, bool executeExe, IntPtr executeEXEPtr, IntPtr executeDLLPtr)
        {
            bool isManaged = IsManagedAssembly(path);

            IntPtr lib = NativeMethods.LoadLibrary(path);

            if (!isManaged)
            {
                Debugger.Break();
                return true;
            }

            Thread thread;

            if (executeExe)
            {
                StructureViews.ExeContext context = new()
                {
                    lib = lib,
                    func = executeEXEPtr
                };

                thread = new Thread(context.ExecuteExe);
            }
            else
            {
                StructureViews.DllContext context = new()
                {
                    lib = lib,
                    func = executeDLLPtr,
                    dwReason = 1,
                    fFromThunk = 0
                };

                thread = new Thread(context.ExecuteDll);
            }

            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            return true;
        }

        private static bool IsManagedAssembly(string path)
        {
            try
            {
                using FileStream stream = File.OpenRead(path);
                using PEReader peReader = new(stream);

                return peReader.HasMetadata && peReader.PEHeaders.CorHeader is not null;
            }
            catch (BadImageFormatException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }
    }
}


