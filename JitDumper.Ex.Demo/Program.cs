
using Microsoft.Extensions.Logging;
using System.Dynamic;

namespace LoaderExDemo
{
    internal class Program : ProgramBase
    {
        [STAThread]
        private static void Main(string[] args)
        {
            AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
            ThisStaticClass.ConfigureLogger(new ConsoleLogger());
            ThisStaticClass.Logger.LogInformation(ThisStaticClass.TargetFramework.FrameworkName);
            ThisStaticClass.Logger.LogInformation(ThisStaticClass.TargetFramework.FrameworkDisplayName);


            ThisStaticClass.Logger.LogInformation("================================================");

            string testTargetFile = string.Empty;
            string testTargetFileOut = string.Empty;

            if (args.Length == 0)
            {
                StaticMethods.OutTarget(out testTargetFile, out testTargetFileOut);
            }
            else
            {
                testTargetFile = args[0];
                testTargetFileOut = StaticMethods.BuildJitDumpPath(testTargetFile);
            }

            if (!File.Exists(testTargetFile))
            {
                throw new FileNotFoundException("Test target file not found: " + testTargetFile);
            }

            dynamic osInfo = HelperClass.All.HelperViewsStatic.GetOsInformation;
            dynamic frameworkInfo = HelperClass.All.HelperViewsStatic.GetFrameWorkInfos;
            dynamic runtimeDiagnostics = new ExpandoObject();
            runtimeDiagnostics.OperatingSystemInfo = string.Join(Environment.NewLine, osInfo.OsinfoFromKernel32);
            runtimeDiagnostics.FrameworkInfo = string.Join(Environment.NewLine, frameworkInfo.MsCorLibInfos);

            ThisStaticClass.Logger.LogInformation("{OperatingSystemInfo}", (string)runtimeDiagnostics.OperatingSystemInfo);
            ThisStaticClass.Logger.LogInformation("{FrameworkInfo}", (string)runtimeDiagnostics.FrameworkInfo);

            StaticMethods.PrepareTargetAndLoadUnloadEventArgs(testTargetFile, testTargetFileOut, ThisStaticClass.targetInfos.ExeCution);
        }

        
    }
}
