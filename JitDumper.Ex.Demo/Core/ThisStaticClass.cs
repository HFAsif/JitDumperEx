using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Reflection;
using System.Runtime.Versioning;

namespace LoaderExDemo
{
    internal static class ThisStaticClass
    {
        public static TargetFrameworkAttribute TargetFramework { get; } =
            typeof(Program).Assembly.GetCustomAttribute<TargetFrameworkAttribute>()
            ?? throw new InvalidOperationException("TargetFrameworkAttribute is missing.");



        internal static ILogger Logger
        {
            get;
            private set => field = value ?? NullLogger.Instance;
        } = NullLogger.Instance;

        internal static void ConfigureLogger(ILogger? logger) => Logger = logger ?? NullLogger.Instance;

        public static TargetInfos targetInfos { get; } = new();

        public static int RuntimeKeyStatic => (IntPtr.Size * 10) + Environment.Version.Major;

        public static bool IsNet4 => Environment.Version.Major == 4;

    }
}
