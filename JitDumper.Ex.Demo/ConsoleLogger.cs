using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    internal sealed class ConsoleLogger : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) => EmptyScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
                return;

            string message = formatter(state, exception);

            ConsoleColor oldColor = Console.ForegroundColor;

            try
            {
                Console.ForegroundColor = logLevel switch
                {
                    LogLevel.Trace => ConsoleColor.DarkGray,
                    LogLevel.Debug => ConsoleColor.Gray,
                    LogLevel.Information => ConsoleColor.White,
                    LogLevel.Warning => ConsoleColor.Yellow,
                    LogLevel.Error => ConsoleColor.Red,
                    LogLevel.Critical => ConsoleColor.Magenta,
                    _ => oldColor
                };

                Console.WriteLine("[{0}] {1}", logLevel, message);

                if (exception != null)
                    Console.WriteLine(exception);
            }
            finally
            {
                Console.ForegroundColor = oldColor;
            }
        }

        private sealed class EmptyScope : IDisposable
        {
            internal static readonly EmptyScope Instance = new();

            public void Dispose()
            {
            }
        }
    }
}
