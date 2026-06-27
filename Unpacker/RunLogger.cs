namespace Unpacker
{
    using System;
    using System.IO;

    internal sealed class RunLogger : IDisposable
    {
        private readonly Verbosity verbosity;
        private readonly StreamWriter writer;

        public RunLogger(Verbosity verbosity, string logPath)
        {
            this.verbosity = verbosity;

            if (!string.IsNullOrWhiteSpace(logPath))
            {
                OutputPath.EnsureParentDirectory(logPath);
                writer = new StreamWriter(logPath, false);
                writer.AutoFlush = true;
                LogOnly($"Log: {logPath}");
            }
        }

        public void Info(string message)
        {
            LogOnly(message);

            if (ShouldWriteToConsole(message))
            {
                Console.WriteLine(message);
            }
        }

        public void Error(string message)
        {
            LogOnly("ERROR: " + message);
            Console.Error.WriteLine(message);
        }

        public void Summary(string message)
        {
            LogOnly(message);
            if (verbosity != Verbosity.Quiet)
            {
                Console.WriteLine(message);
            }
        }

        public void Dispose()
        {
            writer?.Dispose();
        }

        private void LogOnly(string message)
        {
            writer?.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
        }

        private bool ShouldWriteToConsole(string message)
        {
            if (verbosity == Verbosity.Quiet)
            {
                return false;
            }

            if (verbosity == Verbosity.Verbose)
            {
                return true;
            }

            return !message.StartsWith("Extracting:", StringComparison.OrdinalIgnoreCase)
                && !message.StartsWith("Testing:", StringComparison.OrdinalIgnoreCase)
                && !message.StartsWith("Checking for", StringComparison.OrdinalIgnoreCase)
                && !message.StartsWith("Version:", StringComparison.OrdinalIgnoreCase);
        }
    }
}
