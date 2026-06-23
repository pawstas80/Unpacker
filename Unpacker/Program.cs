namespace Unpacker
{
    using System;
    using System.IO;
    using System.Reflection;

    internal class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length == 1 && IsVersion(args[0]))
            {
                Console.WriteLine($"Unpacker {GetVersion()}");
                return 0;
            }

            if (args.Length == 0 || args.Length > 2 || IsHelp(args[0]))
            {
                WriteUsage();
                return args.Length == 0 ? 1 : 0;
            }

            var inputFile = Path.GetFullPath(args[0]);
            if (!File.Exists(inputFile))
            {
                Console.Error.WriteLine($"Input file does not exist: {inputFile}");
                return 2;
            }

            var outputDirectory = args.Length == 2
                ? Path.GetFullPath(args[1])
                : OutputPath.GetDefaultDirectory(inputFile);

            IsSetupStream.Message += WriteInfo;
            InstallShield.Message += WriteInfo;

            Console.WriteLine($"Input : {inputFile}");
            Console.WriteLine($"Output: {outputDirectory}");

            if (IsSetupStream.Unpack(inputFile, outputDirectory))
            {
                Console.WriteLine("Done.");
                return 0;
            }

            if (InstallShield.Unpack(inputFile, outputDirectory))
            {
                Console.WriteLine("Done.");
                return 0;
            }

            Console.Error.WriteLine("No supported InstallShield overlay was found, or extraction failed.");
            return 3;
        }

        private static bool IsHelp(string value)
        {
            return string.Equals(value, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "/?", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsVersion(string value)
        {
            return string.Equals(value, "-v", StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "--version", StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteUsage()
        {
            Console.WriteLine("Unpacker extracts supported InstallShield setup payloads.");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  Unpacker.exe <setup.exe> [output-directory]");
            Console.WriteLine("  Unpacker.exe --version");
        }

        private static void WriteInfo(string message)
        {
            Console.WriteLine(message);
        }

        private static string GetVersion()
        {
            var assembly = typeof(Program).Assembly;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            return string.IsNullOrWhiteSpace(version)
                ? assembly.GetName().Version.ToString()
                : version;
        }
    }
}
