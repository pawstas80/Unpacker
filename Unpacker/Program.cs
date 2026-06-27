namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Reflection;

    internal class Program
    {
        private static readonly string[] RecursiveExtensions = { ".exe", ".msi", ".cab", ".hdr" };

        private static RunLogger logger;

        private static int Main(string[] args)
        {
            if (args.Length == 1 && IsVersion(args[0]))
            {
                Console.WriteLine($"Unpacker {GetVersion()}");
                return 0;
            }

            if (args.Length == 0 || HasHelp(args))
            {
                WriteUsage();
                return args.Length == 0 ? 1 : 0;
            }

            CommandOptions options;
            string parseError;
            if (!TryParseOptions(args, out options, out parseError))
            {
                Console.Error.WriteLine(parseError);
                Console.Error.WriteLine();
                WriteUsage();
                return 1;
            }

            if (!File.Exists(options.InputFile))
            {
                Console.Error.WriteLine($"Input file does not exist: {options.InputFile}");
                return 2;
            }

            using (logger = new RunLogger(options.Verbosity, GetLogPath(options)))
            {
                SubscribeMessages();

                logger.Info($"Input : {options.InputFile}");
                if (options.Mode == CommandMode.Extract)
                {
                    logger.Info($"Output: {options.OutputDirectory}");
                }

                var processedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var result = ProcessFile(options.InputFile, options.OutputDirectory, options, processedFiles, 0);

                if (result)
                {
                    logger.Summary(options.Mode == CommandMode.Test ? "Test completed." : "Done.");
                    return 0;
                }

                logger.Error("No supported installer payload was found, or extraction failed.");
                return 3;
            }
        }

        private static bool ProcessFile(
            string inputFile,
            string outputDirectory,
            CommandOptions options,
            ISet<string> processedFiles,
            int depth)
        {
            inputFile = Path.GetFullPath(inputFile);
            if (!processedFiles.Add(inputFile))
            {
                logger.Info($"Skipping already processed file: {inputFile}");
                return true;
            }

            switch (options.Mode)
            {
                case CommandMode.List:
                    return ListFile(inputFile);

                case CommandMode.Test:
                    return TestFile(inputFile);

                default:
                    break;
            }

            outputDirectory = string.IsNullOrWhiteSpace(outputDirectory)
                ? OutputPath.GetDefaultDirectory(inputFile)
                : Path.GetFullPath(outputDirectory);

            var extracted = ExtractFile(inputFile, outputDirectory);
            if (!extracted)
            {
                return false;
            }

            if (options.Recursive && depth < options.MaxDepth)
            {
                ExtractNestedPackages(outputDirectory, options, processedFiles, depth + 1);
            }

            return true;
        }

        private static bool ExtractFile(string inputFile, string outputDirectory)
        {
            var isMsiPackage = string.Equals(Path.GetExtension(inputFile), ".msi", StringComparison.OrdinalIgnoreCase);
            if (MsiPackage.Unpack(inputFile, outputDirectory))
            {
                return true;
            }

            if (isMsiPackage)
            {
                logger.Error("MSI extraction failed.");
                return false;
            }

            return CabinetPackage.Unpack(inputFile, outputDirectory)
                || InstallShieldCabinetPackage.Unpack(inputFile, outputDirectory)
                || IsSetupStream.Unpack(inputFile, outputDirectory)
                || InstallShield.Unpack(inputFile, outputDirectory);
        }

        private static bool ListFile(string inputFile)
        {
            return MsiPackage.List(inputFile)
                || CabinetPackage.List(inputFile)
                || InstallShieldCabinetPackage.List(inputFile)
                || IsSetupStream.List(inputFile)
                || InstallShield.List(inputFile);
        }

        private static bool TestFile(string inputFile)
        {
            return MsiPackage.Test(inputFile)
                || CabinetPackage.Test(inputFile)
                || InstallShieldCabinetPackage.Test(inputFile)
                || IsSetupStream.Test(inputFile)
                || InstallShield.Test(inputFile);
        }

        private static void ExtractNestedPackages(
            string outputDirectory,
            CommandOptions options,
            ISet<string> processedFiles,
            int depth)
        {
            if (!Directory.Exists(outputDirectory))
            {
                return;
            }

            var nestedFiles = Directory
                .EnumerateFiles(outputDirectory, "*", SearchOption.AllDirectories)
                .Where(IsRecursiveCandidate)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var nestedFile in nestedFiles)
            {
                if (processedFiles.Contains(Path.GetFullPath(nestedFile)))
                {
                    continue;
                }

                var nestedOutput = OutputPath.GetDefaultDirectory(nestedFile);
                logger.Info($"Recursive depth {depth}: {nestedFile}");
                ProcessFile(nestedFile, nestedOutput, options, processedFiles, depth);
            }
        }

        private static bool IsRecursiveCandidate(string file)
        {
            var extension = Path.GetExtension(file);
            return RecursiveExtensions.Any(value => string.Equals(value, extension, StringComparison.OrdinalIgnoreCase));
        }

        private static void SubscribeMessages()
        {
            IsSetupStream.Message += WriteInfo;
            InstallShield.Message += WriteInfo;
            MsiPackage.Message += WriteInfo;
            CabinetPackage.Message += WriteInfo;
            InstallShieldCabinetPackage.Message += WriteInfo;
        }

        private static bool TryParseOptions(string[] args, out CommandOptions options, out string error)
        {
            options = new CommandOptions();
            error = null;
            var positional = new List<string>();

            for (var i = 0; i < args.Length; i += 1)
            {
                var arg = args[i];
                if (!arg.StartsWith("-", StringComparison.Ordinal) && !arg.StartsWith("/", StringComparison.Ordinal))
                {
                    positional.Add(arg);
                    continue;
                }

                if (IsHelp(arg) || IsVersion(arg))
                {
                    error = $"Unexpected option here: {arg}";
                    return false;
                }

                if (EqualsOption(arg, "--list"))
                {
                    options.Mode = CommandMode.List;
                }
                else if (EqualsOption(arg, "--test"))
                {
                    options.Mode = CommandMode.Test;
                }
                else if (EqualsOption(arg, "--recursive") || EqualsOption(arg, "-r"))
                {
                    options.Recursive = true;
                }
                else if (EqualsOption(arg, "--quiet") || EqualsOption(arg, "-q"))
                {
                    options.Verbosity = Verbosity.Quiet;
                }
                else if (EqualsOption(arg, "--verbose"))
                {
                    options.Verbosity = Verbosity.Verbose;
                }
                else if (EqualsOption(arg, "--no-log"))
                {
                    options.NoLog = true;
                }
                else if (EqualsOption(arg, "--max-depth"))
                {
                    if (!TryReadIntValue(args, ref i, "--max-depth", out var value, out error))
                    {
                        return false;
                    }

                    if (value < 0 || value > 20)
                    {
                        error = "--max-depth must be between 0 and 20.";
                        return false;
                    }

                    options.MaxDepth = value;
                }
                else if (EqualsOption(arg, "--log"))
                {
                    if (!TryReadStringValue(args, ref i, "--log", out var value, out error))
                    {
                        return false;
                    }

                    options.LogPath = Path.GetFullPath(value);
                }
                else
                {
                    error = $"Unknown option: {arg}";
                    return false;
                }
            }

            if (options.Mode != CommandMode.Extract && options.Recursive)
            {
                error = "--recursive can only be used with extraction.";
                return false;
            }

            if (positional.Count == 0 || positional.Count > 2)
            {
                error = "Expected input file and optional output directory.";
                return false;
            }

            options.InputFile = Path.GetFullPath(positional[0]);
            options.OutputDirectory = positional.Count == 2
                ? Path.GetFullPath(positional[1])
                : OutputPath.GetDefaultDirectory(options.InputFile);

            return true;
        }

        private static bool TryReadStringValue(string[] args, ref int index, string optionName, out string value, out string error)
        {
            value = null;
            error = null;

            if (index + 1 >= args.Length)
            {
                error = $"{optionName} requires a value.";
                return false;
            }

            value = args[index + 1];
            index += 1;
            return true;
        }

        private static bool TryReadIntValue(string[] args, ref int index, string optionName, out int value, out string error)
        {
            value = 0;
            if (!TryReadStringValue(args, ref index, optionName, out var text, out error))
            {
                return false;
            }

            if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            {
                error = $"{optionName} requires an integer value.";
                return false;
            }

            return true;
        }

        private static string GetLogPath(CommandOptions options)
        {
            if (options.NoLog)
            {
                return null;
            }

            if (!string.IsNullOrWhiteSpace(options.LogPath))
            {
                return options.LogPath;
            }

            return options.Mode == CommandMode.Extract
                ? Path.Combine(options.OutputDirectory, "Unpacker.log")
                : null;
        }

        private static bool HasHelp(string[] args)
        {
            return args.Length == 1 && IsHelp(args[0]);
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

        private static bool EqualsOption(string value, string expected)
        {
            return string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteUsage()
        {
            Console.WriteLine("Unpacker extracts supported installer payloads.");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  Unpacker.exe [options] <setup.exe|package.msi|archive.cab|data1.hdr> [output-directory]");
            Console.WriteLine("  Unpacker.exe --help");
            Console.WriteLine("  Unpacker.exe --version");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --list             list supported package contents without extracting");
            Console.WriteLine("  --test             test supported package extraction without keeping files");
            Console.WriteLine("  --recursive, -r    extract nested supported packages");
            Console.WriteLine("  --max-depth <n>    recursive extraction depth, default 3");
            Console.WriteLine("  --quiet, -q        write only errors to console");
            Console.WriteLine("  --verbose          write every processed file to console");
            Console.WriteLine("  --log <file>       write detailed log to a custom file");
            Console.WriteLine("  --no-log           disable default extraction log");
        }

        private static void WriteInfo(string message)
        {
            logger?.Info(message);
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
