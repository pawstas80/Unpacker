namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    internal static class OutputPath
    {
        private static readonly char[] DirectorySeparators = { '\\', '/' };
        private static readonly char[] InvalidFileNameChars = Path.GetInvalidFileNameChars();
        private static readonly string[] ReservedDeviceNames =
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };
        private const int MaxSegmentLength = 120;

        public static string GetDefaultDirectory(string inputFile)
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(inputFile));
            var name = Path.GetFileNameWithoutExtension(inputFile);
            return Path.Combine(directory ?? Directory.GetCurrentDirectory(), name);
        }

        public static string GetSafeFilePath(string outputDirectory, string relativePath)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
            {
                throw new ArgumentException("Output directory cannot be empty.", nameof(outputDirectory));
            }

            if (string.IsNullOrWhiteSpace(relativePath))
            {
                throw new InvalidDataException("Archive entry has an empty file name.");
            }

            if (Path.IsPathRooted(relativePath))
            {
                throw new InvalidDataException($"Archive entry uses an absolute path: {relativePath}");
            }

            var outputRoot = Path.GetFullPath(outputDirectory);
            var safeParts = new List<string>();
            foreach (var part in relativePath.Split(DirectorySeparators, StringSplitOptions.RemoveEmptyEntries))
            {
                if (part == ".")
                {
                    continue;
                }

                if (part == "..")
                {
                    throw new InvalidDataException($"Archive entry attempts to leave the output directory: {relativePath}");
                }

                safeParts.Add(SanitizeFileName(part));
            }

            if (safeParts.Count == 0)
            {
                throw new InvalidDataException("Archive entry does not contain a usable file name.");
            }

            var safeRelativePath = Path.Combine(safeParts.ToArray());
            var fullPath = Path.GetFullPath(Path.Combine(outputRoot, safeRelativePath));
            var outputRootWithSeparator = EnsureTrailingSeparator(outputRoot);

            if (!fullPath.StartsWith(outputRootWithSeparator, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(fullPath, outputRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"Archive entry resolves outside the output directory: {relativePath}");
            }

            return fullPath;
        }

        public static void EnsureParentDirectory(string filePath)
        {
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        private static string SanitizeFileName(string value)
        {
            var chars = value.ToCharArray();
            for (var i = 0; i < chars.Length; i += 1)
            {
                if (Array.IndexOf(InvalidFileNameChars, chars[i]) >= 0)
                {
                    chars[i] = '_';
                }
            }

            var sanitized = new string(chars).TrimEnd(' ', '.');
            if (string.IsNullOrWhiteSpace(sanitized))
            {
                sanitized = "_";
            }

            var deviceName = sanitized.Split('.')[0];
            if (Array.Exists(ReservedDeviceNames, name => string.Equals(name, deviceName, StringComparison.OrdinalIgnoreCase)))
            {
                sanitized = "_" + sanitized;
            }

            if (sanitized.Length > MaxSegmentLength)
            {
                sanitized = sanitized.Substring(0, MaxSegmentLength).TrimEnd(' ', '.');
            }

            return string.IsNullOrWhiteSpace(sanitized) ? "_" : sanitized;
        }

        private static string EnsureTrailingSeparator(string path)
        {
            if (path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                || path.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            {
                return path;
            }

            return path + Path.DirectorySeparatorChar;
        }
    }
}
