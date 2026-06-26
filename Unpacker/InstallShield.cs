namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public class InstallShield
    {
        private const int MaxEntryCount = 100000;
        private const int MaxNameBytes = 8192;
        private const int MaxVersionBytes = 1024;
        private const int MaxSizeBytes = 32;
        private const int CopyBufferSize = 81920;

        private static readonly Encoding LegacyEncoding = Encoding.Default;

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            if (string.IsNullOrWhiteSpace(directoryOutput))
            {
                directoryOutput = OutputPath.GetDefaultDirectory(fileToUnpack);
            }

            try
            {
                Message?.Invoke("Checking for InstallShield overlay.");
                if (!PeHeaderReader.IsOverlay(fileToUnpack, out var overlayPositionStart, out var overlayLength))
                {
                    return false;
                }

                using (var fs = new FileStream(fileToUnpack, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    if (!TryParseOverlay(br, overlayPositionStart, overlayLength, directoryOutput, out var formatName, out var entries, out var error))
                    {
                        Message?.Invoke($"InstallShield overlay was not recognized: {error}");
                        return false;
                    }

                    Message?.Invoke($"Detected: {formatName}");
                    Message?.Invoke($"Overlay start: 0x{overlayPositionStart:X8}");
                    Message?.Invoke($"Files: {entries.Count}");

                    foreach (var entry in entries)
                    {
                        ExtractEntry(br, directoryOutput, entry);
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                Message?.Invoke($"InstallShield extraction failed: {ex.Message}");
                return false;
            }
        }

        private static bool TryParseOverlay(
            BinaryReader br,
            long overlayPositionStart,
            long overlayLength,
            string directoryOutput,
            out string formatName,
            out List<InstallShieldEntry> entries,
            out string error)
        {
            string unicodeError;
            if (TryParseCountedUnicodeOverlay(br, overlayPositionStart, overlayLength, directoryOutput, out entries, out unicodeError))
            {
                formatName = "InstallShield UTF-16 overlay table";
                error = null;
                return true;
            }

            string legacyError;
            if (TryParseLegacyAnsiOverlay(br, overlayPositionStart, directoryOutput, out entries, out legacyError))
            {
                formatName = "legacy InstallShield ANSI overlay table";
                error = null;
                return true;
            }

            formatName = null;
            entries = null;
            error = $"UTF-16 parser: {unicodeError}; legacy ANSI parser: {legacyError}";
            return false;
        }

        private static bool TryParseCountedUnicodeOverlay(
            BinaryReader br,
            long overlayPositionStart,
            long overlayLength,
            string directoryOutput,
            out List<InstallShieldEntry> entries,
            out string error)
        {
            entries = new List<InstallShieldEntry>();

            try
            {
                br.BaseStream.Position = overlayPositionStart;
                EnsureAvailable(br, 4);

                var fileCount = br.ReadUInt32();
                ValidateEntryCount(fileCount, overlayLength);

                for (var i = 0u; i < fileCount; i += 1)
                {
                    entries.Add(ReadEntryMetadata(
                        br,
                        directoryOutput,
                        "UTF-16",
                        ReadNullTerminatedUtf16String));
                }

                if (!IsAtEndOrPadding(br))
                {
                    throw new InvalidDataException($"Unexpected data after the last UTF-16 entry at offset 0x{br.BaseStream.Position:X}.");
                }

                error = null;
                return true;
            }
            catch (Exception ex) when (IsParseException(ex))
            {
                entries = null;
                error = ex.Message;
                return false;
            }
        }

        private static bool TryParseLegacyAnsiOverlay(
            BinaryReader br,
            long overlayPositionStart,
            string directoryOutput,
            out List<InstallShieldEntry> entries,
            out string error)
        {
            entries = new List<InstallShieldEntry>();

            try
            {
                br.BaseStream.Position = overlayPositionStart;

                while (!IsAtEndOrPadding(br))
                {
                    if (entries.Count >= MaxEntryCount)
                    {
                        throw new InvalidDataException($"Too many legacy entries. Limit is {MaxEntryCount}.");
                    }

                    var before = br.BaseStream.Position;
                    entries.Add(ReadEntryMetadata(
                        br,
                        directoryOutput,
                        "legacy ANSI",
                        ReadNullTerminatedAnsiString));

                    if (br.BaseStream.Position <= before)
                    {
                        throw new InvalidDataException("Legacy parser did not advance in the overlay stream.");
                    }
                }

                if (entries.Count == 0)
                {
                    throw new InvalidDataException("No legacy entries were found.");
                }

                error = null;
                return true;
            }
            catch (Exception ex) when (IsParseException(ex))
            {
                entries = null;
                error = ex.Message;
                return false;
            }
        }

        private static InstallShieldEntry ReadEntryMetadata(
            BinaryReader br,
            string directoryOutput,
            string formatName,
            Func<BinaryReader, int, string, string> stringReader)
        {
            var fileName = stringReader(br, MaxNameBytes, "file name");
            var fullFileName = stringReader(br, MaxNameBytes, "full file name");
            var version = stringReader(br, MaxVersionBytes, "version");
            var fileSizeText = stringReader(br, MaxSizeBytes, "file size");
            var outputName = string.IsNullOrWhiteSpace(fullFileName) ? fileName : fullFileName;

            if (string.IsNullOrWhiteSpace(outputName))
            {
                throw new InvalidDataException($"{formatName} entry has an empty file name.");
            }

            if (!long.TryParse(fileSizeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileSize)
                || fileSize < 0)
            {
                throw new InvalidDataException($"Invalid {formatName} file size for {outputName}: {fileSizeText}");
            }

            EnsureAvailable(br, fileSize);
            OutputPath.GetSafeFilePath(directoryOutput, outputName);

            var entry = new InstallShieldEntry
            {
                OutputName = outputName,
                Version = version,
                DataOffset = br.BaseStream.Position,
                Size = fileSize
            };

            br.BaseStream.Position += fileSize;
            return entry;
        }

        private static void ExtractEntry(BinaryReader br, string directoryOutput, InstallShieldEntry entry)
        {
            Message?.Invoke($"Extracting: {entry.OutputName}");

            br.BaseStream.Position = entry.DataOffset;
            var outputPath = OutputPath.GetSafeFilePath(directoryOutput, entry.OutputName);
            OutputPath.EnsureParentDirectory(outputPath);
            using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                CopyBytesRequired(br.BaseStream, output, entry.Size);
            }

            if (!string.IsNullOrWhiteSpace(entry.Version))
            {
                Message?.Invoke($"Version: {entry.Version}");
            }
        }

        private static string ReadNullTerminatedUtf16String(BinaryReader br, int maxBytes, string fieldName)
        {
            using (var buffer = new MemoryStream())
            {
                while (buffer.Length < maxBytes)
                {
                    EnsureAvailable(br, 2);

                    var low = br.ReadByte();
                    var high = br.ReadByte();
                    if (low == 0 && high == 0)
                    {
                        return Encoding.Unicode.GetString(buffer.ToArray());
                    }

                    buffer.WriteByte(low);
                    buffer.WriteByte(high);
                }
            }

            throw new InvalidDataException($"UTF-16 {fieldName} is longer than {maxBytes} bytes.");
        }

        private static string ReadNullTerminatedAnsiString(BinaryReader br, int maxBytes, string fieldName)
        {
            using (var buffer = new MemoryStream())
            {
                while (buffer.Length < maxBytes)
                {
                    EnsureAvailable(br, 1);

                    var value = br.ReadByte();
                    if (value == 0)
                    {
                        return LegacyEncoding.GetString(buffer.ToArray());
                    }

                    buffer.WriteByte(value);
                }
            }

            throw new InvalidDataException($"Legacy ANSI {fieldName} is longer than {maxBytes} bytes.");
        }

        private static void ValidateEntryCount(uint fileCount, long overlayLength)
        {
            if (fileCount == 0)
            {
                throw new InvalidDataException("UTF-16 overlay file count is zero.");
            }

            var maxEntriesByLength = Math.Max(1, (overlayLength - 4) / 8);
            if (fileCount > MaxEntryCount || fileCount > maxEntriesByLength)
            {
                throw new InvalidDataException($"Unreasonable UTF-16 overlay file count: {fileCount}.");
            }
        }

        private static void EnsureAvailable(BinaryReader br, long count)
        {
            if (count < 0 || br.BaseStream.Length - br.BaseStream.Position < count)
            {
                throw new EndOfStreamException($"Expected {count} bytes at offset 0x{br.BaseStream.Position:X}, but the overlay ended early.");
            }
        }

        private static bool IsAtEndOrPadding(BinaryReader br)
        {
            var originalPosition = br.BaseStream.Position;
            try
            {
                while (br.BaseStream.Position < br.BaseStream.Length)
                {
                    if (br.ReadByte() != 0)
                    {
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                br.BaseStream.Position = originalPosition;
            }
        }

        private static void CopyBytesRequired(Stream input, Stream output, long count)
        {
            var buffer = new byte[CopyBufferSize];
            var remaining = count;

            while (remaining > 0)
            {
                var readSize = (int)Math.Min(buffer.Length, remaining);
                var read = input.Read(buffer, 0, readSize);
                if (read <= 0)
                {
                    throw new EndOfStreamException($"Expected {count} payload bytes, but the overlay ended early.");
                }

                output.Write(buffer, 0, read);
                remaining -= read;
            }
        }

        private static bool IsParseException(Exception ex)
        {
            return ex is InvalidDataException
                || ex is EndOfStreamException
                || ex is IOException
                || ex is OverflowException
                || ex is ArgumentException;
        }

        private sealed class InstallShieldEntry
        {
            public string OutputName { get; set; }

            public string Version { get; set; }

            public long DataOffset { get; set; }

            public long Size { get; set; }
        }
    }
}
