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
        private const int EncryptedHeaderSize = 46;
        private const int EncryptedEntrySize = 0x138;
        private const int EncryptedFileNameBytes = 260;
        private const int EncryptedDecodeBlockSize = 1024;
        private const int EncryptedSignatureSearchBytes = 64 * 1024;

        private static readonly Encoding LegacyEncoding = Encoding.Default;
        private static readonly byte[] InstallShieldSignatureBytes = Encoding.ASCII.GetBytes("InstallShield\0");

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            return Run(fileToUnpack, directoryOutput, InstallShieldOperation.Extract);
        }

        public static bool List(string fileToUnpack)
        {
            return Run(fileToUnpack, null, InstallShieldOperation.List);
        }

        public static bool Test(string fileToUnpack)
        {
            return Run(fileToUnpack, null, InstallShieldOperation.Test);
        }

        private static bool Run(string fileToUnpack, string directoryOutput, InstallShieldOperation operation)
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
                        if (operation == InstallShieldOperation.List)
                        {
                            Message?.Invoke($"{entry.Size,12}  {entry.OutputName}");
                        }
                        else if (operation == InstallShieldOperation.Test)
                        {
                            TestEntry(br, entry);
                        }
                        else
                        {
                            ExtractEntry(br, directoryOutput, entry);
                        }
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                Message?.Invoke($"InstallShield operation failed: {ex.Message}");
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

            string encryptedError;
            if (TryParseEncryptedInstallShieldArchive(br, overlayPositionStart, directoryOutput, out entries, out encryptedError))
            {
                formatName = "encrypted InstallShield archive";
                error = null;
                return true;
            }

            formatName = null;
            entries = null;
            error = $"UTF-16 parser: {unicodeError}; legacy ANSI parser: {legacyError}; encrypted parser: {encryptedError}";
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

        private static bool TryParseEncryptedInstallShieldArchive(
            BinaryReader br,
            long overlayPositionStart,
            string directoryOutput,
            out List<InstallShieldEntry> entries,
            out string error)
        {
            entries = new List<InstallShieldEntry>();

            try
            {
                var headerOffset = FindSignature(br, overlayPositionStart, EncryptedSignatureSearchBytes, InstallShieldSignatureBytes);
                if (headerOffset < 0)
                {
                    throw new InvalidDataException("InstallShield encrypted archive signature was not found near the overlay start.");
                }

                br.BaseStream.Position = headerOffset;
                var signature = Encoding.ASCII.GetString(br.ReadBytesRequired(InstallShieldSignatureBytes.Length)).TrimEnd('\0');
                if (!string.Equals(signature, "InstallShield", StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Invalid encrypted InstallShield signature.");
                }

                var fileCount = br.ReadUInt16();
                var archiveType = br.ReadUInt32();
                if (archiveType > 4)
                {
                    throw new InvalidDataException($"Unsupported encrypted InstallShield archive type: {archiveType}.");
                }

                br.ReadBytesRequired(8);
                br.ReadUInt16();
                br.ReadBytesRequired(16);

                if (fileCount == 0)
                {
                    throw new InvalidDataException($"Unreasonable encrypted InstallShield file count: {fileCount}.");
                }

                for (var i = 0; i < fileCount; i += 1)
                {
                    entries.Add(ReadEncryptedEntryMetadata(br, directoryOutput));
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

        private static InstallShieldEntry ReadEncryptedEntryMetadata(BinaryReader br, string directoryOutput)
        {
            EnsureAvailable(br, EncryptedEntrySize);

            var entryOffset = br.BaseStream.Position;
            var fileName = ReadFixedNullTerminatedString(br, EncryptedFileNameBytes, LegacyEncoding);
            if (string.IsNullOrWhiteSpace(fileName))
            {
                throw new InvalidDataException($"Encrypted InstallShield entry at 0x{entryOffset:X} has an empty file name.");
            }

            var encodedFlags = br.ReadUInt32();
            br.ReadUInt32();
            var fileSize = br.ReadUInt32();
            br.ReadBytesRequired(8);
            var inflateAfterDecode = br.ReadUInt16() != 0;
            br.ReadBytesRequired(30);

            EnsureAvailable(br, fileSize);
            OutputPath.GetSafeFilePath(directoryOutput, fileName);

            var entry = new InstallShieldEntry
            {
                OutputName = fileName,
                DataOffset = br.BaseStream.Position,
                Size = fileSize,
                IsEncrypted = true,
                EncodedFlags = encodedFlags,
                InflateAfterDecode = inflateAfterDecode
            };

            br.BaseStream.Position += fileSize;
            return entry;
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

            if (entry.IsEncrypted)
            {
                ExtractEncryptedEntry(br, directoryOutput, entry);
                return;
            }

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

        private static void TestEntry(BinaryReader br, InstallShieldEntry entry)
        {
            Message?.Invoke($"Testing: {entry.OutputName}");

            if (entry.IsEncrypted)
            {
                TestEncryptedEntry(br, entry);
                return;
            }

            br.BaseStream.Position = entry.DataOffset;
            CopyBytesRequired(br.BaseStream, Stream.Null, entry.Size);
        }

        private static void ExtractEncryptedEntry(BinaryReader br, string directoryOutput, InstallShieldEntry entry)
        {
            br.BaseStream.Position = entry.DataOffset;
            var data = ReadEntryBytes(br, entry.Size);
            DecodeEncryptedInstallShieldData(data, entry.OutputName, entry.EncodedFlags);

            var outputPath = OutputPath.GetSafeFilePath(directoryOutput, entry.OutputName);
            OutputPath.EnsureParentDirectory(outputPath);
            using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                if (entry.InflateAfterDecode)
                {
                    using (var input = new MemoryStream(data))
                    using (var inflater = new ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream(input))
                    {
                        CopyStream(inflater, output);
                    }
                }
                else
                {
                    output.Write(data, 0, data.Length);
                }
            }
        }

        private static void TestEncryptedEntry(BinaryReader br, InstallShieldEntry entry)
        {
            br.BaseStream.Position = entry.DataOffset;
            var data = ReadEntryBytes(br, entry.Size);
            DecodeEncryptedInstallShieldData(data, entry.OutputName, entry.EncodedFlags);

            if (!entry.InflateAfterDecode)
            {
                return;
            }

            using (var input = new MemoryStream(data))
            using (var inflater = new ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream(input))
            {
                CopyStream(inflater, Stream.Null);
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

        private static string ReadFixedNullTerminatedString(BinaryReader br, int byteCount, Encoding encoding)
        {
            var bytes = br.ReadBytesRequired(byteCount);
            var length = Array.IndexOf(bytes, (byte)0);
            if (length < 0)
            {
                length = bytes.Length;
            }

            return encoding.GetString(bytes, 0, length);
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

        private static long FindSignature(BinaryReader br, long start, int maxBytes, byte[] signature)
        {
            var end = Math.Min(br.BaseStream.Length, start + maxBytes);
            var matched = 0;
            br.BaseStream.Position = start;

            while (br.BaseStream.Position < end)
            {
                var position = br.BaseStream.Position;
                var value = br.ReadByte();
                if (value == signature[matched])
                {
                    matched += 1;
                    if (matched == signature.Length)
                    {
                        return position - signature.Length + 1;
                    }
                }
                else
                {
                    matched = value == signature[0] ? 1 : 0;
                }
            }

            return -1;
        }

        private static byte[] ReadEntryBytes(BinaryReader br, long count)
        {
            if (count > int.MaxValue)
            {
                throw new InvalidDataException($"Entry is too large to decode in memory: {count} bytes.");
            }

            return br.ReadBytesRequired((int)count);
        }

        private static void DecodeEncryptedInstallShieldData(byte[] data, string seed, uint encodedFlags)
        {
            if ((encodedFlags & 6) == 0)
            {
                return;
            }

            var seedBytes = LegacyEncoding.GetBytes(seed);
            if (seedBytes.Length == 0)
            {
                throw new InvalidDataException("Cannot decode encrypted InstallShield entry with an empty file name.");
            }

            var key = BuildInstallShieldKey(seedBytes);
            if ((encodedFlags & 4) == 4)
            {
                for (var offset = 0; offset < data.Length; offset += EncryptedDecodeBlockSize)
                {
                    var count = Math.Min(EncryptedDecodeBlockSize, data.Length - offset);
                    DecodeEncryptedInstallShieldRange(data, offset, count, key);
                }

                return;
            }

            DecodeEncryptedInstallShieldRange(data, 0, data.Length, key);
        }

        private static byte[] BuildInstallShieldKey(byte[] seed)
        {
            var magic = new byte[] { 0x13, 0x35, 0x86, 0x07 };
            var key = new byte[seed.Length];
            for (var i = 0; i < seed.Length; i += 1)
            {
                key[i] = (byte)(seed[i] ^ magic[i % magic.Length]);
            }

            return key;
        }

        private static void DecodeEncryptedInstallShieldRange(byte[] data, int offset, int count, byte[] key)
        {
            for (var i = 0; i < count; i += 1)
            {
                var value = data[offset + i];
                var rotated = ((value << 4) | (value >> 4)) & 0xFF;
                data[offset + i] = (byte)(~(key[i % key.Length] ^ rotated));
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

        private static void CopyStream(Stream input, Stream output)
        {
            var buffer = new byte[CopyBufferSize];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
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

        private enum InstallShieldOperation
        {
            Extract,
            List,
            Test
        }

        private sealed class InstallShieldEntry
        {
            public string OutputName { get; set; }

            public string Version { get; set; }

            public long DataOffset { get; set; }

            public long Size { get; set; }

            public bool IsEncrypted { get; set; }

            public uint EncodedFlags { get; set; }

            public bool InflateAfterDecode { get; set; }
        }
    }
}
