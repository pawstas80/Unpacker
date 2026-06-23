namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    /// <summary>
    /// Extracts payloads stored after an InstallShield setup executable as an ISSetupStream overlay.
    /// Format details are based on the MIT-licensed ISSetupStream extractor credited in THIRD-PARTY-NOTICES.md.
    /// </summary>
    public class IsSetupStream
    {
        private const string Signature = "ISSetupStream";
        private const int ChunkSize = 0x400;

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            if (string.IsNullOrWhiteSpace(directoryOutput))
            {
                directoryOutput = OutputPath.GetDefaultDirectory(fileToUnpack);
            }

            try
            {
                Message?.Invoke("Checking for ISSetupStream overlay.");
                if (!PeHeaderReader.IsOverlay(fileToUnpack, out var overlayPositionStart, out _))
                {
                    return false;
                }

                using (var fs = new FileStream(fileToUnpack, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    br.BaseStream.Position = overlayPositionStart;
                    if (!HasSignature(br))
                    {
                        return false;
                    }

                    Message?.Invoke("Detected: ISSetupStream");
                    Message?.Invoke($"Overlay start: 0x{overlayPositionStart:X8}");

                    WriteEmbeddedSetup(br, overlayPositionStart, directoryOutput);

                    br.BaseStream.Position = overlayPositionStart + Signature.Length + 1;
                    var numFiles = br.ReadUInt16();
                    Message?.Invoke($"Files: {numFiles}");

                    var formatVersion = br.ReadUInt32();
                    br.ReadBytesRequired(8);
                    br.ReadUInt16();
                    br.ReadBytesRequired(16);

                    for (var i = 0; i < numFiles; i += 1)
                    {
                        ExtractEntry(br, directoryOutput, formatVersion);
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                Message?.Invoke($"ISSetupStream extraction failed: {ex.Message}");
                return false;
            }
        }

        private static bool HasSignature(BinaryReader br)
        {
            var signatureBytes = br.ReadBytesRequired(Signature.Length);
            if (!string.Equals(Encoding.ASCII.GetString(signatureBytes), Signature, StringComparison.Ordinal))
            {
                return false;
            }

            return br.ReadByte() == 0;
        }

        private static void WriteEmbeddedSetup(BinaryReader br, long overlayPositionStart, string directoryOutput)
        {
            var setupSize = checked((int)overlayPositionStart);
            var setupPath = OutputPath.GetSafeFilePath(directoryOutput, "Setup.exe");
            OutputPath.EnsureParentDirectory(setupPath);

            br.BaseStream.Position = 0;
            File.WriteAllBytes(setupPath, br.ReadBytesRequired(setupSize));
        }

        private static void ExtractEntry(BinaryReader br, string directoryOutput, uint formatVersion)
        {
            var nameLength = br.ReadInt32();
            if (nameLength <= 0)
            {
                throw new InvalidDataException($"Invalid entry name length: {nameLength}");
            }

            var encryptionFlags = br.ReadInt32();
            br.ReadBytesRequired(2);

            var fileLength = checked((int)br.ReadUInt32());
            br.ReadBytesRequired(8);

            var isCompressed = br.ReadUInt16() == 1;
            var writeTime = ReadFileTime(br, formatVersion);
            var creationTime = ReadFileTime(br, formatVersion);
            var accessTime = ReadFileTime(br, formatVersion);
            var fileName = Encoding.Unicode.GetString(br.ReadBytesRequired(nameLength)).TrimEnd('\0');
            var encryptedData = br.ReadBytesRequired(fileLength);

            Message?.Invoke($"Extracting: {fileName}");

            var key = BuildKey(Encoding.UTF8.GetBytes(fileName));
            var fileData = DecryptPayload(encryptedData, encryptionFlags, key);
            if (isCompressed)
            {
                fileData = fileData.UnZlib();
            }

            var outputPath = OutputPath.GetSafeFilePath(directoryOutput, fileName);
            OutputPath.EnsureParentDirectory(outputPath);
            File.WriteAllBytes(outputPath, fileData.ToArray());
            NativeMethods.TrySetAllFileTimesUtc(outputPath, creationTime, accessTime, writeTime);
        }

        private static DateTime ReadFileTime(BinaryReader br, uint formatVersion)
        {
            return formatVersion > 3
                ? DateTime.FromFileTimeUtc(br.ReadInt64())
                : DateTime.UtcNow;
        }

        private static List<byte> DecryptPayload(byte[] encryptedData, int encryptionFlags, byte[] key)
        {
            var output = new List<byte>(encryptedData.Length);
            var isType4 = (encryptionFlags & 4) == 4;
            if (!isType4)
            {
                output.AddRange(Decrypt(encryptedData, 0, encryptedData.Length, key));
                return output;
            }

            for (var offset = 0; offset < encryptedData.Length; offset += ChunkSize)
            {
                var count = Math.Min(ChunkSize, encryptedData.Length - offset);
                output.AddRange(Decrypt(encryptedData, offset, count, key));
            }

            return output;
        }

        private static byte Decrypt(byte value, byte key)
        {
            return (byte)((~(key ^ ((value << 4) | (value >> 4)))) & 0xFF);
        }

        private static List<byte> Decrypt(byte[] buffer, int position, int length, byte[] key)
        {
            if (key.Length == 0)
            {
                throw new InvalidDataException("Cannot decrypt an entry with an empty file name.");
            }

            var output = new List<byte>(length);
            for (var i = 0; i < length; i += 1)
            {
                output.Add(Decrypt(buffer[position + i], key[i % key.Length]));
            }

            return output;
        }

        private static byte[] BuildKey(byte[] seed)
        {
            var magic = new byte[] { 0x13, 0x35, 0x86, 0x07 };
            var buffer = new byte[seed.Length];
            for (var i = 0; i < seed.Length; i += 1)
            {
                buffer[i] = (byte)(seed[i] ^ magic[i % magic.Length]);
            }

            return buffer;
        }
    }
}
