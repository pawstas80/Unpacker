namespace Unpacker
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public class InstallShield
    {
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
                if (!PeHeaderReader.IsOverlay(fileToUnpack, out var overlayPositionStart, out _))
                {
                    return false;
                }

                using (var fs = new FileStream(fileToUnpack, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    br.BaseStream.Position = overlayPositionStart;
                    var fileCount = br.ReadUInt32();
                    Message?.Invoke("Detected: InstallShield overlay");
                    Message?.Invoke($"Files: {fileCount}");

                    for (var i = 0u; i < fileCount; i += 1)
                    {
                        ExtractEntry(br, directoryOutput);
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

        private static void ExtractEntry(BinaryReader br, string directoryOutput)
        {
            var fileName = ReadNullTerminatedUtf16String(br);
            var fullFileName = ReadNullTerminatedUtf16String(br);
            var version = ReadNullTerminatedUtf16String(br);
            var fileSizeText = ReadNullTerminatedUtf16String(br);

            if (!int.TryParse(fileSizeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileSize)
                || fileSize < 0)
            {
                throw new InvalidDataException($"Invalid file size for {fullFileName}: {fileSizeText}");
            }

            var outputName = string.IsNullOrWhiteSpace(fullFileName) ? fileName : fullFileName;
            Message?.Invoke($"Extracting: {outputName}");

            var buffer = br.ReadBytesRequired(fileSize);
            var outputPath = OutputPath.GetSafeFilePath(directoryOutput, outputName);
            OutputPath.EnsureParentDirectory(outputPath);
            File.WriteAllBytes(outputPath, buffer);

            if (!string.IsNullOrWhiteSpace(version))
            {
                Message?.Invoke($"Version: {version}");
            }
        }

        private static string ReadNullTerminatedUtf16String(BinaryReader br)
        {
            using (var buffer = new MemoryStream())
            {
                while (true)
                {
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
        }
    }
}
