namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using ICSharpCode.SharpZipLib.Zip.Compression;

    public static class InstallShieldCabinetPackage
    {
        private const uint InstallShieldCabinetSignature = 0x28635349; // ISc(
        private const int CommonHeaderSize = 20;
        private const int Version5VolumeHeaderSize = 40;
        private const int Version6VolumeHeaderSize = 64;
        private const int MaxFileGroupCount = 71;
        private const int MaxComponentCount = 71;
        private const int MaxFileCount = 100000;
        private const int BufferSize = 64 * 1024;
        private const ushort FileSplit = 1;
        private const ushort FileObfuscated = 2;
        private const ushort FileCompressed = 4;
        private const ushort FileInvalid = 8;
        private const byte LinkPrevious = 1;

        private static readonly byte[] EndOfChunk = { 0x00, 0x00, 0xFF, 0xFF };
        private static readonly Encoding LegacyEncoding = Encoding.Default;

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            return Run(fileToUnpack, directoryOutput, InstallShieldCabinetOperation.Extract);
        }

        public static bool List(string fileToUnpack)
        {
            return Run(fileToUnpack, null, InstallShieldCabinetOperation.List);
        }

        public static bool Test(string fileToUnpack)
        {
            return Run(fileToUnpack, null, InstallShieldCabinetOperation.Test);
        }

        private static bool Run(string fileToUnpack, string directoryOutput, InstallShieldCabinetOperation operation)
        {
            if (!IsCandidate(fileToUnpack) || !HasInstallShieldCabinetSignature(fileToUnpack))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(directoryOutput))
            {
                directoryOutput = OutputPath.GetDefaultDirectory(fileToUnpack);
            }

            try
            {
                var archive = InstallShieldCabinetArchive.Open(fileToUnpack);
                if (operation == InstallShieldCabinetOperation.Extract)
                {
                    Directory.CreateDirectory(directoryOutput);
                }

                Message?.Invoke("Detected: InstallShield Cabinet package");
                Message?.Invoke($"Version: {archive.MajorVersion}");
                Message?.Invoke($"Files: {archive.FileCount}");

                if (operation == InstallShieldCabinetOperation.List)
                {
                    var listed = archive.ListAll(Message);
                    Message?.Invoke($"Listed: {listed}");
                    return listed > 0;
                }

                if (operation == InstallShieldCabinetOperation.Test)
                {
                    var tested = archive.TestAll(Message);
                    Message?.Invoke($"Tested: {tested}");
                    return tested > 0;
                }

                var extracted = archive.ExtractAll(directoryOutput, Message);
                Message?.Invoke($"Extracted: {extracted}");
                return extracted > 0;
            }
            catch (Exception ex)
            {
                Message?.Invoke($"InstallShield Cabinet extraction failed: {ex.Message}");
                return false;
            }
        }

        private enum InstallShieldCabinetOperation
        {
            Extract,
            List,
            Test
        }

        private static bool IsCandidate(string file)
        {
            var extension = Path.GetExtension(file);
            return string.Equals(extension, ".hdr", StringComparison.OrdinalIgnoreCase)
                || string.Equals(extension, ".cab", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasInstallShieldCabinetSignature(string file)
        {
            try
            {
                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    return fs.Length >= 4 && br.ReadUInt32() == InstallShieldCabinetSignature;
                }
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        private sealed class InstallShieldCabinetArchive
        {
            private readonly string sourceFile;
            private readonly string sourceDirectory;
            private readonly string filePrefix;
            private readonly Header header;
            private readonly Dictionary<int, FileDescriptor> descriptors = new Dictionary<int, FileDescriptor>();

            private InstallShieldCabinetArchive(string sourceFile, Header header)
            {
                this.sourceFile = sourceFile;
                this.header = header;
                sourceDirectory = Path.GetDirectoryName(sourceFile) ?? Directory.GetCurrentDirectory();
                filePrefix = GetFilePrefix(sourceFile);
            }

            public int MajorVersion => header.MajorVersion;

            public int FileCount => checked((int)header.Cab.FileCount);

            public static InstallShieldCabinetArchive Open(string sourceFile)
            {
                var archive = new InstallShieldCabinetArchive(sourceFile, ReadHeader(sourceFile));
                archive.ReadFileGroups();
                return archive;
            }

            public int ExtractAll(string outputDirectory, Action<string> message)
            {
                var count = 0;
                foreach (var entry in GetEntries())
                {
                    var outputPath = ResolveOutputFilePath(outputDirectory, entry.RelativePath);
                    message?.Invoke($"Extracting: {entry.RelativePath}");
                    if (ExtractFile(entry.Index, outputPath))
                    {
                        count += 1;
                    }
                }

                return count;
            }

            public int ListAll(Action<string> message)
            {
                var count = 0;
                foreach (var entry in GetEntries())
                {
                    message?.Invoke($"{entry.Size,12}  {entry.RelativePath}");
                    count += 1;
                }

                return count;
            }

            public int TestAll(Action<string> message)
            {
                var count = 0;
                foreach (var entry in GetEntries())
                {
                    message?.Invoke($"Testing: {entry.RelativePath}");
                    if (TestFile(entry.Index))
                    {
                        count += 1;
                    }
                }

                return count;
            }

            private IEnumerable<ArchiveEntry> GetEntries()
            {
                var groups = header.FileGroups
                    .Where(group => group.FirstFile >= 0 && group.LastFile >= group.FirstFile)
                    .ToList();

                if (groups.Count == 0)
                {
                    foreach (var entry in GetEntriesInRange(null, 0, FileCount - 1))
                    {
                        yield return entry;
                    }

                    yield break;
                }

                foreach (var group in groups)
                {
                    foreach (var entry in GetEntriesInRange(group.Name, group.FirstFile, group.LastFile))
                    {
                        yield return entry;
                    }
                }
            }

            private IEnumerable<ArchiveEntry> GetEntriesInRange(string groupName, int firstFile, int lastFile)
            {
                var last = Math.Min(lastFile, FileCount - 1);
                for (var i = Math.Max(0, firstFile); i <= last; i += 1)
                {
                    var descriptor = GetFileDescriptor(i);
                    if (!IsValidFile(descriptor))
                    {
                        continue;
                    }

                    var relativePath = BuildRelativePath(groupName, GetDirectoryName((int)descriptor.DirectoryIndex), GetFileName(descriptor));
                    yield return new ArchiveEntry
                    {
                        Index = i,
                        RelativePath = relativePath,
                        Size = descriptor.ExpandedSize
                    };
                }
            }

            private bool ExtractFile(int index, string outputPath)
            {
                EnsureNoParentFileConflicts(outputPath);
                OutputPath.EnsureParentDirectory(outputPath);
                TryDelete(outputPath);

                string error;
                using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    if (SaveFile(index, output, false, out error))
                    {
                        return true;
                    }
                }

                TryDelete(outputPath);
                using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    if (SaveFile(index, output, true, out var oldError))
                    {
                        Message?.Invoke($"Used old InstallShield compression for: {Path.GetFileName(outputPath)}");
                        return true;
                    }

                    TryDelete(outputPath);
                    throw new InvalidDataException($"{GetFileName(GetFileDescriptor(index))}: {error}; old compression: {oldError}");
                }
            }

            private bool TestFile(int index)
            {
                string error;
                if (SaveFile(index, Stream.Null, false, out error))
                {
                    return true;
                }

                if (SaveFile(index, Stream.Null, true, out var oldError))
                {
                    return true;
                }

                throw new InvalidDataException($"{GetFileName(GetFileDescriptor(index))}: {error}; old compression: {oldError}");
            }

            private bool SaveFile(int index, Stream output, bool oldCompression, out string error)
            {
                error = null;
                var descriptor = GetFileDescriptor(index);

                if ((descriptor.LinkFlags & LinkPrevious) == LinkPrevious)
                {
                    return SaveFile((int)descriptor.LinkPrevious, output, oldCompression, out error);
                }

                try
                {
                    using (var reader = new InstallShieldCabinetReader(this, index, descriptor))
                    using (var md5 = header.MajorVersion >= 6 ? MD5.Create() : null)
                    {
                        if ((descriptor.Flags & FileCompressed) == FileCompressed)
                        {
                            if (oldCompression)
                            {
                                ExtractCompressedOld(reader, output, md5, descriptor);
                            }
                            else
                            {
                                ExtractCompressedNew(reader, output, md5, descriptor);
                            }
                        }
                        else
                        {
                            ExtractStored(reader, output, md5, descriptor);
                        }

                        FinalizeAndVerifyHash(md5, descriptor);
                    }

                    return true;
                }
                catch (Exception ex) when (IsExtractionException(ex))
                {
                    error = ex.Message;
                    return false;
                }
            }

            private static void ExtractCompressedNew(
                InstallShieldCabinetReader reader,
                Stream output,
                HashAlgorithm md5,
                FileDescriptor descriptor)
            {
                var bytesLeft = checked((long)descriptor.CompressedSize);
                long totalWritten = 0;

                while (bytesLeft > 0)
                {
                    var sizeBytes = new byte[2];
                    reader.ReadRequired(sizeBytes, 0, sizeBytes.Length);
                    var compressedChunkSize = ReadUInt16(sizeBytes, 0);
                    if (compressedChunkSize == 0)
                    {
                        throw new InvalidDataException("Compressed chunk size is zero.");
                    }

                    var compressed = new byte[compressedChunkSize + 1];
                    reader.ReadRequired(compressed, 0, compressedChunkSize);

                    var inflated = InflateRaw(compressed, compressedChunkSize + 1);
                    WriteAndHash(output, md5, inflated, 0, inflated.Length);
                    totalWritten += inflated.Length;

                    bytesLeft -= 2 + compressedChunkSize;
                }

                if (totalWritten != checked((long)descriptor.ExpandedSize))
                {
                    throw new InvalidDataException($"Expanded size expected {descriptor.ExpandedSize}, got {totalWritten}.");
                }
            }

            private static void ExtractCompressedOld(
                InstallShieldCabinetReader reader,
                Stream output,
                HashAlgorithm md5,
                FileDescriptor descriptor)
            {
                var bytesLeft = checked((long)descriptor.ExpandedSize);
                long totalWritten = 0;

                while (bytesLeft > 0)
                {
                    if (reader.VolumeBytesLeft == 0)
                    {
                        reader.OpenNextVolume();
                    }

                    var compressed = new byte[reader.VolumeBytesLeft];
                    reader.ReadRequired(compressed, 0, compressed.Length);

                    var offset = 0;
                    while (offset < compressed.Length && bytesLeft > 0)
                    {
                        var chunkEnd = FindBytes(compressed, offset, compressed.Length - offset, EndOfChunk);
                        if (chunkEnd < 0)
                        {
                            throw new InvalidDataException("Old compressed chunk terminator was not found.");
                        }

                        while (chunkEnd + EndOfChunk.Length < compressed.Length
                               && (compressed[chunkEnd + EndOfChunk.Length] & 1) == 1)
                        {
                            var next = FindBytes(
                                compressed,
                                chunkEnd + EndOfChunk.Length,
                                compressed.Length - chunkEnd - EndOfChunk.Length,
                                EndOfChunk);
                            if (next < 0)
                            {
                                throw new InvalidDataException("Old compressed chunk terminator was not found.");
                            }

                            chunkEnd = next;
                        }

                        var chunkSize = chunkEnd - offset;
                        var chunk = new byte[chunkSize + 1];
                        Buffer.BlockCopy(compressed, offset, chunk, 0, chunkSize);

                        var inflated = InflateRaw(chunk, chunk.Length);
                        WriteAndHash(output, md5, inflated, 0, inflated.Length);
                        totalWritten += inflated.Length;
                        bytesLeft -= inflated.Length;

                        offset = chunkEnd + EndOfChunk.Length;
                    }
                }

                if (totalWritten != checked((long)descriptor.ExpandedSize))
                {
                    throw new InvalidDataException($"Expanded size expected {descriptor.ExpandedSize}, got {totalWritten}.");
                }
            }

            private static void ExtractStored(
                InstallShieldCabinetReader reader,
                Stream output,
                HashAlgorithm md5,
                FileDescriptor descriptor)
            {
                var buffer = new byte[BufferSize];
                var bytesLeft = checked((long)descriptor.ExpandedSize);

                while (bytesLeft > 0)
                {
                    var count = (int)Math.Min(buffer.Length, bytesLeft);
                    reader.ReadRequired(buffer, 0, count);
                    WriteAndHash(output, md5, buffer, 0, count);
                    bytesLeft -= count;
                }
            }

            private static byte[] InflateRaw(byte[] compressed, int count)
            {
                var inflater = new Inflater(true);
                inflater.SetInput(compressed, 0, count);

                using (var output = new MemoryStream())
                {
                    var buffer = new byte[BufferSize];
                    while (!inflater.IsFinished)
                    {
                        var read = inflater.Inflate(buffer, 0, buffer.Length);
                        if (read > 0)
                        {
                            output.Write(buffer, 0, read);
                            continue;
                        }

                        if (inflater.IsNeedingInput)
                        {
                            break;
                        }

                        throw new InvalidDataException("Deflate stream did not make progress.");
                    }

                    if (output.Length == 0 && count > 0)
                    {
                        throw new InvalidDataException("Deflate stream produced no data.");
                    }

                    return output.ToArray();
                }
            }

            private FileDescriptor GetFileDescriptor(int index)
            {
                if (descriptors.TryGetValue(index, out var descriptor))
                {
                    return descriptor;
                }

                descriptor = ReadFileDescriptor(index);
                descriptors.Add(index, descriptor);
                return descriptor;
            }

            private FileDescriptor ReadFileDescriptor(int index)
            {
                if (index < 0 || index >= FileCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                var descriptor = new FileDescriptor();
                int offset;

                switch (header.MajorVersion)
                {
                    case 0:
                    case 5:
                        offset = checked(header.Common.CabDescriptorOffset + header.Cab.FileTableOffset + (int)header.FileTable[header.Cab.DirectoryCount + index]);
                        descriptor.Volume = checked((uint)header.Index);
                        descriptor.NameOffset = ReadUInt32(header.Data, offset);
                        offset += 4;
                        descriptor.DirectoryIndex = ReadUInt16(header.Data, offset);
                        offset += 4;
                        descriptor.Flags = ReadUInt16(header.Data, offset);
                        offset += 2;
                        descriptor.ExpandedSize = ReadUInt32(header.Data, offset);
                        offset += 4;
                        descriptor.CompressedSize = ReadUInt32(header.Data, offset);
                        offset += 4 + 0x14;
                        descriptor.DataOffset = ReadUInt32(header.Data, offset);
                        offset += 4;
                        if (header.MajorVersion == 5)
                        {
                            Buffer.BlockCopy(header.Data, offset, descriptor.Md5, 0, descriptor.Md5.Length);
                        }

                        break;

                    default:
                        offset = checked(header.Common.CabDescriptorOffset
                            + header.Cab.FileTableOffset
                            + header.Cab.FileTableOffset2
                            + index * 0x57);

                        descriptor.Flags = ReadUInt16(header.Data, offset);
                        offset += 2;
                        descriptor.ExpandedSize = ReadUInt64(header.Data, offset);
                        offset += 8;
                        descriptor.CompressedSize = ReadUInt64(header.Data, offset);
                        offset += 8;
                        descriptor.DataOffset = ReadUInt64(header.Data, offset);
                        offset += 8;
                        Buffer.BlockCopy(header.Data, offset, descriptor.Md5, 0, descriptor.Md5.Length);
                        offset += 0x20;
                        descriptor.NameOffset = ReadUInt32(header.Data, offset);
                        offset += 4;
                        descriptor.DirectoryIndex = ReadUInt16(header.Data, offset);
                        offset += 2 + 0x0C;
                        descriptor.LinkPrevious = ReadUInt32(header.Data, offset);
                        offset += 4;
                        descriptor.LinkNext = ReadUInt32(header.Data, offset);
                        offset += 4;
                        descriptor.LinkFlags = header.Data[offset];
                        offset += 1;
                        descriptor.Volume = ReadUInt16(header.Data, offset);
                        break;
                }

                return descriptor;
            }

            private static Header ReadHeader(string sourceFile)
            {
                var pattern = CreatePattern(sourceFile);
                Header previous = null;

                for (var i = 1; ; i += 1)
                {
                    var headerPath = FindCaseInsensitiveFile(pattern.Directory, pattern.Prefix + i + ".hdr");
                    var iterate = headerPath == null;
                    var path = headerPath ?? FindCaseInsensitiveFile(pattern.Directory, pattern.Prefix + i + ".cab");

                    if (path == null)
                    {
                        break;
                    }

                    var data = File.ReadAllBytes(path);
                    if (data.Length < CommonHeaderSize)
                    {
                        throw new InvalidDataException($"Header file is too small: {path}");
                    }

                    var header = new Header
                    {
                        Index = i,
                        Data = data,
                        Common = ReadCommonHeader(data, 0)
                    };

                    header.MajorVersion = DetectMajorVersion(header.Common.Version);
                    ReadCabDescriptor(header);
                    ReadFileTable(header);

                    previous = header;

                    if (!iterate)
                    {
                        break;
                    }
                }

                if (previous == null)
                {
                    throw new InvalidDataException("No InstallShield Cabinet header was found.");
                }

                return previous;
            }

            private void ReadFileGroups()
            {
                for (var i = 0; i < header.Cab.FileGroupOffsets.Length; i += 1)
                {
                    var nextOffset = header.Cab.FileGroupOffsets[i];
                    while (nextOffset != 0)
                    {
                        var listOffset = GetHeaderBufferOffset(nextOffset);
                        var descriptorOffset = ReadUInt32(header.Data, listOffset + 4);
                        nextOffset = ReadUInt32(header.Data, listOffset + 8);
                        header.FileGroups.Add(ReadFileGroup(descriptorOffset));
                    }
                }
            }

            private FileGroup ReadFileGroup(uint descriptorOffset)
            {
                var offset = GetHeaderBufferOffset(descriptorOffset);
                var name = GetHeaderString(ReadUInt32(header.Data, offset));
                offset += 4;

                offset += header.MajorVersion <= 5 ? 0x48 : 0x12;
                var firstFile = ReadInt32(header.Data, offset);
                offset += 4;
                var lastFile = ReadInt32(header.Data, offset);

                return new FileGroup
                {
                    Name = name,
                    FirstFile = firstFile,
                    LastFile = lastFile
                };
            }

            private static void ReadCabDescriptor(Header header)
            {
                if (header.Common.CabDescriptorSize == 0)
                {
                    throw new InvalidDataException("No InstallShield CAB descriptor is available.");
                }

                var offset = checked(header.Common.CabDescriptorOffset + 0x0C);
                header.Cab.FileTableOffset = ReadInt32(header.Data, offset);
                offset += 8;
                header.Cab.FileTableSize = ReadInt32(header.Data, offset);
                offset += 4;
                header.Cab.FileTableSize2 = ReadInt32(header.Data, offset);
                offset += 4;
                header.Cab.DirectoryCount = ReadInt32(header.Data, offset);
                offset += 12;
                header.Cab.FileCount = ReadInt32(header.Data, offset);
                offset += 4;
                header.Cab.FileTableOffset2 = ReadInt32(header.Data, offset);
                offset += 4 + 0x0E;

                if (header.Cab.DirectoryCount < 0
                    || header.Cab.FileCount <= 0
                    || header.Cab.FileCount > MaxFileCount)
                {
                    throw new InvalidDataException($"Invalid InstallShield file count: {header.Cab.FileCount}.");
                }

                header.Cab.FileGroupOffsets = new uint[MaxFileGroupCount];
                for (var i = 0; i < MaxFileGroupCount; i += 1)
                {
                    header.Cab.FileGroupOffsets[i] = ReadUInt32(header.Data, offset);
                    offset += 4;
                }

                offset += MaxComponentCount * 4;
            }

            private static void ReadFileTable(Header header)
            {
                var count = checked(header.Cab.DirectoryCount + header.Cab.FileCount);
                var offset = checked(header.Common.CabDescriptorOffset + header.Cab.FileTableOffset);
                header.FileTable = new uint[count];

                for (var i = 0; i < count; i += 1)
                {
                    header.FileTable[i] = ReadUInt32(header.Data, offset);
                    offset += 4;
                }
            }

            private static CommonHeader ReadCommonHeader(byte[] data, int offset)
            {
                var signature = ReadUInt32(data, offset);
                if (signature != InstallShieldCabinetSignature)
                {
                    throw new InvalidDataException("Invalid InstallShield Cabinet signature.");
                }

                return new CommonHeader
                {
                    Signature = signature,
                    Version = ReadUInt32(data, offset + 4),
                    VolumeInfo = ReadUInt32(data, offset + 8),
                    CabDescriptorOffset = ReadInt32(data, offset + 12),
                    CabDescriptorSize = ReadInt32(data, offset + 16)
                };
            }

            private static int DetectMajorVersion(uint version)
            {
                if ((version >> 24) == 1)
                {
                    return (int)((version >> 12) & 0x0F);
                }

                if ((version >> 24) == 2 || (version >> 24) == 4)
                {
                    var major = (int)(version & 0xFFFF);
                    return major == 0 ? 0 : major / 100;
                }

                return 0;
            }

            private VolumeHeader ReadVolumeHeader(int volume)
            {
                var path = FindCaseInsensitiveFile(sourceDirectory, filePrefix + volume + ".cab");
                if (path == null)
                {
                    throw new FileNotFoundException($"InstallShield volume was not found: {filePrefix}{volume}.cab");
                }

                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    var commonBytes = br.ReadBytesRequired(CommonHeaderSize);
                    ReadCommonHeader(commonBytes, 0);

                    var volumeHeader = new VolumeHeader
                    {
                        FileName = path
                    };

                    if (header.MajorVersion <= 5)
                    {
                        var data = br.ReadBytesRequired(Version5VolumeHeaderSize);
                        var offset = 0;
                        volumeHeader.DataOffset = ReadUInt32(data, offset);
                        offset += 8;
                        volumeHeader.FirstFileIndex = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.LastFileIndex = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.FirstFileOffset = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.FirstFileSizeExpanded = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.FirstFileSizeCompressed = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.LastFileOffset = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.LastFileSizeExpanded = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.LastFileSizeCompressed = ReadUInt32(data, offset);

                        if (volumeHeader.LastFileOffset == 0)
                        {
                            volumeHeader.LastFileOffset = int.MaxValue;
                        }
                    }
                    else
                    {
                        var data = br.ReadBytesRequired(Version6VolumeHeaderSize);
                        var offset = 0;
                        volumeHeader.DataOffset = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.FirstFileIndex = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.LastFileIndex = ReadUInt32(data, offset);
                        offset += 4;
                        volumeHeader.FirstFileOffset = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.FirstFileSizeExpanded = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.FirstFileSizeCompressed = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.LastFileOffset = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.LastFileSizeExpanded = ReadUInt64FromParts(data, offset);
                        offset += 8;
                        volumeHeader.LastFileSizeCompressed = ReadUInt64FromParts(data, offset);
                    }

                    return volumeHeader;
                }
            }

            private string GetFileName(FileDescriptor descriptor)
            {
                return GetHeaderString(descriptor.NameOffset);
            }

            private string GetDirectoryName(int index)
            {
                if (index < 0 || index >= header.Cab.DirectoryCount)
                {
                    return string.Empty;
                }

                var offset = header.FileTable[index];
                return GetHeaderString(offset);
            }

            private string GetHeaderString(uint offset)
            {
                var absoluteOffset = GetHeaderBufferOffset(offset);
                if (header.MajorVersion >= 17)
                {
                    return ReadNullTerminatedString(header.Data, absoluteOffset, Encoding.Unicode, 2);
                }

                return ReadNullTerminatedString(header.Data, absoluteOffset, LegacyEncoding, 1);
            }

            private int GetHeaderBufferOffset(uint offset)
            {
                var absoluteOffset = checked(header.Common.CabDescriptorOffset + (int)offset);
                if (absoluteOffset <= 0 || absoluteOffset >= header.Data.Length)
                {
                    throw new InvalidDataException($"InstallShield header offset is outside the file: 0x{offset:X8}.");
                }

                return absoluteOffset;
            }

            private static string BuildRelativePath(params string[] parts)
            {
                var cleanParts = parts
                    .Where(part => !string.IsNullOrWhiteSpace(part))
                    .ToArray();

                return cleanParts.Length == 0
                    ? string.Empty
                    : NormalizeRelativePath(string.Join("\\", cleanParts));
            }

            private static string NormalizeRelativePath(string relativePath)
            {
                var invalid = Path.GetInvalidFileNameChars();
                var chars = relativePath.ToCharArray();

                for (var i = 0; i < chars.Length; i += 1)
                {
                    if (chars[i] == '\\' || chars[i] == '/')
                    {
                        continue;
                    }

                    if (char.IsControl(chars[i]) || Array.IndexOf(invalid, chars[i]) >= 0)
                    {
                        chars[i] = '_';
                    }
                }

                return new string(chars);
            }

            private static string ResolveOutputFilePath(string outputDirectory, string relativePath)
            {
                var outputPath = OutputPath.GetSafeFilePath(outputDirectory, relativePath);
                if (Directory.Exists(outputPath))
                {
                    return MakeUniquePath(outputPath + ".__file");
                }

                if (File.Exists(outputPath))
                {
                    return MakeUniquePath(outputPath + ".__dup");
                }

                return outputPath;
            }

            private static void EnsureNoParentFileConflicts(string outputPath)
            {
                var directories = new Stack<string>();
                var directory = Path.GetDirectoryName(outputPath);

                while (!string.IsNullOrEmpty(directory))
                {
                    directories.Push(directory);
                    directory = Path.GetDirectoryName(directory);
                }

                while (directories.Count > 0)
                {
                    var current = directories.Pop();
                    if (File.Exists(current))
                    {
                        File.Move(current, MakeUniquePath(current + ".__file"));
                    }
                }
            }

            private static string MakeUniquePath(string path)
            {
                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    return path;
                }

                for (var i = 1; i < 10000; i += 1)
                {
                    var candidate = path + "." + i.ToString("0000");
                    if (!File.Exists(candidate) && !Directory.Exists(candidate))
                    {
                        return candidate;
                    }
                }

                throw new IOException($"Cannot create a unique output path for: {path}");
            }

            private static bool IsValidFile(FileDescriptor descriptor)
            {
                return (descriptor.Flags & FileInvalid) == 0
                    && descriptor.NameOffset != 0
                    && descriptor.DataOffset != 0;
            }

            private static void WriteAndHash(Stream output, HashAlgorithm md5, byte[] buffer, int offset, int count)
            {
                if (count == 0)
                {
                    return;
                }

                if (md5 != null)
                {
                    md5.TransformBlock(buffer, offset, count, null, 0);
                }

                output.Write(buffer, offset, count);
            }

            private static void FinalizeAndVerifyHash(HashAlgorithm md5, FileDescriptor descriptor)
            {
                if (md5 == null)
                {
                    return;
                }

                md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                if (!descriptor.Md5.All(value => value == 0) && !md5.Hash.SequenceEqual(descriptor.Md5))
                {
                    throw new InvalidDataException("MD5 checksum mismatch.");
                }
            }

            private static int FindBytes(byte[] buffer, int offset, int count, byte[] pattern)
            {
                var end = offset + count - pattern.Length;
                for (var i = offset; i <= end; i += 1)
                {
                    var matched = true;
                    for (var j = 0; j < pattern.Length; j += 1)
                    {
                        if (buffer[i + j] != pattern[j])
                        {
                            matched = false;
                            break;
                        }
                    }

                    if (matched)
                    {
                        return i;
                    }
                }

                return -1;
            }

            private static string ReadNullTerminatedString(byte[] data, int offset, Encoding encoding, int terminatorSize)
            {
                var end = offset;
                while (end + terminatorSize <= data.Length)
                {
                    if (terminatorSize == 1 && data[end] == 0)
                    {
                        break;
                    }

                    if (terminatorSize == 2 && data[end] == 0 && data[end + 1] == 0)
                    {
                        break;
                    }

                    end += terminatorSize;
                }

                if (end > data.Length)
                {
                    throw new InvalidDataException("String in InstallShield header is not terminated.");
                }

                return encoding.GetString(data, offset, end - offset);
            }

            private static HeaderPattern CreatePattern(string file)
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(file)) ?? Directory.GetCurrentDirectory();
                var name = Path.GetFileName(file);
                var prefixLength = 0;

                while (prefixLength < name.Length)
                {
                    var value = name[prefixLength];
                    if (value == '.' || char.IsDigit(value))
                    {
                        break;
                    }

                    prefixLength += 1;
                }

                if (prefixLength == 0)
                {
                    throw new InvalidDataException($"Cannot derive InstallShield cabinet prefix from: {file}");
                }

                return new HeaderPattern
                {
                    Directory = directory,
                    Prefix = name.Substring(0, prefixLength)
                };
            }

            private static string GetFilePrefix(string file)
            {
                return CreatePattern(file).Prefix;
            }

            private static string FindCaseInsensitiveFile(string directory, string fileName)
            {
                if (!Directory.Exists(directory))
                {
                    return null;
                }

                return Directory.EnumerateFiles(directory)
                    .FirstOrDefault(path => string.Equals(Path.GetFileName(path), fileName, StringComparison.OrdinalIgnoreCase));
            }

            private static void TryDelete(string path)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            private static bool IsExtractionException(Exception ex)
            {
                return ex is InvalidDataException
                    || ex is EndOfStreamException
                    || ex is IOException
                    || ex is OverflowException
                    || ex is ArgumentException;
            }

            private static ushort ReadUInt16(byte[] data, int offset)
            {
                EnsureAvailable(data, offset, 2);
                return (ushort)(data[offset] | (data[offset + 1] << 8));
            }

            private static int ReadInt32(byte[] data, int offset)
            {
                return unchecked((int)ReadUInt32(data, offset));
            }

            private static uint ReadUInt32(byte[] data, int offset)
            {
                EnsureAvailable(data, offset, 4);
                return (uint)(data[offset]
                    | (data[offset + 1] << 8)
                    | (data[offset + 2] << 16)
                    | (data[offset + 3] << 24));
            }

            private static ulong ReadUInt64(byte[] data, int offset)
            {
                return ((ulong)ReadUInt32(data, offset + 4) << 32) | ReadUInt32(data, offset);
            }

            private static ulong ReadUInt64FromParts(byte[] data, int offset)
            {
                var low = ReadUInt32(data, offset);
                var high = ReadUInt32(data, offset + 4);
                return ((ulong)high << 32) | low;
            }

            private static void EnsureAvailable(byte[] data, int offset, int count)
            {
                if (offset < 0 || count < 0 || offset > data.Length - count)
                {
                    throw new EndOfStreamException($"InstallShield header ended early at offset 0x{offset:X8}.");
                }
            }

            private sealed class InstallShieldCabinetReader : IDisposable
            {
                private readonly InstallShieldCabinetArchive archive;
                private readonly int index;
                private readonly FileDescriptor descriptor;
                private FileStream volumeStream;
                private int volume;
                private uint obfuscationOffset;

                public InstallShieldCabinetReader(InstallShieldCabinetArchive archive, int index, FileDescriptor descriptor)
                {
                    this.archive = archive;
                    this.index = index;
                    this.descriptor = descriptor;
                    OpenVolume((int)descriptor.Volume);

                    while (archive.header.MajorVersion <= 5 && index > VolumeHeader.LastFileIndex)
                    {
                        descriptor.Volume += 1;
                        OpenVolume((int)descriptor.Volume);
                    }
                }

                public int VolumeBytesLeft { get; private set; }

                private VolumeHeader VolumeHeader { get; set; }

                public void OpenNextVolume()
                {
                    OpenVolume(volume + 1);
                }

                public void ReadRequired(byte[] buffer, int offset, int count)
                {
                    var bytesLeft = count;
                    var position = offset;

                    while (bytesLeft > 0)
                    {
                        if (VolumeBytesLeft == 0)
                        {
                            OpenNextVolume();
                        }

                        var bytesToRead = Math.Min(bytesLeft, VolumeBytesLeft);
                        if (bytesToRead <= 0)
                        {
                            throw new EndOfStreamException("InstallShield volume has no more data for this file.");
                        }

                        var read = volumeStream.Read(buffer, position, bytesToRead);
                        if (read != bytesToRead)
                        {
                            throw new EndOfStreamException($"Expected {bytesToRead} bytes from InstallShield volume.");
                        }

                        VolumeBytesLeft -= read;
                        bytesLeft -= read;
                        position += read;
                    }

                    if ((descriptor.Flags & FileObfuscated) == FileObfuscated)
                    {
                        Deobfuscate(buffer, offset, count, ref obfuscationOffset);
                    }
                }

                public void Dispose()
                {
                    volumeStream?.Dispose();
                }

                private void OpenVolume(int requestedVolume)
                {
                    volumeStream?.Dispose();
                    VolumeHeader = archive.ReadVolumeHeader(requestedVolume);
                    volumeStream = new FileStream(VolumeHeader.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);

                    ulong dataOffset;
                    ulong expandedBytes;
                    ulong compressedBytes;

                    if (archive.header.MajorVersion == 5)
                    {
                        if (index < archive.FileCount - 1
                            && index == VolumeHeader.LastFileIndex
                            && VolumeHeader.LastFileSizeCompressed != descriptor.CompressedSize)
                        {
                            descriptor.Flags |= FileSplit;
                        }
                        else if (index > 0
                                 && index == VolumeHeader.FirstFileIndex
                                 && VolumeHeader.FirstFileSizeCompressed != descriptor.CompressedSize)
                        {
                            descriptor.Flags |= FileSplit;
                        }
                    }

                    if ((descriptor.Flags & FileSplit) == FileSplit)
                    {
                        if (index == VolumeHeader.LastFileIndex && VolumeHeader.LastFileOffset != int.MaxValue)
                        {
                            dataOffset = VolumeHeader.LastFileOffset;
                            expandedBytes = VolumeHeader.LastFileSizeExpanded;
                            compressedBytes = VolumeHeader.LastFileSizeCompressed;
                        }
                        else if (index == VolumeHeader.FirstFileIndex)
                        {
                            dataOffset = VolumeHeader.FirstFileOffset;
                            expandedBytes = VolumeHeader.FirstFileSizeExpanded;
                            compressedBytes = VolumeHeader.FirstFileSizeCompressed;
                        }
                        else
                        {
                            dataOffset = VolumeHeader.DataOffset;
                            expandedBytes = descriptor.ExpandedSize;
                            compressedBytes = (ulong)Math.Max(0, volumeStream.Length - checked((long)dataOffset));
                        }
                    }
                    else
                    {
                        dataOffset = descriptor.DataOffset;
                        expandedBytes = descriptor.ExpandedSize;
                        compressedBytes = descriptor.CompressedSize;
                    }

                    VolumeBytesLeft = checked((int)(((descriptor.Flags & FileCompressed) == FileCompressed) ? compressedBytes : expandedBytes));
                    volumeStream.Position = checked((long)dataOffset);
                    volume = requestedVolume;
                }

                private static void Deobfuscate(byte[] buffer, int offset, int count, ref uint seed)
                {
                    for (var i = 0; i < count; i += 1)
                    {
                        var value = (byte)(buffer[offset + i] ^ 0xD5);
                        var rotated = RotateRight(value, 2);
                        buffer[offset + i] = unchecked((byte)(rotated - (seed % 0x47)));
                        seed += 1;
                    }
                }

                private static byte RotateRight(byte value, int bits)
                {
                    return (byte)((value >> bits) | (value << (8 - bits)));
                }
            }
        }

        private struct HeaderPattern
        {
            public string Directory;
            public string Prefix;
        }

        private sealed class Header
        {
            public int Index;
            public byte[] Data;
            public int MajorVersion;
            public CommonHeader Common;
            public CabDescriptor Cab = new CabDescriptor();
            public uint[] FileTable;
            public List<FileGroup> FileGroups = new List<FileGroup>();
        }

        private struct CommonHeader
        {
            public uint Signature;
            public uint Version;
            public uint VolumeInfo;
            public int CabDescriptorOffset;
            public int CabDescriptorSize;
        }

        private sealed class CabDescriptor
        {
            public int FileTableOffset;
            public int FileTableSize;
            public int FileTableSize2;
            public int DirectoryCount;
            public int FileCount;
            public int FileTableOffset2;
            public uint[] FileGroupOffsets;
        }

        private sealed class FileGroup
        {
            public string Name;
            public int FirstFile;
            public int LastFile;
        }

        private sealed class ArchiveEntry
        {
            public int Index;
            public string RelativePath;
            public ulong Size;
        }

        private sealed class FileDescriptor
        {
            public uint NameOffset;
            public uint DirectoryIndex;
            public ushort Flags;
            public ulong ExpandedSize;
            public ulong CompressedSize;
            public ulong DataOffset;
            public readonly byte[] Md5 = new byte[16];
            public uint Volume;
            public uint LinkPrevious;
            public uint LinkNext;
            public byte LinkFlags;
        }

        private sealed class VolumeHeader
        {
            public string FileName;
            public ulong DataOffset;
            public uint FirstFileIndex;
            public uint LastFileIndex;
            public ulong FirstFileOffset;
            public ulong FirstFileSizeExpanded;
            public ulong FirstFileSizeCompressed;
            public ulong LastFileOffset;
            public ulong LastFileSizeExpanded;
            public ulong LastFileSizeCompressed;
        }
    }
}
