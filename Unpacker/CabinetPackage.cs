namespace Unpacker
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices;

    public static class CabinetPackage
    {
        private const int CabinetSignature = 0x4643534D; // MSCF
        private const int CpuTypeUnknown = -1;
        private const int SeekBegin = 0;
        private const int SeekCurrent = 1;
        private const int SeekEnd = 2;

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            return Run(fileToUnpack, directoryOutput, CabinetOperation.Extract);
        }

        public static bool List(string fileToUnpack)
        {
            return Run(fileToUnpack, null, CabinetOperation.List);
        }

        public static bool Test(string fileToUnpack)
        {
            return Run(fileToUnpack, null, CabinetOperation.Test);
        }

        private static bool Run(string fileToUnpack, string directoryOutput, CabinetOperation operation)
        {
            if (!string.Equals(Path.GetExtension(fileToUnpack), ".cab", StringComparison.OrdinalIgnoreCase)
                || !HasMicrosoftCabinetSignature(fileToUnpack))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(directoryOutput))
            {
                directoryOutput = OutputPath.GetDefaultDirectory(fileToUnpack);
            }

            try
            {
                if (operation == CabinetOperation.Extract)
                {
                    Directory.CreateDirectory(directoryOutput);
                }

                var extractor = new CabinetExtractor(fileToUnpack, directoryOutput, operation, Message);
                extractor.Extract();

                Message?.Invoke("Detected: Microsoft Cabinet package");
                Message?.Invoke($"Files: {extractor.ExtractedFiles}");
                return true;
            }
            catch (Exception ex)
            {
                Message?.Invoke($"Cabinet extraction failed: {ex.Message}");
                return false;
            }
        }

        private static bool HasMicrosoftCabinetSignature(string file)
        {
            try
            {
                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var br = new BinaryReader(fs))
                {
                    return fs.Length >= 4 && br.ReadInt32() == CabinetSignature;
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

        private sealed class CabinetExtractor
        {
            private readonly string cabinetFile;
            private readonly string outputDirectory;
            private readonly CabinetOperation operation;
            private readonly Action<string> message;
            private readonly Dictionary<IntPtr, Stream> streams = new Dictionary<IntPtr, Stream>();
            private readonly Dictionary<IntPtr, string> outputPaths = new Dictionary<IntPtr, string>();
            private int nextHandle = 1;

            private readonly FdiAllocDelegate allocDelegate;
            private readonly FdiFreeDelegate freeDelegate;
            private readonly FdiOpenDelegate openDelegate;
            private readonly FdiReadDelegate readDelegate;
            private readonly FdiWriteDelegate writeDelegate;
            private readonly FdiCloseDelegate closeDelegate;
            private readonly FdiSeekDelegate seekDelegate;
            private readonly FdiNotifyDelegate notifyDelegate;

            public CabinetExtractor(string cabinetFile, string outputDirectory, CabinetOperation operation, Action<string> message)
            {
                this.cabinetFile = cabinetFile;
                this.outputDirectory = outputDirectory;
                this.operation = operation;
                this.message = message;

                allocDelegate = Alloc;
                freeDelegate = Free;
                openDelegate = Open;
                readDelegate = Read;
                writeDelegate = Write;
                closeDelegate = Close;
                seekDelegate = Seek;
                notifyDelegate = Notify;
            }

            public int ExtractedFiles { get; private set; }

            public void Extract()
            {
                var erf = new Erf();
                var hfdi = NativeMethods.FDICreate(
                    allocDelegate,
                    freeDelegate,
                    openDelegate,
                    readDelegate,
                    writeDelegate,
                    closeDelegate,
                    seekDelegate,
                    CpuTypeUnknown,
                    ref erf);

                if (hfdi == IntPtr.Zero)
                {
                    throw new InvalidOperationException($"FDICreate failed. Error: {erf.ErfOper}/{erf.ErfType}");
                }

                try
                {
                    var cabinetName = Path.GetFileName(cabinetFile);
                    var cabinetPath = EnsureTrailingSeparator(Path.GetDirectoryName(cabinetFile) ?? Directory.GetCurrentDirectory());

                    if (operation == CabinetOperation.Extract)
                    {
                        message?.Invoke("Extracting Microsoft Cabinet through cabinet.dll.");
                    }
                    else if (operation == CabinetOperation.Test)
                    {
                        message?.Invoke("Testing Microsoft Cabinet through cabinet.dll.");
                    }
                    else
                    {
                        message?.Invoke("Listing Microsoft Cabinet contents through cabinet.dll.");
                    }
                    var ok = NativeMethods.FDICopy(
                        hfdi,
                        cabinetName,
                        cabinetPath,
                        0,
                        notifyDelegate,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    if (!ok)
                    {
                        throw new InvalidDataException($"FDICopy failed. Error: {erf.ErfOper}/{erf.ErfType}");
                    }
                }
                finally
                {
                    NativeMethods.FDIDestroy(hfdi);
                    CloseAllStreams();
                }
            }

            private IntPtr Alloc(int cb)
            {
                return Marshal.AllocHGlobal(cb);
            }

            private void Free(IntPtr memory)
            {
                if (memory != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(memory);
                }
            }

            private IntPtr Open(string fileName, int oflag, int pmode)
            {
                try
                {
                    var access = (oflag & 0x0003) == 0 ? FileAccess.Read : FileAccess.ReadWrite;
                    var mode = (oflag & 0x0100) != 0 ? FileMode.Create : FileMode.Open;
                    var stream = new FileStream(fileName, mode, access, FileShare.Read);
                    return AddStream(stream, null);
                }
                catch
                {
                    return new IntPtr(-1);
                }
            }

            private uint Read(IntPtr hf, IntPtr pv, uint cb)
            {
                if (!streams.TryGetValue(hf, out var stream))
                {
                    return uint.MaxValue;
                }

                if (cb > int.MaxValue)
                {
                    return uint.MaxValue;
                }

                var buffer = new byte[(int)cb];
                var read = stream.Read(buffer, 0, (int)cb);
                Marshal.Copy(buffer, 0, pv, read);
                return (uint)read;
            }

            private uint Write(IntPtr hf, IntPtr pv, uint cb)
            {
                if (!streams.TryGetValue(hf, out var stream))
                {
                    return uint.MaxValue;
                }

                if (cb > int.MaxValue)
                {
                    return uint.MaxValue;
                }

                var buffer = new byte[(int)cb];
                Marshal.Copy(pv, buffer, 0, (int)cb);
                stream.Write(buffer, 0, (int)cb);
                return cb;
            }

            private int Close(IntPtr hf)
            {
                return CloseStream(hf) ? 0 : -1;
            }

            private int Seek(IntPtr hf, int dist, int seektype)
            {
                if (!streams.TryGetValue(hf, out var stream))
                {
                    return -1;
                }

                SeekOrigin origin;
                switch (seektype)
                {
                    case SeekBegin:
                        origin = SeekOrigin.Begin;
                        break;
                    case SeekCurrent:
                        origin = SeekOrigin.Current;
                        break;
                    case SeekEnd:
                        origin = SeekOrigin.End;
                        break;
                    default:
                        return -1;
                }

                return checked((int)stream.Seek(dist, origin));
            }

            private IntPtr Notify(FdiNotificationType notificationType, IntPtr notificationPointer)
            {
                var notification = (FdiNotification)Marshal.PtrToStructure(
                    notificationPointer,
                    typeof(FdiNotification));

                switch (notificationType)
                {
                    case FdiNotificationType.CopyFile:
                        if (operation == CabinetOperation.List)
                        {
                            var fileName = PtrToString(notification.Psz1);
                            message?.Invoke($"{notification.Cb,12}  {fileName}");
                            ExtractedFiles += 1;
                            return IntPtr.Zero;
                        }

                        if (operation == CabinetOperation.Test)
                        {
                            var fileName = PtrToString(notification.Psz1);
                            message?.Invoke($"Testing: {fileName}");
                            return AddStream(Stream.Null, null);
                        }

                        return OpenOutputFile(notification);

                    case FdiNotificationType.CloseFileInfo:
                        return CloseOutputFile(notification);

                    case FdiNotificationType.NextCabinet:
                        message?.Invoke($"Continuing with cabinet: {PtrToString(notification.Psz1)}");
                        return IntPtr.Zero;

                    default:
                        return IntPtr.Zero;
                }
            }

            private IntPtr OpenOutputFile(FdiNotification notification)
            {
                var fileName = PtrToString(notification.Psz1);
                var outputPath = OutputPath.GetSafeFilePath(outputDirectory, fileName);
                OutputPath.EnsureParentDirectory(outputPath);

                message?.Invoke($"Extracting: {fileName}");
                var stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
                return AddStream(stream, outputPath);
            }

            private IntPtr CloseOutputFile(FdiNotification notification)
            {
                if (outputPaths.TryGetValue(notification.Hf, out var outputPath))
                {
                    TryApplyFileMetadata(outputPath, notification.Date, notification.Time, notification.Attribs);
                    ExtractedFiles += 1;
                }
                else if (operation == CabinetOperation.Test)
                {
                    ExtractedFiles += 1;
                }

                return CloseStream(notification.Hf) ? new IntPtr(1) : IntPtr.Zero;
            }

            private IntPtr AddStream(Stream stream, string outputPath)
            {
                var handle = new IntPtr(nextHandle);
                nextHandle += 1;
                streams.Add(handle, stream);

                if (outputPath != null)
                {
                    outputPaths.Add(handle, outputPath);
                }

                return handle;
            }

            private bool CloseStream(IntPtr handle)
            {
                if (!streams.TryGetValue(handle, out var stream))
                {
                    return false;
                }

                stream.Dispose();
                streams.Remove(handle);
                outputPaths.Remove(handle);
                return true;
            }

            private void CloseAllStreams()
            {
                foreach (var stream in streams.Values)
                {
                    stream.Dispose();
                }

                streams.Clear();
                outputPaths.Clear();
            }

            private static string PtrToString(IntPtr value)
            {
                return value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(value);
            }

            private static void TryApplyFileMetadata(string outputPath, ushort date, ushort time, ushort attribs)
            {
                try
                {
                    var timestamp = FromDosDateTime(date, time);
                    File.SetLastWriteTime(outputPath, timestamp);
                    File.SetAttributes(outputPath, (FileAttributes)(attribs & 0x27));
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (ArgumentException)
                {
                }
            }

            private static DateTime FromDosDateTime(ushort date, ushort time)
            {
                var rawDate = date;
                var rawTime = time;
                var year = 1980 + ((rawDate >> 9) & 0x7F);
                var month = (rawDate >> 5) & 0x0F;
                var day = rawDate & 0x1F;
                var hour = (rawTime >> 11) & 0x1F;
                var minute = (rawTime >> 5) & 0x3F;
                var second = (rawTime & 0x1F) * 2;

                if (month == 0 || day == 0)
                {
                    return DateTime.Now;
                }

                return new DateTime(year, month, day, hour, minute, second);
            }

            private static string EnsureTrailingSeparator(string path)
            {
                if (path.EndsWith("\\", StringComparison.Ordinal) || path.EndsWith("/", StringComparison.Ordinal))
                {
                    return path;
                }

                return path + Path.DirectorySeparatorChar;
            }
        }

        private enum CabinetOperation
        {
            Extract,
            List,
            Test
        }

        private enum FdiNotificationType
        {
            CabinetInfo = 0,
            PartialFile = 1,
            CopyFile = 2,
            CloseFileInfo = 3,
            NextCabinet = 4,
            Enumerate = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Erf
        {
            public int ErfOper;
            public int ErfType;
            public int FError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct FdiNotification
        {
            public int Cb;

            public IntPtr Psz1;

            public IntPtr Psz2;

            public IntPtr Psz3;

            public IntPtr Pv;
            public IntPtr Hf;
            public ushort Date;
            public ushort Time;
            public ushort Attribs;
            public ushort SetId;
            public ushort ICabinet;
            public ushort IFolder;
            public int Fdie;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr FdiAllocDelegate(int cb);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void FdiFreeDelegate(IntPtr memory);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate IntPtr FdiOpenDelegate([MarshalAs(UnmanagedType.LPStr)] string fileName, int oflag, int pmode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint FdiReadDelegate(IntPtr hf, IntPtr pv, uint cb);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint FdiWriteDelegate(IntPtr hf, IntPtr pv, uint cb);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int FdiCloseDelegate(IntPtr hf);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int FdiSeekDelegate(IntPtr hf, int dist, int seektype);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr FdiNotifyDelegate(FdiNotificationType notificationType, IntPtr notificationPointer);

        private static class NativeMethods
        {
            [DllImport("cabinet.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr FDICreate(
                FdiAllocDelegate alloc,
                FdiFreeDelegate free,
                FdiOpenDelegate open,
                FdiReadDelegate read,
                FdiWriteDelegate write,
                FdiCloseDelegate close,
                FdiSeekDelegate seek,
                int cpuType,
                ref Erf erf);

            [DllImport("cabinet.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FDICopy(
                IntPtr hfdi,
                [MarshalAs(UnmanagedType.LPStr)] string cabinetName,
                [MarshalAs(UnmanagedType.LPStr)] string cabinetPath,
                int flags,
                FdiNotifyDelegate notify,
                IntPtr decrypt,
                IntPtr userData);

            [DllImport("cabinet.dll", CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FDIDestroy(IntPtr hfdi);
        }
    }
}
