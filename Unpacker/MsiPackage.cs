namespace Unpacker
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;

    public static class MsiPackage
    {
        private const uint ErrorSuccess = 0;
        private const uint ErrorMoreData = 234;
        private const uint ErrorNoMoreItems = 259;
        private const int ExtractionTimeoutMilliseconds = 30 * 60 * 1000;

        public static event Action<string> Message;

        public static bool Unpack(string fileToUnpack, string directoryOutput = null)
        {
            if (!string.Equals(Path.GetExtension(fileToUnpack), ".msi", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(directoryOutput))
            {
                directoryOutput = OutputPath.GetDefaultDirectory(fileToUnpack);
            }

            try
            {
                return RunAdministrativeExtract(fileToUnpack, directoryOutput, MsiOperation.Extract);
            }
            catch (Exception ex)
            {
                Message?.Invoke($"MSI extraction failed: {ex.Message}");
                return false;
            }
        }

        public static bool List(string fileToUnpack)
        {
            if (!string.Equals(Path.GetExtension(fileToUnpack), ".msi", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            try
            {
                Message?.Invoke("Detected: Windows Installer package");
                Message?.Invoke("Listing Windows Installer File table.");

                var count = 0;
                using (var database = OpenDatabase(fileToUnpack))
                using (var view = OpenView(database.Handle, "SELECT `FileName`, `FileSize` FROM `File`"))
                {
                    ThrowIfError(NativeMethods.MsiViewExecute(view.Handle, IntPtr.Zero), "MsiViewExecute");

                    while (FetchRecord(view.Handle, out var record))
                    {
                        using (record)
                        {
                            var fileName = NormalizeMsiFileName(GetRecordString(record.Handle, 1));
                            var fileSize = NativeMethods.MsiRecordGetInteger(record.Handle, 2);
                            var displaySize = fileSize == int.MinValue ? 0 : fileSize;

                            Message?.Invoke($"{displaySize,12}  {fileName}");
                            count += 1;
                        }
                    }
                }

                Message?.Invoke($"Files: {count}");
                return true;
            }
            catch (Exception ex)
            {
                Message?.Invoke($"MSI list failed: {ex.Message}");
                return false;
            }
        }

        public static bool Test(string fileToUnpack)
        {
            if (!string.Equals(Path.GetExtension(fileToUnpack), ".msi", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tempDirectory = Path.Combine(
                Path.GetTempPath(),
                "Unpacker-msi-test-" + Guid.NewGuid().ToString("N"));

            try
            {
                return RunAdministrativeExtract(fileToUnpack, tempDirectory, MsiOperation.Test);
            }
            catch (Exception ex)
            {
                Message?.Invoke($"MSI test failed: {ex.Message}");
                return false;
            }
            finally
            {
                TryDeleteDirectory(tempDirectory);
            }
        }

        private static bool RunAdministrativeExtract(string fileToUnpack, string directoryOutput, MsiOperation operation)
        {
            Directory.CreateDirectory(directoryOutput);

            var logFile = Path.Combine(
                directoryOutput,
                Path.GetFileNameWithoutExtension(fileToUnpack) + ".msiexec.log");

            Message?.Invoke("Detected: Windows Installer package");
            Message?.Invoke(operation == MsiOperation.Test
                ? "Testing MSI administrative image."
                : "Extracting MSI administrative image.");

            if (operation == MsiOperation.Extract)
            {
                Message?.Invoke($"Log: {logFile}");
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = GetMsiExecPath(),
                Arguments =
                    "/a " + Quote(fileToUnpack) +
                    " /qn TARGETDIR=" + Quote(directoryOutput) +
                    " /L*v " + Quote(logFile),
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using (var process = Process.Start(processStartInfo))
            {
                if (process == null)
                {
                    throw new InvalidOperationException("Failed to start msiexec.exe.");
                }

                if (!process.WaitForExit(ExtractionTimeoutMilliseconds))
                {
                    TryKill(process);
                    throw new TimeoutException("MSI extraction timed out.");
                }

                if (process.ExitCode != 0)
                {
                    throw new InvalidDataException($"msiexec.exe returned exit code {process.ExitCode}.");
                }
            }

            var extractedFiles = Directory
                .EnumerateFiles(directoryOutput, "*", SearchOption.AllDirectories)
                .Where(path => !string.Equals(path, logFile, StringComparison.OrdinalIgnoreCase))
                .ToList();

            Message?.Invoke($"Files: {extractedFiles.Count}");
            return true;
        }

        private static SafeMsiHandle OpenDatabase(string fileToUnpack)
        {
            IntPtr handle;
            ThrowIfError(NativeMethods.MsiOpenDatabase(fileToUnpack, IntPtr.Zero, out handle), "MsiOpenDatabase");
            return new SafeMsiHandle(handle);
        }

        private static SafeMsiHandle OpenView(IntPtr database, string query)
        {
            IntPtr handle;
            ThrowIfError(NativeMethods.MsiDatabaseOpenView(database, query, out handle), "MsiDatabaseOpenView");
            return new SafeMsiHandle(handle);
        }

        private static bool FetchRecord(IntPtr view, out SafeMsiHandle record)
        {
            IntPtr handle;
            var result = NativeMethods.MsiViewFetch(view, out handle);
            if (result == ErrorNoMoreItems)
            {
                record = null;
                return false;
            }

            ThrowIfError(result, "MsiViewFetch");
            record = new SafeMsiHandle(handle);
            return true;
        }

        private static string GetRecordString(IntPtr record, uint field)
        {
            var capacity = 256u;
            var buffer = new StringBuilder((int)capacity);
            var result = NativeMethods.MsiRecordGetString(record, field, buffer, ref capacity);

            if (result == ErrorMoreData)
            {
                capacity += 1;
                buffer = new StringBuilder((int)capacity);
                result = NativeMethods.MsiRecordGetString(record, field, buffer, ref capacity);
            }

            ThrowIfError(result, "MsiRecordGetString");
            return buffer.ToString();
        }

        private static string NormalizeMsiFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                return string.Empty;
            }

            var separator = fileName.LastIndexOf('|');
            return separator >= 0 && separator + 1 < fileName.Length
                ? fileName.Substring(separator + 1)
                : fileName;
        }

        private static void ThrowIfError(uint result, string apiName)
        {
            if (result != ErrorSuccess)
            {
                throw new InvalidDataException($"{apiName} failed with Windows Installer error {result}.");
            }
        }

        private static string GetMsiExecPath()
        {
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var systemMsiExec = Path.Combine(windowsDirectory, "System32", "msiexec.exe");
            return File.Exists(systemMsiExec)
                ? systemMsiExec
                : "msiexec.exe";
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static void TryKill(Process process)
        {
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException)
            {
            }
            catch (System.ComponentModel.Win32Exception)
            {
            }
        }

        private static void TryDeleteDirectory(string directory)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, true);
                }
            }
            catch (IOException)
            {
                Message?.Invoke($"Temporary MSI test directory could not be removed: {directory}");
            }
            catch (UnauthorizedAccessException)
            {
                Message?.Invoke($"Temporary MSI test directory could not be removed: {directory}");
            }
        }

        private enum MsiOperation
        {
            Extract,
            Test
        }

        private sealed class SafeMsiHandle : IDisposable
        {
            public SafeMsiHandle(IntPtr handle)
            {
                Handle = handle;
            }

            public IntPtr Handle { get; }

            public void Dispose()
            {
                if (Handle != IntPtr.Zero)
                {
                    NativeMethods.MsiCloseHandle(Handle);
                }
            }
        }

        private static class NativeMethods
        {
            [DllImport("msi.dll", CharSet = CharSet.Unicode)]
            public static extern uint MsiOpenDatabase(
                string databasePath,
                IntPtr persist,
                out IntPtr database);

            [DllImport("msi.dll", CharSet = CharSet.Unicode)]
            public static extern uint MsiDatabaseOpenView(
                IntPtr database,
                string query,
                out IntPtr view);

            [DllImport("msi.dll")]
            public static extern uint MsiViewExecute(IntPtr view, IntPtr record);

            [DllImport("msi.dll")]
            public static extern uint MsiViewFetch(IntPtr view, out IntPtr record);

            [DllImport("msi.dll", CharSet = CharSet.Unicode)]
            public static extern uint MsiRecordGetString(
                IntPtr record,
                uint field,
                StringBuilder value,
                ref uint valueLength);

            [DllImport("msi.dll")]
            public static extern int MsiRecordGetInteger(IntPtr record, uint field);

            [DllImport("msi.dll")]
            public static extern uint MsiCloseHandle(IntPtr handle);
        }
    }
}
