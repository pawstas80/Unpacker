namespace Unpacker
{
    using System;
    using System.IO;

    public static class NativeMethods
    {
        public static bool TrySetAllFileTimesUtc(
            string path,
            DateTime creationTimeUtc,
            DateTime lastAccessTimeUtc,
            DateTime lastWriteTimeUtc)
        {
            try
            {
                File.SetCreationTimeUtc(path, creationTimeUtc);
                File.SetLastAccessTimeUtc(path, lastAccessTimeUtc);
                File.SetLastWriteTimeUtc(path, lastWriteTimeUtc);
                return true;
            }
            catch (Exception ex) when (
                ex is ArgumentException
                || ex is IOException
                || ex is NotSupportedException
                || ex is UnauthorizedAccessException)
            {
                return false;
            }
        }
    }
}
