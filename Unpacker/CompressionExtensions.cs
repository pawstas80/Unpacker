namespace Unpacker
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    public static class CompressionExtensions
    {
        public static byte[] ReadFully(string fileName)
        {
            return File.ReadAllBytes(fileName);
        }

        public static byte[] ReadFully(this Stream input)
        {
            using (var output = new MemoryStream())
            {
                input.CopyTo(output);
                return output.ToArray();
            }
        }

        public static List<byte> Zlib(this byte[] input)
        {
            var compressor = new ICSharpCode.SharpZipLib.Zip.Compression.Deflater();
            compressor.SetLevel(ICSharpCode.SharpZipLib.Zip.Compression.Deflater.BEST_COMPRESSION);
            compressor.SetInput(input);
            compressor.Finish();

            using (var output = new MemoryStream(input.Length))
            {
                var buffer = new byte[1024];
                while (!compressor.IsFinished)
                {
                    var count = compressor.Deflate(buffer);
                    output.Write(buffer, 0, count);
                }

                return output.ToArray().ToList();
            }
        }

        public static List<byte> Zlib(this List<byte> data)
        {
            return data.ToArray().Zlib();
        }

        public static List<byte> Zlib(this Stream stream)
        {
            return stream.ReadFully().Zlib();
        }

        public static List<byte> UnZlib(this List<byte> data)
        {
            var buffer = new byte[16 * 1024];
            using (var memory = new MemoryStream(data.ToArray()))
            using (var inflater = new ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream(memory))
            using (var decompressedBuffer = new MemoryStream())
            {
                int read;
                while ((read = inflater.Read(buffer, 0, buffer.Length)) > 0)
                {
                    decompressedBuffer.Write(buffer, 0, read);
                }

                return decompressedBuffer.ToArray().ToList();
            }
        }
    }
}
