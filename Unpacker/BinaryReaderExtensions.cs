namespace Unpacker
{
    using System;
    using System.IO;
    using System.Text;

    public static class BinaryReaderExtensions
    {
        [System.Diagnostics.Contracts.Pure]
        public static string ToHex(this byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            const string alphabet = @"0123456789ABCDEF";
            var result = new char[checked(value.Length * 2)];
            for (var i = 0; i < value.Length; i += 1)
            {
                result[i * 2] = alphabet[value[i] >> 4];
                result[(i * 2) + 1] = alphabet[value[i] & 0xF];
            }

            return new string(result);
        }

        [System.Diagnostics.Contracts.Pure]
        public static byte[] FromHex(this string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            value = value.Replace(" ", "").Trim();
            if (value.Length % 2 != 0)
            {
                throw new ArgumentException("Hexadecimal value length must be even.", nameof(value));
            }

            var result = new byte[value.Length / 2];
            for (var i = 0; i < result.Length; i += 1)
            {
                var high = FromHexNibble(value[i * 2]);
                var low = FromHexNibble(value[(i * 2) + 1]);
                result[i] = (byte)((high << 4) | low);
            }

            return result;
        }

        /// <summary>
        ///     Get a unicode string at a specific position in a buffer.
        /// </summary>
        /// <param name="br">Containing buffer.</param>
        /// <param name="stringOffset">Offset of the string.</param>
        /// <param name="length">Lengh of the string to parse.</param>
        /// <returns>The parsed unicode string.</returns>
        public static string GetUnicodeString(this BinaryReader br, ulong stringOffset, int length)
        {
            br.BaseStream.Position = (long)stringOffset;
            var bytes = br.ReadBytes(length);
            return Encoding.Unicode.GetString(bytes);
        }

        /// <summary>
        ///     For a given offset in an byte array, find the next
        ///     null value which terminates a C string.
        /// </summary>
        /// <param name="br">Buffer which contains the string.</param>
        /// <param name="stringOffset">Offset of the string.</param>
        /// <returns>Length of the string in bytes.</returns>
        public static ulong GetCStringLength(this BinaryReader br, ulong stringOffset)
        {
            var offset = stringOffset;
            ulong length = 0;
            br.BaseStream.Position = (long)offset;
            while (br.ReadByte() != 0x00)
            {
                length++;
            }
            return length;
        }

        /// <summary>
        ///     Get a name (C string) at a specific position in a buffer.
        /// </summary>
        /// <param name="buff">Containing buffer.</param>
        /// <param name="stringOffset">Offset of the string.</param>
        /// <returns>The parsed C string.</returns>
        public static string GetCString(this BinaryReader br, ulong stringOffset)
        {
            var length = GetCStringLength(br, stringOffset);
            var tmp = new char[length];
            br.BaseStream.Position = (long)stringOffset;
            for (ulong i = 0; i < length; i++)
            {
                tmp[i] = (char)br.ReadChar();
            }

            return new string(tmp);
        }
        #region ReadString
        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="number"></param>
        /// <returns></returns>
        public static string ReadString(this BinaryReader br, int number)
        {
            return Encoding.UTF8.GetString(br.ReadBytes(number));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset"></param>
        /// <param name="number"></param>
        /// <returns></returns>
        public static string ReadString(this BinaryReader br, int offset, int number)
        {
            br.BaseStream.Position = offset;
            return Encoding.UTF8.GetString(br.ReadBytes(number));
        }
        #endregion

        #region ReadByte
        /// <summary>
        ///     Read byte from a stream at offset
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <returns></returns>
        public static byte ReadByte(this BinaryReader br, int offset)
        {
            br.BaseStream.Position = offset;
            return br.ReadByte();
        }

        /// <summary>
        ///     Read byte from a stream at offset
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <returns></returns>
        public static byte ReadByte(this BinaryReader br, uint offset)
        {
            br.BaseStream.Position = offset;
            return br.ReadByte();
        }

        /// <summary>
        ///     Read byte from a stream at offset
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <returns></returns>
        public static byte ReadByte(this BinaryReader br, ulong offset)
        {
            br.BaseStream.Position = (long)offset;
            return br.ReadByte();
        }

        /// <summary>
        ///     Read byte from a stream at offset
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <returns></returns>
        public static byte ReadByte(this BinaryReader br, long offset)
        {
            br.BaseStream.Position = offset;
            return br.ReadByte();
        }
        #endregion

        #region Read Bytes
        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, long offset, int Length)
        {
            br.BaseStream.Position = offset;
            return br.ReadBytes(Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, long offset, uint Length)
        {
            br.BaseStream.Position = offset;
            return br.ReadBytes((int)Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, ulong offset, int Length)
        {
            br.BaseStream.Position = (long)offset;
            return br.ReadBytes(Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, ulong offset, uint Length)
        {
            br.BaseStream.Position = (long)offset;
            return br.ReadBytes((int)Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, uint offset, int Length)
        {
            br.BaseStream.Position = offset;
            return br.ReadBytes(Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="br"></param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <param name="Length"></param>
        /// <returns></returns>
        public static byte[] ReadBytes(this BinaryReader br, uint offset, uint Length)
        {
            br.BaseStream.Position = offset;
            return br.ReadBytes((int)Length);
        }
        #endregion

        #region BytesToUInt16
        /// <summary>
        ///     Convert a two bytes in a stream to an 16 bit unsigned integer.
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Position of the high byte. Low byte is i+1.</param>
        /// <returns>UInt16 of the bytes in the buffer at position i and i+1.</returns>
        public static ushort BytesToUInt16(this BinaryReader br, ulong offset)
        {
            br.BaseStream.Position = (long)offset;
            return BitConverter.ToUInt16(new[] { br.ReadByte(), br.ReadByte() }, 0);
        }

        /// <summary>
        ///     Convert up to 2 bytes out of a buffer to an 16 bit unsigned integer.
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Offset of the highest byte.</param>
        /// <param name="numOfBytes">Number of bytes to read.</param>
        /// <returns>UInt16 of numOfBytes bytes.</returns>
        public static uint BytesToUInt16(this BinaryReader br, uint offset, uint numOfBytes)
        {
            br.BaseStream.Position = offset;
            var bytes = new byte[2];
            for (var i = 0; i < numOfBytes; i++)
                bytes[i] = br.ReadByte();

            return BitConverter.ToUInt16(bytes, 0);
        }
        #endregion

        #region BytesToUInt32
        /// <summary>
        ///     Convert 4 consecutive bytes out of a buffer to an 32 bit unsigned integer.
        /// </summary>
        /// <param name="br">Binary Reader.</param>
        /// <param name="offset">Offset of the highest byte.</param>
        /// <returns>UInt32 of 4 bytes.</returns>
        public static uint BytesToUInt32(this BinaryReader br, uint offset)
        {
            br.BaseStream.Position = offset;
            return br.ReadUInt32();
        }
        #endregion

        /// <summary>
        ///     Convert 8 consecutive byte in a buffer to an
        ///     64 bit unsigned integer.
        /// </summary>
        /// <param name="br">Byte buffer.</param>
        /// <param name="offset">Offset of the highest byte.</param>
        /// <returns>UInt64 of the byte sequence at offset i.</returns>
        public static ulong BytesToUInt64(this BinaryReader br, ulong offset)
        {
            br.BaseStream.Position = (long)offset;
            return br.ReadUInt64();
        }


        public static ushort GetOrdinal(this BinaryReader br, uint ordinal)
        {
            return BitConverter.ToUInt16(new[] { br.ReadByte(ordinal), br.ReadByte(ordinal + 1) }, 0);
        }

        public static byte[] ReadBytesRequired(this BinaryReader br, int count)
        {
            var bytes = br.ReadBytes(count);
            if (bytes.Length != count)
            {
                throw new EndOfStreamException($"Expected {count} bytes, but only {bytes.Length} bytes were available.");
            }

            return bytes;
        }

        private static int FromHexNibble(char value)
        {
            if (value >= '0' && value <= '9')
            {
                return value - '0';
            }

            if (value >= 'A' && value <= 'F')
            {
                return value - 'A' + 10;
            }

            if (value >= 'a' && value <= 'f')
            {
                return value - 'a' + 10;
            }

            throw new ArgumentException($"Invalid hexadecimal character: {value}");
        }
    }
}
