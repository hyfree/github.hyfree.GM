using System;
using System.Collections.Generic;
using System.Text;

namespace github.hyfree.GM.Common
{
    public class HexUtil
    {
        public static byte[] XOR(byte[] x, byte[] y)
        {
            if (x.Length != y.Length)
            {
                throw new ArgumentException("x.Length!=y.Length");
            }

            var result = new byte[x.Length];
            for (int i = 0; i < x.Length; i++)
            {
                result[i] = (byte)((x[i] ^ y[i]) & 0xff);
            }
            return result;
        }
        public static string ByteArrayToHex(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static byte[] HexToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
