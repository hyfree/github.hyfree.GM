using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using github.hyfree.GM.Common;
using github.hyfree.GM.SM3;

namespace github.hyfree.GM.PBKDF
{
    public class PBKDF2
    {

        int hLen = 32;
        int r = 0;
        public byte[] Generate(byte[] passowrd, byte[] salt, int c, int dkLen)
        {

            if (dkLen < hLen)
            {
                var t1 = F(passowrd, salt, c, 1);
                var dk = new byte[dkLen];
                Array.Copy(t1, 0, dk, 0, dkLen);
                return dk;
            }
            else
            {
                int block = dkLen / hLen;
                r = dkLen % hLen;

                var output = new byte[dkLen];

                var dk = new List<byte>(dkLen);

                for (int i = 1; i < block + 1; i++)
                {
                    var ti = F(passowrd, salt, c, i);
                    dk.AddRange(ti);
                }
                var tLast = F(passowrd, salt, c, block + 1);
                var tLastyu = new byte[r];
                Array.Copy(tLast, 0, tLastyu, 0, r);
                dk.AddRange(tLastyu);
                return dk.ToArray();

            }
            return null;
        }

        public byte[] F(byte[] p, byte[] s, int c, int i)
        {
            var U = new byte[hLen];
            var U1 = PRF(p, s, i);

            var Uxor = xor(U, U1);

            U = U1;


            for (int x = 0; x < c - 1; x++)
            {
                var Ux = PRF(p, U);
                U = Ux;
                Uxor = xor(Uxor, Ux);
            }
            return Uxor;
        }

        public byte[] PRF(byte[] p, byte[] s, int i)
        {
            byte[] iArray = intToBytes(i);
            byte[] hash = Hmac(p, s.Concat(iArray).ToArray());

            var hex = HexUtil.ByteArrayToHex(hash);
            return hash;
        }
        public byte[] PRF(byte[] p, byte[] s)
        {

            byte[] hash = Hmac(p, s);

            var hex = HexUtil.ByteArrayToHex(hash);
            return hash;
        }
        public byte[] Hmac(byte[] key, byte[] data)
        {
            SM3Util sm3 = new SM3Util();
            byte[] hash = sm3.Hmac(input: data, sm3_key: key);
            return hash;

        }

        public byte[] xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                throw new Exception();
            }
            var c = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                c[i] = (byte)(a[i] ^ b[i]);
            }
            return c;
        }
        public byte[] intToBytes(int value)
        {
            byte[] src = new byte[4];

            src[0] = (byte)(value >> 24 & 0xFF);
            src[1] = (byte)(value >> 16 & 0xFF);
            src[2] = (byte)(value >> 8 & 0xFF);
            src[3] = (byte)(value & 0xFF);

            return src;
        }
    }
}
