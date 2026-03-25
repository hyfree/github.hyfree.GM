using System;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
using Org.BouncyCastle.Crypto;

namespace github.hyfree.GM.SM3
{
    public abstract class GeneralDigest : IDigest
    {
        private const int BYTE_LENGTH = 64;

        private byte[] xBuf;
        private int xBufOff;

        private long byteCount;

        internal GeneralDigest()
        {
            xBuf = new byte[4];
        }

        internal GeneralDigest(GeneralDigest t)
        {
            xBuf = new byte[t.xBuf.Length];
            Array.Copy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

            xBufOff = t.xBufOff;
            byteCount = t.byteCount;
        }

        public void Update(byte input)
        {
            xBuf[xBufOff++] = input;

            if (xBufOff == xBuf.Length)
            {
                ProcessWord(xBuf, 0);
                xBufOff = 0;
            }

            byteCount++;
        }

        public void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            //
            // fill the current word
            //
            while (xBufOff != 0 && length > 0)
            {
                Update(input[inOff]);
                inOff++;
                length--;
            }

            //
            // process whole words.
            //
            while (length > xBuf.Length)
            {
                ProcessWord(input, inOff);

                inOff += xBuf.Length;
                length -= xBuf.Length;
                byteCount += xBuf.Length;
            }

            //
            // load in the remainder.
            //
            while (length > 0)
            {
                Update(input[inOff]);

                inOff++;
                length--;
            }
        }

        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            for (int i = 0; i < input.Length; i++)
            {
                Update(input[i]);
            }
        }

        public void Finish()
        {
            long bitLength = byteCount << 3;

            //
            // add the pad bytes.
            //
            Update(unchecked(128));

            while (xBufOff != 0) Update(unchecked(0));
            ProcessLength(bitLength);
            ProcessBlock();
        }

        public virtual void Reset()
        {
            byteCount = 0;
            xBufOff = 0;
            Array.Clear(xBuf, 0, xBuf.Length);
        }

        public int GetByteLength()
        {
            return BYTE_LENGTH;
        }

        internal abstract void ProcessWord(byte[] input, int inOff);
        internal abstract void ProcessLength(long bitLength);
        internal abstract void ProcessBlock();
        public abstract string AlgorithmName { get; }
        public abstract int GetDigestSize();
        public abstract int DoFinal(byte[] output, int outOff);

        public int DoFinal(Span<byte> output)
        {
            if (output.Length < GetDigestSize())
            {
                throw new ArgumentException("Output span is too small.", nameof(output));
            }

            byte[] tmp = new byte[GetDigestSize()];
            int len = DoFinal(tmp, 0);
            tmp.AsSpan(0, len).CopyTo(output);
            return len;
        }
    }

    public class SupportClass
    {
        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static int URShift(int number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2 << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static int URShift(int number, long bits)
        {
            return URShift(number, (int)bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static long URShift(long number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2L << ~bits);
        }

        /// <summary>
        /// Performs an unsigned bitwise right shift with the specified number
        /// </summary>
        /// <param name="number">Number to operate on</param>
        /// <param name="bits">Ammount of bits to shift</param>
        /// <returns>The resulting number from the shift operation</returns>
        public static long URShift(long number, long bits)
        {
            return URShift(number, (int)bits);
        }

    }

    //{
    //    {
    //        get
    //        {
    //            return "SM3";
    //        }

    //    }
    //    {
    //        return DIGEST_LENGTH;
    //    }

    //    {
    //        Reset();
    //    }

    //    {

    //        Array.Copy(t.X, 0, X, 0, t.X.Length);
    //        xOff = t.xOff;

    //        Array.Copy(t.v, 0, v, 0, t.v.Length);
    //    }

    //    {
    //        base.Reset();

    //        Array.Copy(v0, 0, v, 0, v0.Length);

    //        xOff = 0;
    //        Array.Copy(X0, 0, X, 0, X0.Length);
    //    }

    //    internal override void ProcessBlock()
    //    {
    //        int i;

    //        int[] ww = X;
    //        int[] ww_ = new int[64];

    //        {
    //            ww[i] = P1(ww[i - 16] ^ ww[i - 9] ^ (ROTATE(ww[i - 3], 15))) ^ (ROTATE(ww[i - 13], 7)) ^ ww[i - 6];
    //        }

    //        {
    //            ww_[i] = ww[i] ^ ww[i + 4];
    //        }

    //        int[] vv = v;
    //        int[] vv_ = v_;

    //        Array.Copy(vv, 0, vv_, 0, v0.Length);

    //        int SS1, SS2, TT1, TT2, aaa;
    //        {
    //            aaa = ROTATE(vv_[0], 12);
    //            SS1 = aaa + vv_[4] + ROTATE(T_00_15, i);
    //            SS1 = ROTATE(SS1, 7);
    //            SS2 = SS1 ^ aaa;

    //            TT1 = FF_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
    //            TT2 = GG_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
    //            vv_[3] = vv_[2];
    //            vv_[2] = ROTATE(vv_[1], 9);
    //            vv_[1] = vv_[0];
    //            vv_[0] = TT1;
    //            vv_[7] = vv_[6];
    //            vv_[6] = ROTATE(vv_[5], 19);
    //            vv_[5] = vv_[4];
    //            vv_[4] = P0(TT2);
    //        }
    //        {
    //            aaa = ROTATE(vv_[0], 12);
    //            SS1 = aaa + vv_[4] + ROTATE(T_16_63, i);
    //            SS1 = ROTATE(SS1, 7);
    //            SS2 = SS1 ^ aaa;

    //            TT1 = FF_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
    //            TT2 = GG_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
    //            vv_[3] = vv_[2];
    //            vv_[2] = ROTATE(vv_[1], 9);
    //            vv_[1] = vv_[0];
    //            vv_[0] = TT1;
    //            vv_[7] = vv_[6];
    //            vv_[6] = ROTATE(vv_[5], 19);
    //            vv_[5] = vv_[4];
    //            vv_[4] = P0(TT2);
    //        }
    //        {
    //            vv[i] ^= vv_[i];
    //        }

    //        // Reset
    //        xOff = 0;
    //        Array.Copy(X0, 0, X, 0, X0.Length);
    //    }

    //    internal override void ProcessWord(byte[] in_Renamed, int inOff)
    //    {
    //        int n = in_Renamed[inOff] << 24;
    //        n |= (in_Renamed[++inOff] & 0xff) << 16;
    //        n |= (in_Renamed[++inOff] & 0xff) << 8;
    //        n |= (in_Renamed[++inOff] & 0xff);
    //        X[xOff] = n;

    //        {
    //            ProcessBlock();
    //        }
    //    }

    //    internal override void ProcessLength(long bitLength)
    //    {
    //        {
    //            ProcessBlock();
    //        }

    //        X[14] = (int)(SupportClass.URShift(bitLength, 32));
    //        X[15] = (int)(bitLength & unchecked((int)0xffffffff));
    //    }

    //    {
    //        bs[off] = (byte)(SupportClass.URShift(n, 24));
    //        bs[++off] = (byte)(SupportClass.URShift(n, 16));
    //        bs[++off] = (byte)(SupportClass.URShift(n, 8));
    //        bs[++off] = (byte)(n);
    //    }

    //    {
    //        Finish();

    //        {
    //            IntToBigEndian(v[i], out_Renamed, outOff + i * 4);
    //        }

    //        Reset();

    //        return DIGEST_LENGTH;
    //    }

    //    {
    //    }

    //    {
    //    }

    //    {
    //    }

    //    {
    //    }

    //    {
    //    }

    //    {
    //    }

    //    {
    //    }

    //    //[STAThread]
    //    //public static void  Main()
    //    //{
    //    //    byte[] md = new byte[32];
    //    //    byte[] msg1 = Encoding.Default.GetBytes("ererfeiisgod");
    //    //    SM3Digest sm3 = new SM3Digest();
    //    //    sm3.BlockUpdate(msg1, 0, msg1.Length);
    //    //    sm3.DoFinal(md, 0);
    //    //    System.String s = new UTF8Encoding().GetString(Hex.Encode(md));
    //    //    System.Console.Out.WriteLine(s.ToUpper());

    //    //    Console.ReadLine();
    //    //}
    //}
}
