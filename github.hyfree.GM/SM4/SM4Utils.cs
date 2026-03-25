using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using github.hyfree.GM.Common;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace github.hyfree.GM.SM4
{
    public class SM4Utils
    {
        public byte[] secretKey ;
        public byte[] iv ;
        //public bool hexString = true;//默认使用Hex

        private void ValidateKey()
        {
            if (secretKey == null || secretKey.Length != 16)
            {
                throw new ArgumentException("SM4 key must be exactly 16 bytes", nameof(secretKey));
            }
        }

        private void ValidateIv()
        {
            if (iv == null || iv.Length != 16)
            {
                throw new ArgumentException("SM4 IV must be exactly 16 bytes", nameof(iv));
            }
        }

        public string Encrypt_ECB(byte[] plainText)
        {
            if (plainText == null)
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            ValidateKey();

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new SM4Engine(), new Pkcs7Padding());
            cipher.Init(true, new KeyParameter(secretKey));
            byte[] encrypted = ProcessCipher(cipher, plainText);

            string cipherText = HexUtil.ByteArrayToHex(encrypted);
            return cipherText;
        }

        public byte[] Encrypt_CBC(byte[] plainText)
        {
            if (plainText == null)
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            ValidateKey();
            ValidateIv();
            byte[] ivBytes = (byte[])iv.Clone();

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()), new Pkcs7Padding());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(secretKey), ivBytes));
            byte[] encrypted = ProcessCipher(cipher, plainText);
            return encrypted;

        }

        public byte[] Decrypt_CBC(byte[] cipherText)
        {
            if (cipherText == null)
            {
                throw new ArgumentNullException(nameof(cipherText));
            }

            ValidateKey();
            ValidateIv();
            byte[] ivBytes = (byte[])iv.Clone();

            try
            {
                IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()), new Pkcs7Padding());
                cipher.Init(false, new ParametersWithIV(new KeyParameter(secretKey), ivBytes));
                byte[] decrypted = ProcessCipher(cipher, cipherText);
                return decrypted;
            }
            catch (InvalidCipherTextException ex)
            {
                throw new CryptographicException("Invalid SM4 ciphertext or padding.", ex);
            }

        }

        private static byte[] ProcessCipher(IBufferedCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);

            if (len == output.Length)
            {
                return output;
            }

            byte[] result = new byte[len];
            Array.Copy(output, 0, result, 0, len);
            return result;
        }

        //[STAThread]
        //public static void Main()
        //    String plainText = "ererfeiisgod";

        //    SM4Utils sm4 = new SM4Utils();
        //    sm4.secretKey = "JeF8U9wHFOMfs2Y8";
        //    sm4.hexString = false;

        //    System.Console.Out.WriteLine("ECB模式");
        //    String cipherText = sm4.Encrypt_ECB(plainText);
        //    System.Console.Out.WriteLine("密文: " + cipherText);
        //    System.Console.Out.WriteLine("");

        //    plainText = sm4.Decrypt_ECB(cipherText);
        //    System.Console.Out.WriteLine("明文: " + plainText);
        //    System.Console.Out.WriteLine("");

        //    System.Console.Out.WriteLine("CBC模式");
        //    sm4.iv = "UISwD9fW6cFh9SNS";
        //    cipherText = sm4.Encrypt_CBC(plainText);
        //    System.Console.Out.WriteLine("密文: " + cipherText);
        //    System.Console.Out.WriteLine("");

        //    plainText = sm4.Decrypt_CBC(cipherText);
        //    System.Console.Out.WriteLine("明文: " + plainText);

        //    Console.ReadLine();
        //}
    }
}
