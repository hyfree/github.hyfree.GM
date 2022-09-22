using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace github.hyfree.GM
{
    public class SM2Utils
    {
        public static void GenerateKeyPairHex(out string pubKey,out string priKey)
        {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;
            pubKey= Encoding.Default.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper();
            priKey= Encoding.Default.GetString(Hex.Encode(privateKey.ToByteArray32())).ToUpper();
            
        }

        public static SM2KeyPair GenerateKeyPair()
        {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            SM2KeyPair kp=new SM2KeyPair();
            kp.PubKey= publicKey.GetEncoded();
            kp.PriKey= privateKey.ToByteArray32();
            return kp;
        }

        public static byte[] Sign(byte[] msg, byte[] privateKey, byte[] id=null)
        {
            if (id==null)
            {
                //31323334353637383132333435363738
                id = new byte[] { 0x31, 0x32 ,0x33, 0x34, 0x35, 0x36, 0x37, 0x38 ,0x31, 0x32, 0x33, 0x34, 0x35 ,0x36 ,0x37, 0x38 };
            }
            BigInteger userD = new BigInteger(1, privateKey);

            throw new NotImplementedException("此版本不支持SM2签名验签，将在下一个版本支持");
        }

        public static bool VerifySign(byte[] msg, byte[] signature, byte[] pucKey, byte[] id = null)
        {
            if (id == null)
            {
                id = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            }

            throw new NotImplementedException("此版本不支持SM2签名验签，将在下一个版本支持");

        }

        public static String Encrypt(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            String sc1 = Encoding.Default.GetString(Hex.Encode(c1.GetEncoded()));
            String sc2 = Encoding.Default.GetString(Hex.Encode(source));
            String sc3 = Encoding.Default.GetString(Hex.Encode(c3));

            return (sc1 + sc2 + sc3).ToUpper();
        }

        public static byte[] EncryptC1C3C2(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            //String sc1 = Encoding.Default.GetString(Hex.Encode(c1.GetEncoded()));
            //String sc2 = Encoding.Default.GetString(Hex.Encode(source));
            //String sc3 = Encoding.Default.GetString(Hex.Encode(c3));

            return c1.GetEncoded()
                 .Concat(c3)
                .Concat(source).ToArray();
        }

        public static byte[] Decrypt(byte[] privateKey, byte[] encryptedData)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            String data = Encoding.Default.GetString(Hex.Encode(encryptedData));

            byte[] c1Bytes = Hex.Decode(Encoding.Default.GetBytes(data.Substring(0, 130)));
            int c2Len = encryptedData.Length - 97;
            byte[] c2 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130, 2 * c2Len)));
            byte[] c3 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="encryptedData">加密数据，前面必须有04</param>
        /// <returns></returns>
        public static byte[] DecryptC1C3C2(byte[] privateKey, byte[] encryptedData)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            byte[] c1Bytes = encryptedData.Take(65).ToArray();
            byte[] c3 = encryptedData.Skip(65).Take(32).ToArray();
            byte[] c2 = encryptedData.Skip(97).ToArray();

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }

        //[STAThread]
        //public static void Main()
        //{
        //    GenerateKeyPair();

        //    String plainText = "ererfeiisgod";
        //    byte[] sourceData = Encoding.Default.GetBytes(plainText);

        //    //下面的秘钥可以使用generateKeyPair()生成的秘钥内容
        //    // 国密规范正式私钥
        //    String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
        //    // 国密规范正式公钥
        //    String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

        //    System.Console.Out.WriteLine("加密: ");
        //    String cipherText = SM2Utils.Encrypt(Hex.Decode(pubk), sourceData);
        //    System.Console.Out.WriteLine(cipherText);
        //    System.Console.Out.WriteLine("解密: ");
        //    plainText = Encoding.Default.GetString(SM2Utils.Decrypt(Hex.Decode(prik), Hex.Decode(cipherText)));
        //    System.Console.Out.WriteLine(plainText);

        //    Console.ReadLine();
        //}
    }
}