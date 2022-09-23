



using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using github.hyfree.GM.Common;
using github.hyfree.GM.SM2;

namespace github.hyfree.GM
{
    public class GMService
    {

      

        public  SM2KeyPair   GenerateKeyPair()
        {
           return  SM2Utils.GenerateKeyPair();
        }
        public string SM2Sign(string msg, string priKey)
        {

            var sign = SM2Utils.Sign(HexUtil.HexToByteArray(msg), HexUtil.HexToByteArray(priKey), null);
            return HexUtil.ByteArrayToHex(sign.ToByteArray());
        }
        public byte[] SM2Sign(byte[] msg, byte[] PriKey, byte[] userId=null )
        {
            var sign = SM2Utils.Sign(msg, PriKey, userId);
            return sign.ToByteArray();
        }
        public bool SM2VerifySign(byte[] msg, byte[] signData, byte[] pubKey, byte[] userId = null)
        {
            var signature=new SM2Signature(signData);
            var verify = SM2Utils.VerifySign(msg, signature, pubKey, userId);
            return verify;
        }
        public bool SM2VerifySign(string msg, string signData, string pubKey,string userId= null)
        {   byte[] userIdBuffer=null;
            if (userId!=null)
            {
                userIdBuffer=HexUtil.HexToByteArray(userId);
            }
            var signature = new SM2Signature(HexUtil.HexToByteArray(signData));
            var verify = SM2Utils.VerifySign(HexUtil.HexToByteArray(msg), signature, HexUtil.HexToByteArray(pubKey), userIdBuffer);
            return verify;
        }


        public string SM2Encrypt(string dataHex, string keyHex)
        {

            var enc = SM2Utils.EncryptC1C3C2(HexUtil.HexToByteArray(keyHex), HexUtil.HexToByteArray(dataHex));
            return HexUtil.ByteArrayToHex(enc);
        }
        public byte[] SM2Encrypt(byte[] data, byte[] key)
        {
            var enc = SM2Utils.EncryptC1C3C2(key, data);
            return enc;
        }
        public byte[] SM2Decrypt(byte[] data, byte[] key)
        {
            var dec = SM2Utils.DecryptC1C3C2(data, key);
            return dec;
        }
        public string SM2Decrypt(string dataHex, string keyHex,bool outHex=true)
        {
          var dec= SM2Utils.DecryptC1C3C2(HexUtil.HexToByteArray(keyHex), HexUtil.HexToByteArray(dataHex));
            if (outHex)
            {
                var hex = HexUtil.ByteArrayToHex(dec);
                return hex;
            }
            else
            {
                return Encoding.UTF8.GetString(dec);
            }
        }

        public string SM3(string hex)
        {
            SM3Util sm3 = new SM3Util();
            var result = sm3.Hash(hex);
            return result;
        }

        public byte[] SM3(byte[] data)
        {
            SM3Util sm3 = new SM3Util();
            var result = sm3.Hash(data);
            return result;
        }

        public byte[] Hmac(byte[] input, byte[] key)
        {
            SM3Util sm3 = new SM3Util();
            var result = sm3.Hmac(input,key);
            return result;
        }
        public string Hmac(string input,string key)
        {
            var result=Hmac(HexUtil.HexToByteArray(input),HexUtil.HexToByteArray(key));

            return HexUtil.ByteArrayToHex(result);
        }



        public string SM4_Encrypt_CBC(string value, string key,string iv,bool outHex)
        {
            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;
            
            sm4.iv = iv;
            return sm4.Encrypt_CBC(value, outHex);
        }
        /// <summary>
        ///  SM4解密
        /// </summary>
        /// <param name="data">SM4加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="outHex">解密结果输出为utf8字符串还是Hex字符串</param>
        /// <returns></returns>
        public string SM4_Decrypt_CBC(string data, string key,string iv, bool outHex)
        {
            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;
            sm4.iv = iv;
            
            return sm4.Decrypt_CBC(data, outHex);
        }
        public byte[] PBKDF2_SM3(byte[] passowrd, byte[] salt, int c, int dkLen)
        {
            PBKDF2 pbkdf = new PBKDF2();
            return  pbkdf.Generate(passowrd, salt, c, dkLen);
        }
        public string PBKDF2_SM3(string  passowrd, string salt, int c, int dkLen)
        {
            PBKDF2 pbkdf = new PBKDF2();
            var result= pbkdf.Generate(HexUtil.HexToByteArray(passowrd), HexUtil.HexToByteArray(salt), c, dkLen);
            return HexUtil.ByteArrayToHex(result);
        }


    }
}
