



using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



namespace github.hyfree.GM
{
    public class GMService
    {
        public string SM2Encrypt(string data, string key)
        {
            var enc = SM2Utils.EncryptC1C3C2(HexUtil.HexToByteArray(key),HexUtil.HexToByteArray(data));
            return enc;
        }

        public string SM2Decrypt(string data, string key,bool outHex)
        {
          var dec= SM2Utils.DecryptC1C3C2(HexUtil.HexToByteArray(key), HexUtil.HexToByteArray(data));
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
