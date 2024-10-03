



using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using github.hyfree.GM.Common;
using github.hyfree.GM.HDKF;
using github.hyfree.GM.PBKDF;
using github.hyfree.GM.SM2;
using github.hyfree.GM.SM3;
using github.hyfree.GM.SM4;

namespace github.hyfree.GM
{
    public class GMService
    {
        /// <summary>
        /// HDKF：　　HKDF的主要目的使用原始的密钥材料,派生出一个或更多个能达到密码学强度的密钥(主要是保证随机性)—
        /// 就是将较短的密钥材料扩展成较长的密钥材料，过程中需要保证随机性。
        /// </summary>
        /// <param name="ikm">原始密钥材料</param>
        /// <param name="salt">加盐操作的盐，如果不提供则全部初始化为0的字符串，长度则为所采用哈希函数的散列值长度</param>
        /// <param name="info">可选上下文和应用程序特定信息(可以是零长度字符串)</param>
        /// <param name="len">输出长度，一般不长于哈希函数输出摘要长度的255倍。</param>
        /// <returns></returns>
        public byte[] HKDF(byte[] ikm, byte[] salt, byte[] info, int len)
        {
            
            var prk = HKDFUtil.HKDF_Extract(ikm, salt);
            var okm = HKDFUtil.HKDF_Expand(prk, info, len);
            return okm;
        }

        public  SM2KeyPair   GenerateKeyPair()
        {
           return  SM2Utils.GenerateKeyPair();
        }
        public SM2KeyPair GenerateKeyPair(byte[] priKey)
        {
            return SM2Utils.GenerateKeyPair(priKey);
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
        /// <summary>
        /// 使用输入的e签名
        /// </summary>
        /// <param name="e">e</param>
        /// <param name="PriKey">私钥</param>
        /// <param name="userId">userId</param>
        /// <returns></returns>
        public byte[] SM2SignWithE(byte[] e, byte[] PriKey, byte[] userId = null)
        {
            var sign = SM2Utils.SignWithE(e, PriKey, userId);
            return sign.ToByteArray();
        }
        /// <summary>
        /// 根据GMT009计算SM2签名值
        /// </summary>
        /// <param name="m">代签名原文 </param>
        /// <param name="priKey">私钥</param>
        /// <param name="userId">用户身份标识，如果是null，则采用SM2默认值</param>
        /// <returns></returns>
        public byte[] GMT0009_SM2Sign(byte[] m, byte[] priKey, byte[] userId = null)
        {
            var keyPair=GenerateKeyPair(priKey);

            var z=Preprocessing1(keyPair.PubKey, userId);
            var h=Preprocessing2(z,m);
            return SM2SignWithE(h,priKey,userId);
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
        public bool VerifySignWithE(byte[] e, byte[] signData, byte[] pubKey, byte[] userId = null)
        {
            var signature = new SM2Signature(signData);
            var verify = SM2Utils.VerifySignWithE(e, signature, pubKey, userId);
            return verify;
        }
        /// <summary>
        /// 根据GMT009验证SM2签名值
        /// </summary>
        /// <param name="m">代签名原文 </param>
        /// <param name="pubkey">公钥</param>
        /// <param name="userId">用户身份标识，如果是null，则采用SM2默认值</param>
        /// <returns></returns>
        public bool GMT0009_VerifySign(byte[] m, byte[] pubkey, byte[] userId = null)
        {

            var z = Preprocessing1(pubkey, userId);
            var h = Preprocessing2(z, m);
            return VerifySignWithE(h, pubkey, userId);
        }


        /// <summary>
        /// 预处理1
        /// </summary>
        /// <param name="Q">用户的公钥没有0x04的部分;</param>
        /// <returns></returns>
        public byte[] Preprocessing1( byte[] Q,byte[] userId)
        {
            if (Q.Length==66)
            {
                Q=Q.Skip(2).ToArray();
            }

            //   Z = SM3( ENTL || ID || a || b || x_G || y_G || x_A || y_A )
            if (userId==null)
            {
                userId = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            }
         

            List<byte> inData = new List<byte>();
            //inData.AddRange(HexUtil.HexToByteArray("0080"));//ID比特长度
            var len=(ushort)(userId.Length*8);
            var ENTL = BitConverter.GetBytes(len);
            Array.Reverse(ENTL);
            inData.AddRange(ENTL);//ID比特长度
            inData.AddRange(userId);
            inData.AddRange(HexUtil.HexToByteArray("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"));//a
            inData.AddRange(HexUtil.HexToByteArray("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"));//b
            inData.AddRange(HexUtil.HexToByteArray("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"));//c
            inData.AddRange(HexUtil.HexToByteArray("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));//d
        
            inData.AddRange(Q);//pubk,没有0x04的部分;
            var hash=SM3(inData.ToArray());
            return hash;

        }
        /// <summary>
        /// 预处理2
        /// </summary>
        /// <param name="Z">预处理1的输出</param>
        /// <param name="M">待签名消息</param>
        /// <returns></returns>
        public byte[] Preprocessing2(byte[] Z, byte[] M)
        {
            //    H = SM3( Z || M ）
            var inData=new List<byte>();
            inData.AddRange(Z);
            inData.AddRange(M);
            var hash=SM3(inData.ToArray()); 
            return hash;    
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
          var dec= SM2Utils.DecryptC1C3C2( HexUtil.HexToByteArray(dataHex), HexUtil.HexToByteArray(keyHex));
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

        public string SM3String(string str)
        {
            var data=Encoding.UTF8.GetBytes(str);
            SM3Util sm3 = new SM3Util();
            var result = sm3.Hash(data);
            return result.ByteArrayToHex();
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

        public byte[] SM4_Encrypt_CBC(byte[] value, byte[] key, byte[] iv)
        {
            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;

            sm4.iv = iv;
            var buffer= sm4.Encrypt_CBC(value);
           return buffer;

        }


     
        /// <summary>
        ///  SM4解密
        /// </summary>
        /// <param name="data">SM4加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="outHex">解密结果输出为utf8字符串还是Hex字符串</param>
        /// <returns></returns>
        public byte[] SM4_Decrypt_CBC(byte[] data, byte[] key,byte[] iv)
        {
            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;
            sm4.iv = iv;
            
            return sm4.Decrypt_CBC(data);
        }
        public byte[] PBKDF2_SM3(byte[] passowrd, byte[] salt, int c, int dkLen)
        {
            PBKDF2Util pbkdf = new PBKDF2Util();
            return  pbkdf.PBDKF2(passowrd, salt, c, dkLen);
        }
        public string PBKDF2_SM3(string  passowrd, string salt, int c, int dkLen)
        {
            PBKDF2Util pbkdf = new PBKDF2Util();
            var result= pbkdf.PBDKF2(HexUtil.HexToByteArray(passowrd), HexUtil.HexToByteArray(salt), c, dkLen);
            return HexUtil.ByteArrayToHex(result);
        }
        
        private string GetOutputFormat(byte[] buffer, OutputFormat outputFormat)
        {
            switch (outputFormat)
            {
                case OutputFormat.UTF8:
                    return Encoding.UTF8.GetString(buffer);
                case OutputFormat.ASCII:
                    return Encoding.ASCII.GetString(buffer);
                case OutputFormat.Hex:
                    return HexUtil.ByteArrayToHex(buffer);
                case OutputFormat.Base64:
                    return Convert.ToBase64String(buffer);
                default:
                    return null;
            }
        }
    }

}
