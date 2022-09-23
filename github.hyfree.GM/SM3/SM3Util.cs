using github.hyfree.GM.Common;
using Org.BouncyCastle.Crypto.Digests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace github.hyfree.GM.SM3
{
    public class SM3Util
    {
        public byte[] Hash(byte[] data)
        {
            byte[] md = new byte[32];
            byte[] msg1 = data;
            //计算SM3
            SM3Digest sm3 = new SM3Digest();
            sm3.BlockUpdate(msg1, 0, msg1.Length);
            sm3.DoFinal(md, 0);


            return md;

        }


        public string Hash(string dataHex)
        {
            byte[] md = new byte[32];
            byte[] msg1 = HexUtil.HexToByteArray(dataHex);
            //计算SM3
            SM3Digest sm3 = new SM3Digest();
            sm3.BlockUpdate(msg1, 0, msg1.Length);
            sm3.DoFinal(md, 0);

            string hex = HexUtil.ByteArrayToHex(md);
            return hex;

        }

        public byte[] Hmac(byte[] input, byte[] sm3_key)
        {
            var BLOCK_LENGTH = 64;
            var structured_key = new byte[BLOCK_LENGTH];

            var IPAD = new byte[BLOCK_LENGTH];
            var OPAD = new byte[BLOCK_LENGTH];



            //1 密钥填充
            if (sm3_key.Length > BLOCK_LENGTH)
            {
                sm3_key = Hash(sm3_key);
                for (var i = 0; i < sm3_key.Length; i++)
                {
                    structured_key[i] = sm3_key[i];
                }
            }
            else
            {
                for (var i = 0; i < sm3_key.Length; i++)
                {
                    structured_key[i] = sm3_key[i];
                }
            }
            //2 与ipad异或运算
            for (var i = 0; i < BLOCK_LENGTH; i++)
            {
                IPAD[i] = 0x36;
                OPAD[i] = 0x5c;
            }
            var ipadkey = HexUtil.XOR(structured_key, IPAD);
            //3  拼接组合
            var ipadkey_message = ipadkey.Concat(input).ToArray();
            //4  计算散列值
            var hash1 = Hash(ipadkey_message);

            //5 与opad异或运算
            var opadkey = HexUtil.XOR(structured_key, OPAD);
            //6 hash1结合
            var opadkey_hash1 = opadkey.Concat(hash1).ToArray();
            //7 计算散列值
            var hash2 = Hash(opadkey_hash1);
            return hash2;

        }



    }
}
