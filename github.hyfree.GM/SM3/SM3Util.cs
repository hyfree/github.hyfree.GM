using github.hyfree.GM.Common;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
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
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (sm3_key == null)
            {
                throw new ArgumentNullException(nameof(sm3_key));
            }

            var hmac = new HMac(new SM3Digest());
            hmac.Init(new KeyParameter(sm3_key));
            hmac.BlockUpdate(input, 0, input.Length);

            var output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);
            return output;

        }



    }
}
