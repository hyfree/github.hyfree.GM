using github.hyfree.GM.SM3;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace github.hyfree.GM.HDKF
{
    public class HKDFUtil
    {
        const  int HLen=32;
        public static byte[] HKDF_Extract(byte[] iKM, byte[] salt)
        {
            SM3Util sM3Util = new SM3Util();
            //prk = HKDF-Extract(H, salt, IKM) = HMAC-Hash(H, salt, IKM)
            //其实就相当于用salt作为HMAC - Hash的K，对IKM进行消息完整性认证
            //使用salt增加IKM的随机性
            var PRF = sM3Util.Hmac(iKM, salt);
            return PRF;
        }

        public static byte[] HKDF_Expand(byte[] prk, byte[] info,int L)
        {
            var t=new byte[0];
            var okm=new byte[0];
            SM3Util sM3Util = new SM3Util();
            var N=Math.Ceiling((float)L/HLen);
            for (int i = 0; i < N; i++)
            {
                t=sM3Util.Hmac(prk, t.Concat(info).Concat(new byte[] {(byte)(i+1)}).ToArray());
                okm=okm.Concat(t).ToArray();
            }
            return okm.Take(L).ToArray();

        }
        public static byte[] HKDF(byte[] ikm, byte[] salt, byte[] info,int len)
        {
            var prk=HKDF_Extract(ikm,salt);
            var okm=HKDF_Expand(prk,info,len);
            return okm;
        }
    }
}