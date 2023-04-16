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
        /// <summary>
        /// 提取：将用户输入的密钥材料尽量的伪随机化
        /// </summary>
        /// <param name="iKM">原始密钥材料</param>
        /// <param name="salt">加盐操作的盐，如果不提供则全部初始化为0的字符串，长度则为所采用哈希函数的散列值长度。</param>
        /// <returns></returns>
        public static byte[] HKDF_Extract(byte[] iKM, byte[] salt)
        {
            SM3Util sM3Util = new SM3Util();
            //prk = HKDF-Extract(H, salt, IKM) = HMAC-Hash(H, salt, IKM)
            //其实就相当于用salt作为HMAC - Hash的K，对IKM进行消息完整性认证
            //使用salt增加IKM的随机性
            var PRF = sM3Util.Hmac(iKM, salt);
            return PRF;
        }
        /// <summary>
        /// 扩展，通过一系列的哈希运算将密钥扩展到我们需要的长度
        /// </summary>
        /// <param name="prk">提取阶段得到的输出，是一个伪随机的密钥，长度不小于所采用的哈希算法的输出摘要长度</param>
        /// <param name="info">可选上下文和应用程序特定信息(可以是零长度字符串)</param>
        /// <param name="L">以字节计算的密钥原料的长度，一般不长于哈希函数输出摘要长度的255倍</param>
        /// <returns>OKM，输出，长度为L的密钥材料输出</returns>
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