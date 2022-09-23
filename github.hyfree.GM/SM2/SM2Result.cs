using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

using System;
using System.Collections.Generic;
using System.Text;

namespace github.hyfree.GM.SM2
{
    public class SM2Result
    {
        public SM2Result()
        {
        }

    
        //验签R
        public BigInteger R;
        public BigInteger S;

        // 密钥交换
        public byte[] sa;
        public byte[] sb;
        public byte[] s1;
        public byte[] s2;

        public ECPoint keyra;
        public ECPoint keyrb;

    }
}
