using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace github.hyfree.GM.SM2
{
     public class SM2Signature
    {
        
        public SM2Signature()
        {

        }
        public SM2Signature(byte[] signData)
        {
            if (signData.Length==65)
            {
                signData=signData.Skip(1).ToArray();
            }
            if (signData.Length==64)
            {
                this.R=signData.Take(32).ToArray();
                this.S=signData.Skip(32).ToArray();

            }
        }

        public byte[] R { get; set; }
        public byte[] S { get; set; }

         
        public byte[] ToByteArray()
        {
            return R.Concat(S).ToArray();
        }
        public byte[] ToByteArray04()
        {
            var buffer=new byte[65];
            buffer[0]=0x04;

           Array.Copy(this.R,0,buffer,1,32);
           Array.Copy(this.S,0,buffer,33,32);

            return buffer;
        }

    }
}
