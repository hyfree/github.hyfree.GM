using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace github.hyfree.GM.SM4
{
    class SM4_Context
    {
        public int mode;

        public long[] sk;

        public bool isPadding;

        public SM4_Context()
        {
            mode = 1;
            isPadding = true;
            sk = new long[32];
        }
    }
}
