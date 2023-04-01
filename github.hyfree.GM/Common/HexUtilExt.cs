using System;
using System.Collections.Generic;
using System.Text;

namespace github.hyfree.GM.Common
{
    public static class HexUtilExt
    {
       
        public static string ByteArrayToHex(this byte[] data )
        {
          return HexUtil.ByteArrayToHex(data);
        }
        public static byte[] HexToByteArray(this string hex)
        {
            return HexUtil.HexToByteArray(hex);
        }
    }
}
