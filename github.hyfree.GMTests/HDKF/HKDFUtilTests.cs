using Microsoft.VisualStudio.TestTools.UnitTesting;
using github.hyfree.GM.HDKF;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using github.hyfree.GM.Common;

namespace github.hyfree.GM.HDKF.Tests
{
    [TestClass()]
    public class HKDFUtilTests
    {
        [TestMethod()]
        public void HKDFTest()
        {
            var ikm= HexUtil.HexToByteArray("0102030405060708");
            var salt= HexUtil.HexToByteArray("0102030405060708");
            var infos=HexUtil.HexToByteArray("0102030405060708");
            var len=70;
           var okm=  HKDFUtil.HKDF(ikm, salt, infos, len);
            Console.WriteLine(HexUtil.ByteArrayToHex(okm));
        }
    }
}