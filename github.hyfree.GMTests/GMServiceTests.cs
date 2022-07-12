using Microsoft.VisualStudio.TestTools.UnitTesting;

using github.hyfree.GM;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace github.hyfree.GM.Tests
{
    [TestClass()]
    public class GMServiceTests
    {
        [TestMethod()]
        public void SM2EncryptTest()
        {
            var data = "00000000000000000000000000000000";
            var pubk = "04F54CEEB470BAFCCE989A98D65BE1AEF562FC0C94DE152A1D658689E1D01692E7BB81C76DBA09CEF76C1386F9E0D02846F3C28BBDB11D697E9DE56341F90B1DE3";
            GMService gMService = new GMService();
            var enc = gMService.SM2Encrypt(data, pubk);
            Console.WriteLine(enc);
        }

        [TestMethod()]
        public void SM2DecryptTest()
        {
            var data = "04a68d2adbbb5a186de7e26c026f07a9d8039a4f1fe2347e35317261de7757ded5864cca6a1e5c27b1c7ecd05c906867664ce26794f901c24622501dd2e7280df4639e0a1a646997bb33935b5c7f2ad8bc7feca2ac9d77d9e2934749b20d1705678feea82576e7cd9a50d37308b77dfd3df1c126b72b4f068b6c455a503532adcb";
            var priKey = "811ED43E4D4A716D6192F04A204E6DBDDF1F99EFEE3B6D85C0328B17C5E11612";
            GMService gMService = new GMService();
            var dec = gMService.SM2Decrypt(data, priKey, true);
            Console.WriteLine(dec);

        }

        [TestMethod()]
        public void SM4DecTest()
        {
            var data = "b7d8fd16a6469166af53594a09f94a67a94b6cdea71f7acaa342e2ad9635b090c4b6918401bcb76ef414bad5c41fd685";
            var key = "00000000000000000000000000000000";
            var iv = "00000000000000000000000000000000";//测试用途
            var expect = "3030303030303030303030303030303030303030303030303030303030303030";
            GMService gMService = new GMService();
            var dec = gMService.SM4_Decrypt_CBC(data, key, iv, true);
            Console.WriteLine(dec);
            Assert.AreEqual(dec, expect);
        }

        [TestMethod()]
        public void SM4EncTest()
        {
            //原始数据
            var data = "E9F4BDE3A1C5807D89C9F0FD980DEA90352AF7DC026DC100AAD8FC6E8646B366";
            var key = "00000000000000000000000000000000";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var enc = gMService.SM4_Encrypt_CBC(data, key, iv, true);
            enc = enc.ToUpper();
            //期望数据
            var expect = "b7d8fd16a6469166af53594a09f94a67a94b6cdea71f7acaa342e2ad9635b090c4b6918401bcb76ef414bad5c41fd685";

            Console.WriteLine(enc);
            Assert.AreEqual(enc.ToUpper(), expect.ToUpper());
        }

        [TestMethod()]
        public void SM3Test()
        {
            var data = "3030303030303030303030303030303030303030303030303030303030303030";
            var expect = "557D7424ACA47640B500A525D2B53C4B2E59E552704722291AAC4D52695546AA";
            var gm = new GMService();
            var sm3 = gm.SM3(data);
            Console.WriteLine(sm3);
            Assert.AreEqual(sm3.ToUpper(), expect);

        }

        [TestMethod()]
        public void HmacTest()
        {
            var hex32 = "0102030405060708010203040506070801020304050607080102030405060708";
            var hex64 = "01020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708";
            var hex128 = "0102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708";
            var gm = new GMService();
            //32字节输入
            var test1 = gm.Hmac(hex32, hex32);  
            Assert.AreEqual(test1.ToLower(), "41e6589cde89b4f8c810a820c2fb6f0ad86bf2c136a19cfb3a5c0835f598e07b");
            
            //不固定长度输入
            var test2 =gm.Hmac("313233343536", "31323334353637383930");
            Assert.AreEqual(test2.ToLower(), "bc1f71eef901223ae7a9718e3ae1dbf97353c81acb429b491bbdbefd2195b95e");

            //64字节
            var test3=gm.Hmac(hex64, hex64);
            Assert.AreEqual(test3.ToLower(), "d6fb17c240930a21996373aa9fc0b1092931b016640809297911cd3f8cc9dcdd");

            //128字节
            var test4= gm.Hmac(hex128, hex128);
            Assert.AreEqual(test4.ToLower(), "d374f8adb0e9d1f12de94c1406fe8b2d53f84129e033f0d269400de8e8e7ca1a");
        }
    }
}