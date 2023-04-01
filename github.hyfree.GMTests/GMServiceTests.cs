using github.hyfree.GM.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Diagnostics;

namespace github.hyfree.GM.Tests
{
    [TestClass()]
    public class GMServiceTests
    {

        string pubK= "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";
        string priK= "0B1CE43098BC21B8E82B5C065EDB534CB86532B1900A49D49F3C53762D2997FA";
        [TestMethod()]
        public void SM2EncryptTest()
        {
            var data = "00000000000000000000000000000000";
            GMService gMService = new GMService();
            var enc = gMService.SM2Encrypt(data, pubK);

            var result=gMService.SM2Decrypt(enc,priK,true);

            Console.WriteLine(enc);
            Assert.AreEqual(result,data);
        }
        [TestMethod()]
        public void SM2EncryptPerformanceTest()
        {
            byte[] buffer=new byte[4096];
            var pubkBuffer = HexUtil.HexToByteArray(pubK);
            for (int i = 0; i < 4096; i++)
            {
                buffer[i] = (byte)(i % 256);
            }
            Stopwatch stopwatch=new Stopwatch();
            GMService gMService = new GMService();

            stopwatch.Start();
            for (int i = 0; i < 243; i++)
            {
                var enc = gMService.SM2Encrypt(buffer, pubkBuffer);
            }
           
            stopwatch.Stop();
            Console.WriteLine(stopwatch.ElapsedMilliseconds);
        }

        [TestMethod()]
        public void SM2DecryptTest()
        {
            var data = "04CD527A9EC14E1665E9D48E5D5215C753C5B38592D088B95F0B387078A498421651F8F383837FD9104511F56B44DA76AF28A2B0652A8C81650EAB80A5EF8DE9850DDCEAC471ADE04C6A976E5AC06CF23F504DD59598F5BFBA27384E4954629BFFF77D9309D524D4E236A4767E10918A6B0639B5E3F4F3AA8D8FB047DE3D1F4D1F";
            //预期的正确大难
            var expect = "3030303030303030303030303030303030303030303030303030303030303030";
            GMService gMService = new GMService();
            var dec = gMService.SM2Decrypt(data, priK, true);
            Console.WriteLine(dec);
            Assert.AreEqual(dec, expect);
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
            var data = "3030303030303030303030303030303030303030303030303030303030303030";
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
        public void SM4Enc_Byte16_Test()
        {
            //原始数据
            var data = "48d23c70a22d4b566f1b9bb97cfa37db";
            var key = "8b625fa71322d93058150d65c1257701";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var enc = gMService.SM4_Encrypt_CBC(data, key, iv, true);
            enc = enc.ToUpper();
            //期望数据
            var expect = "B733A460FF310A259566E910B4A5D8E95D117E570F65562BB65B5A50B7275400";
            Console.WriteLine("enc=" + enc);
            Console.WriteLine("exp=" + expect);
            Assert.AreEqual(enc.ToUpper(), expect.ToUpper());
        }

        [TestMethod()]
        public void SM4Enc_Byte17_Test()
        {
            //原始数据
            var data = "48d23c70a22d4b566f1b9bb97cfa37db01";
            var key = "8b625fa71322d93058150d65c1257701";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var enc = gMService.SM4_Encrypt_CBC(data, key, iv, true);
            enc = enc.ToUpper();
            //期望数据
            var expect = "B733A460FF310A259566E910B4A5D8E949D03616A91F0F65BE0732C28C987F97";
            Console.WriteLine("enc=" + enc);
            Console.WriteLine("exp=" + expect);
            Assert.AreEqual(enc.ToUpper(), expect.ToUpper());
        }

        [TestMethod()]
        public void SM4Enc_Byte15_Test()
        {
            //原始数据
            var data = "48d23c70a22d4b566f1b9bb97cfa37";
            var key = "8b625fa71322d93058150d65c1257701";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var enc = gMService.SM4_Encrypt_CBC(data, key, iv, true);
            enc = enc.ToUpper();
            //期望数据
            var expect = "ED684A40910B5DC0C7C1B167B9149594";
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
        public void SM3_1M_Test()
        {
            var data = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
            var input="";
            for (var index = 0; index < 1024 * 1; index++)
            {
                input = input + data;
            }
            var input_array=System.Text.ASCIIEncoding.ASCII.GetBytes(input);
            var expect = "581d6f2a835fb934b9a3363629e72ccd37e6f683404e4d84d79347f2571e6db2";
            var gm = new GMService();
            Stopwatch stopwatch= new Stopwatch();
            stopwatch.Start();
            var sm3 = gm.SM3(input_array);
            stopwatch.Stop();
            var sm3Hex= (HexUtil.ByteArrayToHex(sm3));
            Console.WriteLine(sm3Hex);
            Console.WriteLine($"sm3计算1MB，时间={stopwatch.ElapsedMilliseconds}毫秒");
            Assert.AreEqual(sm3Hex.ToUpper(), expect.ToUpper());
        }




        [TestMethod()]
        public void PBKDF2Test()
        {
            var password = "368c1adba8b9d783";
            var salt = "b4ab70c69fed2e09";
            var c = 1024;
            var dkLen = 32;
            var expect = "2375a8cbe0137d9cda66aff24ea99c5d632576a6a4ed677eaae2833c06bfbd4f";
            var gm = new GMService();
            var result = gm.PBKDF2_SM3(password, salt, c, dkLen);
            Console.WriteLine(result);
            Assert.AreEqual(result.ToUpper(), expect.ToUpper());
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
            var test2 = gm.Hmac("313233343536", "31323334353637383930");
            Assert.AreEqual(test2.ToLower(), "bc1f71eef901223ae7a9718e3ae1dbf97353c81acb429b491bbdbefd2195b95e");

            //64字节
            var test3 = gm.Hmac(hex64, hex64);
            Assert.AreEqual(test3.ToLower(), "d6fb17c240930a21996373aa9fc0b1092931b016640809297911cd3f8cc9dcdd");

            //128字节
            var test4 = gm.Hmac(hex128, hex128);
            Assert.AreEqual(test4.ToLower(), "d374f8adb0e9d1f12de94c1406fe8b2d53f84129e033f0d269400de8e8e7ca1a");
        }

        [TestMethod()]
        public void GenerateKeyPairTest()
        {
            GMService gm = new GMService();
            var kp = gm.GenerateKeyPair();
            Console.WriteLine(HexUtil.ByteArrayToHex(kp.PubKey));
            Console.WriteLine(HexUtil.ByteArrayToHex(kp.PriKey));

        }

        [TestMethod()]
        public void SM2SignTest()
        {
            var hex32 = "0102030405060708010203040506070801020304050607080102030405060708";
            var gm = new GMService();
            var sign = gm.SM2Sign(hex32, priK);
            Console.WriteLine(sign);
            var verify = gm.SM2VerifySign(hex32, sign, pubK);
            Assert.IsTrue(verify);
        }

        [TestMethod()]
        public void SM2VerifySignTest()
        {
            var hex32 = "0102030405060708010203040506070801020304050607080102030405060708";
            var gm = new GMService();
            var sign = "044FF2026B5EFDFD060CF86575EEE681487494E290C640CB69F3718BE19935239A13F175A9FC9E0C31401822BCF9F1CA70F276762C739FF6CE369EC23DC2EBCB21";
            var verify = gm.SM2VerifySign(hex32, sign, pubK);
            Assert.IsTrue(verify);
            Console.WriteLine("验签1通过");
            var signFake = "044EF2026B5EFDFD060CF86575EEE681487494E290C640CB69F3718BE19935239A13F175A9FC9E0C31401822BCF9F1CA70F276762C739FF6CE369EC23DC2EBCB21";
            var verify2 = gm.SM2VerifySign(hex32, signFake, pubK);
            Assert.IsFalse(verify2);
            Console.WriteLine("验签2通过");


        }
    }
}