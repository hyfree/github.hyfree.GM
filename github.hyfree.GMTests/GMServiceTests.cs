using github.hyfree.GM.Common;
using github.hyfree.GM.HDKF;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Diagnostics;
using System.Text;

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
        public void SM2PassDecryptTest()
        {
            var data = "04f59c679e38cb3ff2a0851591c505f03f082b23fa9276a58c548a2558296967ea35450d3e829aa85aff7ace71699b300dfd41f3633f84da3cfddb8cc0840ff03bd7af65fcafcb5dce9deb55c500ad7b33ef6313393a20093c89501f22721800e985a3ac64e60ec46bc5b24d64ea8045754e10";
            //预期的正确大难
           var sm2PriKey= "811ED43E4D4A716D6192F04A204E6DBDDF1F99EFEE3B6D85C0328B17C5E11612";
            GMService gMService = new GMService();
            var dec = gMService.SM2Decrypt(data, sm2PriKey, true);
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
            var dec = gMService.SM4_Decrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
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
            var enc = gMService.SM4_Encrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
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
            var enc = gMService.SM4_Encrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
            enc = enc.ToUpper();
            //期望数据
            var expect = "B733A460FF310A259566E910B4A5D8E95D117E570F65562BB65B5A50B7275400";
            Console.WriteLine("enc=" + enc);
            Console.WriteLine("exp=" + expect);
            Assert.AreEqual(enc.ToUpper(), expect.ToUpper());
        }
        [TestMethod()]
        public void SM4Dec_Byte11_Test()
        {
            //原始数据
            var data = "57D78A41981F9C9A1729ADF8CC7B136E9E5230DAB8BFBC0D43101916AB2A018A394DE1F77EBCD7D776A0EF6526A8E58DA68489535336027E4961F4A29D680D42BA83805FF7C44E257BC233E9A17E4F7A2032AFA725200220E8AAE44ABFD3A8319A5FE96C92C6D841BF8B10DB113D97B98B7D4C2BE2E0D9117A14CE17AD62890B3E33111B5944A2B272A61DE5F9649F5114C5CAB0C28D8EACB941FD7F6F0456E9BF9E31D8FC69352A7B89618BF3A05B4AEC20E4FC659B7E2556F20BDA6FAF2FC9B04E6B31F27FA32B32E271BB29DF3A20BA524B95D47852219BB7567DE3C6CAB030BBDCC891E6DC875F2ABF393EFC08509F293BF9EAE58D3C7C7B92794B17B59C79D16C8CA378977F8F24247F38FE4747F0FB0D1161D580FC31DB462D79D2755932FCD15274ACE5FC4129DD93E19C2FCDD3A6C675D0564ED9915D480B8B1F089A8B5175942857C59B68EA066F45987249AB1AB7D28FC6B335CDD5743FA9E8174742F00C276E0F2608EDC60C499F9348F4520562242D2013A504F4B6C989997986CBCFF6E18FC852E1F5155BD38FDE95C6337DF4467A4B64F328E119B5D4F37458D77D2BDFC3A14796955BD1E0FC889C2A27D08FD4F342216356CBEC978144E274064DAB47D4794ADE6406E8627A7FEDAA3419B5EF5E5780D9375ED6A384855DACDBB12171E19F9B9C7F45DA995D9E58DFD6C905009086EEE2E3C9710D76E5CC7DE5828FA990B6FA1C7B75AF0A13ECEAF2D0806D7FE3725C401B9417D11C64DBA4F9E6C57CC5C5BF86667DAE1C84F47E39D75CC09740B808DD7BF69C8229C80A4FF9CF60C70641D99D47AFE4788A4DB0D3CAA235CC78754F787BA81F89F74AED79E9E800B6184E369CB50CF1817A2C4E7B70147D1A948D8F4CAD6C82D351D1C4F453D3A4E106B6EB8A16A6014D93EC051B085F2BC120F6F884EC92F760A62614A33C3F2035DEA28378F531FEF630AD8D2CADB9D298C32A147A765C57DAB3BC43DFAE114B0DCAD3F64B1D1E9DD57602FD7CA6F50637328A015A430611D42C1A5BFBE675BDC02E1760A9DF8F094DF27B45E83E893D3C20E83581FA964E17E7D78638CF5726EC067416DCE0C8D162116D922020885AD3B05005CFC538404FD58F3DC60A6345B28A6DA590D2800B3DC42483AB3C816A1EA577A18657206CB12B3218074768C419CF2EB948A603468C1B870BB81FFF6CC1C52BB17E34AD3887057303D0D1E0E249545D5E8FCB2152FF04D91FE5335A95E3B5379C6C51965399686FFA511211575173C1E7CB7566C4A255FCC37F5782F2D79B9648932BF486A76ED67CDE43E315A9B04A9262B158F58871796B980C0CA36B723B6C33E73E63BEECDF63AC1D48D015D25DE1214A3623441E87AC0F4751621B188F22B261912B3C15CDD2B78657DB49E0D62EBFFA25AE536E26A268BE7AF9549422CC1D748436ED44F617A1D0C6BE1ACD6E454288F4DB5A7AA24768C2A1DD6834C6DD857A7DD9FE0E35C1E4911EE381CD062E97D125BA368442AF4051F4375E8C44619698AC169DF62DF747B2F6B93CB14D9CCFAAD53295A1A1CD4BCCB849E8F85EF68CFAA9CE932F2957DE45BB6770D7CA99C5942DA7A7A8557F1872FFD781D206BFED3652641EBF2B15D1DD9DE1C06AFFC1046957DC7F2B2B586DD678BBFB2B2633B94DB45BF256707C95D29F829BAE8E9B9678480FF5D6CDD00F35B04F451DBD075F76AE11C9BCE9C4AE786C437C13743613578EF2BD0A0F15707560599B4516AF50E304B18325A17B9CC54251F95CB417B519F584A61344A6267C17F216AAA8A152D2E35980F2484ADA53CC93E24B363A853BBB3A529431549A0745AEC90464C3F59709AE354B484759";
            var key = "00000000000000000000000000000000";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var dec = gMService.SM4_Decrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
          
            //期望数据
            var str=Encoding.UTF8.GetString(dec.HexToByteArray());
            Console.WriteLine(str);
           
        }

        [TestMethod()]
        public void SM4Enc_Byte17_Test()
        {
            //原始数据
            var data = "48d23c70a22d4b566f1b9bb97cfa37db01";
            var key = "8b625fa71322d93058150d65c1257701";
            var iv = "00000000000000000000000000000000";//测试用途
            GMService gMService = new GMService();
            var enc = gMService.SM4_Encrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
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
            var enc = gMService.SM4_Encrypt_CBC(data.HexToByteArray(), key.HexToByteArray(), iv.HexToByteArray()).ByteArrayToHex();
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
        public void HKDFTest()
        {
            var ikm = HexUtil.HexToByteArray("0102030405060708");
            var salt = HexUtil.HexToByteArray("0102030405060708");
            var infos = HexUtil.HexToByteArray("0102030405060708");
            var len = 16;
            var gm = new GMService();
            var okm = gm.HKDF(ikm, salt, infos, len);
            Console.WriteLine(HexUtil.ByteArrayToHex(okm));
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