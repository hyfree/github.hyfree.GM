namespace github.hyfree.GM.ConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string pubK = "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";
            string priK = "0B1CE43098BC21B8E82B5C065EDB534CB86532B1900A49D49F3C53762D2997FA";
            var hex32 = "0102030405060708010203040506070801020304050607080102030405060708";
            var gm = new GMService();
            var sign = gm.SM2Sign(hex32, priK);
            Console.WriteLine(sign);
           // var verify = gm.SM2VerifySign(hex32, sign, pubK);
        }
    }
}
