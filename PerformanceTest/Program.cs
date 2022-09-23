// See https://aka.ms/new-console-template for more information
using github.hyfree.GM;
using System.Diagnostics;
string pubK = "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";
Console.WriteLine("Hello, World!");
byte[] buffer = new byte[4096];
var pubkBuffer = HexUtil.HexToByteArray(pubK);
for (int i = 0; i < 4096; i++)
{
    buffer[i] = (byte)(i % 256);
}
Stopwatch stopwatch = new Stopwatch();
GMService gMService = new GMService();

stopwatch.Start();
for (int i = 0; i < 243; i++)
{
    var enc = gMService.SM2Encrypt(buffer, pubkBuffer);
}

stopwatch.Stop();
Console.WriteLine(stopwatch.ElapsedMilliseconds);
