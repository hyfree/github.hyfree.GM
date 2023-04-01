using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using github.hyfree.GM.Common;

namespace github.hyfree.GM.SM4
{
    public class SM4Utils
    {
        public byte[] secretKey ;
        public byte[] iv ;
        public bool hexString = true;//默认使用Hex

        public string Encrypt_ECB(byte[] plainText)
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes= secretKey;
          

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText);

            string cipherText = Encoding.Default.GetString(encrypted);
            return cipherText;
        }


        public byte[] Encrypt_CBC(byte[] plainText)
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes = secretKey;
            byte[] ivBytes=iv;
           

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText);
            return encrypted;

        }

   

        public byte[] Decrypt_CBC(byte[] cipherText)
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes = secretKey;
            byte[] ivBytes = iv;
           

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, cipherText);
            return decrypted;

        }

        //[STAThread]
        //public static void Main()
        //{
        //    String plainText = "ererfeiisgod";  

        //    SM4Utils sm4 = new SM4Utils();  
        //    sm4.secretKey = "JeF8U9wHFOMfs2Y8";  
        //    sm4.hexString = false;  

        //    System.Console.Out.WriteLine("ECB模式");  
        //    String cipherText = sm4.Encrypt_ECB(plainText);  
        //    System.Console.Out.WriteLine("密文: " + cipherText);  
        //    System.Console.Out.WriteLine("");  

        //    plainText = sm4.Decrypt_ECB(cipherText);  
        //    System.Console.Out.WriteLine("明文: " + plainText);  
        //    System.Console.Out.WriteLine("");  

        //    System.Console.Out.WriteLine("CBC模式");  
        //    sm4.iv = "UISwD9fW6cFh9SNS";  
        //    cipherText = sm4.Encrypt_CBC(plainText);  
        //    System.Console.Out.WriteLine("密文: " + cipherText);  
        //    System.Console.Out.WriteLine("");  

        //    plainText = sm4.Decrypt_CBC(cipherText);  
        //    System.Console.Out.WriteLine("明文: " + plainText);

        //    Console.ReadLine();
        //}
    }
}
