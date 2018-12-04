using lhtzbj12.Encryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            //对称加密测试
            DesTest();
            Console.WriteLine("********* 这是分割线 *********");
            Console.WriteLine();
            //非对称加密测试
            RsaTest();
            Console.WriteLine("********* 这是分割线 *********");
            Console.WriteLine();
            //Rsa签名测试
            RsaSignTest();

            Console.ReadLine();
        }
        /// <summary>
        /// 对称加密测试
        /// </summary>
        public static void DesTest()
        {
            string key = @"aksjwj2w";
            string iv = @"jahajhgj";
            string data = @"Hello 中国，这是一段很神奇的代码";
            string encData = DesHelper.Encrypt(data, key, iv);
            string decData = DesHelper.Decrypt(encData, key, iv);
            Console.WriteLine("原文：{0}", data);
            Console.WriteLine("密文：{0}", encData);
            Console.WriteLine("解密：{0}", decData);
        }

        public static void RsaTest()
        {
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            string privateKeyPk8 = string.Empty;
            // 生成密钥对
            RsaKeyHelper.GenKey(out publicKey, out privateKey, out privateKeyPk8);

            string data = @"Hello 中国，这是一段很神奇的代码";
            string encData = RsaBCHelper.Encrypt(data, publicKey);
            string decData = RsaBCHelper.Decrypt(encData, privateKey);
            Console.WriteLine("原文：{0}", data);
            Console.WriteLine("密文：{0}", encData);
            Console.WriteLine("解密：{0}", decData);
        }
        public static void RsaSignTest() {
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            string privateKeyPk8 = string.Empty;
            // 生成密钥对
            RsaKeyHelper.GenKey(out publicKey, out privateKey, out privateKeyPk8);

            string data = @"Hello 中国，这是一段很神奇的代码";
            string signedData = RsaBCHelper.Sign(data,privateKey);
            bool success = RsaBCHelper.Verify(data, signedData, publicKey);
            Console.WriteLine("原文：{0}", data);
            Console.WriteLine("签名：{0}", signedData);
            Console.WriteLine("验签：{0}", success);
        }
    }

}
