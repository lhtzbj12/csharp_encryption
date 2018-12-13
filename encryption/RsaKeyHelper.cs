using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO;
using System.Text.RegularExpressions;

namespace lhtzbj12.Encryption
{
    /// <summary>
    /// Rsa密钥对生成工具
    /// </summary>
    public class RsaKeyHelper
    {
        public static void GenKey(out string publicKey, out string privateKey, out string privateKeyPk8)
        {
            publicKey = string.Empty;
            privateKey = string.Empty;
            privateKeyPk8 = string.Empty;
            try
            {
                //RSA密钥对的构造器 
                RsaKeyPairGenerator r = new RsaKeyPairGenerator();
                //RSA密钥构造器的参数 
                RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                    Org.BouncyCastle.Math.BigInteger.ValueOf(3),
                    new SecureRandom(),
                    1024,   //密钥长度 
                    25);
                r.Init(param);
                AsymmetricCipherKeyPair keyPair = r.GenerateKeyPair();
                //获取公钥和密钥 
                AsymmetricKeyParameter private_key = keyPair.Private;
                AsymmetricKeyParameter public_key = keyPair.Public;
                if (((RsaKeyParameters)public_key).Modulus.BitLength < 1024)
                {
                    Console.WriteLine("failed key generation (1024) length test");
                }
                using (TextWriter textWriter = new StringWriter())
                {
                    PemWriter pemWriter = new PemWriter(textWriter);
                    pemWriter.WriteObject(keyPair.Private);
                    pemWriter.Writer.Flush();
                    privateKey = textWriter.ToString();
                }
                using (TextWriter textpubWriter = new StringWriter())
                {
                    PemWriter pempubWriter = new PemWriter(textpubWriter);
                    pempubWriter.WriteObject(keyPair.Public);
                    pempubWriter.Writer.Flush();
                    publicKey = textpubWriter.ToString();                   
                }
                //keyPair = ReadPem(privateKey); // 直接读取字符串生成密码钥                 
                //public_key = keyPair.Public;//公钥  
                //private_key = keyPair.Private;//私钥 
                // 前面私钥为pkcs1格式，经过下面处理后，变成pkcs8格式
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(public_key);
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(private_key);
                Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
                byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
                Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
                byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();

                var pubkeyb64 = Convert.ToBase64String(publicInfoByte);
                // 这里生成的是Pkcs8的密钥
                privateKeyPk8 = PrivateKeyPk8Format(Convert.ToBase64String(privateInfoByte));

                privateKey = PrivateKeyFormat(privateKey);
                publicKey = PublicKeyFormat(publicKey);
            }
            catch (Exception ex) {
                throw ex;
            }            
        }

        /// <summary>
        /// 加载Pkcs8格式的私钥
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter loadPrivateKeyPk8(string privateKey)
        {
            try
            {
                privateKey = KeyClear(privateKey);
                byte[] prikey = Convert.FromBase64String(privateKey);
                Asn1Object priKeyObj = Asn1Object.FromByteArray(prikey);//这里也可以从流中读取，从本地导入
                AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(PrivateKeyInfo.GetInstance(priKeyObj));
                return priKey;
            }
            catch (Exception)
            {
                throw new Exception("密钥格式不正确");
            }
        }

        /// <summary>
        /// 加载Pkcs1格式的私钥
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter loadPrivateKeyPk1(string privateKey)
        {
            AsymmetricCipherKeyPair keyPair = null;
            try
            {
                keyPair = ReadPem(privateKey); // 直接读取字符串生成密码钥
            }
            catch (Exception)
            {
                throw new Exception("密钥格式不正确");
            }
            try
            {
                AsymmetricKeyParameter private_key = keyPair.Private;             
                // 前面私钥为pkcs1格式，经过下面处理后，变成pkcs8格式              
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(private_key);              
                Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();              
                AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(PrivateKeyInfo.GetInstance(asn1ObjectPrivate));
                return priKey;
            }
            catch (Exception)
            {
                throw new Exception("加载失败");
            }          
        }

        /// <summary>
        /// 加载公钥
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter loadPublicKey(string publicKey)
        {
            try
            {
                publicKey = KeyClear(publicKey);
                byte[] pubkey = Convert.FromBase64String(publicKey);
                Asn1Object pubKeyObj = Asn1Object.FromByteArray(pubkey);//这里也可以从流中读取，从本地导入   
                AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(pubKeyObj));
                return pubKey;
            }
            catch (Exception)
            {
                throw new Exception("密钥格式不正确");
            }
        }

        /// <summary>
        /// 将Pkcs1格式的私转成Pkcs8格式
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPriPk1ToPk8(string privateKey)
        {
            AsymmetricCipherKeyPair keyPair = null;
            try
            {
                keyPair = ReadPem(privateKey); // 直接读取字符串生成密码钥
            }
            catch (Exception)
            {
                throw new Exception("密钥格式不正确");
            }
            try
            {
                AsymmetricKeyParameter private_key = keyPair.Private;
                AsymmetricKeyParameter public_key = keyPair.Public;
                // 前面私钥为pkcs1格式，经过下面处理后，变成pkcs8格式
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(public_key);
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(private_key);
                Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
                byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
                Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
                byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();
                var pubkeyb64 = Convert.ToBase64String(publicInfoByte);
                // 这里生成的是Pkcs8的密钥
                return PrivateKeyFormat(Convert.ToBase64String(privateInfoByte));

            }
            catch (Exception)
            {
                throw new Exception("转换失败");
            }
        }

        public static string KeyClear(string key)
        {
            key = Regex.Replace(key, @"(-----BEGIN PRIVATE KEY-----)|(-----END PRIVATE KEY-----)|(-----BEGIN RSA PRIVATE KEY-----)|(-----END RSA PRIVATE KEY-----)|(-----BEGIN PUBLIC KEY-----)|(-----END PUBLIC KEY-----)|(-----BEGIN RSA PUBLIC KEY-----)|(-----END RSA PUBLIC KEY-----)|\n|\r", "");
            return key;
        }

        private static string PrivateKeyFormat(string privateKey)
        {
            privateKey = KeyClear(privateKey);
            privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" + privateKey + "\r\n-----END RSA PRIVATE KEY-----";
            return privateKey;
        }

        private static string PrivateKeyPk8Format(string privateKey)
        {
            privateKey = KeyClear(privateKey);
            privateKey = "-----BEGIN PRIVATE KEY-----\r\n" + privateKey + "\r\n-----END PRIVATE KEY-----";
            return privateKey;
        }

        private static string PublicKeyFormat(string publicKey)
        {
            publicKey = KeyClear(publicKey);
            publicKey = "-----BEGIN PUBLIC KEY-----\r\n" + publicKey + "\r\n-----END PUBLIC KEY-----";
            return publicKey;
        }
        static AsymmetricCipherKeyPair ReadPem(string pem)
        {
            // 判断字符串是否是标准pem
            if (!pem.StartsWith("-----BEGIN") && !pem.EndsWith("KEY-----"))
            {
                pem = PrivateKeyFormat(pem);
            }
            using (TextReader reader = new StringReader(pem))
            {
                var obj = new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                return obj as AsymmetricCipherKeyPair;
            }
        }
    }
}
