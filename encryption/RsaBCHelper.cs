using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace lhtzbj12.Encryption
{
    /// <summary>
    /// Rsa非对称加密工具类
    /// </summary>
    public  class RsaBCHelper
    {      
        /// <summary>    
        /// 签名    
        /// </summary>    
        /// <param name="content">待签名字符串</param>    
        /// <param name="privateKey">私钥</param>   
       
        /// <returns>签名后字符串</returns>    
        public static string Sign(string content, string privateKey)
        {
            AsymmetricKeyParameter priKey = RsaKeyHelper.loadPrivateKeyPk1(privateKey);
            ISigner sig = SignerUtilities.GetSigner("SHA256withRSA"); //其他算法 如SHA1withRSA
            sig.Init(true, priKey);
            var bytes = Encoding.UTF8.GetBytes(content);
            sig.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = sig.GenerateSignature();
            var signedString = Convert.ToBase64String(signature);
            return signedString;
        }

        /// <summary>    
        /// 验签    
        /// </summary>    
        /// <param name="content">待验签字符串</param>    
        /// <param name="signedString">签名</param>    
        /// <param name="publicKey">公钥</param> 
        /// <returns>true(通过)，false(不通过)</returns>    
        public static bool Verify(string content, string signedString, string publicKey)
        {
            AsymmetricKeyParameter pubKey = RsaKeyHelper.loadPublicKey(publicKey);
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA"); //其他算法 如SHA1withRSA
            signer.Init(false, pubKey);
            var expectedSig = Convert.FromBase64String(signedString);
            var msgBytes = Encoding.UTF8.GetBytes(content);
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            return signer.VerifySignature(expectedSig);
        }       

        /// <summary>    
        /// 公钥加密    
        /// </summary>    
        /// <param name="resData">需要加密的字符串</param>    
        /// <param name="publicKey">公钥</param>  
        /// <returns>明文</returns>    
        public static string Encrypt(string resData, string publicKey)
        {
            try
            {
                AsymmetricKeyParameter pubKey = RsaKeyHelper.loadPublicKey(publicKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(true, pubKey);//true表示加密  
                var data = Encoding.UTF8.GetBytes(resData.Trim());
                byte[] encryptData = cipher.DoFinal(data);
                return Convert.ToBase64String(encryptData);
            }
            catch (Exception)
            {
                throw new Exception("加密失败");
            }
        }

        /// <summary>    
        /// 私钥解密
        /// </summary>    
        /// <param name="resData">加密字符串</param>    
        /// <param name="privateKey">私钥</param>    
        /// <param name="input_charset">编码格式</param>    
        /// <returns>明文</returns>    
        public static string Decrypt(string resData, string privateKey)
        {
            try
            {
                AsymmetricKeyParameter priKey = RsaKeyHelper.loadPrivateKeyPk1(privateKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(false, priKey);//false表示解密  
                var encryptData = Convert.FromBase64String(resData);
                var decryptData = cipher.DoFinal(encryptData);
                return Encoding.UTF8.GetString(decryptData);
            }
            catch (Exception) {
                throw new Exception("解密失败");
            }
            
        }
        /// <summary>    
        /// 私钥加密    
        /// </summary>    
        /// <param name="resData">需要加密的字符串</param>    
        /// <param name="privateKey">私钥</param>  
        /// <returns>明文</returns>    
        public static string EncryptByPrivateKey(string resData, string privateKey)
        {
            try
            {
                AsymmetricKeyParameter priKey = RsaKeyHelper.loadPrivateKeyPk1(privateKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(true, priKey);//true表示加密  
                var data = Encoding.UTF8.GetBytes(resData.Trim());
                byte[] encryptData = cipher.DoFinal(data);
                return Convert.ToBase64String(encryptData);
            }
            catch (Exception)
            {
                throw new Exception("加密失败");
            }
        }

        /// <summary>    
        /// 公钥解密
        /// </summary>    
        /// <param name="resData">加密字符串</param>    
        /// <param name="publicKey">公钥</param>           
        /// <returns>明文</returns>    
        public static string DecryptByPublicKey(string resData, string publicKey)
        {
            try
            {
                AsymmetricKeyParameter pubKey = RsaKeyHelper.loadPublicKey(publicKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(false, pubKey);//false表示解密  
                var encryptData = Convert.FromBase64String(resData);
                var decryptData = cipher.DoFinal(encryptData);
                return Encoding.UTF8.GetString(decryptData);
            }
            catch (Exception)
            {
                throw new Exception("解密失败");
            }

        }       
    }
}
