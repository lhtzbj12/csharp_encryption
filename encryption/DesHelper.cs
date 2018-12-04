using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace lhtzbj12.Encryption
{
    /// <summary>
    /// Des对称加密工具类
    /// </summary>
    public class DesHelper
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data">待加密的数据</param>
        /// <param name="key">加/解密key 8位</param>
        /// <param name="iv">偏移向量 8位</param>
        /// <param name="model">密码模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, string iv, CipherMode model = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] _KeyByte = null;
            if (!string.IsNullOrWhiteSpace(key))
            {
                _KeyByte = Encoding.UTF8.GetBytes(key);
            }

            byte[] _IVByte = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                _IVByte = Encoding.UTF8.GetBytes(iv);
            }

            var sa = new DESCryptoServiceProvider();
            sa.Mode = model;
            sa.Padding = padding;           
            var ct = sa.CreateEncryptor(_KeyByte, _IVByte);

            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, ct, CryptoStreamMode.Write);
            byte[] byt = Encoding.UTF8.GetBytes(data);
            cs.Write(byt, 0, byt.Length);
            cs.FlushFinalBlock();
            cs.Close();
            return Convert.ToBase64String(ms.ToArray());
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encData">加密生成的Base64密文</param>
        /// <param name="key">加/解密key 8位</param>
        /// <param name="iv">偏移向量 8位</param>
        /// <param name="model">密码模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns></returns>
        public static string Decrypt(string encData, string key, string iv, CipherMode model = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] _KeyByte = null;
            if (!string.IsNullOrWhiteSpace(key))
            {
                _KeyByte = Encoding.UTF8.GetBytes(key);
            }

            byte[] _IVByte = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                _IVByte = Encoding.UTF8.GetBytes(iv);
            }

            using (ICryptoTransform ct = new DESCryptoServiceProvider()
            { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 }.CreateDecryptor(_KeyByte, _IVByte))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, ct, CryptoStreamMode.Write))
                    {
                        byte[] byt = Convert.FromBase64String(encData);
                        try
                        {
                            cs.Write(byt, 0, byt.Length);
                            cs.FlushFinalBlock();
                            cs.Close();
                        }
                        catch (Exception)
                        {
                            return string.Empty;
                        }
                    }
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
        }
    }
}
