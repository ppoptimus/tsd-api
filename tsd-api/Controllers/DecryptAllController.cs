using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.OpenSsl;
using System.Text;

namespace tsd_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DecryptAllController : ControllerBase
    {
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        
        [HttpPost]
        public void Post([FromBody] InputEncrypted body)
        {
            var secret = DecryptSecret(body.Secret);
            var byteKey = Encoding.UTF8.GetBytes(secret);
            var byteEncrypt = Convert.FromBase64String(body.Input);

         
            string roundtrip = DecryptStringFromBytes_AesMe(byteEncrypt, byteKey).ToString();
         
            var test = DecryptStringFromBytes_AesTsd(byteEncrypt, byteKey);
        }

        public static string DecryptSecret(string encryptSecret)
        {
            String secret = String.Empty;

            try
            {
                RSACryptoServiceProvider RSAprivateKey = ImportPrivateKey();
                var byteEncrypt = Convert.FromBase64String(encryptSecret);
                var byteDecryptedSecret = RSAprivateKey.Decrypt(byteEncrypt, false);
                secret = System.Text.Encoding.UTF8.GetString(byteDecryptedSecret);
            }
            catch (Exception)
            {

                throw;
            }
            return secret;
        }
        public static RSACryptoServiceProvider ImportPrivateKey()
        {
            string pem = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4Y8ZFG/GRfDqs5BtKMy11V6SR0oJqrqQiigpqKkKJAxbU4qg
mQZYonqoMNwTfQSnxjSlcs3AYtAbazcW79ivDnG79wGCRQJXPDxdYV9L+NmAY7iX
Ymk1LCsGj8So/2zSSYzSWKm7XNlm3P0rjcWhVRPnbZBtmCMTaJy2t+hnlzBXJes9
TOZ0ZhMzMrstEd2nkvx0Oe3uM7oWQsuPcnPnG/2t0dBZui9p5ZriR/hEaQK3pSxf
IzCRQ1Q6afHZsuV1twrOUSlxghNeI7nR9fZcY/akHLsFankCcohcwVt9xXIFRSYj
D5Sm8SU6//ob3B4nLCa2NSKatdxBcXJ9lJTGEwIDAQABAoIBAQCgywEG95Nxgofd
j+SxRBWP0IYYuefgRHULeAwShsaK4iAsktNfow2Gbkf95LUj1zC+9ALJr3EpP898
A96fBmnssxlawUGbbkq/zwyGgIfJE0waSpnodrWIEffwfzI2O95AvlmpCP5e90AD
45qryynyW2kMSvxFiyOn3KfIvK00MdPRUcEeqr/sdNmoqmMERS8QTEuBQyERH/if
YeJrP7T0iWCUJrWpjCiYsphJ4g8HYRmkOMXYeKhcp2uyWy85e+aPRKxJfQB/xuXY
Vbe6sjYd9/EUub5MiMGml4+eMG8a3xAJJrbCovInEUj8LxAD7AarKnqYZ40r2qUj
7VFS+Oc5AoGBAPrtdgyLQEh8/UFwYEiMvBwwMoLkhYW3i07PWzWS8iAUfc9Qy0TU
Rv9oiK7mMticsiVW7xaOiuP+H2KSXrNtJYgiIt3JXQkVld1o+U5zsoBpUXhb4wn7
U/2pTsmRVke4BD2VyQMRPvcvYSjCrahNG5hKXGXJZqsc4+P1tcqoVmD9AoGBAOYe
Wv7mqKlXmVJnrzKUETap48erXiumRs2MOcUpjTqIJDprvbjjo+uqKroy2QQ58wH7
o1ng2UoxShR8VzMoIGES2N+JlU4wVr4RB7yewPFEJz6h2imzvjcpzRhColjeMxKK
TSQ8/V41ukYDaYZgJJxEfMvFpcdkR5a8ecfyQ7hPAoGAQ3x+FV2WSmijTGhG3PxM
01/7Fc0URCRbKTUHmN8Ok6YvOATIxpg5CBQ7Pp7W6f8qwnQhFXX80NjV5BLtuWAP
ig90RSYVCY5uof/LnVfsmDC7Ip3D8DlSG5TfhcK668sICPAyAcsvnhd2EBpbzjn+
w/Sr6QxDup2ohPTekcS4hpkCgYBQS79MuoeXr21ch7lmWKw4+sb0YSOW74o9JvTx
izIwfljF2dp1rVkBXntSRXPcOaxFwNya/A5WCSTkSQ7UVugVd1IdjhB/G/bok2Cz
vGFuzm0zOZ66dnGlJfzevkGP6NjBW2jXgECYov7Ad2hW7y1XKb6yC+Fw1dj1DAci
cbKXmQKBgASYKW4lDtUtRQS73xilb04qjRgC1hmIjFG/KCSj/2hwqHr9JIw28C74
41Qc2he7V8+UBpilGrxFaM1UBU4LshtArpZqCsLZCu4y68+vGfAheBKJt2ggngB2
+z62l/y8g8vCqJ8g5CHLI9Vh2l+Qqzv4g4OtOlQ+omtT7SJkI4Lp
-----END RSA PRIVATE KEY-----";
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

        static string DecryptStringFromBytes_AesMe(byte[] cipherText, byte[] Key)
        {

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
            byte[] IV = new byte[aesAlg.BlockSize / 8];
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        public static string DecryptStringFromBytes_AesTsd(byte[] cipherTextCombined, byte[] Key)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
    }

    public class InputEncrypted
    {
        public string Input { get; set; }
        public string Secret { get; set; }
    }
}
