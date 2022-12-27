using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.OpenSsl;
using System.Text;
using System.Text.Json;

namespace tsd_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DecryptAllController : ControllerBase
    {
        //[HttpGet]
        //public IEnumerable<string> Get()
        //{
        //    return new string[] { "value1", "value2" };
        //}

        
        [HttpPost]
        public ActionResult Post([FromBody] InputEncrypted body)
        {
            var secret = DecryptSecret(body.Secret); Console.WriteLine("secret = ",secret);
            var byteKey = Encoding.UTF8.GetBytes(secret);
            var byteEncrypt = Convert.FromBase64String(body.Input);


                var decryptAes = DecryptStringFromBytes_AesTsd(byteEncrypt, byteKey);Console.WriteLine("decrypted Aes = ", decryptAes);
            try
            {


                OutputDecrypted res = JsonSerializer.Deserialize<OutputDecrypted>(decryptAes);
                var userName = res.username;
                var password = res.password;

                var response = new { responseCode = "000", responseStatus = "S", responseMessage = "Success" };
                if (userName == "TSD" && password == "Tsd@12345#.")
                {

                    return Ok(response);
                }
                else
                {
                    return Ok(new { responseCode = "111", responseStatus = "N", responseMessage = "invalid username or password" });
                }
            }
            catch (Exception e)
            {

                return Ok(decryptAes);
            }

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
            catch (Exception e)
            {

                return e.Message;
            }
            return secret;
        }
        public static RSACryptoServiceProvider ImportPrivateKey()
        {
            string dr = Environment.CurrentDirectory + "\\Keys\\private.pem";
            StreamReader sr = new StreamReader(dr);
            string pem = sr.ReadToEnd();

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
                aesAlg.Padding = PaddingMode.PKCS7;

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
                try
                {
                    aesAlg.Key = Key;

                    byte[] IV = new byte[aesAlg.BlockSize / 8];
                    byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                    Array.Copy(cipherTextCombined, IV, IV.Length);
                    Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                    aesAlg.IV = IV;

                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

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
                catch (Exception e)
                {

                    return e.Message;
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

    public class OutputDecrypted
    {
        public string username { get; set; }
        public string password { get; set; }
    }
}
