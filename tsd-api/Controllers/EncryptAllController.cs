using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.Crmf;
using System.Xml.Linq;
using System.Security.Cryptography.X509Certificates;

namespace tsd_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptAllController : ControllerBase
    {
       
        // POST api/<EncrypAllController>
        [HttpPost]
        public ActionResult Post([FromBody] string original)
        {
            original = @"{""username"": ""TSD"",""password"": ""Tsd@12345#.""}";
            String inputEncrypt = String.Empty;
            String secretEncrypt = String.Empty;

            string secretKey = GetSecretKey();

            #region----Encrypt AES
            var byteKey = Encoding.UTF8.GetBytes(secretKey);
            using (Aes myAes = Aes.Create())
            {
                byte[] encrypted = EncryptStringToBytes_Aes(original, byteKey, myAes.IV);
                inputEncrypt = Convert.ToBase64String(encrypted);
            }
            #endregion----Encrypt AES

            #region----Encrypt RSA
            string publicKey = "";
            RSACryptoServiceProvider RSApublicKey = ImportPublicKey(publicKey);
            var bytesSecretKey = Encoding.UTF8.GetBytes(secretKey);
            var bytesEncrypted = RSApublicKey.Encrypt(bytesSecretKey, false);
            var base64Encrypted = Convert.ToBase64String(bytesEncrypted);
            #endregion----Encrypt RSA

            OutputEncrypted output = new OutputEncrypted
            {
                Input = inputEncrypt,
                Secret = base64Encrypted
            };
            return Ok(output);
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private string GetSecretKey()
        {
            string toReturn = string.Empty;

            try
            {
                RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
                byte[] randomBytes = new byte[16];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                toReturn = Convert.ToBase64String(randomBytes);

            }
            catch (Exception ex)
            {
                throw ex;
            }

            return toReturn;
        }

        public static RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            pem = @"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4Y8ZFG/GRfDqs5BtKMy11V6SR0oJqrqQiigpqKkKJAxbU4qgmQZY
onqoMNwTfQSnxjSlcs3AYtAbazcW79ivDnG79wGCRQJXPDxdYV9L+NmAY7iXYmk1
LCsGj8So/2zSSYzSWKm7XNlm3P0rjcWhVRPnbZBtmCMTaJy2t+hnlzBXJes9TOZ0
ZhMzMrstEd2nkvx0Oe3uM7oWQsuPcnPnG/2t0dBZui9p5ZriR/hEaQK3pSxfIzCR
Q1Q6afHZsuV1twrOUSlxghNeI7nR9fZcY/akHLsFankCcohcwVt9xXIFRSYjD5Sm
8SU6//ob3B4nLCa2NSKatdxBcXJ9lJTGEwIDAQAB
-----END RSA PUBLIC KEY-----
        ";
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

    }
    public class OutputEncrypted
    {
        public string Input { get; set; }
        public string Secret { get; set; }
    }
}
