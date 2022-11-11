using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.IO;

namespace tsd_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptRSAController : ControllerBase
    {

        [HttpPost]
        public IEnumerable<string> Post([FromBody] Body value)
        {
            var test = DecryptSecret(value.Secret);

            return new string[] { GetSecretKey(), "value2" };
        }

        public static string DecryptSecret(string secret)
        {
            string result = "";
            string publicKey = @"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4Y8ZFG/GRfDqs5BtKMy11V6SR0oJqrqQiigpqKkKJAxbU4qgmQZY
onqoMNwTfQSnxjSlcs3AYtAbazcW79ivDnG79wGCRQJXPDxdYV9L+NmAY7iXYmk1
LCsGj8So/2zSSYzSWKm7XNlm3P0rjcWhVRPnbZBtmCMTaJy2t+hnlzBXJes9TOZ0
ZhMzMrstEd2nkvx0Oe3uM7oWQsuPcnPnG/2t0dBZui9p5ZriR/hEaQK3pSxfIzCR
Q1Q6afHZsuV1twrOUSlxghNeI7nR9fZcY/akHLsFankCcohcwVt9xXIFRSYjD5Sm
8SU6//ob3B4nLCa2NSKatdxBcXJ9lJTGEwIDAQAB
-----END RSA PUBLIC KEY-----
        ";

            string privateKey = @"-----BEGIN RSA PRIVATE KEY-----
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

            try
            {
                RSACryptoServiceProvider RSApublicKey = ImportPublicKey(publicKey);

                RSACryptoServiceProvider RSAprivateKey = ImportPrivateKey(privateKey);

                var plainTextData = secret;

                //for encryption, always handle bytes...
                var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

                //apply pkcs#1.5 padding and encrypt our data 
                var bytesCypherText = RSApublicKey.Encrypt(bytesPlainTextData, false);

                //we might want a string representation of our cypher text... base64 will do
                var cypherText = Convert.ToBase64String(bytesCypherText);

                
                //first, get our bytes back from the base64 string ...
                bytesCypherText = Convert.FromBase64String(cypherText);


                //decrypt and strip pkcs#1.5 padding
                bytesPlainTextData = RSAprivateKey.Decrypt(bytesCypherText, false);

                //get our original plainText back...
                plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine("err : " + e.StackTrace);
            }

            return result;
        }

        public static RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        public static RSACryptoServiceProvider ImportPrivateKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
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
    }

    public class Body
    {
        public string? Input { get; set; }
        public string? Secret { get; set; }
    }

}
