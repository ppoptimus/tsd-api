using Microsoft.AspNetCore.Mvc;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace tsd_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptController : ControllerBase
    {
       
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

       
        [HttpPost]
        public IEnumerable<string> Post([FromBody] Body value)
        {
            byte[] bytesEncrypted = Convert.FromBase64String(value.Secret);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters privateKey = rsa.ExportParameters(true);

                byte[] decrypted = Decrypt(bytesEncrypted, privateKey, false);

               
            }
            return new string[] { GetSecretKey(), "value2" };
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

        private static byte[] Decrypt(byte[] encrypted, RSAParameters privateKey, bool fOAEP)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);

                return rsa.Decrypt(encrypted, fOAEP);
            }
        }
    }

    public class Body
    {
        public string? Input { get; set; }
        public string? Secret { get; set; }
    }

}
