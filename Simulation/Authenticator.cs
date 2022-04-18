using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;


namespace Simulation {
    internal class Authenticator {
        private string IDx;
        private byte[] PrKx;
        private byte[] PuKx;
        private int Cx;
        private int Rx;
        private int Rp;
        private Random random = new Random();
        private RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        private Aes aes = Aes.Create();

        // called from RP
        public X509Certificate2 getCertificate(string IDr, string Nickr, object Rr) {
            Cx += 1;
            string Subject = "cn=" + getHMAC(IDx, Rx, Rp, Cx);
            string Issuer = "cn=ExampleProvider:" + Convert.ToHexString(aes.EncryptCbc(BitConverter.GetBytes(Cx), aes.Key.Take(16).ToArray()));
            CertificateRequest certificateRequest = new CertificateRequest(Subject, rsa,HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509SignatureGenerator signatureGenerator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
            X509Certificate2 x509Certificate = certificateRequest.Create(new X500DistinguishedName(Issuer),signatureGenerator, DateTimeOffset.Now, DateTimeOffset.MaxValue, new byte[] { 0x00});

            return x509Certificate;
        }

        // this method is same as the one in IdP
        private string getHMAC(string IDx, int Rx, int Rp, int Cx) {
            byte[] hashKey = SHA256.HashData(BitConverter.GetBytes(Rx * Rp));
            string hmac = Convert.ToHexString(HMACSHA256.HashData(hashKey, Encoding.ASCII.GetBytes(IDx + Cx.ToString())));
            return hmac;
        }

        // called from IdP
        public object[] getPuKxAndRx(string IDx) {
            this.IDx = IDx;
            Rx = generateRx();
            
            PuKx = rsa.ExportRSAPublicKey();
            PrKx = rsa.ExportRSAPrivateKey();
            return new object[] {PuKx, Rx};
        }
        private int generateRx() {
            return random.Next();
        }

        // called from IdP
        public byte[] getCounter(byte[] encryptedRp) {
            byte[] decryptData = rsa.Decrypt(encryptedRp, RSAEncryptionPadding.Pkcs1);
            Rp = BitConverter.ToInt32(decryptData, 0);
            Cx = random.Next();
            aes.Key = SHA256.HashData(BitConverter.GetBytes(Rx * Rp));
            byte[] encryptCounter = aes.EncryptCbc(BitConverter.GetBytes(Cx), aes.Key.Take(16).ToArray());
            Debug.WriteLine("autenticator: PuKx=\n" + BitConverter.ToString(PuKx));
            Debug.WriteLine("autenticator: Rx=" + Rx);
            Debug.WriteLine("autenticator: Rp=" + Rp);
            Debug.WriteLine("autenticator: Cx=" + Cx);
            return encryptCounter;
        }
    }
}
