using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Simulation {
    internal class IdentityProvider {
        List<Identity> _identityList = new List<Identity>();
        Random random = new Random();
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        Aes aes = Aes.Create();

        // called from Form1
        public void initialize(Authenticator authenticator, string IDx) {
            Identity identity = new Identity(IDx);

            // get public key and Rx
            object[] PuKxAndRx = authenticator.getPuKxAndRx(IDx);
            byte[] PuKx = (byte[])(PuKxAndRx[0]);
            identity.PuKx = PuKx;
            int Rx = (int)(PuKxAndRx[1]);
            identity.Rx = Rx;
            int Rp = generateRp();
            identity.Rp = Rp;

            // get counter
            byte[] encryptedCounter = authenticator.getCounter(encryptRp(PuKx, Rp));
            int Cx = decryptCounter(Rx,Rp, encryptedCounter);
            identity.Cx = Cx+1;//預先加一

            // calculate hmac
            identity.HMAC = getHMAC(IDx, Rx, Rp, identity.Cx);

            Debug.WriteLine("IdP: PuKx=\n" + BitConverter.ToString(PuKx));
            Debug.WriteLine("IdP: Rx=" + Rx);
            Debug.WriteLine("IdP: Rp=" + Rp);
            Debug.WriteLine("IdP: Cx=" + Cx);
            Debug.WriteLine("IdP: HMAC=" + identity.HMAC);
            _identityList.Add(identity);
        }

        private int generateRp() {
            return random.Next();
        }
        private byte[] encryptRp(byte[] PuKx, int Rp) {
            rsa.ImportRSAPublicKey(PuKx, out _);
            byte[] encryptedRp = rsa.Encrypt(BitConverter.GetBytes(Rp), RSAEncryptionPadding.Pkcs1);
            return encryptedRp;
        }
        private int decryptCounter(int Rx, int Rp, byte[] encryptedCounter) {
            aes.Key = SHA256.HashData(BitConverter.GetBytes(Rx*Rp));
            byte[] decryptedData = aes.DecryptCbc(encryptedCounter, aes.Key.Take(16).ToArray());
            int counter = BitConverter.ToInt32(decryptedData);
            return counter;
        }

        // this method is same as the one in authenticator
        private string getHMAC(string IDx, int Rx, int Rp, int Cx) {
            byte[] hashKey = SHA256.HashData(BitConverter.GetBytes(Rx * Rp));
            string hmac = Convert.ToHexString(HMACSHA256.HashData(hashKey, Encoding.ASCII.GetBytes(IDx + Cx.ToString())));
            return hmac;
        }

        // called from RP
        public string verify(string subject, string issuer) {
            string hmac = subject.Split("=")[1];//"cn=[hmac]"
            byte[] encryptedCounter = Convert.FromHexString(issuer.Split(":")[1]);//"cn=ExampleProvider:[encryptedCounter]"
            Debug.WriteLine(hmac);
            foreach(Identity i in _identityList) {
                if (i.HMAC == hmac) {
                    if (i.Cx == decryptCounter(i.Rx, i.Rp, encryptedCounter))
                        return i.IDx;
                    else {
                        Debug.WriteLine("Cx not match");
                        return null;
                    }
                }
            }
            Debug.WriteLine("HMAC not match");
            return null;
        }
    }
}
 