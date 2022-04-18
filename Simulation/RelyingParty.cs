using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace Simulation {
    internal class RelyingParty {
        Random random = new Random();
        string IDr = "www.exampleRP.com";

        // called from Form1
        public void register(Authenticator authenticator, User user, IdentityProvider identityProvider) {
            string Nickr = user.nickname;
            int Rr = random.Next();

            // get credential from authenticator
            X509Certificate2 x509Certificate = authenticator.getCertificate(IDr, Nickr, Rr);
            string subject = x509Certificate.Subject;
            string issuer = x509Certificate.Issuer;
            Debug.WriteLine("subject= "+subject);
            Debug.WriteLine("issuer= "+issuer);
            verify(identityProvider, subject, issuer);
        }

        // get identity from IdP
        private void verify(IdentityProvider identityProvider, string subject, string issuer) {
            String IDx = identityProvider.verify(subject, issuer);
            Debug.WriteLine("verify: IDx=" + IDx);
        }
    }
}
