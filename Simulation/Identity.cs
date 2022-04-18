using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Simulation {
    /**
     *  Identitiy in IdP
     */
    internal class Identity {
        public string IDx;
        public byte[] PuKx;
        public int Rx;
        public int Rp;
        public int Cx;
        public string HMAC;
        public Identity(string IDx) {
            this.IDx = IDx;
        }
    }
}
