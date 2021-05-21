using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Parameters
{
    public class ShamirParameters
    {
        public BigInteger P { get; }
        private ShamirParameters(BigInteger p)
        {
            P = p;
        }
        public static ShamirParameters Generate()
        {
            Random rand = new Random();
            BigInteger p = Helper.GeneratePrime( rand.Next( 7, 30 ) );
            return new ShamirParameters( p );
        }

    }
}
