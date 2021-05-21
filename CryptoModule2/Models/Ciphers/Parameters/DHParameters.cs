using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Parameters
{
    public class DHParameters
    {

        private readonly BigInteger _p;
        private readonly BigInteger _g;

        public BigInteger P { get => _p; }
        public BigInteger G { get => _g; }


        // Пока нельзя создать экземпляр
        private DHParameters(BigInteger p, BigInteger g)
        {
            _p = p;
            _g = g;
        }

        public static DHParameters Generate( int decimalNubmerCount )
        {
            if( decimalNubmerCount < 6 )
            {
                throw new ArgumentException( "Слишком маленький порядок числа" );
            }

            BigInteger min = BigInteger.Pow( 10, decimalNubmerCount );
            BigInteger max = BigInteger.Pow( 10, decimalNubmerCount + 1 );

            BigInteger p;
            BigInteger q;

            while( true )
            {
                q = Helper.GenerateBigInteger( min, max );
                if( q.IsPrime() )
                {
                    p = (q << 1) + BigInteger.One;

                    if( p.IsPrime() )
                    {
                        break;
                    }
                }
            }


            BigInteger pMinusOne = p - 1;
            BigInteger g;

            do
            {
                g = Helper.GenerateBigInteger( 2, pMinusOne );
            } while( BigInteger.ModPow(g, 2, p) == BigInteger.One
                  || BigInteger.ModPow(g, q, p) == BigInteger.One );

            return new DHParameters( p, g );

        }

    }
}
