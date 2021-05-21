using CryptoModule2.Models.Ciphers.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Keys
{
    public class DHKey : IKey
    {

            public DHParameters PublicParameters { get; }
            public BigInteger X { get; }
            public BigInteger Y { get; }


            public DHKey( DHParameters dhParameters ) : 
                this(dhParameters, Helper.GenerateBigInteger(2, dhParameters.P - 1) )
            {
            
            }

            public DHKey( DHParameters dhParameters, BigInteger x )
            {
                if( dhParameters == null )
                {
                    throw new ArgumentException( "dhParameters is null" );
                }
                if( x < 2 )
                {
                    throw new ArgumentException( "Маленькое либо отрицательное x" );
                }
                PublicParameters = dhParameters;
                X = x;
                Y = BigInteger.ModPow( dhParameters.G, x, dhParameters.P );
            }

            public BigInteger CalcSecret(BigInteger secondY)
            {
                return BigInteger.ModPow( secondY, X, PublicParameters.P );
            }



    }
}
