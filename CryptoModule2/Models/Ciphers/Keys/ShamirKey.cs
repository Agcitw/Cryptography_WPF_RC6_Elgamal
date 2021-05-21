using CryptoModule2.Models.Ciphers.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Keys
{
    public class ShamirKey : IKey
    {
        public ShamirParameters Parameters;
        public BigInteger C { get; }
        public BigInteger D { get; }


        public int MaxOpenTextSize { get; private set; }
        public int MaxCipherTextSize { get; private set; }

        private bool _isFirstTime = true;
        public bool IsFirstTime 
        {
            get => IsFirstTime;
            set
            {
                _isFirstTime = value;

                int modulusByteCount = Parameters.P.ToByteArray( false ).Length;

                MaxOpenTextSize = modulusByteCount - 1;
                MaxCipherTextSize = modulusByteCount;

                if( !value )
                {
                    MaxOpenTextSize = MaxCipherTextSize;
                }

            }
        }

        public ShamirKey( ShamirParameters parameters )
        {
            if( parameters == null )
            {
                throw new ArgumentNullException( "parameters is null" );
            }
            Parameters = parameters;

            BigInteger c;
            BigInteger d;

            BigInteger phi = parameters.P - BigInteger.One;

            while( true )
            {
                try
                {
                    c = Helper.GenerateBigInteger( 2, phi );
                    d = c.Inverse( phi );
                    break;
                }
                catch( Exception )
                {
                    continue; // не удалось найти обратный элемент
                }
            }

            C = c;
            D = d;

            IsFirstTime = true;



        }

    }
}
