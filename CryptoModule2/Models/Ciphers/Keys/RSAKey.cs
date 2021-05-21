using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Keys
{
    public class RSAKey : IKey
    {
        public BigInteger Modulus { get; private set; } = BigInteger.Zero;
        public BigInteger Exponent { get; private set; } = BigInteger.Zero;
        public bool IsPrivate { get; private set; } = false;

        public readonly int MaxOpenTextSize;
        public readonly int MaxCipherTextSize;

        public RSAKey( bool isPrivate, string exponent, string modulus) : 
            this(isPrivate, BigInteger.Parse(exponent), BigInteger.Parse(modulus))
        {

        }

        public RSAKey( bool isPrivate, BigInteger exponent, BigInteger modulus )
        {
            IsPrivate = isPrivate;


            if( exponent <= BigInteger.One )
            {
                throw new ArgumentException( "Экспонента должна быть больше единицы" );
            }
            if( modulus <= 255 )
            {
                throw new ArgumentException( "Модуль должна быть больше 255" );
            }
            if( exponent >= modulus )
            {
                throw new ArgumentException( "Экспонента должна быть меньше модуля" );
            }
            Exponent = exponent;
            Modulus = modulus;

            int modulusByteCount = Modulus.ToByteArray( false ).Length;

            MaxOpenTextSize = modulusByteCount - 1;
            MaxCipherTextSize = modulusByteCount;
        }

        public static AsymmetricCipherKeyPair GenerateKey(BigInteger p, BigInteger q)
        {
            if( ( p.Sign != 1 ) || ( q.Sign != 1 ) )
            {
                throw new ArgumentException( "P и Q должны быть положительными" );
            }

            if( !p.IsPrime() || !q.IsPrime() )
            {
                    throw new ArgumentException( "P и Q должны быть простыми" );
            }

            BigInteger modulus = p * q;

            BigInteger phi = ( p - 1 ) * ( q - 1 );

            BigInteger publicExponent = 65537 > phi ? 17 : 65537;
            BigInteger privateExponent = publicExponent.Inverse( phi ); //Helper.Inverse( publicExponent, phi )

            IKey publicKey = new RSAKey( false, publicExponent, modulus );
            IKey privateKey = new RSAKey( true, privateExponent, modulus );

            return new AsymmetricCipherKeyPair( publicKey, privateKey );
        }

        public static AsymmetricCipherKeyPair GenerateKey(int decimalNubmerCount, out BigInteger p, out BigInteger q)
        {
            if( decimalNubmerCount < 6 )
            {
                throw new ArgumentException( "Слишком маленький порядок числа" );
            }
            int mul = decimalNubmerCount / 2;
            BigInteger min = BigInteger.Pow( 10, mul ) * 2;
            BigInteger max = BigInteger.Pow( 10, mul + 1 );

            while( true ) // Надо ограничть макс значением
            {
                p = Helper.GenerateBigInteger( min, max );
                if( p.IsPrime() )
                {
                    break;
                }
            }

            min = BigInteger.Pow( 10, decimalNubmerCount - 1) /  p + 1 ;
            max = BigInteger.Pow( 10, decimalNubmerCount ) /  p - 1 ;

            while( true ) // Надо ограничть макс значением
            {
                q = Helper.GenerateBigInteger( min, max );
                if( q.IsPrime() )
                {
                    break;
                }
            }


            return GenerateKey( p, q );

        }


    }
}
