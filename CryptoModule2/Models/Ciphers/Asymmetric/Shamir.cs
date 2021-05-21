using CryptoModule2.Models.Ciphers.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers.Asymmetric
{
    public class Shamir : ICipher
    {

        public string CipherName => "Протокол Шамира";

        public byte[] Decrypt( byte[] ciphertext, IKey key = null )
        {
            return Process( ciphertext, key as ShamirKey, false );
        }
        public byte[] Decrypt( byte[] ciphertext, ShamirKey key, bool isFirstTime )
        {
            return Process( ciphertext, key, false, isFirstTime );
        }

        public byte[] Encrypt( byte[] text, IKey key = null )
        {
            return Process( text, key as ShamirKey, true );
        }

        public byte[] Encrypt( byte[] text, ShamirKey key, bool isFirstTime )
        {
            return Process( text, key, true, isFirstTime );
        }


        private byte[] Process( byte[] inputData, ShamirKey key, bool isEncrypt, bool isFirstTime = true )
        {
            if( inputData == null )
            {
                throw new ArgumentNullException( "Пустые входные данные" );
            }
            if( inputData.Length == 0 )
            {
                throw new ArgumentNullException( "Пустые входные данные" );
            }
            List<byte> result = new List<byte>( inputData.Length );

            BigInteger exponent = isEncrypt ? key.C : key.D;
            BigInteger modulus = key.Parameters.P;

            int readSize = 0;
            int writeSize = 0;

            if( isEncrypt )
            {
                readSize = key.MaxOpenTextSize;
                writeSize = key.MaxCipherTextSize;
                           }
            else
            {
                readSize = key.MaxCipherTextSize;
                writeSize = key.MaxOpenTextSize;
            }

            try
            {
                for( int currentByte = 0; currentByte < inputData.Length; currentByte += readSize )
                {
                    int byteCopyCount = Math.Min( readSize, inputData.Length - currentByte );


                    byte[] currentBlock = new byte[ byteCopyCount + 1 ]; // Добавлен 0х00 чтобы число было положительным 

                    Buffer.BlockCopy( inputData, currentByte, currentBlock, 0, byteCopyCount );


                    BigInteger beforeProccesInt = new BigInteger( currentBlock );
                    BigInteger afterProccesInt = BigInteger.ModPow( beforeProccesInt, exponent, modulus );

                    byte[] cipherBlock = afterProccesInt.ToByteArray( false );

                    byte[] packedBlock = new byte[ writeSize ];
                    Buffer.BlockCopy( cipherBlock, 0, packedBlock, 0, cipherBlock.Length );

                    result.AddRange( packedBlock );


                }
            }
            catch( Exception ex )
            {
                throw new Exception( "Ошибка! Проверьте входные параметры.", ex );
            }

            return result.ToArray();

        }
    }
}
