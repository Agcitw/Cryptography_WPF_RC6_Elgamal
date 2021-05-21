using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.HashFunctions
{
    public class SHA1 : IHash
    {
        private const int _digestLength = 20;

        private const int _inputBlockSize = 16; // колличество uint 
        private const int _byteStep = _inputBlockSize * 4;

        private const uint Y1 = 0x5a827999;
        private const uint Y2 = 0x6ed9eba1;
        private const uint Y3 = 0x8f1bbcdc;
        private const uint Y4 = 0xca62c1d6;

        public SHA1()
        {

        }

        public byte[] Hash( byte[] inputBlock )
        {
            uint[] digest = GetInitBlock();
            uint[] currentBlock = new uint[ 80 ];

            int blockCount = inputBlock.Length / _byteStep;
            int bytesLeft = inputBlock.Length % _byteStep;

            for( int i = 0; i < blockCount * _byteStep; i += _byteStep )
            {
                Buffer.BlockCopy( inputBlock, i, currentBlock, 0, _byteStep );
                for( int j = 0; j < _inputBlockSize; j++ )
                {
                    currentBlock[ j ] = ReverseBytes( currentBlock[ j ] );
                }
                ProcessBlock( ref digest, ref currentBlock );
            }

            byte[] finalBlock = new byte[ bytesLeft ];
            Buffer.BlockCopy( inputBlock, inputBlock.Length - bytesLeft, finalBlock, 0, bytesLeft );

            ProcessFinalBlock( ref digest, ref finalBlock, ( ulong )inputBlock.Length * 8 );

            byte[] result = new byte[ _digestLength ];

            for( int i = 0; i < digest.Length; i++ )
            {
                byte[] temp = BitConverter.GetBytes( digest[ i ] );
                Array.Reverse( temp );
                Buffer.BlockCopy( temp, 0, result, i*4, 4 );
            }
            return result;
        }

        public byte[] Hash( string path )
        {
            uint[] digest = GetInitBlock();
            byte[] inputBlock = new byte[ _byteStep ];
            uint[] currentBlock = new uint[ 80 ];

            using FileStream instream = File.OpenRead( path );
            ulong fileSize = ( ulong )instream.Length;

            int byteRead = 0;

            while( ( byteRead = instream.Read( inputBlock, 0, _byteStep ) ) == _byteStep )
            {
                Buffer.BlockCopy( inputBlock, 0, currentBlock, 0, byteRead );
                for( int i = 0; i < _inputBlockSize; i++ )
                {
                    currentBlock[i] = ReverseBytes( currentBlock[ i ] );
                }
                ProcessBlock( ref digest, ref currentBlock );
            }

            byte[] finalBlock = new byte[ byteRead ];
            Buffer.BlockCopy( inputBlock, 0, finalBlock, 0, byteRead );

            ProcessFinalBlock( ref digest, ref finalBlock, fileSize * 8 );

            byte[] result = new byte[ _digestLength ];
            for( int i = 0; i < digest.Length; i++ )
            {
                byte[] temp = BitConverter.GetBytes( digest[ i ] );
                Array.Reverse( temp );
                Buffer.BlockCopy( temp, 0, result, i * 4, 4 );
            }
            return result;
        }

        private void ProcessBlock( ref uint[] digest, ref uint[] x )
        {
            for( int i = 16; i < 80; i++ )
            {
                uint t = x[ i - 3 ] ^ x[ i - 8 ] ^ x[ i - 14 ] ^ x[ i - 16 ];
                x[ i ] = t << 1 | t >> 31;
            }

  
            uint A = digest[ 0 ];
            uint B = digest[ 1 ];
            uint C = digest[ 2 ];
            uint D = digest[ 3 ];
            uint E = digest[ 4 ];

            // Раунд 1
            int idx = 0;

            for( int j = 0; j < 4; j++ )
            {

                E += ( A << 5 | ( A >> 27 ) ) + F( B, C, D ) + x[ idx++ ] + Y1;
                B = B << 30 | ( B >> 2 );

                D += ( E << 5 | ( E >> 27 ) ) + F( A, B, C ) + x[ idx++ ] + Y1;
                A = A << 30 | ( A >> 2 );

                C += ( D << 5 | ( D >> 27 ) ) + F( E, A, B ) + x[ idx++ ] + Y1;
                E = E << 30 | ( E >> 2 );

                B += ( C << 5 | ( C >> 27 ) ) + F( D, E, A ) + x[ idx++ ] + Y1;
                D = D << 30 | ( D >> 2 );

                A += ( B << 5 | ( B >> 27 ) ) + F( C, D, E ) + x[ idx++ ] + Y1;
                C = C << 30 | ( C >> 2 );
            }

            // Раунд 2
            for( int j = 0; j < 4; j++ )
            {

                E += ( A << 5 | ( A >> 27 ) ) + H( B, C, D ) + x[ idx++ ] + Y2;
                B = B << 30 | ( B >> 2 );

                D += ( E << 5 | ( E >> 27 ) ) + H( A, B, C ) + x[ idx++ ] + Y2;
                A = A << 30 | ( A >> 2 );

                C += ( D << 5 | ( D >> 27 ) ) + H( E, A, B ) + x[ idx++ ] + Y2;
                E = E << 30 | ( E >> 2 );

                B += ( C << 5 | ( C >> 27 ) ) + H( D, E, A ) + x[ idx++ ] + Y2;
                D = D << 30 | ( D >> 2 );

                A += ( B << 5 | ( B >> 27 ) ) + H( C, D, E ) + x[ idx++ ] + Y2;
                C = C << 30 | ( C >> 2 );
            }

            // Раунд 3
            for( int j = 0; j < 4; j++ )
            {

                E += ( A << 5 | ( A >> 27 ) ) + G( B, C, D ) + x[ idx++ ] + Y3;
                B = B << 30 | ( B >> 2 );

                D += ( E << 5 | ( E >> 27 ) ) + G( A, B, C ) + x[ idx++ ] + Y3;
                A = A << 30 | ( A >> 2 );

                C += ( D << 5 | ( D >> 27 ) ) + G( E, A, B ) + x[ idx++ ] + Y3;
                E = E << 30 | ( E >> 2 );

                B += ( C << 5 | ( C >> 27 ) ) + G( D, E, A ) + x[ idx++ ] + Y3;
                D = D << 30 | ( D >> 2 );

                A += ( B << 5 | ( B >> 27 ) ) + G( C, D, E ) + x[ idx++ ] + Y3;
                C = C << 30 | ( C >> 2 );
            }

            // Раунд 4
            for( int j = 0; j < 4; j++ )
            {

                E += ( A << 5 | ( A >> 27 ) ) + H( B, C, D ) + x[ idx++ ] + Y4;
                B = B << 30 | ( B >> 2 );

                D += ( E << 5 | ( E >> 27 ) ) + H( A, B, C ) + x[ idx++ ] + Y4;
                A = A << 30 | ( A >> 2 );

                C += ( D << 5 | ( D >> 27 ) ) + H( E, A, B ) + x[ idx++ ] + Y4;
                E = E << 30 | ( E >> 2 );

                B += ( C << 5 | ( C >> 27 ) ) + H( D, E, A ) + x[ idx++ ] + Y4;
                D = D << 30 | ( D >> 2 );

                A += ( B << 5 | ( B >> 27 ) ) + H( C, D, E ) + x[ idx++ ] + Y4;
                C = C << 30 | ( C >> 2 );
            }

            digest[ 0 ] += A;
            digest[ 1 ] += B;
            digest[ 2 ] += C;
            digest[ 3 ] += D;
            digest[ 4 ] += E;

            Array.Clear( x, 0, 16 );

        }

        private void ProcessFinalBlock( ref uint[] digest, ref byte[] block, ulong bitLength )
        {
            List<byte> finalBlock = new List<byte>( block );
            finalBlock.Add( 128 );
            while( finalBlock.Count % 64 != 56 )
            {
                finalBlock.Add( 0 );
            }


            if( finalBlock.Count > _byteStep )
            {
                uint[] prelastBlock = new uint[ 80 ];
                Buffer.BlockCopy( finalBlock.ToArray(), 0, prelastBlock, 0, _byteStep );
                for( int i = 0; i < _inputBlockSize; i++ )
                {
                    prelastBlock[ i ] = ReverseBytes( prelastBlock[ i ] );
                }
                ProcessBlock( ref digest, ref prelastBlock );
                finalBlock = finalBlock.GetRange( _byteStep, _byteStep - 8 );
            }

            uint[] lastBlock = new uint[ 80 ];
            Buffer.BlockCopy( finalBlock.ToArray(), 0, lastBlock, 0, _byteStep - 8 );
            for( int i = 0; i < _inputBlockSize - 2; i++ )
            {
                lastBlock[ i ] = ReverseBytes( lastBlock[ i ] );
            }
            lastBlock[ _inputBlockSize - 2 ] = ( uint )( bitLength >> 32 );
            lastBlock[ _inputBlockSize - 1 ] = ( uint )( bitLength );

            ProcessBlock( ref digest, ref lastBlock );

        }

        private static uint F( uint u, uint v, uint w )
        {
            return ( u & v ) | ( ~u & w );
        }

        private static uint H( uint u, uint v, uint w )
        {
            return u ^ v ^ w;
        }

        private static uint G( uint u, uint v, uint w )
        {
            return ( u & v ) | ( u & w ) | ( v & w );
        }

        private static uint[] GetInitBlock()
        {
            return new uint[] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
        }

        private static uint RotateLeft( uint x, int n )
        {
            return ( x << n ) | ( x >> ( 32 - n ) );
        }
        public static uint ReverseBytes( uint value )
        {
            return ( value & 0x000000FFU ) << 24 | ( value & 0x0000FF00U ) << 8 |
                ( value & 0x00FF0000U ) >> 8 | ( value & 0xFF000000U ) >> 24;
        }
    }
}
