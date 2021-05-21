using CryptoModule2.Models.Ciphers.Asymmetric;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.HashFunctions
{
    public class MD5 : IHash
    {
        private const int _digestLength = 16;

        private const int _inputBlockSize = 16; // колличество uint 
        private const int _byteStep = _inputBlockSize * 4;

        public MD5()
        {

        }

        public byte[] Hash( byte[] inputBlock )
        {
            uint[] digest = GetInitBlock();
            uint[] currentBlock = new uint[ _inputBlockSize ];

            int blockCount = inputBlock.Length / _byteStep;
            int bytesLeft = inputBlock.Length % _byteStep;

            for( int i = 0; i < blockCount * _byteStep; i += _byteStep )
            {
                Buffer.BlockCopy( inputBlock, i, currentBlock, 0, _byteStep );
                ProcessBlock( ref digest, ref currentBlock );
            }

            byte[] finalBlock = new byte[ bytesLeft ];
            Buffer.BlockCopy( inputBlock, inputBlock.Length - bytesLeft, finalBlock, 0, bytesLeft );

            ProcessFinalBlock( ref digest, ref finalBlock, ( ulong )inputBlock.Length * 8 );

            byte[] result = new byte[ _digestLength ];
            Buffer.BlockCopy( digest, 0, result, 0, _digestLength );
            return result;
        }

        public byte[] Hash( string path )
        {
            uint[] digest = GetInitBlock();
            byte[] inputBlock = new byte[ _byteStep ];
            uint[] currentBlock = new uint[ _inputBlockSize ];

            using FileStream instream = File.OpenRead( path );
            ulong fileSize = (ulong)instream.Length;

            int byteRead = 0;

            while( (byteRead = instream.Read(inputBlock, 0, _byteStep)) == _byteStep )
            {
                Buffer.BlockCopy( inputBlock, 0, currentBlock, 0, byteRead );
                ProcessBlock( ref digest, ref currentBlock );
            }

            byte[] finalBlock = new byte[ byteRead ];
            Buffer.BlockCopy( inputBlock, 0, finalBlock, 0, byteRead );

            ProcessFinalBlock( ref digest, ref finalBlock, fileSize * 8 );

            byte[] result = new byte[ _digestLength ];
            Buffer.BlockCopy( digest, 0, result, 0, _digestLength );

            return result;
        }

        private void ProcessBlock( ref uint[] digest, ref uint[] x )
        {
            uint a = digest[ 0 ];
            uint b = digest[ 1 ];
            uint c = digest[ 2 ];
            uint d = digest[ 3 ];

            //
            // Этап 1
            //
            a = b + RotateLeft( ( a + F( b, c, d ) + x[ 0 ] + 0xd76aa478 ), 7 );
            d = a + RotateLeft( ( d + F( a, b, c ) + x[ 1 ] + 0xe8c7b756 ), 12 );
            c = d + RotateLeft( ( c + F( d, a, b ) + x[ 2 ] + 0x242070db ), 17 );
            b = c + RotateLeft( ( b + F( c, d, a ) + x[ 3 ] + 0xc1bdceee ), 22 );
            a = b + RotateLeft( ( a + F( b, c, d ) + x[ 4 ] + 0xf57c0faf ), 7 );
            d = a + RotateLeft( ( d + F( a, b, c ) + x[ 5 ] + 0x4787c62a ), 12 );
            c = d + RotateLeft( ( c + F( d, a, b ) + x[ 6 ] + 0xa8304613 ), 17 );
            b = c + RotateLeft( ( b + F( c, d, a ) + x[ 7 ] + 0xfd469501 ), 22 );
            a = b + RotateLeft( ( a + F( b, c, d ) + x[ 8 ] + 0x698098d8 ), 7 );
            d = a + RotateLeft( ( d + F( a, b, c ) + x[ 9 ] + 0x8b44f7af ), 12 );
            c = d + RotateLeft( ( c + F( d, a, b ) + x[ 10 ] + 0xffff5bb1 ), 17 );
            b = c + RotateLeft( ( b + F( c, d, a ) + x[ 11 ] + 0x895cd7be ), 22 );
            a = b + RotateLeft( ( a + F( b, c, d ) + x[ 12 ] + 0x6b901122 ),  7);
            d = a + RotateLeft( ( d + F( a, b, c ) + x[ 13 ] + 0xfd987193 ), 12 );
            c = d + RotateLeft( ( c + F( d, a, b ) + x[ 14 ] + 0xa679438e ), 17 );
            b = c + RotateLeft( ( b + F( c, d, a ) + x[ 15 ] + 0x49b40821 ), 22 );

            //
            // Этап 2
            //
            a = b + RotateLeft( ( a + G( b, c, d ) + x[ 1 ] + 0xf61e2562 ), 5 );
            d = a + RotateLeft( ( d + G( a, b, c ) + x[ 6 ] + 0xc040b340 ), 9 );
            c = d + RotateLeft( ( c + G( d, a, b ) + x[ 11 ] + 0x265e5a51 ), 14 );
            b = c + RotateLeft( ( b + G( c, d, a ) + x[ 0 ] + 0xe9b6c7aa ), 20 );
            a = b + RotateLeft( ( a + G( b, c, d ) + x[ 5 ] + 0xd62f105d ), 5 );
            d = a + RotateLeft( ( d + G( a, b, c ) + x[ 10 ] + 0x02441453 ), 9 );
            c = d + RotateLeft( ( c + G( d, a, b ) + x[ 15 ] + 0xd8a1e681 ), 14 );
            b = c + RotateLeft( ( b + G( c, d, a ) + x[ 4 ] + 0xe7d3fbc8 ), 20 );
            a = b + RotateLeft( ( a + G( b, c, d ) + x[ 9 ] + 0x21e1cde6 ), 5 );
            d = a + RotateLeft( ( d + G( a, b, c ) + x[ 14 ] + 0xc33707d6 ), 9 );
            c = d + RotateLeft( ( c + G( d, a, b ) + x[ 3 ] + 0xf4d50d87 ), 14 );
            b = c + RotateLeft( ( b + G( c, d, a ) + x[ 8 ] + 0x455a14ed ), 20 );
            a = b + RotateLeft( ( a + G( b, c, d ) + x[ 13 ] + 0xa9e3e905 ), 5 );
            d = a + RotateLeft( ( d + G( a, b, c ) + x[ 2 ] + 0xfcefa3f8 ), 9 );
            c = d + RotateLeft( ( c + G( d, a, b ) + x[ 7 ] + 0x676f02d9 ), 14 );
            b = c + RotateLeft( ( b + G( c, d, a ) + x[ 12 ] + 0x8d2a4c8a ), 20 );

            //
            // Этап 3
            //
            a = b + RotateLeft( ( a + H( b, c, d ) + x[ 5 ] + 0xfffa3942 ), 4 );
            d = a + RotateLeft( ( d + H( a, b, c ) + x[ 8 ] + 0x8771f681 ), 11 );
            c = d + RotateLeft( ( c + H( d, a, b ) + x[ 11 ] + 0x6d9d6122 ), 16 );
            b = c + RotateLeft( ( b + H( c, d, a ) + x[ 14 ] + 0xfde5380c ), 23 );
            a = b + RotateLeft( ( a + H( b, c, d ) + x[ 1 ] + 0xa4beea44 ), 4 );
            d = a + RotateLeft( ( d + H( a, b, c ) + x[ 4 ] + 0x4bdecfa9 ), 11 );
            c = d + RotateLeft( ( c + H( d, a, b ) + x[ 7 ] + 0xf6bb4b60 ), 16 );
            b = c + RotateLeft( ( b + H( c, d, a ) + x[ 10 ] + 0xbebfbc70 ), 23 );
            a = b + RotateLeft( ( a + H( b, c, d ) + x[ 13 ] + 0x289b7ec6 ), 4 );
            d = a + RotateLeft( ( d + H( a, b, c ) + x[ 0 ] + 0xeaa127fa ), 11 );
            c = d + RotateLeft( ( c + H( d, a, b ) + x[ 3 ] + 0xd4ef3085 ), 16 );
            b = c + RotateLeft( ( b + H( c, d, a ) + x[ 6 ] + 0x04881d05 ), 23 );
            a = b + RotateLeft( ( a + H( b, c, d ) + x[ 9 ] + 0xd9d4d039 ), 4 );
            d = a + RotateLeft( ( d + H( a, b, c ) + x[ 12 ] + 0xe6db99e5 ), 11 );
            c = d + RotateLeft( ( c + H( d, a, b ) + x[ 15 ] + 0x1fa27cf8 ), 16 );
            b = c + RotateLeft( ( b + H( c, d, a ) + x[ 2 ] + 0xc4ac5665 ), 23 );

            //
            // Этап 4
            //
            a = b + RotateLeft( ( a + I( b, c, d ) + x[ 0 ] + 0xf4292244 ), 6 );
            d = a + RotateLeft( ( d + I( a, b, c ) + x[ 7 ] + 0x432aff97 ), 10 );
            c = d + RotateLeft( ( c + I( d, a, b ) + x[ 14 ] + 0xab9423a7 ), 15 );
            b = c + RotateLeft( ( b + I( c, d, a ) + x[ 5 ] + 0xfc93a039 ), 21 );
            a = b + RotateLeft( ( a + I( b, c, d ) + x[ 12 ] + 0x655b59c3 ), 6 );
            d = a + RotateLeft( ( d + I( a, b, c ) + x[ 3 ] + 0x8f0ccc92 ), 10 );
            c = d + RotateLeft( ( c + I( d, a, b ) + x[ 10 ] + 0xffeff47d ), 15 );
            b = c + RotateLeft( ( b + I( c, d, a ) + x[ 1 ] + 0x85845dd1 ), 21 );
            a = b + RotateLeft( ( a + I( b, c, d ) + x[ 8 ] + 0x6fa87e4f ), 6 );
            d = a + RotateLeft( ( d + I( a, b, c ) + x[ 15 ] + 0xfe2ce6e0 ), 10 );
            c = d + RotateLeft( ( c + I( d, a, b ) + x[ 6 ] + 0xa3014314 ), 15 );
            b = c + RotateLeft( ( b + I( c, d, a ) + x[ 13 ] + 0x4e0811a1 ), 21 );
            a = b + RotateLeft( ( a + I( b, c, d ) + x[ 4 ] + 0xf7537e82 ), 6 );
            d = a + RotateLeft( ( d + I( a, b, c ) + x[ 11 ] + 0xbd3af235 ), 10 );
            c = d + RotateLeft( ( c + I( d, a, b ) + x[ 2 ] + 0x2ad7d2bb ), 15 );
            b = c + RotateLeft( ( b + I( c, d, a ) + x[ 9 ] + 0xeb86d391 ), 21 );

            digest[ 0 ] += a;
            digest[ 1 ] += b;
            digest[ 2 ] += c;
            digest[ 3 ] += d;
        }

        private void ProcessFinalBlock(ref uint[] digest, ref byte[] block, ulong bitLength)
        {
            List<byte> finalBlock = new List<byte>( block );
            finalBlock.Add( 128 );
            while( finalBlock.Count % 64 != 56 )
            {
                finalBlock.Add( 0 );
            }


            if( finalBlock.Count > _byteStep )
            {
                uint[] prelastBlock = new uint[ _inputBlockSize ];
                prelastBlock = new uint[ _inputBlockSize ];
                Buffer.BlockCopy( finalBlock.ToArray(), 0, prelastBlock, 0, _byteStep );
                ProcessBlock( ref digest, ref prelastBlock );
                finalBlock = finalBlock.GetRange( _byteStep, _byteStep - 8 );
            }

            uint[] lastBlock = new uint[ _inputBlockSize ];
            Buffer.BlockCopy( finalBlock.ToArray(), 0, lastBlock, 0, _byteStep - 8 );
            lastBlock[ _inputBlockSize - 2 ] = ( uint )( bitLength );
            lastBlock[ _inputBlockSize - 1 ] = ( uint )( bitLength >> 32 );

            ProcessBlock( ref digest, ref lastBlock );

        }

        private static uint F( uint x, uint y, uint z )
        {
            return ( x & y ) | ( ~x & z );
        }

        private static uint G( uint x, uint y, uint z )
        {
            return ( x & z ) | ( ~z & y );
        }

        private static uint H( uint x, uint y, uint z )
        {
            return x ^ y ^ z;
        }

        private static uint I( uint x, uint y, uint z )
        {
            return y ^ ( ~z | x );
        }

        private static uint[] GetInitBlock()
        {
            return new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
        }

        private static uint RotateLeft( uint x, int n )
        {
            return ( x << n ) | ( x >> ( 32 - n ) );
        }

    }
}
