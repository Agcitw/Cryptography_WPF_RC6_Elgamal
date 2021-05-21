using System;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoModule2.Models
{
	public static class Helper
	{
		public static BigInteger GenerateBigInteger(BigInteger min, BigInteger max)
		{
			if (min >= max) throw new ArgumentException("min >= max");
			if (min.Sign != 1 || max.Sign != 1) throw new ArgumentException("must be positive");
			var diff = max - min;
			var byteSize = diff.ToByteArray().Length;
			var newBigIntegerChunk = new byte[byteSize + 1];
			var rngGenerator = new RNGCryptoServiceProvider();
			rngGenerator.GetBytes(newBigIntegerChunk);
			newBigIntegerChunk[newBigIntegerChunk.Length - 1] = 0;
			var result = new BigInteger(newBigIntegerChunk);
			BigInteger.DivRem(result, diff, out result);
			result += min;
			return result;
		}

		public static string GenerateRandomKey(int length)
		{
			var resultRandomKey = "";
			var random = new Random();
			for (var i = 0; i < length; i++)
				resultRandomKey += (char) random.Next(33, 126);
			return resultRandomKey;
		}
	}
}