using System;
using System.Collections.Generic;
using System.Numerics;

namespace CryptoModule2.Models
{
	public static class BigIntegerExtension
	{
		public static byte[] ToByteArray(this BigInteger bigInteger, bool isSign)
		{
			if (isSign) return bigInteger.ToByteArray();
			var byteArray = new List<byte>(bigInteger.ToByteArray());
			while (byteArray.Count > 1 && byteArray[byteArray.Count - 1] == 0) byteArray.RemoveAt(byteArray.Count - 1);
			return byteArray.ToArray();
		}

		public static bool IsPrimeMillerRabin(this BigInteger n, uint testCount = 40)
		{
			if (n.Sign != 1) throw new ArgumentException("n must be positive");
			if (n == 2) return true;
			if (n.IsEven) return false;
			ulong s = 0;
			var t = n - BigInteger.One;
			while (t.IsEven)
			{
				s++;
				t >>= 1;
			}

			for (uint i = 0; i < testCount; i++)
			{
				var a = Helper.GenerateBigInteger(2, n - 2);
				var x = BigInteger.ModPow(a, t, n);
				if (x == BigInteger.One || x == n - BigInteger.One) continue;
				for (ulong j = 0; j < s - 1; j++)
				{
					x = BigInteger.ModPow(x, 2, n);
					if (x == BigInteger.One) return false;
					if (x == n - 1) break;
				}

				if (x != n - 1) return false;
			}

			return true;
		}
	}
}