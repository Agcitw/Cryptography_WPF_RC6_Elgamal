using System;
using System.Numerics;

namespace CryptoModule2.Models.Ciphers.Parameters
{
	public class ElgamalParameters
	{
		private ElgamalParameters(BigInteger p, BigInteger g)
		{
			P = p;
			G = g;
		}

		public BigInteger P { get; }
		public BigInteger G { get; }

		public static ElgamalParameters Generate(int decimalOrder)
		{
			if (decimalOrder < 6) throw new ArgumentException("So small");

			BigInteger p, q, g;
			while (true)
			{
				q = Helper.GenerateBigInteger(BigInteger.Pow(10, decimalOrder), BigInteger.Pow(10, decimalOrder + 1));
				if (!q.IsPrimeMillerRabin()) continue;
				p = (q << 1) + BigInteger.One;
				if (p.IsPrimeMillerRabin()) break;
			}

			do
			{
				g = Helper.GenerateBigInteger(2, p - BigInteger.One);
			} while (BigInteger.ModPow(g, 2, p) == BigInteger.One ||
			         BigInteger.ModPow(g, q, p) == BigInteger.One);

			return new ElgamalParameters(p, g);
		}
	}
}