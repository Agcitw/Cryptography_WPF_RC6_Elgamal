using System;
using System.Numerics;
using CryptoModule2.Models.Ciphers.Parameters;

namespace CryptoModule2.Models.Ciphers.Keys
{
	public class ElgamalKey
	{
		public readonly int MaxCipherTextSize;
		public readonly int MaxOpenTextSize;

		private ElgamalKey(bool isPrivate, BigInteger key, ElgamalParameters parameters)
		{
			IsPrivate = isPrivate;
			Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
			if (key < 2) throw new ArgumentException("Bad key");
			switch (isPrivate)
			{
				case true when key >= parameters.P - BigInteger.One:
					throw new ArgumentException("key <= P - 1");
				case false when key >= parameters.P:
					throw new ArgumentException("key <= P");
			}

			var modulusByteCount = Parameters.P.ToByteArray(false).Length;
			MaxOpenTextSize = modulusByteCount - 1;
			MaxCipherTextSize = modulusByteCount;
			Key = key;
		}

		public ElgamalParameters Parameters { get; }
		public BigInteger Key { get; }
		public bool IsPrivate { get; }

		private static KeyPair GenerateKeyPair(ElgamalParameters parameters, BigInteger privateKeyInt)
		{
			return new(new ElgamalKey(false, BigInteger.ModPow(parameters.G, privateKeyInt, parameters.P), parameters),
				new ElgamalKey(true, privateKeyInt, parameters));
		}

		public static KeyPair GenerateKeyPair(ElgamalParameters parameters)
		{
			return GenerateKeyPair(parameters, Helper.GenerateBigInteger(2, parameters.P - BigInteger.One));
		}
	}
}