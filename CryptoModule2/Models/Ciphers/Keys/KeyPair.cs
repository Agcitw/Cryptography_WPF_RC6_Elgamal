using System;

namespace CryptoModule2.Models.Ciphers.Keys
{
	public readonly struct KeyPair
	{
		public KeyPair(ElgamalKey publicKey, ElgamalKey privateKey)
		{
			PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
			PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
		}

		public ElgamalKey PublicKey { get; }
		public ElgamalKey PrivateKey { get; }
	}
}