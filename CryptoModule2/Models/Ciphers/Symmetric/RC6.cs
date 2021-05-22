using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoModule2.Models.Ciphers.Symmetric
{
	public class Rc6
	{
		private const int Rounds = 20;
		private const int W = 32;
		private const uint P32 = 0xB7E15163;
		private const uint Q32 = 0x9E3779B9;
		private static readonly uint[] RoundKey = new uint[2 * Rounds + 4];
		private static byte[] _mainKey;
		
		public const int Size = 16;

		public Rc6(int keyLength)
		{
			GenerateKey(keyLength, null);
		}
		public Rc6(int keyLength, byte[] key)
		{
			GenerateKey(keyLength, key);
		}
		
		private static uint RightShift(uint value, int shift)
		{
			return (value >> shift) | (value << (W - shift));
		}
		private static uint LeftShift(uint value, int shift)
		{
			return (value << shift) | (value >> (W - shift));
		}

		private static void GenerateKey(int length, byte[] keyCheck)
		{
			_mainKey = keyCheck ?? Encoding.UTF8.GetBytes(Helper.GenerateRandomKey(length));
			var wordsCount = 0;
			int i, j;
			wordsCount = length switch
			{
				128 => 4,
				192 => 6,
				256 => 8,
				_ => wordsCount
			};
			var l = new uint[wordsCount];
			for (i = 0; i < wordsCount; i++)
				l[i] = BitConverter.ToUInt32(_mainKey, i * 4);
			RoundKey[0] = P32;
			for (i = 1; i < 2 * Rounds + 4; i++)
				RoundKey[i] = RoundKey[i - 1] + Q32;
			uint b;
			var a = b = 0;
			i = j = 0;
			var max = 3 * Math.Max(wordsCount, 2 * Rounds + 4);
			for (var s = 1; s <= max; s++)
			{
				a = RoundKey[i] = LeftShift(RoundKey[i] + a + b, 3);
				b = l[j] = LeftShift(l[j] + a + b, (int) (a + b));
				i = (i + 1) % (2 * Rounds + 4);
				j = (j + 1) % wordsCount;
			}
		}
		
		private static byte[] ToArrayBytes(IReadOnlyList<uint> uints, int length)
		{
			var arrayBytes = new byte[length * 4];
			for (var i = 0; i < length; i++)
			{
				var temp = BitConverter.GetBytes(uints[i]);
				temp.CopyTo(arrayBytes, i * 4);
			}

			return arrayBytes;
		}

		public IEnumerable<byte> EncryptBlock(byte[] byteText)
		{
			var textLength = byteText.Length;
			while (textLength % 16 != 0)
				textLength++;
			var text = new byte[textLength];
			byteText.CopyTo(text, 0);
			var cipherText = new byte[textLength];
			int i;
			for (i = 0; i < text.Length; i += 16)
			{
				var a = BitConverter.ToUInt32(text, i);
				var b = BitConverter.ToUInt32(text, i + 4);
				var c = BitConverter.ToUInt32(text, i + 8);
				var d = BitConverter.ToUInt32(text, i + 12);
				b += RoundKey[0];
				d += RoundKey[1];
				for (var j = 1; j <= Rounds; j++)
				{
					var t = LeftShift(b * (2 * b + 1), (int) Math.Log(W, 2));
					var u = LeftShift(d * (2 * d + 1), (int) Math.Log(W, 2));
					a = LeftShift(a ^ t, (int) u) + RoundKey[j * 2];
					c = LeftShift(c ^ u, (int) t) + RoundKey[j * 2 + 1];
					var temp = a;
					a = b;
					b = c;
					c = d;
					d = temp;
				}
				a += RoundKey[2 * Rounds + 2];
				c += RoundKey[2 * Rounds + 3];
				var tempWords = new[] {a, b, c, d};
				var block = ToArrayBytes(tempWords, 4);
				block.CopyTo(cipherText, i);
			}
			return cipherText;
		}
		public IEnumerable<byte> DecryptBlock(byte[] cipherText)
		{
			int i;
			var plainText = new byte[cipherText.Length];
			for (i = 0; i < cipherText.Length; i += 16)
			{
				var a = BitConverter.ToUInt32(cipherText, i);
				var b = BitConverter.ToUInt32(cipherText, i + 4);
				var c = BitConverter.ToUInt32(cipherText, i + 8);
				var d = BitConverter.ToUInt32(cipherText, i + 12);
				c -= RoundKey[2 * Rounds + 3];
				a -= RoundKey[2 * Rounds + 2];
				for (var j = Rounds; j >= 1; j--)
				{
					var temp = d;
					d = c;
					c = b;
					b = a;
					a = temp;
					var u = LeftShift(d * (2 * d + 1), (int) Math.Log(W, 2));
					var t = LeftShift(b * (2 * b + 1), (int) Math.Log(W, 2));
					c = RightShift(c - RoundKey[2 * j + 1], (int) t) ^ u;
					a = RightShift(a - RoundKey[2 * j], (int) u) ^ t;
				}
				d -= RoundKey[1];
				b -= RoundKey[0];
				var tempWords = new[] {a, b, c, d};
				var block = ToArrayBytes(tempWords, 4);
				block.CopyTo(plainText, i);
			}
			return plainText;
		}
	}
}