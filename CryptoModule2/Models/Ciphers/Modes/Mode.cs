using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CryptoModule2.Models.Ciphers.Symmetric;

namespace CryptoModule2.Models.Ciphers.Modes
{
	internal class Mode
	{
		public static List<byte> TextBefore = new();
		public static List<byte> TextAfter = new();
		public static byte[] Iv = GenerateIv(16);
		private readonly Rc6 _algorithm;

		public Mode(Rc6 algorithm)
		{
			_algorithm = algorithm;
		}

		public static void UpdateIv(int size)
		{
			Iv = GenerateIv(size);
		}
		private static byte[] GenerateIv(int size)
		{
			var b = new byte[size];
			new Random().NextBytes(b);
			return b;
		}

		private byte[] ExpandData(ref byte[] data)
		{
			if (data.Length % 16 == 0) return data;
			var addByte = new List<byte>();
			for (var i = 0; i < 16 - data.Length % 16; i++)
				addByte.Add(0);
			data = data.Concat(addByte.ToArray()).ToArray();
			return data;
		}

		public async Task<byte[]> EncryptEcb(byte[] data)
		{
			ExpandData(ref data);
			var result = new List<byte>();
			for (var i = 0; i < data.Length; i += Rc6.Size)
			{
				await Task.Run(() => result.AddRange(_algorithm.EncryptBlock(data.Skip(i).Take(Rc6.Size).ToArray())));
			}
			TextAfter = result;
			return result.ToArray();
		}
		public async Task<byte[]> DecryptEcb(byte[] blocks)
		{
			ExpandData(ref blocks);
			var result = new List<byte>();
			for (var i = 0; i < blocks.Length; i += Rc6.Size)
			{
				await Task.Run(() => result.AddRange(_algorithm.DecryptBlock(blocks.Skip(i).Take(Rc6.Size).ToArray())));
			}
			TextBefore = result;
			return result.ToArray();
		}

		public async Task<byte[]> EncryptCbc(byte[] message)
		{
			var messageCopy = ExpandData(ref message);
			var result = new List<byte>();
			var prev = Iv;
			for (var i = 0; i < messageCopy.Length; i += Rc6.Size)
			{
				for (var j = 0; j < Rc6.Size; j++)
					messageCopy[j] ^= prev[j];
				await Task.Run(() => result.AddRange(_algorithm.EncryptBlock(message.Skip(i).Take(Rc6.Size).ToArray())));
				prev = result.Skip(i).Take(Rc6.Size).ToArray();
			}

			TextAfter = result;
			return result.ToArray();
		}
		public async Task<byte[]> DecryptCbc(byte[] code)
		{
			var messageCopy = (byte[]) code.Clone();
			var result = new List<byte>();
			var prev = Iv;
			for (var i = 0; i < messageCopy.Length; i += Rc6.Size)
			{
				for (var j = 0; j < Rc6.Size; j++)
					messageCopy[i + j] ^= prev[j];
				await Task.Run(() => result.AddRange(_algorithm.DecryptBlock(code.Skip(i).Take(Rc6.Size).ToArray())));
				prev = result.Skip(i).Take(Rc6.Size).ToArray();
			}

			TextBefore = result;
			return result.ToArray();
		}

		public async Task<byte[]> EncryptCfb(byte[] message)
		{
			var messageCopy = ExpandData(ref message);
			var result = new List<byte>();
			var prev = Iv;
			for (var i = 0; i < messageCopy.Length; i += Rc6.Size)
			{
				await Task.Run(() => result.AddRange(_algorithm.EncryptBlock(prev)));
				for (var j = 0; j < Rc6.Size; j++)
					result[i + j] ^= messageCopy[j];
				prev = result.Skip(i).Take(Rc6.Size).ToArray();
			}

			TextAfter = result;
			return result.ToArray();
		}
		public async Task<byte[]> DecryptCfb(byte[] code)
		{
			var messageCopy = ExpandData(ref code);
			var result = new List<byte>();
			var prev = Iv;
			for (var i = 0; i < code.Length; i += Rc6.Size)
			{
				await Task.Run(() => result.AddRange(_algorithm.DecryptBlock(prev)));
				for (var j = 0; j < Rc6.Size; j++)
					result[i + j] ^= messageCopy[j];
				prev = messageCopy.Skip(i).Take(Rc6.Size).ToArray();
			}

			TextBefore = result;
			return result.ToArray();
		}

		public async Task<byte[]> EncryptOfb(byte[] message)
		{
			var messageCopy = ExpandData(ref message);
			var result = new List<byte>();
			var prev = Iv;
			for (var i = 0; i < message.Length; i += Rc6.Size)
			{
				await Task.Run(() => result.AddRange(_algorithm.EncryptBlock(prev)));
				prev = result.Skip(i).Take(Rc6.Size).ToArray();
				for (var j = 0; j < Rc6.Size; j++)
					result[i + j] ^= messageCopy[i + j];
			}

			TextAfter = result;
			return result.ToArray();
		}
		public async Task<byte[]> DecryptOfb(byte[] code)
		{
			return await Task.Run(() => EncryptOfb(code));
		}
	}
}