using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Windows;
using CryptoModule2.Models.Ciphers.Keys;

namespace CryptoModule2.Models.Ciphers.Asymmetric
{
	public static class Elgamal
	{
		public static byte[] Encrypt(byte[] text, ElgamalKey key = null)
		{
			if (text.Length == 0 || text == null || text.All(b => b == 0)) throw new ArgumentException("Null data");
			var result = new List<byte>(text.Length);
			try
			{
				if (key != null)
				{
					var readSize = key.MaxOpenTextSize;
					var writeSize = key.MaxCipherTextSize;
					var k = Helper.GenerateBigInteger(2, key.Parameters.P - 3);
					var r = BigInteger.ModPow(key.Parameters.G, k, key.Parameters.P);
					var packedBlock = new byte[writeSize];
					var rBlock = r.ToByteArray(false);
					Buffer.BlockCopy(rBlock, 0, packedBlock, 0, rBlock.Length);
					result.AddRange(packedBlock);
					for (var currentByte = 0; currentByte < text.Length; currentByte += readSize)
					{
						var byteCopyCount = Math.Min(readSize, text.Length - currentByte);
						var currentBlock = new byte[byteCopyCount + 1];
						Buffer.BlockCopy(text, currentByte, currentBlock, 0, byteCopyCount);
						var openInt = new BigInteger(currentBlock);
						var cipherInt = BigInteger.ModPow(key.Key, k, key.Parameters.P);
						BigInteger.DivRem(openInt * cipherInt, key.Parameters.P, out cipherInt);
						var cipherBlock = cipherInt.ToByteArray(false);
						packedBlock = new byte[writeSize];
						Buffer.BlockCopy(cipherBlock, 0, packedBlock, 0, cipherBlock.Length);
						result.AddRange(packedBlock);
					}
				}
			}
			catch (Exception ex)
			{
				throw new Exception("Bad parameters", ex);
			}

			return result.ToArray();
		}

		public static byte[] Decrypt(byte[] text, ElgamalKey key = null)
		{
			if (text.Length == 0 || text == null || text.All(b => b == 0)) throw new ArgumentException("Null data");
			var result = new List<byte>(text.Length);
			try
			{
				if (key != null)
				{
					var readSize = key.MaxCipherTextSize;
					var writeSize = key.MaxOpenTextSize;
					var rBlock = new byte[readSize + 1];
					Buffer.BlockCopy(text, 0, rBlock, 0, readSize);
					var r = new BigInteger(rBlock);
					var decryptConst = BigInteger.ModPow(r, key.Parameters.P - 1 - key.Key, key.Parameters.P);
					for (var currentByte = readSize; currentByte < text.Length; currentByte += readSize)
					{
						var byteCopyCount = Math.Min(readSize, text.Length - currentByte);
						var currentBlock = new byte[byteCopyCount + 1];
						Buffer.BlockCopy(text, currentByte, currentBlock, 0, byteCopyCount);
						var cipherInt = new BigInteger(currentBlock);
						BigInteger.DivRem(cipherInt * decryptConst, key.Parameters.P, out var openInt);
						var openBlock = openInt.ToByteArray(false);
						var packedBlock = new byte[writeSize];
						Buffer.BlockCopy(openBlock, 0, packedBlock, 0, openBlock.Length);
						result.AddRange(packedBlock);
					}
				}
			}
			catch (Exception ex)
			{
				throw new Exception("Bad parameters", ex);
			}

			return result.ToArray();
		}

		public static void Encrypt(string inputPath, string outputPath, ElgamalKey key,
			Action<double> progressChanged = null)
		{
			if (key.IsPrivate) throw new ArgumentException("need key");
			try
			{
				using var inputStream = File.OpenRead(inputPath);
				using var outputStream = File.Open(outputPath, FileMode.Create);
				var fileSize = inputStream.Length;
				var readSize = key.MaxOpenTextSize * 1024;
				var inputChunk = new byte[readSize];
				int size;
				while ((size = inputStream.Read(inputChunk, 0, readSize)) != 0)
				{
					byte[] currentBlock;
					if (size == readSize)
					{
						currentBlock = inputChunk;
					}
					else
					{
						currentBlock = new byte[size];
						Buffer.BlockCopy(inputChunk, 0, currentBlock, 0, size);
					}

					var outputChunk = Encrypt(currentBlock, key);
					outputStream.Write(outputChunk, 0, outputChunk.Length);
					var percent = (int) (inputStream.Position * 100f / fileSize);
					progressChanged?.Invoke(percent);
				}
			}
			catch (IOException)
			{
				MessageBox.Show("This file using another process", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		public static void Decrypt(string inputPath, string outputPath, ElgamalKey key,
			Action<double> progressChanged = null)
		{
			if (!key.IsPrivate) throw new ArgumentException("need key");
			try
			{
				using var inputStream = File.OpenRead(inputPath);
				using var outputStream = File.Open(outputPath, FileMode.Create);
				var fileSize = inputStream.Length;
				var readSize = key.MaxCipherTextSize * 1024 + key.MaxCipherTextSize;
				var inputChunk = new byte[readSize];
				int size;
				while ((size = inputStream.Read(inputChunk, 0, readSize)) != 0)
				{
					byte[] currentBlock;
					if (size == readSize)
					{
						currentBlock = inputChunk;
					}
					else
					{
						currentBlock = new byte[size];
						Buffer.BlockCopy(inputChunk, 0, currentBlock, 0, size);
					}

					var outputChunk = Decrypt(currentBlock, key);
					outputStream.Write(outputChunk, 0, outputChunk.Length);
					var percent = (int) (inputStream.Position * 100f / fileSize);
					progressChanged?.Invoke(percent);
				}
			}
			catch (IOException)
			{
				MessageBox.Show("This file using another process", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}
	}
}