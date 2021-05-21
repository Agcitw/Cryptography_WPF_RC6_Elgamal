using System;
using System.Text;
using System.Threading;
using System.Windows;
using CryptoModule2.Models.Ciphers.Asymmetric;
using CryptoModule2.Models.Ciphers.Keys;
using CryptoModule2.Models.Ciphers.Parameters;
using Microsoft.Win32;
using Prism.Commands;
using Prism.Mvvm;

namespace CryptoModule2.ViewModels
{
	public class ElgamalVm : BindableBase
	{
		private readonly Random _rand = new();
		private KeyPair _aliceKey;
		private string _aliceText = "";
		private KeyPair _bobKey;
		private string _bobText = "";
		private string _cipherText = "";
		private double _currentProgress;
		private bool _isDoingCipher;
		private ElgamalParameters _parameters;

		public ElgamalVm()
		{
			GenerateAll();
			GenerateParametersCommand = new DelegateCommand(GenerateAll);
			GenerateKeyCommand = new DelegateCommand<bool?>(isAlice =>
			{
				switch (isAlice)
				{
					case true:
						AliceKey = ElgamalKey.GenerateKeyPair(Parameters);
						break;
					case false:
						BobKey = ElgamalKey.GenerateKeyPair(Parameters);
						break;
				}
			});
			SendMessageCommand = new DelegateCommand<bool?>(isAlice =>
			{
				try
				{
					string text;
					KeyPair key;
					if (isAlice == true)
					{
						text = AliceText;
						key = BobKey;
					}
					else
					{
						text = BobText;
						key = AliceKey;
					}

					var openBlock = Encoding.Default.GetBytes(text);
					var cipherBlock = Elgamal.Encrypt(openBlock, key.PublicKey);
					var gotBlock = Elgamal.Decrypt(cipherBlock, key.PrivateKey);
					CipherText = BitConverter.ToString(cipherBlock).Replace("-", string.Empty);
					switch (isAlice)
					{
						case true:
							BobText = Encoding.Default.GetString(gotBlock);
							break;
						case false:
							AliceText = Encoding.Default.GetString(gotBlock);
							break;
					}
				}
				catch (Exception ex)
				{
					MessageBox.Show(ex.Message);
				}
			});
			EncryptFileCommand = new DelegateCommand<bool?>(isAlice =>
			{
				var openFileDialog = new OpenFileDialog();
				if (openFileDialog.ShowDialog() != true) return;
				var inputPath = openFileDialog.FileName;
				var outputPath = openFileDialog.FileName.Split('.')[0] + "(enc)." +
				                 openFileDialog.FileName.Split('.')[1];
				var key = isAlice == true ? BobKey.PublicKey : AliceKey.PublicKey;
				new Thread(() =>
				{
					Elgamal.Encrypt(inputPath, outputPath, key, percent => { CurrentProgress = percent; });
					CurrentProgress = 100f;
					MessageBox.Show("File: " + inputPath + "\n" + "Encrypted file: " + outputPath,
						"File encryption completed", MessageBoxButton.OK, MessageBoxImage.Information);
					CurrentProgress = 0f;
				}).Start();
			});
			DecryptFileCommand = new DelegateCommand<bool?>(isAlice =>
			{
				var openFileDialog = new OpenFileDialog();
				var saveFileDialog = new SaveFileDialog();
				if (openFileDialog.ShowDialog() != true) return;
				var inputPath = openFileDialog.FileName;
				if (saveFileDialog.ShowDialog() != true) return;
				var outputPath = saveFileDialog.FileName;
				var key = isAlice == true ? AliceKey.PrivateKey : BobKey.PrivateKey;
				new Thread(() =>
				{
					Elgamal.Decrypt(inputPath, outputPath, key, percent => { CurrentProgress = percent; });
					CurrentProgress = 100f;
					MessageBox.Show("File: " + inputPath + "\n" + "Decrypted file: " + outputPath,
						"File encryption completed", MessageBoxButton.OK, MessageBoxImage.Information);
					CurrentProgress = 0f;
				}).Start();
			});
		}

		public ElgamalParameters Parameters
		{
			get => _parameters;
			private set
			{
				_parameters = value;
				RaisePropertyChanged(nameof(Parameters));
				ClearForm();
			}
		}

		public KeyPair AliceKey
		{
			get => _aliceKey;
			private set
			{
				_aliceKey = value;
				RaisePropertyChanged(nameof(AliceKey));
				ClearForm();
			}
		}

		public KeyPair BobKey
		{
			get => _bobKey;
			private set
			{
				_bobKey = value;
				RaisePropertyChanged(nameof(BobKey));
				ClearForm();
			}
		}

		public string AliceText
		{
			get => _aliceText;
			set
			{
				_aliceText = value;
				RaisePropertyChanged(nameof(AliceText));
			}
		}

		public string BobText
		{
			get => _bobText;
			set
			{
				_bobText = value;
				RaisePropertyChanged(nameof(BobText));
			}
		}

		public string CipherText
		{
			get => _cipherText;
			set
			{
				_cipherText = value;
				RaisePropertyChanged(nameof(CipherText));
			}
		}

		public double CurrentProgress
		{
			get => _currentProgress;
			set
			{
				_currentProgress = value;
				RaisePropertyChanged(nameof(CurrentProgress));
			}
		}

		public bool IsDoingCipher
		{
			get => _isDoingCipher;
			set
			{
				_isDoingCipher = value;
				RaisePropertyChanged(nameof(IsDoingCipher));
			}
		}

		public DelegateCommand GenerateParametersCommand { get; }
		public DelegateCommand<bool?> GenerateKeyCommand { get; }
		public DelegateCommand<bool?> SendMessageCommand { get; }
		public DelegateCommand<bool?> EncryptFileCommand { get; }
		public DelegateCommand<bool?> DecryptFileCommand { get; }

		private void ClearForm()
		{
			AliceText = "";
			BobText = "";
			CipherText = "";
		}

		private void GenerateAll()
		{
			Parameters = ElgamalParameters.Generate(_rand.Next(20, 40));
			AliceKey = ElgamalKey.GenerateKeyPair(Parameters);
			BobKey = ElgamalKey.GenerateKeyPair(Parameters);
		}
	}
}