using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using CryptoModule2.Models;
using CryptoModule2.Models.Ciphers.Modes;
using CryptoModule2.Models.Ciphers.Symmetric;
using CryptoModule2.ViewModels.Command;
using Microsoft.Win32;

namespace CryptoModule2.Views
{
	public enum CipherMode
	{
		Ecb,
		Cbc,
		Cfb,
		Ofb
	}

	public partial class MainWindow
	{
		private Mode _encryptionMode;
		private string _filePath;
		private string _key;
		private int _keyLength = 128;
		private CipherMode _mode = CipherMode.Ecb;
		private ICommand _radioCommand;
		private Rc6 _rc6;
		private byte[] _userFile;

		public MainWindow()
		{
			InitializeComponent();
			UpdateKey();
			Mode.UpdateIv(_keyLength / 8);
			Key128.IsChecked = true;
		}

		public ICommand RadioCommand => _radioCommand ??= new RelayCommand(parameter =>
		{
			_mode = parameter.ToString() switch
			{
				"EBC" => CipherMode.Ecb,
				"CBC" => CipherMode.Cbc,
				"CFB" => CipherMode.Cfb,
				"OFB" => CipherMode.Ofb,
				_ => throw new ArgumentOutOfRangeException()
			};
		});

		private string Iv
		{
			set => IvTextBox.Password = value;
		}

		private void ChooseFile(object sender, RoutedEventArgs e)
		{
			var ofb = new OpenFileDialog();
			if (ofb.ShowDialog() == true)
				_filePath = ofb.FileName;
			FileName.Text = _filePath;
		}

		private static void DoWork(object sender, DoWorkEventArgs e)
		{
			for (var i = 0; i < 100; i++)
			{
				(sender as BackgroundWorker)?.ReportProgress(i);
				Thread.Sleep(10);
			}
		}

		private void ProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			ProgressBar.Value = e.ProgressPercentage;
		}

		private void Encrypt(object sender, RoutedEventArgs e)
		{
			var worker = new BackgroundWorker();
			worker.DoWork += DoWork;
			worker.ProgressChanged += ProgressChanged;
			worker.WorkerReportsProgress = true;
			worker.WorkerSupportsCancellation = true;
			var reading = Task.Run(() => { _userFile = File.ReadAllBytes(_filePath); });
			worker.RunWorkerAsync();
			reading.Wait();
			_rc6 = _key.Length == _keyLength ? new Rc6(_keyLength, Encoding.UTF8.GetBytes(_key)) : new Rc6(_keyLength);
			_encryptionMode = new Mode(_rc6);
			Task k = _mode switch
			{
				CipherMode.Cbc => _encryptionMode.EncryptCbc(_userFile),
				CipherMode.Cfb => _encryptionMode.EncryptCfb(_userFile),
				CipherMode.Ofb => _encryptionMode.EncryptOfb(_userFile),
				CipherMode.Ecb => _encryptionMode.EncryptEcb(_userFile),
				_ => throw new ArgumentOutOfRangeException()
			};
			new Thread(() => {
				k.Wait();
				File.WriteAllBytes(_filePath + ".enc", Mode.TextAfter.ToArray());
			}).Start();
		}

		private void Decrypt(object sender, RoutedEventArgs e)
		{
			var worker = new BackgroundWorker();
			worker.DoWork += DoWork;
			worker.ProgressChanged += ProgressChanged;
			worker.WorkerReportsProgress = true;
			worker.WorkerSupportsCancellation = true;
			var reading = Task.Run(() => { _userFile = File.ReadAllBytes(_filePath); });
			ProgressBar.Value++;
			worker.RunWorkerAsync();
			reading.Wait();
			Task d = _mode switch
			{
				CipherMode.Cbc => _encryptionMode.DecryptCbc(_userFile),
				CipherMode.Cfb => _encryptionMode.DecryptCfb(_userFile),
				CipherMode.Ofb => _encryptionMode.DecryptOfb(_userFile),
				CipherMode.Ecb => _encryptionMode.DecryptEcb(_userFile),
				_ => throw new ArgumentOutOfRangeException()
			};
			new Thread(() => {
				d.Wait();
				File.WriteAllBytes(_filePath + ".dec", Mode.TextBefore.ToArray());
			}).Start();
		}

		private void UpdateKey_OnClick(object sender, RoutedEventArgs e)
		{
			UpdateKey();
		}

		private void UpdateKey()
		{
			_key = Helper.GenerateRandomKey(_keyLength / 8);
			KeyTextBox.Password = _key;
			Mode.UpdateIv(_keyLength / 8);
			Iv = Encoding.UTF8.GetString(Mode.Iv);
		}

		private void KeyChecked_OnChecked(object sender, RoutedEventArgs e)
		{
			if (Key128.IsChecked == true) _keyLength = 128;
			if (Key192.IsChecked == true) _keyLength = 192;
			if (Key256.IsChecked == true) _keyLength = 256;
		}

		private void ShowPasswordCheck_OnChecked(object sender, RoutedEventArgs e)
		{
			MessageBox.Show("Password: " + KeyTextBox.Password + '\n' + "Iv: " + IvTextBox.Password, "Passwords", MessageBoxButton.OK, MessageBoxImage.Information);
		}
	}
}