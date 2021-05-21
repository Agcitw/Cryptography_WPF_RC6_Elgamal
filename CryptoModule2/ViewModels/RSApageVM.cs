using CryptoModule2.Models.Ciphers;
using CryptoModule2.Models.Ciphers.Asymmetric;
using CryptoModule2.Models.Ciphers.Keys;
using CryptoModule2.ViewModels.Interfaces;
using Microsoft.Win32;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace CryptoModule2.ViewModels
{
    class RSApageVM : BindableBase, ICipherVM
    {


        #region Binding properties

        #region fields
        private string _inputText = "";
        private string _outputText = "";

        private string _p = "";
        private string _q = "";

        private string _modulus = "";
        private string _publicExponent = "";
        private string _privateExponent = "";

        private bool _isDoingCipher = false;

        private double _currentProgress = 0.0f;

        #endregion

        public string InputText
        {
            get => _inputText;
            set
            {
                _inputText = value;
                RaisePropertyChanged( nameof( InputText ) );
            }
        }
        public string OutputText
        {
            get => _outputText;
            set
            {
                _outputText = value;
                RaisePropertyChanged( nameof( OutputText ) );
            }
        }
        public string P
        {
            get => _p;
            set
            {
                _p = value;
                RaisePropertyChanged( nameof( P ) );
            }
        }
        public string Q
        {
            get => _q;
            set
            {
                _q = value;
                RaisePropertyChanged( nameof( Q ) );
            }
        }

        public string Modulus
        {
            get => _modulus;
            set
            {
                _modulus = value;
                RaisePropertyChanged( nameof( Modulus ) );
            }
        }
        public string PublicExponent
        {
            get => _publicExponent;
            set
            {
                _publicExponent = value;
                RaisePropertyChanged( nameof( PublicExponent ) );
            }
        }
        public string PrivateExponent
        {
            get => _privateExponent;
            set
            {
                _privateExponent = value;
                RaisePropertyChanged( nameof( PrivateExponent ) );
            }
        }

        public bool IsDoingCipher
        {
            get => _isDoingCipher;
            set
            {
                _isDoingCipher = value;
                RaisePropertyChanged( nameof( IsDoingCipher ) );
            }
        }

        public double CurrentProgress
        {
            get => _currentProgress;
            set
            {
                _currentProgress = value;
                RaisePropertyChanged( nameof( CurrentProgress ) );
            }
        }

        #endregion


        #region Private fields

        private RSA _rsa = new RSA();

        #endregion

        #region Buttons handlers

        public DelegateCommand GenerateCommand { get; }


        public DelegateCommand ConvertKeyCommand { get; }

        public DelegateCommand EncryptCommand { get; }

        public DelegateCommand DecryptCommand { get; }

        public DelegateCommand EncryptFileCommand { get; }

        public DelegateCommand DecryptFileCommand { get; }

        #endregion


        public RSApageVM()
        {
            #region Buttons handlers

            EncryptFileCommand = new DelegateCommand( () =>
            {
                try
                {
                    OpenFileDialog openFileDialog = new OpenFileDialog();
                    if( openFileDialog.ShowDialog() == true )
                    {
                        string inputPath = openFileDialog.FileName;
                        string outputPath = openFileDialog.FileName + ".enc";

                        RSAKey key = GetPublicKey();

                        IsDoingCipher = true;
                        Thread thread = new Thread( () =>
                         {
                             _rsa.Encrypt( inputPath, outputPath, key, percent =>
                             {
                                 CurrentProgress = percent;
                             } );
                             CurrentProgress = 100f;

                             MessageBox.Show( "Файл успешно зашифрован" );
                             IsDoingCipher = false;
                             CurrentProgress = 0f;

                         } );
                        thread.Start();
                    }
                }
                catch( Exception )
                {
                    MessageBox.Show( "Ошибка! Проверьте входные параметры" );
                }

            } );

            DecryptFileCommand = new DelegateCommand( () =>
            {
                try
                {
                    OpenFileDialog openFileDialog = new OpenFileDialog();
                    SaveFileDialog saveFileDialog = new SaveFileDialog();

                    if( openFileDialog.ShowDialog() == true )
                    {
                        string inputPath = openFileDialog.FileName;
                        if( saveFileDialog.ShowDialog() == true )
                        {
                            string outputPath = saveFileDialog.FileName;

                            RSAKey key = GetPrivateKey();

                            IsDoingCipher = true;
                            Thread thread = new Thread( () =>
                            {
                                _rsa.Decrypt( inputPath, outputPath, key, percent =>
                                {
                                    CurrentProgress = percent;
                                } );
                                CurrentProgress = 100f;

                                MessageBox.Show( "Файл успешно расшифрован" );
                                IsDoingCipher = false;
                                CurrentProgress = 0f;

                            } );
                            thread.Start();
                        }

                    }
                }
                catch( Exception )
                {
                    MessageBox.Show( "Ошибка! Проверьте входные параметры" );
                }

            } );

            GenerateCommand = new DelegateCommand( () =>
            {
                try
                {
                    BigInteger p;
                    BigInteger q;

                    AsymmetricCipherKeyPair keyPair = RSAKey.GenerateKey( 60, out p, out q );

                    RSAKey publicKey = keyPair.PublicKey as RSAKey;
                    PublicExponent = publicKey.Exponent.ToString();

                    RSAKey privateKey = keyPair.PrivateKey as RSAKey;
                    PrivateExponent = privateKey.Exponent.ToString();

                    Modulus = publicKey.Modulus.ToString();
                    P = p.ToString();
                    Q = q.ToString();

                }
                catch( Exception ex )
                {
                    MessageBox.Show( ex.Message );
                }
            } );

            ConvertKeyCommand = new DelegateCommand( () =>
            {
                BigInteger p;
                BigInteger q;
                if( !BigInteger.TryParse( P, out p ) )
                {
                    MessageBox.Show( "Введите корректное значения P" );
                    return;
                }
                if( !BigInteger.TryParse( Q, out q ) )
                {
                    MessageBox.Show( "Введите корректное значения Q" );
                    return;
                }

                try
                {
                    AsymmetricCipherKeyPair keyPair = RSAKey.GenerateKey( p, q );

                    RSAKey publicKey = keyPair.PublicKey as RSAKey;
                    PublicExponent = publicKey.Exponent.ToString();

                    RSAKey privateKey = keyPair.PrivateKey as RSAKey;
                    PrivateExponent = privateKey.Exponent.ToString();

                    Modulus = publicKey.Modulus.ToString();

                }
                catch( Exception ex )
                {
                    MessageBox.Show( ex.Message );
                }
            } );

            EncryptCommand = new DelegateCommand( () =>
            {
                if( string.IsNullOrEmpty( InputText ) )
                {
                    MessageBox.Show( "Введите текст" );
                    return;
                }

                try
                {
                    RSAKey key = GetPublicKey();
                    byte[] result = _rsa.Encrypt( Encoding.Default.GetBytes( InputText ), key );
                    OutputText = BitConverter.ToString( result ).Replace( "-", string.Empty );
                }
                catch( Exception ex )
                {

                    MessageBox.Show( ex.Message );
                }

            } );

            DecryptCommand = new DelegateCommand( () =>
            {
                if( string.IsNullOrEmpty( InputText ) )
                {
                    MessageBox.Show( "Введите текст" );
                    return;
                }
                Regex regex = new Regex( "^[0-9A-F]{1,}$", RegexOptions.IgnoreCase );
                if( !regex.IsMatch( InputText ) || ( InputText.Length % 2 == 1 ) )
                {
                    MessageBox.Show( "Неверная строка HEX" );
                    return;
                }

                try
                {

                    RSAKey key = GetPrivateKey();

                    byte[] input = Enumerable.Range( 0, InputText.Length )
                     .Where( x => x % 2 == 0 )
                     .Select( x => Convert.ToByte( InputText.Substring( x, 2 ), 16 ) )
                     .ToArray();

                    byte[] result = _rsa.Decrypt( input, key );
                    OutputText = Encoding.Default.GetString( result );
                }
                catch( Exception ex )
                {

                    MessageBox.Show( ex.Message );
                }



            } );

            #endregion
        }

        public void ClearForm()
        {
            InputText = "";
            OutputText = "";
            P = "";
            Q = "";
            Modulus = "";
            PublicExponent = "";
            PrivateExponent = "";
        }

        private RSAKey GetPrivateKey()
        {
            return new RSAKey( true, PrivateExponent, Modulus );
        }

        private RSAKey GetPublicKey()
        {
            return new RSAKey( false, PublicExponent, Modulus );
        }
    }
}
