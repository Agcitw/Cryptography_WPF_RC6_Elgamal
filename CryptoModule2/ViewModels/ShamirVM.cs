using CryptoModule2.Models.Ciphers.Asymmetric;
using CryptoModule2.Models.Ciphers.Keys;
using CryptoModule2.Models.Ciphers.Parameters;
using CryptoModule2.ViewModels.Interfaces;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace CryptoModule2.ViewModels
{
    public class ShamirVM : BindableBase, ICipherVM
    {
        private ShamirParameters _parameters;
        public ShamirParameters Parameters
        {
            get => _parameters;
            private set
            {
                _parameters = value;
                RaisePropertyChanged( nameof( Parameters ) );
                AliceKey = new ShamirKey( value );
                BobKey = new ShamirKey( value );
            }
        }

        private ShamirKey _aliceKey;
        public ShamirKey AliceKey
        {
            get => _aliceKey;
            private set
            {
                _aliceKey = value;
                RaisePropertyChanged( nameof( AliceKey ) );
                ClearOutput();
            }
        }

        private ShamirKey _bobKey;

        public ShamirKey BobKey
        {
            get => _bobKey;
            private set
            {
                _bobKey = value;
                RaisePropertyChanged( nameof( BobKey ) );
                ClearOutput();
            }
        }

        private string _aliceMessage = "";
        public string AliceMessage
        {
            get => _aliceMessage;
            set
            {
                _aliceMessage = value;
                RaisePropertyChanged( nameof( AliceMessage ) );
            }
        }

        private string _x1 = "";
        public string X1
        {
            get => _x1;
            private set
            {
                _x1 = value;
                RaisePropertyChanged( nameof( X1 ) );
            }
        }
        private string _x2 = "";
        public string X2
        {
            get => _x2;
            private set
            {
                _x2 = value;
                RaisePropertyChanged( nameof( X2 ) );
            }
        }

        private string _x3 = "";
        public string X3
        {
            get => _x3;
            private set
            {
                _x3 = value;
                RaisePropertyChanged( nameof( X3 ) );
            }
        }

        private string _x4 = "";
        public string X4
        {
            get => _x4;
            private set
            {
                _x4 = value;
                RaisePropertyChanged( nameof( X4 ) );
            }
        }

        public DelegateCommand GenerateParametersCommand { get; }
        public DelegateCommand<bool?> GenerateKeyCommand { get; }
        public DelegateCommand SendMessageCommand { get; }

        private Shamir _shamir = new Shamir();

        public ShamirVM()
        {
            Parameters = ShamirParameters.Generate();

            GenerateParametersCommand = new DelegateCommand( () =>
             {
                 Parameters = ShamirParameters.Generate();
             } );

            GenerateKeyCommand = new DelegateCommand<bool?>( isAlice =>
            {
                if( isAlice == true )
                {
                    AliceKey = new ShamirKey( Parameters );
                }
                else if( isAlice == false )
                {
                    BobKey = new ShamirKey( Parameters );
                }
            } );

            SendMessageCommand = new DelegateCommand( () =>
             {
                 if( string.IsNullOrEmpty(AliceMessage) )
                 {
                     MessageBox.Show( "Введите сообщение" );
                     return;
                 }

                 try
                 {
                     AliceKey.IsFirstTime = true;
                     BobKey.IsFirstTime = true;

                     byte[] openMessage = Encoding.Default.GetBytes( AliceMessage );

                     byte[] x1 = _shamir.Encrypt( openMessage, AliceKey, true );

                     AliceKey.IsFirstTime = false;
                     BobKey.IsFirstTime = false;

                     byte[] x2 = _shamir.Encrypt( x1, BobKey, false );
                     byte[] x3 = _shamir.Decrypt( x2, AliceKey, false );

                     AliceKey.IsFirstTime = true;
                     BobKey.IsFirstTime = true;

                     byte[] x4 = _shamir.Decrypt( x3, BobKey, true );

                     X1 = Encoding.Default.GetString( x1 );
                     X2 = Encoding.Default.GetString( x2 );
                     X3 = Encoding.Default.GetString( x3 );
                     X4 = Encoding.Default.GetString( x4 );

                 }
                 catch( Exception )
                 {
                     MessageBox.Show( "Ошибка! Проверьте входные параметры!" );
                     return;
                 }


             } );

        }


        private void ClearOutput()
        {
            X1 = "";
            X2 = "";
            X3 = "";
            X4 = "";
        }

        public void ClearForm()
        {
            ClearOutput();
        }
    }
}
