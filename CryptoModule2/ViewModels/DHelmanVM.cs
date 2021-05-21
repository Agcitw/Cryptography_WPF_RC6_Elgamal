using CryptoModule2.Models.Ciphers;
using CryptoModule2.Models.Ciphers.Keys;
using CryptoModule2.Models.Ciphers.Parameters;
using CryptoModule2.ViewModels.Interfaces;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace CryptoModule2.ViewModels
{
    public class DHelmanVM : BindableBase, ICipherVM
    {

        public DHParameters PublicParameters { get; set; } = DHParameters.Generate( 30 );

        private string _alicePrivateKey = "";
        private string _alicePublicKey = "";

        private string _bobPrivateKey = "";
        private string _bobPublicKey = "";



        public string AlicePrivateKey
        {
            get => _alicePrivateKey;
            set
            {
                _alicePrivateKey = value;
                RaisePropertyChanged( nameof( AlicePrivateKey ) );
                AlicePublicKey = "";

            }
        }

        public string AlicePublicKey
        {
            get => _alicePublicKey;
            set
            {
                _alicePublicKey = value;
                RaisePropertyChanged( nameof( AlicePublicKey ) );

            }
        }

        public string BobPrivateKey
        {
            get => _bobPrivateKey;
            set
            {
                _bobPrivateKey = value;
                RaisePropertyChanged( nameof( BobPrivateKey ) );
                BobPublicKey = "";

            }
        }

        public string BobPublicKey
        {
            get => _bobPublicKey;
            set
            {
                _bobPublicKey = value;
                RaisePropertyChanged( nameof( BobPublicKey ) );
            }
        }


        public string Key { get; private set; } = "";




        public DelegateCommand GeneratePublicParameters { get; }
        public DelegateCommand CalcKey { get; }

        public DelegateCommand<bool?> GeneratePublicKey { get; }
        public DelegateCommand<bool?> GenerateKey { get; }

        public DHelmanVM()
        {

            GeneratePublicParameters = new DelegateCommand( () =>
            {
                Random rand = new Random();
                PublicParameters = DHParameters.Generate( rand.Next( 7, 30 ) );
                ClearForm();
            } );

            GenerateKey = new DelegateCommand<bool?>( isAlice =>
            {
                var keyPair = new DHKey( PublicParameters );
                if( isAlice == true )
                {
                    AlicePrivateKey = keyPair.X.ToString();
                    AlicePublicKey = keyPair.Y.ToString();
                }
                else
                {
                    BobPrivateKey = keyPair.X.ToString();
                    BobPublicKey = keyPair.Y.ToString();
                }
            } );

            GeneratePublicKey = new DelegateCommand<bool?>( isAlice =>
            {
                try
                {
                    string privateKey = isAlice == true ? AlicePrivateKey : BobPrivateKey;

                    BigInteger x;
                    if( !BigInteger.TryParse( privateKey, out x ) )
                    {
                        throw new Exception( "Ошибка в приватном ключе" );
                    }

                    var key = new DHKey( PublicParameters, x );


                    if( isAlice == true )
                    {
                        AlicePublicKey = key.Y.ToString();
                    }
                    else
                    {
                        BobPublicKey = key.Y.ToString();
                    }

                }
                catch( Exception ex )
                {
                    MessageBox.Show( ex.Message );
                }
            } );

            CalcKey = new DelegateCommand( () =>
            {
                if( string.IsNullOrEmpty( AlicePublicKey ) )
                {
                    MessageBox.Show( "Посчитайте публичный ключ Алисы" );
                    return;
                }
                if( string.IsNullOrEmpty( BobPublicKey ) )
                {
                    MessageBox.Show( "Посчитайте публичный ключ Боба" );
                    return;
                }

                try
                {
                    BigInteger x1 = BigInteger.Parse( AlicePrivateKey );
                    BigInteger x2 = BigInteger.Parse( BobPrivateKey );

                    DHKey aliceKey = new DHKey( PublicParameters, x1 );
                    DHKey bobKey = new DHKey( PublicParameters, x2 );

                    BigInteger result = aliceKey.CalcSecret( bobKey.Y );

                    Key = result.ToString();
                    RaisePropertyChanged( nameof( Key ) );

                }
                catch( Exception ex )
                {
                    MessageBox.Show( ex.Message );
                }
            } );

        }

        public void ClearForm()
        {
            RaisePropertyChanged( nameof( PublicParameters ) );
            AlicePublicKey = "";
            AlicePrivateKey = "";
            BobPrivateKey = "";
            BobPublicKey = "";
        }
    }
}
