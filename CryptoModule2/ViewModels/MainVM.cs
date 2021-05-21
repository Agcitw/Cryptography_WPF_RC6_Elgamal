using CryptoModule2.Models.HashFunctions;
using CryptoModule2.Views.Pages;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace CryptoModule2.ViewModels
{
    class MainVM : BindableBase
    {
        private Page _currentPageContent;
        public Page CurrentPageContent
        {
            get
            {
                return _currentPageContent;
            }
            private set
            {
                _currentPageContent = value;
                RaisePropertyChanged( nameof( CurrentPageContent ) );
            }
        }

        private CipherForm _currentCipher;
        public CipherForm CurrentCipher
        {
            get => _currentCipher;
            set
            {
                _currentCipher = value;
                _currentCipher.ClearForm();
                RaisePropertyChanged( nameof( CurrentCipher ) );
            }
        }

        public List<CipherForm> Ciphers { get; }

        public DelegateCommand<CipherForm> ChangeCipher { get; }

        public MainVM()
        {
            Ciphers = new List<CipherForm>();

            Ciphers.Add( new CipherForm( new RSAPage(), "RSA" ) );
            Ciphers.Add( new CipherForm( new DHPage(), "Диффи—Хеллман" ) );
            Ciphers.Add( new CipherForm( new ShamirPage(), "Шамир" ) );
            Ciphers.Add( new CipherForm( new ElgamalPage(), "Эль-Гамаль" ) );
            Ciphers.Add( new CipherForm( new HashPage( new MD5() ), "MD5" ) );
            Ciphers.Add( new CipherForm( new HashPage( new SHA1() ), "SHA1" ) );
            Ciphers.Add( new CipherForm( new HashPage( new Streebog() ), "ГОСТ2012" ) );

            RaisePropertyChanged( nameof( Ciphers ) );

            CurrentCipher = Ciphers[ 0 ];
            ChangeCipher = new DelegateCommand<CipherForm>( cipher =>
            {
                CurrentCipher = cipher;
            } );




        }
    }

}

