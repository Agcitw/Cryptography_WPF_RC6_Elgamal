using CryptoModule2.Models.HashFunctions;
using CryptoModule2.ViewModels.Interfaces;
using Microsoft.Win32;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace CryptoModule2.ViewModels
{
    public class HashVM : BindableBase, ICipherVM
    {

        private readonly IHash _hash;

        private string _inputText = "";
        public string InputText
        {
            get => _inputText;
            set
            {
                _inputText = value;
                RaisePropertyChanged( nameof( InputText ) );
            }
        }

        private string _outputText = "";
        public string OutputText
        {
            get => _outputText;
            set
            {
                _outputText = value;
                RaisePropertyChanged( nameof( OutputText ) );
            }
        }

        private bool _isCalc = false;
        public bool IsCalc
        {
            get => _isCalc;
            set
            {
                _isCalc = value;
                RaisePropertyChanged( nameof( IsCalc ) );
            }
        }

        public DelegateCommand HashTextCommand { get; }
        public DelegateCommand HashFileCommand { get; }

        public HashVM(IHash hash)
        {
            _hash = hash;

            HashTextCommand = new DelegateCommand( () =>
             {
                 byte[] text = Encoding.Default.GetBytes( InputText );
                 byte[] digest = _hash.Hash( text );
                 OutputText = BitConverter.ToString( digest ).Replace( "-", string.Empty );
             } );

            HashFileCommand = new DelegateCommand( () =>
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if( openFileDialog.ShowDialog() == true )
                {
                    IsCalc = true;
                    Thread thread = new Thread( () =>
                    {
                        byte[] digest = _hash.Hash( openFileDialog.FileName );
                        OutputText = BitConverter.ToString( digest ).Replace( "-", string.Empty );
                        IsCalc = false;
                    } );
                    thread.Start();
                }

            } );

        }

        public void ClearForm()
        {
            InputText = "";
            OutputText = "";
        }
    }
}
