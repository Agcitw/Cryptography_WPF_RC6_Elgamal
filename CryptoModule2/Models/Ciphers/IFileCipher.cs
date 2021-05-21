using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers
{
    public interface IFileCipher
    {
        void Encrypt( string inputPath, string outputPath, IKey key, Action<double> ProgressChanged = null );
        void Decrypt( string inputPath, string outputPath, IKey key, Action<double> ProgressChanged = null );
        string CipherName { get; }
    }
}
