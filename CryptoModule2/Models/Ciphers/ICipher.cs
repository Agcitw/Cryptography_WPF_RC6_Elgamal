using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.Ciphers
{
    public interface ICipher
    {
        byte[] Encrypt(byte[] text, IKey key = null);
        byte[] Decrypt(byte[] ciphertext, IKey key = null);
        string CipherName { get; }
    }
}
