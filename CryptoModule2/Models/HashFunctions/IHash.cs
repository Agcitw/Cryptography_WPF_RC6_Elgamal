using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoModule2.Models.HashFunctions
{
    public interface IHash
    {
        public byte[] Hash( byte[] inputBlock );
        public byte[] Hash( string path );

    }
}
