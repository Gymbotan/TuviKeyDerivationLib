using System;
using System.Collections.Generic;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Enum contains reasons for key creation (way how the key will be used).
    /// </summary>
    public enum KeyReason
    {
        Encryption,
        Signing
    }
}
