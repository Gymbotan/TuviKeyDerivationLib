///////////////////////////////////////////////////////////////////////////////
//   Copyright 2022 Eppie (https://eppie.io)
//
//   Licensed under the Apache License, Version 2.0(the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
///////////////////////////////////////////////////////////////////////////////

using KeyDerivation.Keys;
using NBitcoin;
using NBitcoin.Crypto;
using System;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Implementation of hierarchical key derivation for separate accounts distinguished with user identities.
    /// Based on BIP-32 hierarchical key derivation.
    /// </summary>
    public static class AccountKeyFactory
    {
        /// <summary>
        /// Account key derivation from master key and user ID (based on BIP-32).
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userId">User ID.</param>
        /// <returns>Account key.</returns>
        public static PrivateKey DeriveAccountKey(MasterKey masterKey, string userId)
        {
            byte[] hashInput = masterKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(userId);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateKey();
        }

        /// <summary>
        /// Derivation of child key with choosen index from master key and user ID (based on BIP-32).
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userId">User ID.</param>
        /// <param name="index">Child key index.</param>
        /// <returns>Child key.</returns>
        public static byte[] DeriveAccountChildKey(MasterKey masterKey, string userId, int index)
        {
            PrivateKey accountKey = DeriveAccountKey(masterKey, userId);
            return DeriveAccountChildKey(accountKey, index);
        }

        /// <summary>
        /// New way of child key derivation using account subkeys. 
        /// Derivation of child key for encryption with choosen index (based on BIP-32).
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userId">User ID.</param>
        /// <param name="index">Child key index.</param>
        /// <returns>Child key.</returns>
        public static byte[] DeriveAccountChildEncryptionKey(MasterKey masterKey, string userId, int index)
        {
            return DeriveAccountChildKeyForReason(masterKey, userId, index, KeyReason.Encryption);
        }

        /// <summary>
        /// New way of child key derivation using account subkeys. 
        /// Derivation of child key for signing with choosen index (based on BIP-32).
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userId">User ID.</param>
        /// <param name="index">Child key index.</param>
        /// <returns>Child key.</returns>
        public static byte[] DeriveAccountChildSigningKey(MasterKey masterKey, string userId, int index)
        {
            return DeriveAccountChildKeyForReason(masterKey, userId, index, KeyReason.Signing);
        }

        /// <summary>
        /// Creation (forking) of account subkey for choosen reason to derive child key with the same reason.
        /// </summary>
        /// <param name="masterKey">Master key.</param>
        /// <param name="userId">User ID.</param>
        /// <param name="index">Child key index.</param>
        /// <param name="reason">Reason for key creation.</param>
        /// <returns>Child key.</returns>
        private static byte[] DeriveAccountChildKeyForReason(MasterKey masterKey, string userId, int index, KeyReason reason)
        {
            PrivateKey accountKey = DeriveAccountKey(masterKey, userId);
            MasterKey accKey = new MasterKey() { Scalar = accountKey.Scalar, ChainCode = accountKey.ChainCode };
            PrivateKey accountEncryptSubKey = ForkAccountKey(accKey, reason); // rename into DeriveAccountSubKey?
            return DeriveAccountChildKey(accountEncryptSubKey, index);
        }

        /// <summary>
        /// Creates a "fork" of an account key to create child keys for different reason (encryption, signing etc.).
        /// </summary>
        /// <param name="accountKey">"Main" account key.</param>
        /// <param name="keyReason">Reason of key creation.</param>
        /// <returns>Account subkey for child key creation with choosen reason.</returns>
        private static PrivateKey ForkAccountKey(MasterKey accountKey, KeyReason keyReason)
        {
            byte[] hashInput = accountKey.ToByteBuffer();

            byte[] hashKey = BitConverter.GetBytes((int)keyReason);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateKey();
        }

        private static byte[] DeriveAccountChildKey(PrivateKey accountKey, int index)
        {
            using (var eccKey = new Key(accountKey.Scalar))
            {
                ExtKey accountExtKey = new ExtKey(eccKey, accountKey.ChainCode);
                return accountExtKey.Derive(index, true).PrivateKey.ToBytes();
            }
        }
    }
}
