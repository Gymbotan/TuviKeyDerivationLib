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
        public static PrivateDrivationKey CreatePrivateDerivationKey(PrivateDrivationKey masterKey, string userId)
        {
            byte[] hashInput = masterKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(userId);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateDerivationKey();
        }

        public static byte[] DerivePrivateChildKey(PrivateDrivationKey accountKey, int index)
        {
            if (accountKey is null)
            {
                throw new ArgumentNullException(nameof(accountKey));
            }

            using (var eccKey = new Key(accountKey.Scalar))
            {
                ExtKey accountExtKey = new ExtKey(eccKey, accountKey.ChainCode);
                return accountExtKey.Derive(index, true).PrivateKey.ToBytes();
            }
        }
    }
}
