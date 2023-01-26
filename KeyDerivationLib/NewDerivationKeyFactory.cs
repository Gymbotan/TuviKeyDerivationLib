///////////////////////////////////////////////////////////////////////////////
//   Copyright 2023 Eppie (https://eppie.io)
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

using NBitcoin.Crypto;
using NBitcoin;
using System;
using System.Text;
using KeyDerivation.Keys;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;

namespace KeyDerivationLib
{
    public static class PrivateDerivationKeyFactory
    {
        /// <summary>
        /// Derivation key creation from derivation (master) key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="tag">Tag to identify key(like user ID).</param>
        /// <returns>New (deeper) private derivation key.</returns>
        public static PrivateDerivationKey CreatePrivateDerivationKey(PrivateDerivationKey derivationKey, string tag)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            byte[] hashInput = derivationKey.PublicDerivationKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(tag);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateDerivationKey(derivationKey); 
        }

        /// <summary>
        /// Derive private child key from private derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="index">Private child key index.</param>
        /// <returns>Private child key.</returns>
        public static byte[] DerivePrivateChildKey(PrivateDerivationKey derivationKey, uint index)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            using (var eccKey = new Key(derivationKey.Scalar))
            {
                ExtKey derivationExtKey = new ExtKey(eccKey, derivationKey.ChainCode);
                return derivationExtKey.Derive(index).PrivateKey.ToBytes();
            }
        }
    }

    public static class PublicDerivationKeyFactory
    {
        public const string BitcoinEllipticCurveName = "secp256k1";

        /// <summary>
        /// Public derivation key creation from public derivation key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="tag">Tag to identify key(like user ID).</param>
        /// <returns>New (deeper) public derivation key.</returns>
        public static PublicDerivationKey CreatePublicDerivationKey(PublicDerivationKey derivationKey, string tag)
        {
            byte[] hashInput = derivationKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(tag);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPublicDerivationKey(derivationKey);
        }

        /// <summary>
        /// Public derivation key creation from private derivation key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="tag">Tag to identify key(like user ID).</param>
        /// <returns>New (deeper) public derivation key.</returns>
        public static PublicDerivationKey CreatePublicDerivationKey(PrivateDerivationKey derivationKey, string tag)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            return CreatePublicDerivationKey(derivationKey.PublicDerivationKey, tag);
        }

        /// <summary>
        /// Derive public child key as byte array (compressed) from public derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="index">Public child key's index.</param>
        /// <returns>Public child key.</returns>
        public static byte[] DerivePublicChildKeyAsBytes(PublicDerivationKey derivationKey, uint index)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            var eccKey = new PubKey(derivationKey.PublicKey.GetEncoded(true));

            ExtPubKey derivationExtKey = new ExtPubKey(eccKey, derivationKey.ChainCode);
            return derivationExtKey.Derive(index).PubKey.ToBytes();
        }

        /// <summary>
        /// Derive public child key as ECPoint from public derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="index">Public child key's index.</param>
        /// <returns>Public child key.</returns>
        public static ECPoint DerivePublicChildKeyAsECPoint(PublicDerivationKey derivationKey, uint index)
        {
            var keyBytes = DerivePublicChildKeyAsBytes(derivationKey, index);
            return ECNamedCurveTable.GetByName(BitcoinEllipticCurveName).Curve.DecodePoint(keyBytes);
        }
    }
}
