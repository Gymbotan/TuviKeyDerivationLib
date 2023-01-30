using KeyDerivation.Keys;
using NBitcoin.Crypto;
using NBitcoin;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;
using System;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Factory that derivate public keys from parent private or public keys.
    /// </summary>
    public static class PublicDerivationKeyFactory
    {
        public const string BitcoinEllipticCurveName = "secp256k1";

        /// <summary>
        /// Public derivation key creation from public derivation key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="tag">Tag to identify key (like user ID).</param>
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
        /// <param name="tag">Tag to identify key (like user ID).</param>
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
        /// <returns>Public child key as byte array.</returns>
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
        /// <returns>Public child key as EC point.</returns>
        public static ECPoint DerivePublicChildKeyAsECPoint(PublicDerivationKey derivationKey, uint index)
        {
            var keyBytes = DerivePublicChildKeyAsBytes(derivationKey, index);
            return ECNamedCurveTable.GetByName(BitcoinEllipticCurveName).Curve.DecodePoint(keyBytes);
        }

        private static PublicDerivationKey ToPublicDerivationKey(this byte[] buffer, PublicDerivationKey oldKey)
        {
            if (oldKey == null)
            {
                throw new ArgumentNullException(nameof(oldKey));
            }

            const int KeyChainCodeLength = 32;
            const int PrivateKeyLength = 32;

            byte[] point = new byte[PrivateKeyLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, point, 0, PrivateKeyLength);
            Buffer.BlockCopy(buffer, PrivateKeyLength, chainCode, 0, KeyChainCodeLength);

            PublicDerivationKey tempKey = new PublicDerivationKey(point, chainCode);

            return new PublicDerivationKey(tempKey.PublicKey.Add(oldKey.PublicKey), chainCode);
        }
    }
}
