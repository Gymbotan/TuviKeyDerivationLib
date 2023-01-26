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

using KeyDerivation.Entities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using System.Linq;
using System.Numerics;

namespace KeyDerivation.Keys
{
    // Use this as Data Transfer Object only.
    public class MasterKey : PrivateDerivationKey
    {
    }

    public class PrivateDerivationKey
    {
        private byte[] scalar;
        private byte[] chainCode;

#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Scalar 
        { 
            get
            {
                return scalar;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key scalar can not be a null.");
                }

                scalar = value;
            }
        }

        public byte[] ChainCode {
            get
            {
                return chainCode;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key chain code can not be a null.");
                }

                chainCode = value;
            }
        }
#pragma warning restore CA1819 // Properties should not return arrays

        public PublicDerivationKey PublicDerivationKey => new PublicDerivationKey(Scalar, ChainCode);

        public override bool Equals(object obj)
        {
            if (obj is PrivateDerivationKey other)
            {
                if ((Scalar == null && other.Scalar == null) ||
                     Scalar.SequenceEqual(other.Scalar))
                {
                    if ((ChainCode == null && other.ChainCode == null) ||
                         ChainCode.SequenceEqual(other.ChainCode))
                    {
                        return true;
                    }
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }

    public class PublicDerivationKey
    {
        private const string BitcoinEllipticCurveName = "secp256k1";
        private DerObjectIdentifier curveOid;
        private ECKeyGenerationParameters keyParams;

        private readonly ECMultiplier multiplier = new FixedPointCombMultiplier();

        private const int KeyChainCodeLength = 32;
        private ECPoint publicKey; 
        private byte[] chainCode;

        private PublicDerivationKey()
        {
            curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());
        }

        public PublicDerivationKey(byte[] privateKey, byte[] chainCode) : this()
        {
            PublicKey = multiplier.Multiply(keyParams.DomainParameters.G, new Org.BouncyCastle.Math.BigInteger(1, privateKey));
            ChainCode = chainCode;
        }

        public PublicDerivationKey(ECPoint publicKey, byte[] chainCode) : this()
        {
            PublicKey = publicKey;
            ChainCode = chainCode;
        }

        public ECKeyGenerationParameters KeyParams 
        {
            get => keyParams;
        }

        public ECPoint PublicKey
        {
            get 
            { 
                return publicKey; 
            }

            internal set
            {
                publicKey = value ?? throw new KeyCreationException($"Derivation public key can not be a null.");
            }
        }

#pragma warning disable CA1819 // Properties should not return arrays
        
        public byte[] ChainCode
        {
            get
            {
                return chainCode;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key chain code can not be a null.");
                }

                if (value.Length != KeyChainCodeLength)
                {
                    throw new KeyCreationException($"Derivation key chain code length should be equal to {KeyChainCodeLength} bytes.");
                }

                chainCode = value;
            }
        }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            if (obj is PublicDerivationKey other)
            {
                if ((PublicKey == null && other.PublicKey == null) ||
                     PublicKey.GetEncoded().SequenceEqual(other.PublicKey.GetEncoded()))
                {
                    if ((ChainCode == null && other.ChainCode == null) ||
                         ChainCode.SequenceEqual(other.ChainCode))
                    {
                        return true;
                    }
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
