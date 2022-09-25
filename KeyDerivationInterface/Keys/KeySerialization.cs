using System;

namespace Entities
{
    public static class KeySerialization
    {
        public const int KeyChainCodeLength = 32;
        public const int PrivateKeyLength = 32;

        public static MasterKey ToMasterKey(this byte[] buffer)
        {
            var privateKey = buffer.ToPrivateKey();
            return new MasterKey
            {
                Scalar = privateKey.Scalar,
                ChainCode = privateKey.ChainCode
            };
        }

        public static byte[] ToByteBuffer(this MasterKey key)
        {
            var privateKey = key as PrivateKey;
            return privateKey?.ToByteBuffer();
        }

        public static PrivateKey ToPrivateKey(this byte[] buffer)
        {
            byte[] scalar = new byte[PrivateKeyLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, scalar, 0, PrivateKeyLength);
            Buffer.BlockCopy(buffer, PrivateKeyLength, chainCode, 0, KeyChainCodeLength);

            return new PrivateKey
            {
                Scalar = scalar,
                ChainCode = chainCode
            };
        }

        public static byte[] ToByteBuffer(this PrivateKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] buffer = new byte[KeyChainCodeLength + PrivateKeyLength];

            Buffer.BlockCopy(key.Scalar, 0, buffer, 0, PrivateKeyLength);
            Buffer.BlockCopy(key.ChainCode, 0, buffer, PrivateKeyLength, KeyChainCodeLength);

            return buffer;
        }
    }
}
