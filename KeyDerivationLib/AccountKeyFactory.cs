using Entities;
using NBitcoin;
using NBitcoin.Crypto;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Implementation of hierarchical key derivation for separate accounts distinguished with user identities.
    /// </summary>
    public static class AccountKeyFactory
    {
        public static PrivateKey DeriveAccountKey(MasterKey masterKey, string userId)
        {
            byte[] hashInput = masterKey.ToByteBuffer();

            byte[] hashkey = Encoding.UTF8.GetBytes(userId);
            var hashMAC = Hashes.HMACSHA512(hashkey, hashInput);

            return hashMAC.ToPrivateKey();
        }

        public static byte[] DeriveAccountChildKey(MasterKey masterKey, string userId, int index)
        {
            PrivateKey accountKey = DeriveAccountKey(masterKey, userId);
            return DeriveAccountChildKey(accountKey, index);
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
