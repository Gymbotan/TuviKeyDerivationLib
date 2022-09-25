using Entities;
using KeyDerivation;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using System;

namespace KeyDerivationLib
{
    /// <summary>
    /// Implementation of BIP39 mnemonic generation and BIP32 hierarchical key derivation.
    /// </summary>
    public class MasterKeyFactory
    {
        private IKeyDerivationDetailsProvider Provider;

        private Mnemonic Mnemonic;

        private const WordCount SeedPhraseLength = WordCount.Twelve;
        private static readonly Wordlist SeedPhraseWordlist = Wordlist.English;

        public MasterKeyFactory(IKeyDerivationDetailsProvider provider)
        {
            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            if (provider.GetSeedPhraseLength() == (int)SeedPhraseLength)
            {
                Provider = provider;
            }
            else
            {
                throw new ArgumentException("Required parameters are not supported.");
            }
        }

        public string[] GenerateSeedPhrase()
        {
            Mnemonic = new Mnemonic(SeedPhraseWordlist, SeedPhraseLength);
            return Mnemonic.Words;
        }

        public void RestoreSeedPhrase(string[] seedPhrase)
        {
            const string MnemonicWordsSeparator = " ";
            string concatenatedPhrase = string.Join(MnemonicWordsSeparator, seedPhrase);
            Mnemonic = new Mnemonic(concatenatedPhrase, SeedPhraseWordlist);
        }

        public MasterKey GetMasterKey()
        {
            return DeriveTuviMasterKey();
        }

        public static bool IsWordExistInDictionary(string word)
        {
            return SeedPhraseWordlist.WordExists(word, out _);
        }

        private MasterKey DeriveTuviMasterKey()
        {
            if (Mnemonic == null)
            {
                throw new ArgumentNullException(nameof(Mnemonic));
            }

            string ApplicationHaskKey = Provider.GetSaltPhrase();
            byte[] hashkey = Encoders.ASCII.DecodeData(ApplicationHaskKey);

            byte[] seed = Mnemonic.DeriveSeed();
            var hashMAC = Hashes.HMACSHA512(hashkey, seed);

            return hashMAC.ToMasterKey();
        }
    }
}
