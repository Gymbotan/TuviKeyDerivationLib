using System.Collections.Generic;

namespace KeyDerivation
{
    /// <summary>
    /// Used to require some information from Application during master key generation process.
    /// </summary>
    public interface IKeyDerivationDetailsProvider
    {
        /// <summary>
        /// Each application has to return constant unique phrase used as a salt in key derivation process.
        /// </summary>
        string GetSaltPhrase();

        /// <summary>
        /// Get required seed phrase length.
        /// </summary>
        /// <returns></returns>
        int GetSeedPhraseLength();

        /// <summary>
        /// Get table of special PGP key identities.
        /// </summary>
        Dictionary<SpecialPgpKeyType, string> GetSpecialPgpKeyIdentities();
    }
    
    /// <summary>
    /// Enumeration of special PGP key types.
    /// </summary>
    public enum SpecialPgpKeyType
    {
        Backup
    }
}
