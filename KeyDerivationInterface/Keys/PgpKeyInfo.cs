using System;

namespace Entities.Keys
{
    public class PgpKeyInfo
    {
        public long KeyId { get; set; }

        public string Algorithm { get; set; }

        public int BitStrength { get; set; }

        public DateTime CreationTime { get; set; }

        public long ValidSeconds { get; set; }

        public string UserIdentity { get; set; }

        public string Fingerprint { get; set; }
        
        public bool IsMasterKey { get; set; }

        public bool IsEncryptionKey { get; set; }

        public bool IsRevoked { get; set; }
        
        public bool IsNeverExpires()
        {
            return ValidSeconds == 0;
        }
    }
}
