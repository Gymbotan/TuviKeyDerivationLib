using System.Linq;

namespace Entities
{
    // Use this as Data Transfer Object only.
    public class MasterKey : PrivateKey
    {
    }

    public class PrivateKey
    {
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Scalar { get; set; }

        public byte[] ChainCode { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            if (obj is PrivateKey other)
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

    public class PgpPublicKeyBundle : PgpKeyBundle
    {
    }

    public class PgpSecretKeyBundle : PgpKeyBundle
    {
    }

    public class PgpKeyBundle
    {
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Data { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            if (obj is PgpKeyBundle other)
            {
                if ((Data == null && other.Data == null) ||
                     Data.SequenceEqual(other.Data))
                {
                    return true;
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
