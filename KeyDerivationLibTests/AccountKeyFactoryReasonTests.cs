using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class AccountKeyFactoryReasonTests
    {
        [Test]
        public void DifferentChildKeyForDifferentReasons()
        {
            for (int i = 0; i < 10; i++)
            {
                var childEncryptKey = AccountKeyFactory.DeriveAccountChildEncryptionKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), i);
                var childSignKey = AccountKeyFactory.DeriveAccountChildSigningKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), i);

                Assert.That(childSignKey, Is.Not.EqualTo(childEncryptKey), "Child keys have to be different with Account keys they derived from");
            }
        }

        [Test]
        public void AccountChildReasonKeysAreDeterministic()
        {
            var encKey1 = AccountKeyFactory.DeriveAccountChildEncryptionKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);
            var signKey1 = AccountKeyFactory.DeriveAccountChildSigningKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);

            Assert.That(TestData.ChildEncryptionKey1, Is.EqualTo(encKey1), "Key is not same as predicted");
            Assert.That(TestData.ChildSigningKey1, Is.EqualTo(signKey1), "Key is not same as predicted");
        }

    }
}
