using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class AccountKeyFactoryTests
    {
        [Test]
        public void AccountKeysAreDeterministic()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.That(TestData.AccountKey1, Is.EqualTo(key1), "Key is not same as predicted");
            Assert.That(TestData.AccountKey2, Is.EqualTo(key2), "Key is not same as predicted");
        }

        [Test]
        public void AccountKeysAreDifferentWithMasterKey()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity());

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountKeysAreDifferentWithAccountId()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDeterministic()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);

            Assert.That(TestData.ChildKey1, Is.EqualTo(key1), "Key is not same as predicted");
            Assert.That(TestData.ChildKey2, Is.EqualTo(key2), "Key is not same as predicted");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithMasterKey()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity(), 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithUserId()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.WrongPgpIdentity, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithKeyIndex()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different KeyIndex have to be different too");
        }
    }
}
