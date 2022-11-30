using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    internal class AccountKeyFactoryTest
    {
        [Test]
        public void AccountKeysAreDeterministic()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.AreEqual(key1, TestData.AccountKey1, "Key is not same as predicted");
            Assert.AreEqual(key2, TestData.AccountKey2, "Key is not same as predicted");
        }

        [Test]
        public void AccountKeysAreDifferentWithMasterKey()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity());

            Assert.AreNotEqual(key1, key2, "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountKeysAreDifferentWithAccountId()
        {
            var key1 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.DeriveAccountKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.AreNotEqual(key1, key2, "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDeterministic()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);

            Assert.AreEqual(key1, TestData.ChildKey1, "Key is not same as predicted");
            Assert.AreEqual(key2, TestData.ChildKey2, "Key is not same as predicted");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithMasterKey()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity(), 0);

            Assert.AreNotEqual(key1, key2, "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithUserId()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.WrongPgpIdentity, 0);

            Assert.AreNotEqual(key1, key2, "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithKeyIndex()
        {
            var key1 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 0);
            var key2 = AccountKeyFactory.DeriveAccountChildKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity(), 1);

            Assert.AreNotEqual(key1, key2, "Keys with different KeyIndex have to be different too");
        }
    }
}
