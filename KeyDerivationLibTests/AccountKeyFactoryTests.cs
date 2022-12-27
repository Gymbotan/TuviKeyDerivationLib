///////////////////////////////////////////////////////////////////////////////
//   Copyright 2022 Eppie (https://eppie.io)
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
