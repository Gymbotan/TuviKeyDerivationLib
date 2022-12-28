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
            var key1 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.That(TestData.AccountKey1, Is.EqualTo(key1), "Key is not same as predicted");
            Assert.That(TestData.AccountKey2, Is.EqualTo(key2), "Key is not same as predicted");
        }

        [Test]
        public void AccountKeysAreDifferentWithMasterKey()
        {
            var key1 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity());

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountKeysAreDifferentWithAccountId()
        {
            var key1 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var key2 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.WrongPgpIdentity);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDeterministic()
        {
            var derivationKey = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            var key1 = AccountKeyFactory.DerivePrivateChildKey(derivationKey, 0);
            var key2 = AccountKeyFactory.DerivePrivateChildKey(derivationKey, 1);

            Assert.That(TestData.ChildKey1, Is.EqualTo(key1), "Key is not same as predicted");
            Assert.That(TestData.ChildKey2, Is.EqualTo(key2), "Key is not same as predicted");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithMasterKey()
        {
            var derivationKey1 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var derivationKey2 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey2, TestData.GetAccount().GetPgpIdentity());

            var key1 = AccountKeyFactory.DerivePrivateChildKey(derivationKey1, 0);
            var key2 = AccountKeyFactory.DerivePrivateChildKey(derivationKey2, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithUserId()
        {
            var derivationKey1 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());
            var derivationKey2 = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey2, TestData.WrongPgpIdentity);

            var key1 = AccountKeyFactory.DerivePrivateChildKey(derivationKey1, 0);
            var key2 = AccountKeyFactory.DerivePrivateChildKey(derivationKey2, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void AccountChildKeysAreDifferentWithKeyIndex()
        {
            var derivationKey = AccountKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.GetAccount().GetPgpIdentity());

            var key1 = AccountKeyFactory.DerivePrivateChildKey(derivationKey, 0);
            var key2 = AccountKeyFactory.DerivePrivateChildKey(derivationKey, 1);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different KeyIndex have to be different too");
        }
    }
}
