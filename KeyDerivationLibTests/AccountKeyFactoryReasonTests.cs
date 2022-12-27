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
