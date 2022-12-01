using Entities;
using NUnit.Framework.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyDerivationLibTests
{
    public class KeySerializationTest
    {
        [Test]
        public void SerializeDeserializePrivateKey()
        {
            var buffer = TestData.AccountKey1.ToByteBuffer();
            PrivateKey privateKey = buffer.ToPrivateKey();

            Assert.That(privateKey, Is.EqualTo(TestData.AccountKey1));
        }

        [Test]
        public void SerializeDeserializeMasterKey()
        {
            var buffer = TestData.MasterKey.ToByteBuffer();
            MasterKey masterKey = buffer.ToMasterKey();

            Assert.That(masterKey, Is.EqualTo(TestData.MasterKey));
        }
    }
}
