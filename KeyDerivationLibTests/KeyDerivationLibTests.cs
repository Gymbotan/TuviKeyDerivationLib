using KeyDerivation;
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class KeyDerivationLibTests
    {
        [Test]
        public void MasterKeyFactoryCreation_NullProvider_ThrowArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new MasterKeyFactory(null),
                message: "Provider can not be a null.");
        }

        [TestCase(11)]
        [TestCase(13)]
        [TestCase(15)]
        [TestCase(18)]
        [TestCase(21)]
        [TestCase(24)]
        public void MasterKeyFactoryCreation_WrongSeedPhraseLength_ThrowArgumentException(int length)
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(length);

            Assert.Throws<ArgumentException>(() => new MasterKeyFactory(mock.Object),
                message: "Provider required parameters are not supported.");
        }

        [Test]
        public void MasterKeyFactoryCreation_SuccessfulCreation()
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(12);
            MasterKeyFactory factory = new MasterKeyFactory(mock.Object);
            Assert.Pass();
        }
        
        [Test]
        public void GetMasterKey_NullMnemonic_ThrowArgumentNullException()
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(12);
            MasterKeyFactory factory = new MasterKeyFactory(mock.Object);
            Assert.Throws<ArgumentNullException>(() => factory.GetMasterKey(),
                message: "Mnemonic can not be a null.");
        }
    }
}