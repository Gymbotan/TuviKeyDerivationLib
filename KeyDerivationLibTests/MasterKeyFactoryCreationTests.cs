using KeyDerivation;
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class MasterKeyFactoryCreationTests
    {
        [Test]
        public void MasterKeyFactoryCreationNullProviderThrowArgumentNullException()
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
        public void MasterKeyFactoryCreationWrongSeedPhraseLengthThrowArgumentException(int length)
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(length);

            Assert.Throws<ArgumentException>(() => new MasterKeyFactory(mock.Object),
                message: "Provider required parameters are not supported.");
        }

        [Test]
        public void MasterKeyFactoryCreationSuccessfulCreation()
        {
            int correctMnemonicLength = 12;
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(correctMnemonicLength);
            Assert.DoesNotThrow(() => new MasterKeyFactory(mock.Object), "Exception was thrown but shouldn't.");
        }
        
        [Test]
        public void GetMasterKeyNullMnemonicThrowArgumentNullException()
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(12);
            MasterKeyFactory factory = new MasterKeyFactory(mock.Object);
            Assert.Throws<ArgumentNullException>(() => factory.GetMasterKey(),
                message: "Mnemonic can not be a null.");
        }
    }
}