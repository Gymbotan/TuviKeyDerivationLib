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

using KeyDerivation.Keys;
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    internal static class TestData
    {
        public static readonly string[] TestSeedPhrase = { 
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon"
        };

        public static readonly string[] TestSeedPhrase2 = { 
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "ability"
        };

        public static string[] GetTestSeed()
        {
            return new string[] {
                "ozone",    "drill",    "grab",
                "fiber",    "curtain",  "grace",
                "pudding",  "thank",    "cruise",
                "elder",    "eight",    "picnic"
            };
        }

        public static List<KeyValuePair<string, bool>> GetDictionaryTestData()
        {
            return new List<KeyValuePair<string, bool>>()
            {
                new KeyValuePair<string, bool>("hello", true),
                new KeyValuePair<string, bool>("shine", true),
                new KeyValuePair<string, bool>("abracadabra", false),
                new KeyValuePair<string, bool>("fakdfbmsp", false)
            };
        }

        public static readonly MasterKey MasterKey = CreateMasterKey(TestSeedPhrase);

        public static readonly MasterKey MasterKey2 = CreateMasterKey(TestSeedPhrase2);

        private static MasterKey CreateMasterKey(string[] seedPhrase)
        {
            MasterKeyFactory factory = new MasterKeyFactory(new TestKeyDerivationDetailsProvider());
            factory.RestoreSeedPhrase(seedPhrase);
            return factory.GetMasterKey();
        }

        public static (byte[] scalar, byte[] chainCode) PrivateDerivationKey1 = (
            new byte[] {
                0xbc, 0xb9, 0x21, 0x03, 0x63, 0x5a, 0x32, 0xdf, 0x37, 0x20, 0x5c, 0xec, 0x13, 0x44, 0xb7, 0x1b,
                0x48, 0x5a, 0x7d, 0xc6, 0x63, 0x20, 0xa0, 0x08, 0x6c, 0x07, 0x80, 0xd7, 0x8f, 0x87, 0x3b, 0x70
            },
            new byte[] {
                0xb7, 0xa7, 0x80, 0xf0, 0xf9, 0x9e, 0x27, 0xb1, 0x37, 0xcf, 0x51, 0x7f, 0xcc, 0x0b, 0x1f, 0xe0,
                0xc5, 0x8c, 0xff, 0xca, 0x3e, 0x59, 0x2a, 0xf9, 0x94, 0x80, 0x1e, 0xdc, 0xa7, 0x23, 0x72, 0x45
            }
        );

        public static (byte[] scalar, byte[] chainCode) PrivateDerivationKey2 = (
            new byte[] {
                0x4a, 0x97, 0x03, 0xb2, 0xfd, 0x9e, 0x87, 0x17, 0x75, 0xbc, 0x54, 0x7f, 0x6d, 0x03, 0xb0, 0x74,
                0xb6, 0x3d, 0xa1, 0x5b, 0xc4, 0xd4, 0x03, 0x4c, 0xcb, 0x42, 0x0f, 0x17, 0xbf, 0x5c, 0xff, 0xc7
            },
            new byte[] {
                0xdc, 0xd9, 0x49, 0x37, 0x8f, 0xc6, 0x7f, 0xba, 0xe6, 0xc9, 0x86, 0x46, 0xbc, 0x5d, 0x00, 0x8b,
                0x45, 0x4c, 0xbb, 0x3c, 0xff, 0xc7, 0x5a, 0xdd, 0x71, 0xe3, 0x95, 0x91, 0x03, 0x6d, 0x4d, 0xc7
            }
        );

        public static PrivateDerivationKey DerivationKeyForSerialization = 
            DerivationKeyFactory.CreatePrivateDerivationKey(MasterKey, RightTag);

        public static readonly byte[] PrivateChildKey1 = new byte[32]
        {
            0xe4, 0x3f, 0x20, 0xe9, 0x2f, 0x3c, 0x0c, 0xee, 0xc0, 0x11, 0xff, 0xcb, 0x30, 0x7b, 0x69, 0x90,
            0x3b, 0x5b, 0x2c, 0x30, 0xe5, 0x03, 0x70, 0x91, 0xa3, 0x34, 0xea, 0x6d, 0xc0, 0x17, 0x8f, 0x88
        };

        public static readonly byte[] PrivateChildKey2 = new byte[32]
        {
            0xdf, 0xb4, 0xd8, 0xe4, 0x46, 0x65, 0xbe, 0xd1, 0xe9, 0xe3, 0xf1, 0x16, 0x44, 0xe3, 0xb5, 0x7f,
            0xac, 0xcd, 0x8b, 0xec, 0xed, 0x6e, 0xae, 0x3b, 0x95, 0x80, 0x94, 0x36, 0xc7, 0x26, 0xf4, 0x1e
        };

        public const string RightTag = "test@user.net";

        public const string WrongTag = "abra-cadabra...";
    }
}
