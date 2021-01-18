using System;
using Xunit;
using IIG.CoSFE.DatabaseUtils;
using IIG.BinaryFlag;
using IIG.FileWorker;
using IIG.PasswordHashingUtils;


namespace lab4
{
    public class PasswordHashing_Test
    {
        private string path = BaseFileWorker.MkDir("FileWorker");

        const string password = "password";
        const string passwordCaseSensitive = "PaSsWoRd";

        const string salt = "salt";
        const uint _adlerMod32 = 123456789;

        [Fact]
        public void Test_GetHash()
        {
            string hashedPassword = PasswordHasher.GetHash(password);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

        [Fact]
        public void Test_GetHashEmptyString()
        {
            string hashedEmptyPassword = PasswordHasher.GetHash(string.Empty, string.Empty);

            BaseFileWorker.Write(string.Empty, path + "\\" + "empty.txt");

            string hashedEmptyPasswordFromFile = PasswordHasher.GetHash(BaseFileWorker.ReadAll(path + "\\" + "empty.txt"));

            Assert.Equal(hashedEmptyPassword, hashedEmptyPasswordFromFile);
        }

        [Fact]
        public void Test_GetHashEmptyFilename()
        {
            string hashedPassword = PasswordHasher.GetHash(password);

            BaseFileWorker.Write(hashedPassword, path + "\\" + string.Empty);

            Assert.NotEqual(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + string.Empty));
        }

        [Fact]
        public void Test_GetHashDifferentExtension()
        {
            string hashedPassword = PasswordHasher.GetHash(password);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.a");

            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.a"));
        }


        [Fact]
        public void Test_PasswordSpesialSymbolsTest()
        {
            string specialSymbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

            string hashedPassword = PasswordHasher.GetHash(specialSymbols);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

        [Fact]
        public void Test_SaltSpesialSymbolsTest()
        {
            string specialSymbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            
            string hashedPassword = PasswordHasher.GetHash(password, specialSymbols);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

        private string generateLongString(int length)
        {
            string s = "";

            for (int i = 0; i < length; i++)
            {
                s += "q";
            }

            return s;
        }

        [Theory]
        [InlineData(100)]
        [InlineData(2048)]
        [InlineData(65535)]
        [InlineData(131070)]
        public void Test_PasswordBoundaryValue(int length)
        {
            string pass = generateLongString(length);

            string hashedPassword = PasswordHasher.GetHash(pass);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

      
        [Theory]
        [InlineData(100)]
        [InlineData(2048)]
        [InlineData(65535)]
        [InlineData(131070)]
        public void Test_SaltBoundaryValue(int length)
        {
            string salt = generateLongString(length);

            string hashedPassword = PasswordHasher.GetHash(password, salt);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(4294967296)]
        public void Test__adlerMod32BoundaryValue(long value)
        {

            string hashedPassword = PasswordHasher.GetHash(password, salt, (uint)value);

            BaseFileWorker.Write(hashedPassword, path + "\\" + "hashedPassword.txt");
            Assert.Equal(hashedPassword, BaseFileWorker.ReadAll(path + "\\" + "hashedPassword.txt"));
        }

        [Fact]
        public void Test_InitMethod()
        {
            string hashWithPredefinedSaltAnd_adlerMod32 = PasswordHasher.GetHash(password);

            string hashWithCustomSaltAnd_adlerMod32_WithoutInit = PasswordHasher.GetHash(password, salt, _adlerMod32);

            PasswordHasher.Init(salt, _adlerMod32);
            string hashWithCustomSaltAnd_adlerMod32 = PasswordHasher.GetHash(password);

            BaseFileWorker.Write(hashWithPredefinedSaltAnd_adlerMod32, path + "\\" + "hashedPasswordWithPredefinedParams.txt");
            BaseFileWorker.Write(hashWithCustomSaltAnd_adlerMod32_WithoutInit, path + "\\" + "hashedPasswordWithCustomParams.txt");

            Assert.NotEqual(BaseFileWorker.ReadAll(path + "\\" + "hashedPasswordWithPredefinedParams.txt"), BaseFileWorker.ReadAll(path + "\\" + "hashedPasswordWithCustomParams.txt"));
            Assert.Equal(hashWithCustomSaltAnd_adlerMod32_WithoutInit, BaseFileWorker.ReadAll(path + "\\" + "hashedPasswordWithCustomParams.txt"));
        }
    }

    public class BinaryFlag_Test
    {
        private const string Login = @"sa";
        private const string Password = @"123456";
        private const string Server = @"DESKTOP-LFTKEDQ";
        private const string Database = @"IIG.CoSWE.FlagpoleDB";
        private const bool IsTrusted = true;
        private const int ConnectionTimeout = 75;

        FlagpoleDatabaseUtils flagPoleDB = new FlagpoleDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);

        private int getFlagId(string flagView)
        {
            return (int)flagPoleDB.GetIntBySql($"SELECT MultipleBinaryFlagID FROM dbo.MultipleBinaryFlags WHERE MultipleBinaryFlagView = '{flagView}'");
        }

        private const ulong length_UIntConcreteBinaryFlag = 10;
        private const uint flagValue_UIntConcreteFlag = 4294966272;

        [Fact]
        public void Test_AddFlag_True()
        {
            MultipleBinaryFlag multipleBinaryFlag = new MultipleBinaryFlag(length_UIntConcreteBinaryFlag, true);

            string flagView = multipleBinaryFlag.ToString();
            bool flagValue = multipleBinaryFlag.GetFlag();

            Assert.True(flagPoleDB.AddFlag(flagView, flagValue));
        }

        [Fact]
        public void Test_AddFlag_False()
        {
            MultipleBinaryFlag multipleBinaryFlag = new MultipleBinaryFlag(length_UIntConcreteBinaryFlag, false);

            string flagView = multipleBinaryFlag.ToString();
            bool flagValue = multipleBinaryFlag.GetFlag();

            Assert.True(flagPoleDB.AddFlag(flagView, flagValue));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Test_GetFlagValue(bool _flag)
        {
            MultipleBinaryFlag multipleBinaryFlag = new MultipleBinaryFlag(length_UIntConcreteBinaryFlag, _flag);

            string flagView = multipleBinaryFlag.ToString();
            bool flagValue = multipleBinaryFlag.GetFlag();

            flagPoleDB.AddFlag(flagView, flagValue);

            string flagViewFromDB;
            bool? flagValueFromDB;

            flagPoleDB.GetFlag(getFlagId(flagView), out flagViewFromDB, out flagValueFromDB);

            Assert.True(flagValueFromDB == _flag);
        }

        [Fact]
        public void Test_DataFlow_ResetFlag()
        {
            MultipleBinaryFlag multipleBinaryFlag = new MultipleBinaryFlag(length_UIntConcreteBinaryFlag, true);

            string flagViewBeforeReset = multipleBinaryFlag.ToString();
            bool flagValueBeforeReset = multipleBinaryFlag.GetFlag();

            flagPoleDB.AddFlag(flagViewBeforeReset, flagValueBeforeReset);

            multipleBinaryFlag.ResetFlag(length_UIntConcreteBinaryFlag - 1);

            string flagViewFromDB;
            bool? flagValueFromDB;

            flagPoleDB.GetFlag(getFlagId(flagViewBeforeReset), out flagViewFromDB, out flagValueFromDB);

            bool actualFlagValueAfterReset = multipleBinaryFlag.GetFlag();

            Assert.NotEqual(actualFlagValueAfterReset, flagValueFromDB);
        }

        [Fact]
        public void Test_DataFlow_SetFlag()
        {
            MultipleBinaryFlag multipleBinaryFlag = new MultipleBinaryFlag(length_UIntConcreteBinaryFlag, true);

            string flagViewBeforeSet = multipleBinaryFlag.ToString();
            bool flagValueBeforeSet = multipleBinaryFlag.GetFlag();

            flagPoleDB.AddFlag(flagViewBeforeSet, flagValueBeforeSet);

            multipleBinaryFlag.SetFlag(length_UIntConcreteBinaryFlag - 1);

            string flagViewFromDB;
            bool? flagValueFromDB;

            flagPoleDB.GetFlag(getFlagId(flagViewBeforeSet), out flagViewFromDB, out flagValueFromDB);

            bool flagValueAfterSet = multipleBinaryFlag.GetFlag();

            Assert.True(flagValueAfterSet == flagValueFromDB);

        }

        [Theory]
        [InlineData("T", true)]
        [InlineData("F", false)]
        [InlineData(" or 1=1;", false)]
        [InlineData(" or 1=1; drop table flags; ", false)]
        [InlineData("2333", false)]
        [InlineData("wdadwa dawdaw", false)]
        [InlineData("!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", false)]
        public void Test_AddFlag(string flagView, bool expectedResult)
        {
            Assert.Equal(flagPoleDB.AddFlag(flagView, true), expectedResult);
        }
    }
}
