using KalkanCryptCOMLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PRG.DS.INFRASTRUCTURE.Tests
{
    public class MyTest
    {
        const string Algorithm = "sha256";
        KalkanCryptCOM _kalkanCryptCom = new KalkanCryptCOM();
        public MyTest()
        {
            _kalkanCryptCom.Init();
        }

        [Fact]
        public async System.Threading.Tasks.Task HashDataTest()
        {

            var dataInBase64 = System.Convert.ToBase64String(Encoding.UTF8.GetBytes("Test Hello World"));

            var flags = KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 | KALKANCRYPTCOM_FLAGS.KC_IN_BASE64;
            _kalkanCryptCom.HashData(Algorithm, (int)flags, dataInBase64, out string hash1);

            var flags2 = KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
            _kalkanCryptCom.HashData(Algorithm, (int)flags2, "Test Hello World", out string hash2);


            Assert.Equal(hash1, hash2);
            Assert.Equal("nzHl96RiZbOYbsDisNV9b1Yn0b6hE+xBecJimFVYf9s=", hash1);
        }

        [Fact]
        public async System.Threading.Tasks.Task HashBytesTest()
        {

            var hash1 = await HashBytes(Encoding.UTF8.GetBytes("Test Hello World"));

            // файл содержит ту же строку "Test Hello World"
            var buffer = System.IO.File.ReadAllBytes("test.txt");

            var hash2 = await HashBytes(buffer);

            Assert.Equal(hash1, hash2);
            Assert.Equal("bLmE4owZ0vGwpP8zi28Z7aWxok+sRfAXbWkVcSa0H+8=", hash1);
        }


        public Task<string> HashBytes(byte[] buffer)
        {
            var flags = KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;

            _kalkanCryptCom.HashDataBytes(Algorithm, (int)flags, ref buffer[0], buffer.Length, out string outData);

            return Task.FromResult(outData);
        }

        [Fact]
        public async System.Threading.Tasks.Task HashBytesTest1()
        {

            string outData = "", err_str = "";
            uint err = 0;
            byte[] inData = { };
            var kalkanFlags = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 | (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS;
            inData = File.ReadAllBytes("test.txt");
            int inDataLength = inData.GetLength(0);
            _kalkanCryptCom.HashDataBytes("sha256", kalkanFlags, ref inData[0], inDataLength, out outData);
            _kalkanCryptCom.GetLastErrorString(out err_str, out err);

            Assert.Equal("w51299ciznie2FDnrqB+r/GwzJvlGjx9vQgcJle1DIE=", outData);
        }

        [Fact]
        public async System.Threading.Tasks.Task HashBytesTest2()
        {
            var kalkanFlags = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 | (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS;
            string outData = "", err_str = "";
            uint err = 0;
            var inData = "Test Hello World";
            _kalkanCryptCom.HashData("sha256", kalkanFlags, inData, out outData);
            _kalkanCryptCom.GetLastErrorString(out err_str, out err);

            Assert.Equal("nzHl96RiZbOYbsDisNV9b1Yn0b6hE+xBecJimFVYf9s=", outData);
        }
    


    }
}
