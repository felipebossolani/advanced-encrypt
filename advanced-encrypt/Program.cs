using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace advanced_encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(@"Creator: Felipe Bossolani - fbossolani[at]gmail.com");
            Console.WriteLine(@"Examples based on: http://returnsmart.blogspot.com/2015/10/mcsd-programming-in-c-part-11-70-483.html");
            Console.WriteLine("Choose a Crypto Method: ");
            Console.WriteLine("01- AES Encryption");
            Console.WriteLine("02- RSA Encryption");
            Console.WriteLine("03- RSA - Key Container - Encryption");
            Console.WriteLine("04- SecureString Example");

            int option = 0;
            int.TryParse(Console.ReadLine(), out option);

            switch (option)
            {
                case 1:
                    {
                        AESEncryption.EncryptSomeText();
                        break;
                    }
                case 2:
                    {
                        RSAEncryption.EncryptSomeText();
                        break;
                    }
                case 3:
                    {
                        RSAKeyContainerEncryption.EncryptSomeText();
                        break;
                    }
                case 4:
                    {
                        SecureStringExample.SecureAString();
                        break;
                    }
                default:
                    {
                        Console.WriteLine("Invalid option...");
                        break;
                    }
            }
        }
    }

    class SecureStringExample
    {
        public static void SecureAString()
        {
            using(SecureString ss = new SecureString())
            {
                Console.WriteLine("Please enter a password:");
                while (true)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(true);
                    if (cki.Key == ConsoleKey.Enter) break;

                    ss.AppendChar(cki.KeyChar);
                    Console.Write("*");
                }
                Console.WriteLine("\nPassword encrypted and stored succesfully!");
                ConvertToUnsecureString(ss);
                ss.MakeReadOnly();
            }
        }

        private static void ConvertToUnsecureString(SecureString securePassword)
        {
            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                Console.WriteLine(Marshal.PtrToStringUni(unmanagedString));
            }
            catch (Exception)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

    }

    class RSAKeyContainerEncryption
    {
        public static void EncryptSomeText()
        {
            Console.WriteLine("type any word to encrypt:");
            string original = Console.ReadLine();

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(original);

            string containerName = "MySecretContainer";
            CspParameters csp = new CspParameters() { KeyContainerName = containerName };

            byte[] encryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }

            byte[] decryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                decryptedData = rsa.Decrypt(encryptedData, false);
            }

            string decryptedString = ByteConverter.GetString(decryptedData);
            Console.WriteLine($"Original text: {original}");
            Console.WriteLine($"Decrypted: {decryptedString}");
        }
    }

    class RSAEncryption
    {
        private static string privateKeyXML;
        private static string publicKeyXML;

        public static void EncryptSomeText()
        {
            //Init Keys
            GenerateKeys();

            Console.WriteLine("type any word to encrypt:");
            string original = Console.ReadLine();

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(original);

            byte[] encryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXML);
                encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }

            byte[] decryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXML);
                decryptedData = rsa.Decrypt(encryptedData, false);
            }

            string decryptedString = ByteConverter.GetString(decryptedData);
            Console.WriteLine($"Original text: {original}");
            Console.WriteLine($"Decrypted: {decryptedString}");
        }

        private static void GenerateKeys()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                publicKeyXML = rsa.ToXmlString(false);
                privateKeyXML = rsa.ToXmlString(true);// true: exports the private part of your key
            }
        }
    }

    class AESEncryption
    {
        public static void EncryptSomeText()
        {
            Console.WriteLine("type any word to encrypt:");
            string original = Console.ReadLine();

            using (SymmetricAlgorithm symmetricAlgorithm = new AesManaged())
            {
                symmetricAlgorithm.Padding = PaddingMode.PKCS7;

                byte[] encrypted = Encrypt(symmetricAlgorithm, original);
                string roundtrip = Decrypt(symmetricAlgorithm, encrypted);

                Console.WriteLine($"Original text: {original}");
                Console.WriteLine($"Round Trip: {roundtrip}");
            }
        }

        private static string Decrypt(SymmetricAlgorithm aesAlg, byte[] cipherText)
        {
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        private static byte[] Encrypt(SymmetricAlgorithm aesAlg, string plainText)
        {
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }                
                return msEncrypt.ToArray();
            }
        }
    }
}
