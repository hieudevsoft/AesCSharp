using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
namespace Aes_Bin_Tam
{
    public class Encryption
    {
        private static Aes aes;
        private static byte[] plaintext;
        private static byte[] cipherText;
        public static void ECBEncryptionWithKey()
        {
            while (true)
            {
                try
                {
                    Console.Write("Plain text: ");
                    String plainText = Console.ReadLine();
                    Console.Write("Key: ");
                    String keyInput = Console.ReadLine();
                    byte[] inputText = Encoding.UTF8.GetBytes(pushDataToBlock(plainText));
                    byte[] key;
                    key = Encoding.UTF8.GetBytes(keyInput);
                    aes = new Aes(key);
                    long startTime = nanoTime();
                    Console.WriteLine("Plain text: " + plainText);
                    byte[] cipherBytes = aes.ECB_encrypt(inputText);
                    String a = Encoding.UTF8.GetString(cipherBytes);
                    Console.WriteLine("Cipher text: " + a.Trim());
                    long endTime = nanoTime();
                    Console.WriteLine("ECB Encryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    startTime = nanoTime();
                    Console.WriteLine("Cipher text: " + a.Trim());
                    plainText = Encoding.UTF8.GetString(aes.ECB_decrypt(cipherBytes));
                    Console.WriteLine("Plain text: " + plainText);
                    endTime = nanoTime();
                    Console.WriteLine("ECB Decryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    plaintext = inputText;
                    cipherText = cipherBytes;
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Vui lòng nhập lại: ");
                    Console.WriteLine(e.Data);
                }
            }
        }

        public static void ECBEncryptionWithRandomKey()
        {
            while (true)
            {
                try
                {
                    Console.Write("Plain text: ");
                    String plainText = Console.ReadLine();
                    byte[] inputText = Encoding.UTF8.GetBytes(pushDataToBlock(plainText));
                    byte[] key;
                    key = makeRandomKey();
                    Console.WriteLine("Random Key: " + Encoding.UTF8.GetString(key));
                    aes = new Aes(key);
                    long startTime = nanoTime();
                    byte[] cipherBytes = aes.ECB_encrypt(inputText);
                    String a = Encoding.UTF8.GetString(cipherBytes);
                    Console.WriteLine("Cipher text: " + a.Trim());
                    long endTime = nanoTime();
                    Console.WriteLine("ECB Encryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    startTime = nanoTime();
                    Console.WriteLine("Cipher text: " + a.Trim());
                    plainText = Encoding.UTF8.GetString(aes.ECB_decrypt(cipherBytes));
                    Console.WriteLine("Plain text: " + plainText);
                    endTime = nanoTime();
                    Console.WriteLine("ECB Decryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    plaintext = inputText;
                    cipherText = cipherBytes;
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Vui lòng nhập lại: ");
                    Console.WriteLine(e.Data);
                }
            }
        }

        public static void CBCEncryptionWithKey()
        {
            while (true)
            {
                try
                {
                    Console.Write("Plain text: ");
                    String plainText = Console.ReadLine();
                    Console.Write("Key: ");
                    String keyInput = Console.ReadLine();
                    Console.Write("Initialisation vector: ");
                    String ivInput = Console.ReadLine();
                    byte[] inputText = Encoding.UTF8.GetBytes(pushDataToBlock(plainText));
                    byte[] key;
                    key = Encoding.UTF8.GetBytes(keyInput);
                    byte[] iv = key = Encoding.UTF8.GetBytes(ivInput);
                    aes = new Aes(key, iv);
                    long startTime = nanoTime();
                    Console.WriteLine("Plain text: " + plainText);
                    byte[] cipherBytes = aes.CBC_encrypt(inputText);
                    String a = Encoding.UTF8.GetString(cipherBytes);
                    Console.WriteLine("Cipher text: " + a.Trim());
                    long endTime = nanoTime();
                    Console.WriteLine("CBC Encryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    startTime = nanoTime();
                    Console.WriteLine("Cipher text: " + a.Trim());
                    plainText = Encoding.UTF8.GetString(aes.CBC_encrypt(cipherBytes));
                    Console.WriteLine("Plain text: " + plainText);
                    endTime = nanoTime();
                    Console.WriteLine("CBC Decryption | " + ((float)(endTime - startTime) / 1000.00) + "ms");
                    plaintext = inputText;
                    cipherText = cipherBytes;
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Vui lòng nhập lại: ");
                    Console.WriteLine(e.Data);
                }
            }
        }

        public static void CBCEncryptionWithRandomKey()
        {
            while (true)
            {
                try
                {
                    Console.Write("Plain text: ");
                    String plainText = Console.ReadLine();
                    byte[] inputText = Encoding.UTF8.GetBytes(pushDataToBlock(plainText));
                    byte[] key;
                    key = makeRandomKey();
                    Console.WriteLine("Random Key: " + Encoding.UTF8.GetString(key));
                    byte[] iv = makeRandomIv();
                    aes = new Aes(key, iv);
                    long startTime = nanoTime();
                    byte[] cipherBytes = aes.CBC_encrypt(inputText);
                    String a = Encoding.UTF8.GetString(cipherBytes);
                    Console.WriteLine("Cipher text: " + a.Trim());
                    String b = Encoding.UTF8.GetString(iv);
                    Console.WriteLine("Iv: " + b.Trim());
                    long endTime = nanoTime();
                    Console.WriteLine("CBC Encryption | " + ((float)(endTime - startTime) / 1000000f) + "ms");
                    startTime = nanoTime();
                    Console.WriteLine("Cipher text: " + a.Trim());
                    plainText = Encoding.UTF8.GetString(aes.CBC_decrypt(cipherBytes));
                    Console.WriteLine("Plain text: " + plainText);
                    endTime = nanoTime();
                    Console.WriteLine("CBC Decryption | " + ((float)(endTime - startTime) / 1000000f) + "ms");
                    plaintext = inputText;
                    cipherText = cipherBytes;
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Vui lòng nhập lại: ");
                    Console.WriteLine(e.Data);
                }
            }
        }

        public static void diffBit()
        {
            Console.WriteLine("Plain text: " + Encoding.UTF8.GetString(plaintext));
            Console.WriteLine("Cipher text: " + Encoding.UTF8.GetString(cipherText));
            Console.WriteLine("Số bits khác biệt: " + numBitDiff(plaintext, cipherText));
        }

        private static String pushDataToBlock(String text)
        {
            int spaceNum = Encoding.UTF8.GetBytes(text).Length % 16 == 0 ? 0 : 16 -  Encoding.UTF8.GetBytes(text).Length % 16;
            StringBuilder textBuilder = new StringBuilder(text);
            for(int i = 0; i< spaceNum;i++){
            textBuilder.Append(" ");
            }
            text = textBuilder.ToString();
            return text;
        }

        private static byte[] makeRandomKey()
        {
            var rng = new RNGCryptoServiceProvider();
            long length = new Random().NextInt64(2);
            switch (length)
            {
                case 1:
                    {
                        byte[] bytes = new byte[24];
                        rng.GetBytes(bytes);
                        return bytes;
                    }
                case 2:
                    {
                        byte[] bytes = new byte[32];
                        rng.GetBytes(bytes);
                        return bytes;
                    }
                default:
                    {
                        byte[] bytes = new byte[16];
                        rng.GetBytes(bytes);
                        return bytes;
                    }
            }
        }

        private static byte[] makeRandomIv()
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[16];
            rng.GetBytes(bytes);
            return bytes;
        }

        private static int numBitDiff(byte[] a, byte[] b)
        {
            int num = 0;
            byte[] result = new byte[Math.Min(a.Length, b.Length)];
            for (int j = 0; j < result.Length; j++)
            {
                int xor = a[j] ^ b[j];
                while (xor > 0)
                {
                    int temp = xor % 2;
                    if (temp == 1) num++;
                    xor /= 2;
                }
            }
            return num;
        }
        private static long nanoTime()
        {
            long nano = 10000L * Stopwatch.GetTimestamp();
            nano /= TimeSpan.TicksPerMillisecond;
            nano *= 100L;
            return nano;
        }
    }
}