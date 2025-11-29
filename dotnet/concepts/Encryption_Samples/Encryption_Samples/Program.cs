using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class SymmetricEncryptionExample
{
    static void Main()
    {
        string plainText = "Hello symmetric encryption!";

        // Create AES key (store this safely!)
        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        byte[] key = aes.Key;
        byte[] iv = aes.IV;

        Console.WriteLine("Key (Base64): " + Convert.ToBase64String(key));
        Console.WriteLine("IV  (Base64): " + Convert.ToBase64String(iv));
        Console.WriteLine();

        // Encrypt
        byte[] encrypted = EncryptString(plainText, key, iv);
        string encryptedBase64 = Convert.ToBase64String(encrypted);

        Console.WriteLine("Encrypted: " + encryptedBase64);

        // Decrypt
        string decrypted = DecryptString(encrypted, key, iv);
        Console.WriteLine("Decrypted: " + decrypted);
    }

    // Encrypt
    public static byte[] EncryptString(string text, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using MemoryStream ms = new MemoryStream();
        using (ICryptoTransform encryptor = aes.CreateEncryptor())
        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }

    // Decrypt
    public static string DecryptString(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using MemoryStream ms = new MemoryStream(cipherBytes);
        using (ICryptoTransform decryptor = aes.CreateDecryptor())
        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        using (MemoryStream plain = new MemoryStream())
        {
            cs.CopyTo(plain);
            return Encoding.UTF8.GetString(plain.ToArray());
        }
    }
}
