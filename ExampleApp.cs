using System.Security.Cryptography;

namespace diffie;

public class ExampleApp
{
    public void Run() {
        Console.WriteLine("--- Diffie Hellman example ---");

        // set up two diffie clients, with the same prime and generator argument
        // They generate their own private/public key pairs
        var client1 = new DiffieClient();
        var client2 = new DiffieClient();

        // Creating a shared key is as simple as passing the other client's public key to the SharedKey method
        Console.WriteLine("--- Generating shared key using Diffie Hellman algo:");
        Console.WriteLine(Convert.ToHexString(client1.SharedKey(client2.PublicKey)));
        Console.WriteLine();
        
        
        // write secret message
        var sharedKey1 = client1.SharedKey(client2.PublicKey);
        var encryptedMessage = EncryptMessage("Hello encrypted world", sharedKey1);
        Console.WriteLine("Encrypted message:");
        Console.WriteLine(Convert.ToHexString(encryptedMessage));
        
        // read secret message
        var sharedKey2 = client2.SharedKey(client1.PublicKey);
        var decryptedMessage = DecryptMessage(encryptedMessage, sharedKey2);
        Console.WriteLine("Decrypted message:");
        Console.WriteLine(decryptedMessage);

        Console.WriteLine("---------------------------------");
    }

    private string DecryptMessage(byte[] encryptedMessage, byte[] sharedKey)
    {
        using var aes = Aes.Create();
        using var ms = new MemoryStream(encryptedMessage);
        
        // read iv from memory stream
        var iv = new byte[aes.IV.Length];
        var readCount = ms.Read(iv, 0, iv.Length);

        // Use crypto stream to decrypt message
        using var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(sharedKey, iv), CryptoStreamMode.Read);
        using var decryptor = new StreamReader(cryptoStream);
        var decryptedMessage = decryptor.ReadToEnd();
        
        return decryptedMessage;
    }

    private byte[] EncryptMessage(string message, byte[] key)
    {
        using var memStream = new MemoryStream();
        using var aes = Aes.Create();

        aes.Key = key;
        var iv = aes.IV;
        memStream.Write(iv,0,iv.Length);

        using var writeCrypto = new CryptoStream(memStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        using var encrypt = new StreamWriter(writeCrypto);
        
        encrypt.WriteLine(message);
        
        // Manual flush needed when using new scoped `using var` syntax
        encrypt.Flush();
        writeCrypto.FlushFinalBlock();
        
        var cipher = memStream.ToArray();

        return cipher;
    }
}