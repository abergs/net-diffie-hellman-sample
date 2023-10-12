// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;

Console.WriteLine("Hello, World!");


// Goal: Create a shared key by using Diffie hellman
// Both of these are global/public
var p = 23;
var g = 5;

var client1 = new DiffieClient(p,g);
var client2 = new DiffieClient(p,g);

Console.WriteLine("--- Private keys");
Console.WriteLine("Client 1: " + client1.PrivateKey);
Console.WriteLine("Client 2: " + client2.PrivateKey);


Console.WriteLine("--- Public keys");
Console.WriteLine("Client 1: " + client1.PublicKey);
Console.WriteLine("Client 2: " + client2.PublicKey);

// Handshake - Trade public keys
// Public landscape

// Create message and encrypt it
var sharedKey1 = client1.GenerateSharedKey(client2.PublicKey);
var sharedKey2 = client1.GenerateSharedKey(client2.PublicKey);

Console.WriteLine("--- Shared keys");
Console.WriteLine("Client 1: " + client1.GenerateSharedKey(client2.PublicKey));
Console.WriteLine("Client 2: " + client2.GenerateSharedKey(client1.PublicKey));




public class DiffieClient {
    public DiffieClient(int p = 23, int g = 5)
    {
        _p = p;
        _g = g;

        // Generate key pair, maximum int??
        PrivateKey = RandomNumberGenerator.GetInt32(1000) + 1;
        PublicKey = Math.Pow(g, PrivateKey) % _p;
    }

    private int _p;
    private int _g;

    public double PublicKey { get; set; }
    
    public double PrivateKey { get; set; }

    public double GenerateSharedKey(double otherKey) {
        double sharedkey = Math.Pow(otherKey, PrivateKey) % _p;
        return sharedkey;
    }
}