using System.Security.Cryptography;

/// <summary>
/// This example is a naive implementation of the Diffie-Hellman key exchange.
/// It does not use large integers and primes.
/// It is not secure
/// </summary>
public class NaiveDiffieClient {
    public NaiveDiffieClient(int p = 23, int g = 5)
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