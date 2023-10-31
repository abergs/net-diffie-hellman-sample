using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace diffie;

public class DiffieClient
{
    private BigInteger _privateKey;
    private BigInteger _publicKey;
    private BigInteger _prime;

    /// <summary>
    /// Uses default parameters and prime
    /// </summary>
    public DiffieClient()
    {
        // Prefix with 0 to make sure it's positive, that's how BigInteger parses hex values.
        var rawPrime = 0 + "8d13beca6787cae7b74fe114312acd598d9a52ebfb53644ce154c4256fa9fca6e5b76d1129b5f8917ccf2ce7a11f1c6dfa4bcf8e2bca5bb78395d3118848e2a565398fb9f8d1ae35f78cd7abb9386c44f792617fb8ae19dd347f2cb8730040205ee71589e474abe4e1dc0f80c70ba68006f9772b24446633ba1f5844c52a5ab3";
        var sharedPrime = BigInteger.Parse(rawPrime, NumberStyles.HexNumber);
        
        var g = 5; // Generator
        var keyLength = 540;
        
        Init(g, sharedPrime, keyLength);
    }
    public DiffieClient(int g, BigInteger prime, int keyLength)
    {
        Init(g, prime, keyLength);
    }

    private void Init(int g, BigInteger prime, int keyLength)
    {
        _prime = prime;
        var byteLength = (keyLength / 8) + 8;
        var pkBytes = RandomNumberGenerator.GetBytes(byteLength);
        var pkHex = 0 + Convert.ToHexString(pkBytes);
        var pk = BigInteger.Parse(pkHex, NumberStyles.HexNumber);

        _privateKey = pk;
        _publicKey = BigInteger.ModPow(g, pk, prime);
    }

    public BigInteger PublicKey => _publicKey;
    public BigInteger PrivateKey => _privateKey;

    public byte[] SharedKey(BigInteger otherPublicKey)
    {
        var pk = BigInteger.ModPow(otherPublicKey, _privateKey, _prime);

        var h = SHA256.HashData(pk.ToByteArray());
        return h;
    }
}