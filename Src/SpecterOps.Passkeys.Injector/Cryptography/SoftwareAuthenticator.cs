using System.IO;
using System.Security.Cryptography;

namespace SpecterOps.Passkeys.Injector.Cryptography;

/// <summary>
/// Software-based authenticator that signs WebAuthn assertion requests using a PEM private key.
/// </summary>
public static class SoftwareAuthenticator
{
    /// <summary>
    /// Builds a complete assertion response signed with the given private key.
    /// </summary>
    public static PublicKeyCredential GetAssertion(
        string relyingPartyId,
        byte[] challenge,
        Algorithm algorithm,
        uint signatureCounter,
        AuthenticatorFlags flags,
        byte[] credentialId,
        byte[]? userHandle,
        AsymmetricAlgorithm privateKey)
    {
        ArgumentNullException.ThrowIfNull(relyingPartyId);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(privateKey);

        byte[] authenticatorData = AuthenticatorData.Build(relyingPartyId, flags, signatureCounter);

        byte[] clientDataJson = CollectedClientData.Serialize(WebAuthnConstants.ClientDataTypeGet, challenge, relyingPartyId);
        byte[] clientDataHash = SHA256.HashData(clientDataJson);

        byte[] dataToSign = ConcatArrays(authenticatorData, clientDataHash);
        byte[] signature = Sign(privateKey, dataToSign, algorithm);

        return new PublicKeyCredential
        {
            Id = credentialId,
            RawId = credentialId,
            Type = WebAuthnConstants.PublicKeyCredentialType,
            Response = new AuthenticatorAssertionResponse
            {
                ClientDataJSON = clientDataJson,
                AuthenticatorData = authenticatorData,
                Signature = signature,
                UserHandle = userHandle
            }
        };
    }

    /// <summary>
    /// Loads a private key from a PEM file. The caller is responsible for disposing the returned key.
    /// </summary>
    public static AsymmetricAlgorithm LoadPrivateKeyFromPem(string pemFilePath)
    {
        ArgumentNullException.ThrowIfNull(pemFilePath);

        string pem = File.ReadAllText(pemFilePath);
        return ImportPrivateKeyFromPem(pem);
    }

    /// <summary>
    /// Imports a private key from a PEM string. The caller is responsible for disposing the returned key.
    /// </summary>
    public static AsymmetricAlgorithm ImportPrivateKeyFromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);

        // Try EC first, then RSA, then Ed25519
        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return ecdsa;
        }
        catch (Exception)
        {
            // Not an EC key, try RSA
        }

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception)
        {
            // Not an RSA key, try Ed25519
        }

        try
        {
            var ed25519 = Ed25519.Create();
            ed25519.ImportFromPem(pem);
            return ed25519;
        }
        catch (Exception)
        {
            // Not an Ed25519 key
        }

        throw new CryptographicException("The PEM data does not contain a supported private key (EC, RSA, or Ed25519).");
    }

    /// <summary>
    /// Determines the COSE algorithm that matches the given private key.
    /// </summary>
    public static Algorithm DetectAlgorithm(AsymmetricAlgorithm key)
    {
        return key switch
        {
            ECDsa ecdsa => ecdsa.KeySize switch
            {
                256 => Algorithm.ES256,
                384 => Algorithm.ES384,
                521 => Algorithm.ES512,
                _ => throw new NotSupportedException($"Unsupported EC key size: {ecdsa.KeySize}")
            },
            RSA => Algorithm.RS256,
            Ed25519 => Algorithm.EdDSA,
            _ => throw new NotSupportedException($"Unsupported key type: {key.GetType().Name}")
        };
    }

    private static byte[] Sign(AsymmetricAlgorithm key, byte[] data, Algorithm algorithm)
    {
        HashAlgorithmName hashAlg = GetHashAlgorithm(algorithm);

        if (key is Ed25519 ed25519)
        {
            return ed25519.SignData(data, hashAlg);
        }

        if (key is ECDsa ecdsa)
        {
            return ecdsa.SignData(data, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
        }
        else if (key is RSA rsa)
        {
            RSASignaturePadding padding = GetRsaPadding(algorithm);
            return rsa.SignData(data, hashAlg, padding);
        }

        throw new NotSupportedException($"Unsupported key type for signing: {key.GetType().Name}");
    }

    internal static string GetAlgorithmName(Algorithm algorithm) => algorithm switch
    {
        Algorithm.ES256 or Algorithm.ES384 or Algorithm.ES512 or Algorithm.ES256K => "ECDSA",
        Algorithm.EdDSA => "EdDSA",
        Algorithm.RS256 or Algorithm.RS384 or Algorithm.RS512 or Algorithm.RS1 => "RSASSA-PKCS1-v1_5",
        Algorithm.PS256 or Algorithm.PS384 or Algorithm.PS512 => "RSASSA-PSS",
        _ => algorithm.ToString()
    };

    internal static string? GetKeyType(Algorithm algorithm) => algorithm switch
    {
        Algorithm.EdDSA => "Ed25519",
        Algorithm.ES256 => "P-256",
        Algorithm.ES384 => "P-384",
        Algorithm.ES512 => "P-521",
        Algorithm.RS256 or Algorithm.RS384 or Algorithm.RS512 or Algorithm.RS1
            or Algorithm.PS256 or Algorithm.PS384 or Algorithm.PS512 => "RSA",
        _ => null
    };

    internal static int? GetKeyLength(Algorithm algorithm) => algorithm switch
    {
        Algorithm.ES256 or Algorithm.ES256K or Algorithm.EdDSA => 256,
        Algorithm.ES384 => 384,
        Algorithm.ES512 => 521,
        Algorithm.RS256 or Algorithm.RS384 or Algorithm.RS512 or Algorithm.RS1
            or Algorithm.PS256 or Algorithm.PS384 or Algorithm.PS512 => 2048,
        _ => null
    };

    internal static HashAlgorithmName GetHashAlgorithm(Algorithm algorithm)
    {
        return algorithm switch
        {
            Algorithm.ES256 or Algorithm.RS256 or Algorithm.PS256 => HashAlgorithmName.SHA256,
            Algorithm.ES384 or Algorithm.RS384 or Algorithm.PS384 => HashAlgorithmName.SHA384,
            Algorithm.ES512 or Algorithm.RS512 or Algorithm.PS512 => HashAlgorithmName.SHA512,
            Algorithm.RS1 => HashAlgorithmName.SHA1,
            Algorithm.EdDSA => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }

    private static RSASignaturePadding GetRsaPadding(Algorithm algorithm)
    {
        return algorithm switch
        {
            Algorithm.PS256 or Algorithm.PS384 or Algorithm.PS512 => RSASignaturePadding.Pss,
            Algorithm.RS256 or Algorithm.RS384 or Algorithm.RS512 or Algorithm.RS1 => RSASignaturePadding.Pkcs1,
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not an RSA algorithm.")
        };
    }

    private static byte[] ConcatArrays(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
