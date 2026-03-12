using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector.Cryptography;

/// <summary>
/// Represents a passkey exported from KeePassXC (.passkey JSON format).
/// </summary>
public sealed class KeePassXCPasskey
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("relyingParty")]
    public string? RelyingParty { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("userHandle")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? UserHandle { get; set; }

    [JsonPropertyName("credentialId")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? CredentialId { get; set; }

    [JsonPropertyName("privateKey")]
    public string? PrivateKey { get; set; }

    /// <summary>
    /// Loads and deserializes a KeePassXC passkey from a JSON file.
    /// </summary>
    public static KeePassXCPasskey LoadFromFile(string filePath)
    {
        string json = File.ReadAllText(filePath);
        return JsonSerializer.Deserialize(json, WebAuthnJsonContext.Default.KeePassXCPasskey)
            ?? throw new JsonException("Failed to deserialize passkey file.");
    }

    /// <summary>
    /// Loads the private key from this passkey as an AsymmetricAlgorithm.
    /// The caller is responsible for disposing the returned key.
    /// </summary>
    public AsymmetricAlgorithm LoadPrivateKey()
    {
        if (PrivateKey == null)
            throw new InvalidOperationException("No private key found in passkey file.");

        return SoftwareAuthenticator.ImportPrivateKeyFromPem(PrivateKey);
    }
}
