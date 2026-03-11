using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents a WebAuthn credential response.
/// </summary>
public class PublicKeyCredential
{
    /// <summary>
    /// The credential identifier (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("id")]
    [JsonRequired]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? Id { get; set; }

    /// <summary>
    /// The raw credential identifier (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("rawId")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? RawId { get; set; }

    /// <summary>
    /// The type of the credential (always "public-key").
    /// </summary>
    [JsonPropertyName("type")]
    [JsonRequired]
    public string Type { get; set; } = WebAuthnConstants.PublicKeyCredentialType;

    /// <summary>
    /// The authenticator's response.
    /// </summary>
    [JsonPropertyName("response")]
    [JsonRequired]
    [JsonConverter(typeof(AuthenticatorResponseJsonConverter))]
    public AuthenticatorResponse? Response { get; set; }

    /// <summary>
    /// The authenticator attachment modality.
    /// </summary>
    [JsonPropertyName("authenticatorAttachment")]
    public string? AuthenticatorAttachment { get; set; }

    /// <summary>
    /// Client extension results.
    /// </summary>
    [JsonPropertyName("clientExtensionResults")]
    public JsonElement? ClientExtensionResults { get; set; }

    public static PublicKeyCredential? FromJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, WebAuthnJsonContext.Default.PublicKeyCredential);
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"PublicKeyCredentialJSON deserialization error: {ex.Message}");
            return null;
        }
    }

    override public string ToString()
    {
        return JsonSerializer.Serialize(this, WebAuthnJsonContext.Default.PublicKeyCredential);
    }
}
