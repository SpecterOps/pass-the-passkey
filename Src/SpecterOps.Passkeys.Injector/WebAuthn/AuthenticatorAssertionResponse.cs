using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents an authenticator assertion response.
/// </summary>
public class AuthenticatorAssertionResponse : AuthenticatorResponse
{
    /// <summary>
    /// Contains authenticator data (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("authenticatorData")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? AuthenticatorData { get; set; }

    /// <summary>
    /// The parsed authenticator data structure.
    /// </summary>
    [JsonIgnore]
    public AuthenticatorData? AuthenticatorDataParsed => AuthenticatorData != null ? SpecterOps.Passkeys.Injector.AuthenticatorData.Parse(AuthenticatorData) : null;

    /// <summary>
    /// The raw signature returned by the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("signature")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? Signature { get; set; }

    /// <summary>
    /// The user handle returned by the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("userHandle")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public byte[]? UserHandle { get; set; }

    public static AuthenticatorAssertionResponse? FromJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, WebAuthnJsonContext.Default.AuthenticatorAssertionResponse);
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"AuthenticatorAssertionResponse JSON deserialization error: {ex.Message}");
            return null;
        }
    }

    public override string ToString()
    {
        return JsonSerializer.Serialize(this, WebAuthnJsonContext.Default.AuthenticatorAssertionResponse);
    }
}
