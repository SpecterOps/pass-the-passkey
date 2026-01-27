using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents an authenticator assertion response.
/// </summary>
public class AuthenticatorAssertionResponse
{
    /// <summary>
    /// Contains authenticator data (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("authenticatorData")]
    public string? AuthenticatorData { get; set; }

    /// <summary>
    /// The parsed authenticator data structure.
    /// </summary>
    [JsonIgnore]
    public AuthenticatorData? AuthenticatorDataParsed => AuthenticatorData != null ? SpecterOps.Passkeys.Injector.AuthenticatorData.Parse(AuthenticatorData) : null;

    /// <summary>
    /// The JSON-serialized client data passed to the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("clientDataJSON")]
    public string? ClientDataJSON { get; set; }

    /// <summary>
    /// The raw signature returned by the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    /// <summary>
    /// The user handle returned by the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; set; }

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
