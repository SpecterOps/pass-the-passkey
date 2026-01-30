using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents the options for a WebAuthn credential request (navigator.credentials.get()).
/// </summary>
public class PublicKeyCredentialRequestOptions
{
    /// <summary>
    /// A challenge from the relying party's server.
    /// </summary>
    [JsonPropertyName("challenge")]
    [JsonRequired]
    public string? Challenge { get; set; }

    /// <summary>
    /// The time, in milliseconds, that the caller is willing to wait for the call to complete.
    /// </summary>
    [JsonPropertyName("timeout")]
    public uint? Timeout { get; set; }

    /// <summary>
    /// The relying party identifier.
    /// </summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; set; }

    /// <summary>
    /// A list of credentials acceptable to the caller.
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; set; }

    /// <summary>
    /// Describes the relying party's requirements regarding user verification.
    /// </summary>
    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; set; }

    /// <summary>
    /// Hints to the client about the preferred authenticator types.
    /// Values can be "security-key", "client-device", or "hybrid".
    /// </summary>
    [JsonPropertyName("hints")]
    public string[]? Hints { get; set; }

    /// <summary>
    /// Additional client extension inputs.
    /// </summary>
    [JsonPropertyName("extensions")]
    public JsonElement? Extensions { get; set; }

    public static PublicKeyCredentialRequestOptions? FromJson(string optionsJson)
    {
        try
        {
            return JsonSerializer.Deserialize(optionsJson, WebAuthnJsonContext.Default.PublicKeyCredentialRequestOptions);
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"PublicKeyCredentialRequestOptions JSON deserialization error: {ex.Message}");
            return null;
        }
    }

    override public string ToString()
    {
        return JsonSerializer.Serialize(this, WebAuthnJsonContext.Default.PublicKeyCredentialRequestOptions);
    }
}
