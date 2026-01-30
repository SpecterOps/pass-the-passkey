using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents the options for a WebAuthn credential creation (navigator.credentials.create()).
/// </summary>
public class PublicKeyCredentialCreationOptions
{
    /// <summary>
    /// Relying party information.
    /// </summary>
    [JsonPropertyName("rp")]
    public PublicKeyCredentialRpEntity? RelyingParty { get; set; }

    /// <summary>
    /// User account information.
    /// </summary>
    [JsonPropertyName("user")]
    public PublicKeyCredentialUserEntity? User { get; set; }

    /// <summary>
    /// A challenge from the relying party's server.
    /// </summary>
    [JsonPropertyName("challenge")]
    [JsonRequired]
    public string? Challenge { get; set; }

    /// <summary>
    /// Parameters for the credential to be created.
    /// </summary>
    [JsonPropertyName("pubKeyCredParams")]
    public PublicKeyCredentialParameters[]? PubKeyCredParams { get; set; }

    /// <summary>
    /// The time, in milliseconds, that the caller is willing to wait for the call to complete.
    /// </summary>
    [JsonPropertyName("timeout")]
    public uint? Timeout { get; set; }

    /// <summary>
    /// A list of credentials to exclude from registration.
    /// </summary>
    [JsonPropertyName("excludeCredentials")]
    public PublicKeyCredentialDescriptor[]? ExcludeCredentials { get; set; }

    /// <summary>
    /// The authenticator selection criteria.
    /// </summary>
    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

    /// <summary>
    /// The preferred attestation conveyance.
    /// </summary>
    [JsonPropertyName("attestation")]
    public string? Attestation { get; set; }

    /// <summary>
    /// Preferred attestation statement formats.
    /// </summary>
    [JsonPropertyName("attestationFormats")]
    public string[]? AttestationFormats { get; set; }

    /// <summary>
    /// Additional client extension inputs.
    /// </summary>
    [JsonPropertyName("extensions")]
    public JsonElement? Extensions { get; set; }

    /// <summary>
    /// UI hints for preferred authenticator types.
    /// </summary>
    [JsonPropertyName("hints")]
    public string[]? Hints { get; set; }

    public static PublicKeyCredentialCreationOptions? FromJson(string optionsJson)
    {
        try
        {
            return JsonSerializer.Deserialize(optionsJson, WebAuthnJsonContext.Default.PublicKeyCredentialCreationOptions);
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"PublicKeyCredentialCreationOptions JSON deserialization error: {ex.Message}");
            return null;
        }
    }

    public override string ToString()
    {
        return JsonSerializer.Serialize(this, WebAuthnJsonContext.Default.PublicKeyCredentialCreationOptions);
    }
}
