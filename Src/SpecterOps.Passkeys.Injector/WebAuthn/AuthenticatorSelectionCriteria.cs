using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Criteria used to select an authenticator.
/// </summary>
public class AuthenticatorSelectionCriteria
{
    /// <summary>
    /// The preferred authenticator attachment modality.
    /// </summary>
    [JsonPropertyName("authenticatorAttachment")]
    public string? AuthenticatorAttachment { get; set; }

    /// <summary>
    /// The resident key requirement.
    /// </summary>
    [JsonPropertyName("residentKey")]
    public string? ResidentKey { get; set; }

    /// <summary>
    /// Whether a resident key is required.
    /// </summary>
    [JsonPropertyName("requireResidentKey")]
    public bool? RequireResidentKey { get; set; }

    /// <summary>
    /// The user verification requirement.
    /// </summary>
    [JsonPropertyName("userVerification")]
    public string? UserVerification { get; set; }
}
