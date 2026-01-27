using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Describes a credential for use with credential retrieval.
/// </summary>
public class PublicKeyCredentialDescriptor
{
    /// <summary>
    /// The type of the credential.
    /// </summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>
    /// The credential identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>
    /// Hints as to how the client might communicate with the authenticator.
    /// </summary>
    [JsonPropertyName("transports")]
    public string[]? Transports { get; set; }
}
