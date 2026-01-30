using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Describes the parameters for credential creation.
/// </summary>
public class PublicKeyCredentialParameters
{
    /// <summary>
    /// The type of credential (e.g., "public-key").
    /// </summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>
    /// The COSE algorithm identifier.
    /// </summary>
    [JsonPropertyName("alg")]
    public int? Algorithm { get; set; }
}
