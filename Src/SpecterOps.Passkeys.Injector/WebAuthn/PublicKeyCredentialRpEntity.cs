using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Describes the relying party.
/// </summary>
public class PublicKeyCredentialRpEntity
{
    /// <summary>
    /// The relying party identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>
    /// The relying party name.
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>
    /// The relying party icon URL.
    /// </summary>
    [JsonPropertyName("icon")]
    public string? Icon { get; set; }
}
