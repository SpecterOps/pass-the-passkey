using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Describes the user account.
/// </summary>
public class PublicKeyCredentialUserEntity
{
    /// <summary>
    /// The user handle (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>
    /// The username.
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>
    /// The display name for the user.
    /// </summary>
    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    /// <summary>
    /// The user icon URL.
    /// </summary>
    [JsonPropertyName("icon")]
    public string? Icon { get; set; }
}
