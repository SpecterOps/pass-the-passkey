using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Base type for authenticator responses.
/// </summary>
public abstract class AuthenticatorResponse
{
    /// <summary>
    /// The JSON-serialized client data passed to the authenticator (Base64Url encoded).
    /// </summary>
    [JsonPropertyName("clientDataJSON")]
    public string? ClientDataJSON { get; set; }
}
