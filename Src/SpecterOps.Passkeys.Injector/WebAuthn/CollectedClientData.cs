using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// The client data collected during a WebAuthn ceremony, serialized as the clientDataJSON field.
/// Property declaration order is significant: the WebAuthn spec requires type → challenge → origin → crossOrigin.
/// </summary>
internal sealed class CollectedClientData
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("challenge")]
    [JsonConverter(typeof(Base64UrlJsonConverter))]
    public required byte[] Challenge { get; init; }

    [JsonPropertyName("origin")]
    public required string Origin { get; init; }

    [JsonPropertyName("crossOrigin")]
    public bool CrossOrigin { get; init; }

    public static byte[] Serialize(string type, byte[] challenge, string rpId) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new CollectedClientData { Type = type, Challenge = challenge, Origin = $"https://{rpId}" },
            WebAuthnJsonContext.Default.CollectedClientData);
}
