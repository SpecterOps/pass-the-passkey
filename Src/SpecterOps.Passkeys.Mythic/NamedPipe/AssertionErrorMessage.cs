using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Sent by the hook DLL when the WebAuthn API returns a failure HRESULT.
/// </summary>
internal sealed class AssertionErrorMessage : HookPipeMessage
{
    /// <summary>Relying party identifier from the WebAuthn assertion request.</summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }

    /// <summary>HRESULT returned by the WebAuthn API when the assertion failed.</summary>
    [JsonPropertyName("hresult")]
    public uint HResult { get; init; }
}
