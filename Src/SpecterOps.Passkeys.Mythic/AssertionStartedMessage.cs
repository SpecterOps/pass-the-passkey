using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Sent by the hook DLL immediately before invoking the real WebAuthn API.
/// Carries context about the assertion ceremony specific to this message type.
/// Common context (pid, processName, userName, timestamp) is on the base class.
/// </summary>
internal sealed class AssertionStartedMessage : HookPipeMessage
{
    /// <summary>Relying party identifier from the WebAuthn assertion request.</summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }
}
