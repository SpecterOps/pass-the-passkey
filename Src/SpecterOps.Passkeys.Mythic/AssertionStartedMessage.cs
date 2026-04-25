using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Sent by the hook DLL immediately before invoking the real WebAuthn API.
/// Carries context about the assertion ceremony and the process that initiated it.
/// </summary>
internal sealed class AssertionStartedMessage : HookPipeMessage
{
    /// <summary>Relying party identifier from the WebAuthn assertion request.</summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }

    /// <summary>Image name (without extension) of the browser process that triggered the assertion.</summary>
    [JsonPropertyName("processName")]
    public string? ProcessName { get; init; }

    /// <summary>Windows user name running the browser process.</summary>
    [JsonPropertyName("userName")]
    public string? UserName { get; init; }

    /// <summary>Process ID of the browser that triggered the assertion.</summary>
    [JsonPropertyName("pid")]
    public int Pid { get; init; }
}
