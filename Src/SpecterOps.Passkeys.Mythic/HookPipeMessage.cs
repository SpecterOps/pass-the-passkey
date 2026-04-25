using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Discriminator values used in the <c>type</c> field of every pipe message sent by the hook DLL.
/// New values may be introduced in future versions of the hook DLL; unknown types are ignored.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<HookMessageType>))]
internal enum HookMessageType
{
    [JsonStringEnumMemberName("AssertionStarted")]
    AssertionStarted,

    [JsonStringEnumMemberName("AssertionCompleted")]
    AssertionCompleted,

    [JsonStringEnumMemberName("AssertionError")]
    AssertionError,
}

/// <summary>
/// Represents a single pipe message sent by the hook DLL.
/// Each message carries a <see cref="Type"/> discriminator; only the fields relevant to that type are populated.
/// </summary>
internal sealed class HookPipeMessage
{
    /// <summary>Identifies the kind of event this message represents.</summary>
    [JsonPropertyName("type")]
    public HookMessageType Type { get; init; }

    // ── AssertionStarted fields ──────────────────────────────────────────

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

    // ── AssertionCompleted fields ────────────────────────────────────────

    /// <summary>Full assertion response object as returned by the WebAuthn API.</summary>
    [JsonPropertyName("payload")]
    public JsonElement Payload { get; init; }

    // ── AssertionError fields ────────────────────────────────────────────

    /// <summary>HRESULT returned by the WebAuthn API when the assertion failed.</summary>
    [JsonPropertyName("hresult")]
    public uint HResult { get; init; }
}

/// <summary>
/// Source-generated JSON serialization context for <see cref="HookPipeMessage"/> and its enum discriminator.
/// </summary>
[JsonSerializable(typeof(HookPipeMessage))]
[JsonSerializable(typeof(HookMessageType))]
internal sealed partial class HookPipeMessageJsonContext : JsonSerializerContext
{
}
