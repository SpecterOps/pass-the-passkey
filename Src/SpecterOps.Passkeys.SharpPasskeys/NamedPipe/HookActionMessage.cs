
namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Instruction sent by the pipe server to the native WebAuthn hook after an assertion-started message.
/// </summary>
internal sealed class HookActionMessage
{
    /// <summary>Action the hook should take for the intercepted assertion ceremony.</summary>
    [JsonPropertyName("action")]
    [JsonRequired]
    public HookAction Action { get; init; }

    /// <summary>Optional base64url-encoded challenge used with <see cref="HookAction.Inject"/>.</summary>
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Challenge { get; init; }
}
