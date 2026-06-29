
namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Sent by the hook DLL when the WebAuthn assertion succeeds, carrying the full assertion response.
/// </summary>
internal sealed class AssertionCompletedMessage : HookPipeMessage
{
    /// <summary>Full assertion response object as returned by the WebAuthn API.</summary>
    [JsonPropertyName("payload")]
    public JsonElement Payload { get; init; }
}
