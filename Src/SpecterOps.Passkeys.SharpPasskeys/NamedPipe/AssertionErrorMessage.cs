
namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Sent by the hook DLL when the WebAuthn API returns a failure HRESULT.
/// </summary>
internal sealed class AssertionErrorMessage : HookPipeMessage
{
    /// <summary>HRESULT returned by the WebAuthn API when the assertion failed.</summary>
    [JsonPropertyName("hresult")]
    public uint HResult { get; init; }
}
