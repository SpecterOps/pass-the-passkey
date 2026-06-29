namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Sent by the hook DLL immediately before invoking the real WebAuthn API.
/// Carries context about the assertion ceremony specific to this message type.
/// Common context (pid, processName, userName, timestamp) is on the base class.
/// </summary>
internal sealed class AssertionStartedMessage : HookPipeMessage
{
}
