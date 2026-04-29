using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Action values the pipe server can send back to the native WebAuthn hook.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<HookAction>))]
internal enum HookAction
{
    /// <summary>Continue the intercepted WebAuthn assertion normally and return its result to the caller.</summary>
    [JsonStringEnumMemberName("continue")]
    Continue,

    /// <summary>Send a successful assertion only over the pipe and return a timeout to the caller.</summary>
    [JsonStringEnumMemberName("capture")]
    Capture,

    /// <summary>Inject the supplied challenge before the assertion call and return a timeout to the caller.</summary>
    [JsonStringEnumMemberName("inject")]
    Inject,

    /// <summary>Ask the hook to send another assertion-started message using a longer wait timeout.</summary>
    /// <remarks>This will provide the operator extra time to fetch a challenge from a legitimate relying party.</remarks>
    [JsonStringEnumMemberName("wait")]
    Wait
}
