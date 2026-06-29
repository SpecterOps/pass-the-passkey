
namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Base class for all pipe messages sent by the hook DLL.
/// The <c>type</c> JSON property is used as the polymorphic type discriminator.
/// Every message carries the originating process context, relying party ID, and a timestamp.
/// New message types may be added in future versions of the hook DLL; unknown values are handled gracefully.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AssertionStartedMessage), "AssertionStarted")]
[JsonDerivedType(typeof(AssertionCompletedMessage), "AssertionCompleted")]
[JsonDerivedType(typeof(AssertionErrorMessage), "AssertionError")]
internal abstract class HookPipeMessage
{
    /// <summary>UTC timestamp recorded by the hook DLL when the message was produced.</summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Process ID of the browser that triggered the assertion.</summary>
    [JsonPropertyName("pid")]
    public int Pid { get; init; }

    /// <summary>Image name (without extension) of the browser process that triggered the assertion.</summary>
    [JsonPropertyName("processName")]
    public string? ProcessName { get; init; }

    /// <summary>Windows user name running the browser process.</summary>
    [JsonPropertyName("userName")]
    public string? UserName { get; init; }

    /// <summary>Previous action received by the hook DLL from the pipe server, when one exists.</summary>
    [JsonPropertyName("previousAction")]
    public HookAction? PreviousAction { get; init; }

    /// <summary>Relying party identifier from the WebAuthn assertion request.</summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; init; }
}
