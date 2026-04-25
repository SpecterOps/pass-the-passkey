using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Source-generated JSON serialization context for <see cref="HookPipeMessage"/> and all its derived types.
/// </summary>
[JsonSerializable(typeof(HookPipeMessage))]
[JsonSerializable(typeof(AssertionStartedMessage))]
[JsonSerializable(typeof(AssertionCompletedMessage))]
[JsonSerializable(typeof(AssertionErrorMessage))]
internal sealed partial class HookPipeMessageJsonContext : JsonSerializerContext
{
}
