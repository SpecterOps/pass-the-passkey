using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Base class for all pipe messages sent by the hook DLL.
/// The <c>type</c> JSON property is used as the polymorphic type discriminator.
/// New message types may be added in future versions of the hook DLL; unknown values are handled gracefully.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AssertionStartedMessage), "AssertionStarted")]
[JsonDerivedType(typeof(AssertionCompletedMessage), "AssertionCompleted")]
[JsonDerivedType(typeof(AssertionErrorMessage), "AssertionError")]
internal abstract class HookPipeMessage
{
}
