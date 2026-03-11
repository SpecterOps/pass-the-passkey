using System.Text.Json.Serialization;
using SpecterOps.Passkeys.Injector.Cryptography;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// JSON serialization context for WebAuthn types to support AOT compilation.
/// </summary>
[JsonSerializable(typeof(PublicKeyCredentialRequestOptions))]
[JsonSerializable(typeof(PublicKeyCredentialCreationOptions))]
[JsonSerializable(typeof(PublicKeyCredential))]
[JsonSerializable(typeof(AuthenticatorResponse))]
[JsonSerializable(typeof(AuthenticatorAssertionResponse))]
[JsonSerializable(typeof(AuthenticatorAttestationResponse))]
[JsonSerializable(typeof(KeePassXCPasskey))]
[JsonSerializable(typeof(CollectedClientData))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class WebAuthnJsonContext : JsonSerializerContext
{
}
