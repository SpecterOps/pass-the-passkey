using System.Text.Json.Serialization;

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
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class WebAuthnJsonContext : JsonSerializerContext
{
}
