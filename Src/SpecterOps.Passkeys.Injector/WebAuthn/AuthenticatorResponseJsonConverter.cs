using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Converts AuthenticatorResponse to the correct derived type based on response fields.
/// </summary>
public sealed class AuthenticatorResponseJsonConverter : JsonConverter<AuthenticatorResponse>
{
    public override AuthenticatorResponse? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using JsonDocument document = JsonDocument.ParseValue(ref reader);
        JsonElement root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (root.TryGetProperty("signature", out _))
        {
            return root.Deserialize(WebAuthnJsonContext.Default.AuthenticatorAssertionResponse);
        }

        if (root.TryGetProperty("attestationObject", out _))
        {
            return root.Deserialize(WebAuthnJsonContext.Default.AuthenticatorAttestationResponse);
        }

        return root.Deserialize(WebAuthnJsonContext.Default.AuthenticatorResponse);
    }

    public override void Write(Utf8JsonWriter writer, AuthenticatorResponse value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}
