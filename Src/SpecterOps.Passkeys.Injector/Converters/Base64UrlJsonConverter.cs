using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// JSON converter that serializes <see cref="byte[]"/> as a Base64Url-encoded string
/// and deserializes Base64Url-encoded strings back to <see cref="byte[]"/>.
/// </summary>
public sealed class Base64UrlJsonConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return Base64Url.DecodeFromUtf8(reader.ValueSpan);
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Base64Url.EncodeToString(value));
    }
}
