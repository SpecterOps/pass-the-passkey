using System.ComponentModel;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys.Injector;

[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<PublicKeyCredentialHint>))]
public enum PublicKeyCredentialHint
{
    [Description("None")]
    None = 0,

    [JsonStringEnumMemberName("security-key")]
    [Description("Security Key (Roaming)")]
    SecurityKey = 1,

    [JsonStringEnumMemberName("client-device")]
    [Description("Windows Hello (Platform)")]
    ClientDevice = 2,

    [JsonStringEnumMemberName("hybrid")]
    [Description("QR Code (Hybrid)")]
    Hybrid = 4
}
