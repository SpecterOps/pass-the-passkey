using System.ComponentModel;
using System.Text.Json.Serialization;

namespace SpecterOps.Passkeys;

[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<PublicKeyCredentialHint>))]
public enum PublicKeyCredentialHint
{
    [Description("None")]
    None = 0,

    [JsonStringEnumMemberName(WebAuthnConstants.HintSecurityKey)]
    [Description("Security Key (Roaming)")]
    SecurityKey = 1,

    [JsonStringEnumMemberName(WebAuthnConstants.HintClientDevice)]
    [Description("Windows Hello (Platform)")]
    ClientDevice = 2,

    [JsonStringEnumMemberName(WebAuthnConstants.HintHybrid)]
    [Description("QR Code (Hybrid)")]
    Hybrid = 4
}
