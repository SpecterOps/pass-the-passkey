using System.Diagnostics.CodeAnalysis;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Authenticator data flags.
/// </summary>
[Flags]
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "AuthenticatorFlags is the standard WebAuthn term.")]
public enum AuthenticatorFlags : byte
{
    /// <summary>
    /// User Present (UP) - Bit 0.
    /// </summary>
    UP = 0x01,

    /// <summary>
    /// User Verified (UV) - Bit 2.
    /// </summary>
    UV = 0x04,

    /// <summary>
    /// Backup Eligibility (BE) - Bit 3.
    /// </summary>
    BE = 0x08,

    /// <summary>
    /// Backup State (BS) - Bit 4.
    /// </summary>
    BS = 0x10,

    /// <summary>
    /// Attested Credential Data (AT) - Bit 6.
    /// </summary>
    AT = 0x40,

    /// <summary>
    /// Extension Data (ED) - Bit 7.
    /// </summary>
    ED = 0x80
}
