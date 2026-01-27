using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Represents parsed authenticator data from a WebAuthn assertion.
/// </summary>
/// <remarks>
/// The authenticator data structure is defined in the WebAuthn specification:
/// https://www.w3.org/TR/webauthn/#sec-authenticator-data
/// </remarks>
public sealed class AuthenticatorData
{
    /// <summary>
    /// Minimum length of the authenticator data structure.
    /// </summary>
    private const int MinLength = SHA256HashSizeInBytes + sizeof(AuthenticatorFlags) + sizeof(uint);

    private const int SHA256HashSizeInBytes = 32;

    /// <summary>
    /// SHA-256 hash of the RP ID the credential is scoped to.
    /// </summary>
    public byte[] RpIdHash { get; }

    /// <summary>
    /// Signature counter, 32-bit unsigned big-endian integer.
    /// </summary>
    public uint SignCount { get; }

    /// <summary>
    /// Attested credential data is a variable-length byte array added to the
    /// authenticator data when generating an attestation object for a given credential.
    /// </summary>
    public AttestedCredentialData? AttestedCredentialData { get; }

    /// <summary>
    /// Optional extensions to suit particular use cases.
    /// </summary>
    public byte[]? Extensions { get; }

    /// <summary>
    /// Flags contains information from the authenticator about the authentication
    /// and whether or not certain data is present in the authenticator data.
    /// </summary>
    private readonly AuthenticatorFlags _flags;

    /// <summary>
    /// UserPresent indicates that the user presence test has completed successfully.
    /// </summary>
    public bool UserPresent => _flags.HasFlag(AuthenticatorFlags.UP);

    /// <summary>
    /// UserVerified indicates that the user verification process has completed successfully.
    /// </summary>
    public bool UserVerified => _flags.HasFlag(AuthenticatorFlags.UV);

    /// <summary>
    /// Backup eligibility is signaled in authenticator data's flags along with the current backup state.
    /// </summary>
    public bool IsBackupEligible => _flags.HasFlag(AuthenticatorFlags.BE);

    /// <summary>
    /// The current backup state of a multi-device credential as determined by the current managing authenticator.
    /// </summary>
    public bool IsBackedUp => _flags.HasFlag(AuthenticatorFlags.BS);

    /// <summary>
    /// HasAttestedCredentialData indicates that the authenticator added attested credential data to the authenticator data.
    /// </summary>
    [MemberNotNullWhen(true, nameof(AttestedCredentialData))]
    public bool HasAttestedCredentialData => _flags.HasFlag(AuthenticatorFlags.AT);

    /// <summary>
    /// HasExtensionsData indicates that the authenticator added extension data to the authenticator data.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Extensions))]
    public bool HasExtensionsData => _flags.HasFlag(AuthenticatorFlags.ED);

    private AuthenticatorData(byte[] rpIdHash, AuthenticatorFlags flags, uint signCount, AttestedCredentialData? acd, byte[]? extensions)
    {
        RpIdHash = rpIdHash;
        _flags = flags;
        SignCount = signCount;
        AttestedCredentialData = acd;
        Extensions = extensions;
    }

    /// <summary>
    /// Parses authenticator data from a Base64Url-encoded string.
    /// </summary>
    public static AuthenticatorData Parse(string base64UrlData)
    {
        byte[] data = Base64Url.DecodeFromChars(base64UrlData.AsSpan());
        return Parse(data);
    }

    /// <summary>
    /// Parses authenticator data from a memory buffer.
    /// </summary>
    public static AuthenticatorData Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length < MinLength)
        {
            throw new ArgumentException($"Authenticator data must be at least {MinLength} bytes.", nameof(data));
        }

        ReadOnlySpan<byte> span = data.Span;
        int position = 0;

        // rpIdHash (32 bytes)
        byte[] rpIdHash = span.Slice(position, SHA256HashSizeInBytes).ToArray();
        position += SHA256HashSizeInBytes;

        // flags (1 byte)
        var flags = (AuthenticatorFlags)span[position];
        position += 1;

        // signCount (4 bytes, big-endian)
        uint signCount = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(position, sizeof(uint)));
        position += sizeof(uint);

        AttestedCredentialData? attestedCredentialData = null;

        // Attested credential data is only present if the AT flag is set
        if (flags.HasFlag(AuthenticatorFlags.AT))
        {
            attestedCredentialData = AttestedCredentialData.Parse(data[position..], out int bytesRead);
            position += bytesRead;
        }

        byte[]? extensions = null;

        // Extensions data is only present if the ED flag is set
        if (flags.HasFlag(AuthenticatorFlags.ED))
        {
            // Read the CBOR extension data
            var reader = new CborReader(data[position..]);
            reader.SkipValue();
            int bytesRead = data.Length - position - reader.BytesRemaining;
            extensions = span.Slice(position, bytesRead).ToArray();
            position += bytesRead;
        }

        return new AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData, extensions);
    }
}
