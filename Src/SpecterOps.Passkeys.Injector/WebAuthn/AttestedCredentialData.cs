using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Runtime.InteropServices;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Attested credential data is a variable-length byte array added to the
/// authenticator data when generating an attestation object for a given credential.
/// </summary>
public sealed class AttestedCredentialData
{
    /// <summary>
    /// Minimum length of the attested credential data structure.
    /// </summary>
    private const int MinLength = 20; // 16 (AAGUID) + 2 (credentialID length) + 1 (min credential ID) + 1 (min CBOR)

    private const int MaxCredentialIdLength = 1023;

    /// <summary>
    /// The AAGUID of the authenticator. Can be used to identify the make and model of the authenticator.
    /// </summary>
    public Guid AaGuid { get; }

    /// <summary>
    /// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
    /// </summary>
    public ReadOnlyMemory<byte> CredentialId { get; }

    /// <summary>
    /// The credential public key encoded in COSE_Key format.
    /// </summary>
    public ReadOnlyMemory<byte> CredentialPublicKey { get; }

    private AttestedCredentialData(Guid aaGuid, ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> credentialPublicKey)
    {
        AaGuid = aaGuid;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }

    /// <summary>
    /// Decodes attested credential data.
    /// </summary>
    internal static AttestedCredentialData Parse(ReadOnlyMemory<byte> data, out int bytesRead)
    {
        if (data.Length < MinLength)
        {
            throw new ArgumentException($"Attested credential data must be at least {MinLength} bytes.", nameof(data));
        }

        int position = 0;

        // AAGUID (16 bytes)
        var aaGuid = new Guid(data.Slice(0, Marshal.SizeOf<Guid>()).Span, bigEndian: true);
        position += Marshal.SizeOf<Guid>();

        // Credential ID length (2 bytes, big-endian)
        ushort credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, sizeof(ushort)).Span);
        if (credentialIdLength > MaxCredentialIdLength)
        {
            throw new ArgumentException($"Credential ID length {credentialIdLength} exceeds maximum {MaxCredentialIdLength}.", nameof(data));
        }
        position += sizeof(ushort);

        // Credential ID
        ReadOnlyMemory<byte> credentialId = data.Slice(position, credentialIdLength);
        position += credentialIdLength;

        // Credential public key (CBOR encoded)
        var reader = new CborReader(data[position..]);
        reader.SkipValue();
        int publicKeyLength = data.Length - position - reader.BytesRemaining;
        ReadOnlyMemory<byte> credentialPublicKey = data.Slice(position, publicKeyLength);
        position += publicKeyLength;

        bytesRead = position;

        return new AttestedCredentialData(aaGuid, credentialId, credentialPublicKey);
    }
}
