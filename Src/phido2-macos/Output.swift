import Foundation

// The tool prints each piece of information on standard output as soon as it is known, as a
// standalone JSON document: an ``AuthenticatorInfo`` (with `--info`), then a
// ``CredentialsDocument`` (when listing), then one ``PublicKeyCredential`` per assertion. The documents follow one another
// on the stream, which tools such as `jq` read directly. They are told apart by their
// members: `transport`, `credentials`, and `type` ("public-key") respectively.

/// Printed when credentials have been listed.
struct CredentialsDocument: Encodable {
    /// The credentials found.
    var credentials: [DiscoveredCredential]
    /// Where the list came from.
    var credentialSource: CredentialSource
}

private let emitLock = NSLock()

/// Prints one standalone JSON document on standard output.
///
/// May be called from any thread; documents never interleave.
///
/// - Parameter document: An ``AuthenticatorInfo``, ``CredentialsDocument`` or
///   ``PublicKeyCredential`` from `prompt`; an ``AuthenticatorInfo``, ``ObservedAssertion`` or
///   ``ObservedRegistration`` from `monitor`.
func emit<Document: Encodable>(_ document: Document) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
    // Encoding these plain value types cannot fail.
    let data = try! encoder.encode(document) + Data("\n".utf8)
    emitLock.lock()
    FileHandle.standardOutput.write(data)
    emitLock.unlock()
}

/// How the authenticator was reached.
enum Transport: String, Encodable {
    /// A security key over USB HID, through libfido2.
    case usb
    /// A phone that scanned the QR code, through the system's hybrid (caBLE) client.
    case hybrid
}

/// How the authenticator verified the user.
enum UserVerification: String {
    /// Only presence (touch) was tested.
    case none
    /// The client PIN was sent to the key.
    case pin
    /// The authenticator verified the user itself, e.g. with a fingerprint or the phone's
    /// screen lock.
    case builtIn
}

/// Which CTAP command a credential list was built from.
enum CredentialSource: String, Encodable {
    /// `authenticatorCredentialManagement`: the complete list, with public keys.
    case credentialManagement
    /// The `authenticatorGetAssertion` response: a fallback for keys without credential management.
    case assertion
}

/// Identity and capabilities of an authenticator. Printed with `--info`, as soon as it has
/// been identified.
///
/// Everything except ``transport`` is `nil` for a phone reached over hybrid transport, which
/// does not identify itself to this tool.
struct AuthenticatorInfo: Encodable {
    /// How this tool reached the authenticator.
    var transport: Transport
    /// USB manufacturer string.
    var manufacturer: String?
    /// USB product string.
    var product: String?
    /// The model identifier from `authenticatorGetInfo`, formatted as a UUID.
    var aaguid: String?
    /// Supported protocol versions, e.g. `FIDO_2_0`, `FIDO_2_1`, `U2F_V2`.
    var versions: [String]?
    /// The transports the authenticator says it supports, e.g. `usb`, `nfc`.
    var transports: [String]?
    /// Whether a client PIN is set.
    var pinSet: Bool?
    /// Whether built-in user verification (e.g. a fingerprint) is enrolled.
    var builtInUserVerification: Bool?
}

/// A credential stored on the security key.
struct DiscoveredCredential: Encodable {
    /// The account a credential belongs to.
    struct User: Encodable {
        /// User handle, base64url.
        var id: String?
        var name: String?
        var displayName: String?
    }

    /// Credential ID, base64url.
    var id: String
    var rpId: String
    var user: User
    /// COSE algorithm identifier, e.g. -7 for ES256. Only known through credential management.
    var algorithm: Int32?
    /// Raw public key, base64url. Only known through credential management.
    var publicKey: String?
    /// Credential protection policy (1–3). Only known through credential management.
    var credProtect: Int32?
}

/// An assertion in the shape of WebAuthn's `AuthenticationResponseJSON`. Printed once for
/// every assertion the authenticator returned, exactly as a relying party expects it.
///
/// All binary members are base64url encoded, as `PublicKeyCredential.toJSON()` produces them.
struct PublicKeyCredential: Encodable {
    /// WebAuthn's `AuthenticatorAssertionResponseJSON`.
    struct Response: Encodable {
        var clientDataJSON: String
        var authenticatorData: String
        var signature: String
        /// `nil` when the key returned no user handle.
        var userHandle: String?
    }

    /// Credential ID, base64url.
    var id: String
    /// The same credential ID; WebAuthn carries it twice.
    var rawId: String
    var type = "public-key"
    var authenticatorAttachment = "cross-platform"
    var response: Response
    var clientExtensionResults: [String: String] = [:]
}

// MARK: Documents of `monitor`

// `monitor` sees only what the security key answers, so its documents carry what the key sent
// and nothing from the request: no relying party ID (only its hash), no client data. They are
// told apart by their `event` member.

/// An assertion a security key gave to another program.
struct ObservedAssertion: Encodable {
    var event = "assertion"
    /// `ctap2` or `u2f`.
    var `protocol`: String
    /// Credential ID, base64url. `nil` when the key left it out because the request named a
    /// single credential, and always for U2F.
    var credentialId: String?
    /// SHA-256 of the relying party ID, base64url. `nil` for U2F, which does not send it back.
    var rpIdHash: String?
    /// `false` for a browser's silent check whether the key has a credential.
    var userPresent: Bool
    /// `nil` for U2F, which has no user verification.
    var userVerified: Bool?
    var signCount: UInt32
    /// The signed authenticator data, base64url. `nil` for U2F.
    var authenticatorData: String?
    /// Signature, base64url.
    var signature: String
    /// The account, when the key returned it (discoverable credentials).
    var user: DiscoveredCredential.User?
    /// How many credentials the key has for the relying party, when more than one.
    var numberOfCredentials: Int?
}

/// A credential a security key created for another program.
struct ObservedRegistration: Encodable {
    var event = "registration"
    /// `ctap2` or `u2f`.
    var `protocol`: String
    /// Attestation statement format, e.g. `packed` or `none`. `nil` for U2F.
    var format: String?
    /// SHA-256 of the relying party ID, base64url. `nil` for U2F.
    var rpIdHash: String?
    /// The authenticator model, formatted as a UUID. `nil` for U2F.
    var aaguid: String?
    /// Credential ID (U2F: key handle), base64url.
    var credentialId: String?
    /// COSE algorithm identifier, e.g. -7 for ES256.
    var algorithm: Int?
    /// Public key, base64url: a CBOR-encoded COSE_Key for CTAP2, an uncompressed P-256 point
    /// for U2F.
    var publicKey: String?
    var userPresent: Bool
    /// `nil` for U2F.
    var userVerified: Bool?
    /// `nil` for U2F.
    var signCount: UInt32?
    /// The authenticator data, base64url. `nil` for U2F.
    var authenticatorData: String?
}
