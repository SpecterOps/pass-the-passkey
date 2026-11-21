import Foundation

/// Names the relying party behind an `rpIdHash`.
///
/// A security key's answers carry only the SHA-256 hash of the relying party ID, and a hash
/// cannot be turned back into the ID. It can be compared with the hashes of IDs one expects
/// to see, which is what this list is for. To have another site named, add its ID here.
enum KnownRelyingParties {
    /// Relying party IDs of common sites and of the usual WebAuthn test pages.
    static let ids = [
        "login.microsoft.com",
        "login.microsoftonline.com",
        "login.live.com",
        "microsoft.com",
        "github.com",
        "gitlab.com",
        "google.com",
        "accounts.google.com",
        "apple.com",
        "amazon.com",
        "facebook.com",
        "x.com",
        "dropbox.com",
        "webauthn.io",
        "webauthn.me",
        "demo.yubico.com",
        "passkeys.io",
        "localhost",
    ]

    /// The IDs by their hash, computed once.
    private static let byHash = Dictionary(ids.map { (Data($0.utf8).sha256, $0) }, uniquingKeysWith: { first, _ in first })

    /// Looks up a relying party ID.
    ///
    /// - Parameter hash: The 32-byte `rpIdHash` from authenticator data.
    /// - Returns: The ID whose SHA-256 hash it is, or `nil` if it is not in the list.
    static func id(forHash hash: Data) -> String? {
        byHash[hash]
    }

    /// A log line that says which relying party a hash belongs to, or that it is unknown.
    static func describe(hash: Data) -> String {
        if let id = id(forHash: hash) { return "The relying party is \(id) (its rpIdHash matches)" }
        return "The relying party is not among the \(ids.count) known ones; only its rpIdHash is visible"
    }
}
