import CFido2
import Foundation

extension Data {
    /// The base64url encoding of the data, without padding (RFC 4648 §5).
    ///
    /// Written out by hand: Foundation's own base64url option exists only on recent Apple
    /// systems, not on Linux.
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The SHA-256 hash of the data, computed by libcrypto.
    var sha256: Data {
        var digest = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        withUnsafeBytes { _ = SHA256($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &digest) }
        return Data(digest)
    }

    /// Decodes base64url or standard base64 text, with or without padding.
    ///
    /// Foundation can encode base64url but has no decoding counterpart, so the text is
    /// normalised to padded standard base64 first.
    ///
    /// - Parameter text: The encoded text.
    /// - Returns: `nil` if `text` is not valid base64 in either alphabet.
    init?(base64URLOrBase64 text: String) {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        self.init(base64Encoded: s)
    }
}

/// Builds the `clientDataJSON` of a `webauthn.get` ceremony.
///
/// Members are written in the order the WebAuthn specification serialises them, because some
/// relying parties verify the client data with the spec's limited (string-prefix) algorithm.
///
/// - Parameters:
///   - challenge: The relying party's challenge bytes.
///   - origin: The origin to claim, e.g. `https://login.microsoft.com`.
/// - Returns: The UTF-8 encoded JSON. The authenticator signs its SHA-256 hash.
func makeClientDataJSON(challenge: Data, origin: String) -> Data {
    func quoted(_ s: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        // Encoding a String cannot fail.
        return String(decoding: try! encoder.encode(s), as: UTF8.self)
    }
    let json = "{\"type\":\"webauthn.get\",\"challenge\":\(quoted(challenge.base64URL)),"
        + "\"origin\":\(quoted(origin)),\"crossOrigin\":false}"
    return Data(json.utf8)
}
