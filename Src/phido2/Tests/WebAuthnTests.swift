import Foundation
import Testing
@testable import phido2

/// Tests for the encoding helpers in `WebAuthn.swift`.
///
/// These are the parts of the tool that decide the exact bytes the security key signs and the
/// exact text printed in the JSON result, so a relying party rejects the assertion if they are
/// wrong. They need no security key, unlike everything in `FidoSession`.
@Suite("WebAuthn encoding helpers")
struct WebAuthnTests {
    /// Checks that `Data.base64URL` produces the URL-safe alphabet without padding.
    ///
    /// The bytes `FB FF FE` encode to `+//+` in standard base64, so they exercise both
    /// substituted characters (`+` → `-`, `/` → `_`). A single zero byte encodes to `AA==`,
    /// so it exercises the removal of `=` padding. WebAuthn JSON requires this form.
    @Test("base64url output uses the URL-safe alphabet and no padding")
    func base64URLHasNoPaddingOrBase64Alphabet() {
        #expect(Data([0xfb, 0xff, 0xfe]).base64URL == "-__-")
        #expect(Data([0x00]).base64URL == "AA")
    }

    /// Checks that `Data(base64URLOrBase64:)` accepts every form a challenge may be pasted in.
    ///
    /// The `--challenge` option takes base64url (as WebAuthn JSON carries it) or standard
    /// base64, padded or not; all four combinations must decode to the same bytes. Text that
    /// is not base64 at all must give `nil`, which the tool reports as an argument error.
    @Test("decoding accepts base64url and base64, padded or not, and rejects garbage")
    func decodesBothAlphabetsWithOrWithoutPadding() {
        #expect(Data(base64URLOrBase64: "-__-") == Data([0xfb, 0xff, 0xfe]))
        #expect(Data(base64URLOrBase64: "+//+") == Data([0xfb, 0xff, 0xfe]))
        #expect(Data(base64URLOrBase64: "AA") == Data([0x00]))
        #expect(Data(base64URLOrBase64: "AA==") == Data([0x00]))
        #expect(Data(base64URLOrBase64: "!!") == nil)
    }

    /// Checks the exact bytes of `clientDataJSON` for a known challenge and origin.
    ///
    /// The authenticator signs the SHA-256 of these bytes, and some relying parties verify
    /// them by string comparison rather than by parsing. The test therefore pins the whole
    /// document: the member order from the WebAuthn specification (`type`, `challenge`,
    /// `origin`, `crossOrigin`), the challenge re-encoded as base64url, unescaped slashes in
    /// the origin, and `crossOrigin` being `false`.
    @Test("clientDataJSON matches the WebAuthn serialisation byte for byte")
    func clientDataUsesSpecMemberOrder() {
        let json = makeClientDataJSON(challenge: Data([0, 1, 2, 3]), origin: "https://login.microsoft.com")
        #expect(String(decoding: json, as: UTF8.self) ==
            #"{"type":"webauthn.get","challenge":"AAECAw","origin":"https://login.microsoft.com","crossOrigin":false}"#)
    }

    /// Checks that an origin containing a JSON metacharacter cannot break the document.
    ///
    /// `clientDataJSON` is assembled by hand to control member order, so string values must
    /// still be escaped. An origin with a double quote must survive a round trip through a
    /// real JSON parser unchanged, rather than terminating the string early.
    @Test("clientDataJSON escapes special characters in the origin")
    func clientDataEscapesTheOrigin() throws {
        let json = makeClientDataJSON(challenge: Data([0]), origin: "https://a\"b")
        let parsed = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(parsed["origin"] as? String == "https://a\"b")
    }
}

/// Tests for the standalone JSON documents defined in `Output.swift`.
@Suite("JSON output")
struct OutputTests {
    /// Checks the assertion document: it is the bare WebAuthn credential with the fixed
    /// members a relying party requires, and an absent user handle is left out rather than
    /// written as `null`.
    @Test("assertion document is a complete WebAuthn credential and omits missing values")
    func assertionDocumentShape() throws {
        let assertion = PublicKeyCredential(
            id: "Y3JlZA", rawId: "Y3JlZA",
            response: .init(clientDataJSON: "e30", authenticatorData: "AA", signature: "AA", userHandle: nil))
        let data = try JSONEncoder().encode(assertion)
        let parsed = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(parsed["rawId"] as? String == "Y3JlZA")
        #expect(parsed["type"] as? String == "public-key")
        #expect((parsed["response"] as? [String: Any])?["userHandle"] == nil)
        #expect(!String(decoding: data, as: UTF8.self).contains("null"))
    }

    /// Checks the authenticator document for a phone, which reports nothing about itself:
    /// only the transport may appear, so scripts can tell "unknown" from a real value.
    @Test("authenticator document for a phone carries only the transport")
    func hybridAuthenticatorDocumentShape() throws {
        let data = try JSONEncoder().encode(AuthenticatorInfo(transport: .hybrid))
        let parsed = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(parsed.count == 1)
        #expect(parsed["transport"] as? String == "hybrid")
    }
}
