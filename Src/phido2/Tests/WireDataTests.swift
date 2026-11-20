import Foundation
import Testing
@testable import phido2

/// Feeds captured input reports through the reassembler, 64 bytes at a time.
///
/// - Returns: Every message the reports complete, in order.
private func messages(_ wire: [UInt8]) -> [CtapHidMessage] {
    var reassembler = CtapHidReassembler()
    return stride(from: 0, to: wire.count, by: 64).compactMap { reassembler.add(Data(wire[$0..<min($0 + 64, wire.count)])) }
}

/// Rewrites every packet of a capture to the channel of its first packet.
private func onOneChannel(_ wire: [UInt8]) -> [UInt8] {
    var wire = wire
    for start in stride(from: 64, to: wire.count, by: 64) { wire.replaceSubrange(start..<start + 4, with: wire[0..<4]) }
    return wire
}

/// The CTAP2 response in a capture that holds exactly one `CTAPHID_CBOR` message.
private func response(_ wire: [UInt8]) -> Ctap2Response? {
    let all = messages(wire)
    guard all.count == 1, all[0].command == CtapHidCommand.cbor else { return nil }
    return Ctap2Response(all[0].payload)
}

private func hex(_ text: String) -> Data {
    var bytes: [UInt8] = []
    var rest = Substring(text)
    while let byte = UInt8(rest.prefix(2), radix: 16) {
        bytes.append(byte)
        rest = rest.dropFirst(2)
    }
    return Data(bytes)
}

/// Tests that run `monitor`'s parsing over libfido2's test data (`WireData.swift`).
///
/// The other monitor tests use small hand-built payloads, which prove the logic but share its
/// author's idea of what a key sends. This data was not written for this tool and has what a
/// full answer has: members the tool ignores, full-size keys and certificates, and messages
/// long enough to span many packets.
@Suite("Security key traffic from libfido2's test data")
struct WireDataTests {
    /// Checks the two single-packet messages that are not CTAP2: the answer to `INIT`, which
    /// is sent on the broadcast channel with 17 bytes of data, and a keepalive.
    @Test("INIT and keepalive packets are read with their channel, command and length")
    func readsInitAndKeepalive() {
        let initialize = messages(WireData.initialize)
        #expect(initialize.count == 1)
        #expect(initialize.first?.channel == 0xffff_ffff)
        #expect(initialize.first?.command == CtapHidCommand.initialize)
        // Nonce, the new channel, protocol 2, device version 5.2.1, capabilities 0x05.
        #expect(initialize.first?.payload == hex("80435640b14ed92d002200020205020105"))

        #expect(messages(WireData.keepalive) == [CtapHidMessage(channel: 0x0022_0002, command: CtapHidCommand.keepalive, payload: Data([0x02]))])
    }

    /// Checks a full `authenticatorGetInfo` answer, which has more members than the tool
    /// reads (extensions, maximum message size, PIN protocols, algorithms) and no transports.
    @Test("a full getInfo answer yields versions, AAGUID and options")
    func recognisesInfo() {
        guard case .info(let versions, let aaguid, let options, let transports) = response(WireData.info) else {
            Issue.record("not recognised as getInfo"); return
        }
        #expect(versions == ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"])
        #expect(aaguid.flatMap(formatAAGUID) == "1956e5bd-a374-45f1-a814-356403fdbc18")
        #expect(options == ["rk": true, "up": true, "plat": false, "clientPin": false, "credentialMgmtPreview": true])
        #expect(transports == nil)
    }

    /// Checks the three answers of `authenticatorClientPIN`, each of which is recognised by
    /// a different member: the retry counter (3), the key agreement key (1), the token (2).
    @Test("clientPIN answers are told apart: retries, key agreement, token")
    func recognisesClientPIN() {
        #expect(response(WireData.pinRetries) == .clientPIN(pinRetries: 8, uvRetries: nil, keyAgreement: false, token: false))
        #expect(response(WireData.keyAgreement) == .clientPIN(pinRetries: nil, uvRetries: nil, keyAgreement: true, token: false))
        #expect(response(WireData.pinToken) == .clientPIN(pinRetries: nil, uvRetries: nil, keyAgreement: false, token: true))
        #expect(response(WireData.success) == .empty)
    }

    /// Checks a full-size assertion, 203 bytes in four packets.
    ///
    /// It was made for `localhost` with user verification but without user presence (flags
    /// 0x04), which CTAP allows for a request that only checks whether a credential exists.
    ///
    /// In libfido2's data the continuation packets carry another channel than the first
    /// packet; its test transport does not look at the channel. The channel is made the same
    /// throughout here, so that the content can be checked.
    @Test("a full-size assertion yields its credential ID, flags, counter and signature")
    func recognisesAssertion() {
        let wire = onOneChannel(WireData.assertion)
        guard case .assertion(let assertion) = response(wire) else {
            Issue.record("not recognised as an assertion"); return
        }
        #expect(assertion.credentialId == hex(
            "4a4c9ecc817d42032b41d138d349b4fcfbe44ee4ff76341668069da60132b9ff"
            + "c2350d89436612f88e5bdef4ccec9d0385c2f5e68eeb3f3aecc31d046ef35b88"))
        #expect(assertion.rawAuthenticatorData == hex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630400000009"))
        #expect(assertion.authenticatorData.rpIdHash == Data("localhost".utf8).sha256)
        #expect(!assertion.authenticatorData.userPresent && assertion.authenticatorData.userVerified)
        #expect(assertion.authenticatorData.signCount == 9)
        #expect(assertion.authenticatorData.credentialId == nil)
        #expect(assertion.signature.count == 71 && assertion.signature.prefix(4) == Data([0x30, 0x45, 0x02, 0x21]))
        #expect(assertion.userId == nil && assertion.numberOfCredentials == nil)
    }

    /// Checks a full-size registration, 993 bytes in 17 packets.
    ///
    /// The attested credential data has a 64-byte credential ID and a full ES256 COSE key
    /// with both coordinates, and the attestation statement after it carries a certificate.
    @Test("a full-size registration yields the AAGUID, credential ID and COSE key")
    func recognisesAttestation() {
        #expect(messages(WireData.attestation).first?.payload.count == 993)
        guard case .attestation(let format, let data, let raw) = response(WireData.attestation) else {
            Issue.record("not recognised as an attestation"); return
        }
        #expect(format == "packed")
        #expect(raw.count == 196)
        #expect(data.rpIdHash == Data("localhost".utf8).sha256)
        #expect(data.flags == 0x45 && data.signCount == 0)
        #expect(data.aaguid.flatMap(formatAAGUID) == "f8a011f3-8c0a-4d15-8006-17111f9edc7d")
        #expect(data.credentialId == hex(
            "ed8848a1db564d0f0dc88f0fe916b178a9409871a0b3f2cf05736c12bf0096f3"
            + "7b93ba49ee23b4782efbce27a8c22678cc952d40dbd1403d2ba331a0758263f0"))
        #expect(data.algorithm == -7)
        #expect(data.publicKey == hex(
            "a50102032620012158209d95a1b5d611bfe228a07fca1ed9090f0de78e29e82e11db556213d726c27e2b"
            + "225820be742aacde114076310bed55def303e41cac42638fe83063b7074e5dfb175e9b"))

        var tracker = CeremonyTracker()
        #expect(tracker.observe(messages(WireData.attestation)[0]).first?.outcome
            == CeremonyOutcome(ceremony: .registration, succeeded: true))
    }

    /// Checks that answers of commands the tool does not interpret are not mistaken for ones
    /// it does.
    ///
    /// Responses are recognised by their members alone, and these reuse the same small
    /// integer keys with other meanings: a fingerprint sensor's description has an integer
    /// under 3, like a PIN retry counter, and a large blob has a member 1, like a format.
    @Test("credential management, fingerprint and large blob answers are left unrecognised")
    func leavesOtherCommandsAlone() {
        #expect(response(WireData.credentialMetadata) == .other)
        #expect(response(WireData.fingerprintSensorInfo) == .other)
        #expect(response(WireData.fingerprints) == .other)
        #expect(response(WireData.largeBlobs) == .other)
        #expect(messages(WireData.largeBlobs).first?.payload.count == 486)
    }

    /// Checks captures that hold several messages one after the other on the same channel:
    /// each must come out complete, with the padding of its last packet dropped.
    @Test("consecutive messages on one channel are separated")
    func separatesConsecutiveMessages() {
        let relyingParties = messages(WireData.relyingParties)
        #expect(relyingParties.map(\.payload.count) == [55, 54, 55])
        let credentials = messages(WireData.credentials)
        #expect(credentials.map(\.payload.count) == [197, 160, 160, 195, 195])
        for message in relyingParties + credentials {
            #expect(Ctap2Response(message.payload) == .other)
        }
        // The relying party's name is in the first answer as text.
        #expect(relyingParties.first?.payload.range(of: Data("yubico.com".utf8)) != nil)
    }
}
