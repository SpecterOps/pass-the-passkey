import Foundation
import Testing
@testable import phido2

/// Builds the input reports a security key would send for one CTAPHID message.
///
/// - Returns: 64-byte reports: an initiation packet, then as many continuation packets as
///   the payload needs.
private func reports(channel: UInt32 = 0x0000_0019, command: UInt8, payload: [UInt8]) -> [Data] {
    let cid = [UInt8(channel >> 24), UInt8(channel >> 16 & 0xff), UInt8(channel >> 8 & 0xff), UInt8(channel & 0xff)]
    var packets: [[UInt8]] = [cid + [command | 0x80, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)] + payload.prefix(57)]
    var rest = Array(payload.dropFirst(57))
    var sequence: UInt8 = 0
    while !rest.isEmpty {
        packets.append(cid + [sequence] + rest.prefix(59))
        rest = Array(rest.dropFirst(59))
        sequence += 1
    }
    return packets.map { Data($0 + [UInt8](repeating: 0, count: 64 - $0.count)) }
}

/// 37 bytes of authenticator data: a recognisable RP ID hash, the given flags, counter 5.
private func authData(flags: UInt8, rpIdHash: Data = Data(repeating: 0xab, count: 32)) -> [UInt8] {
    [UInt8](rpIdHash) + [flags, 0, 0, 0, 5]
}

/// A successful `authenticatorGetAssertion` payload: status 0, then `{2: authData, 3: h'aabb'}`.
private func assertionPayload(flags: UInt8) -> [UInt8] {
    [0x00, 0xa2, 0x02, 0x58, 37] + authData(flags: flags) + [0x03, 0x42, 0xaa, 0xbb]
}

/// A successful `authenticatorMakeCredential` payload: `{1: "none", 2: authData, 3: {}}`.
private func attestationPayload(rpIdHash: Data) -> [UInt8] {
    [0x00, 0xa3, 0x01, 0x64] + Array("none".utf8) + [0x02, 0x58, 37] + authData(flags: 0x01, rpIdHash: rpIdHash) + [0x03, 0xa0]
}

private func message(_ command: UInt8, _ payload: [UInt8]) -> CtapHidMessage {
    CtapHidMessage(channel: 0x19, command: command, payload: Data(payload))
}

/// Tests for the parts of `monitor` that turn raw HID reports into events.
///
/// `monitor` never sees a request, so each response must be recognised from its bytes alone,
/// and the decision that a ceremony is over rests on inference. These tests pin that logic
/// down with hand-built packets; they need no security key.
@Suite("Security key monitoring")
struct MonitorTests {
    /// Checks that a message spread over several reports is put back together.
    ///
    /// A 100-byte payload needs an initiation packet (57 bytes) and one continuation packet.
    /// The first report alone must not produce a message; the second must complete it with
    /// the padding of the last packet cut off.
    @Test("a multi-packet message is reassembled and its padding dropped")
    func reassemblesContinuationPackets() {
        let payload = (0..<100).map { UInt8($0) }
        let packets = reports(command: CtapHidCommand.cbor, payload: payload)
        var reassembler = CtapHidReassembler()
        #expect(packets.count == 2)
        #expect(reassembler.add(packets[0]) == nil)
        #expect(reassembler.add(packets[1]) == CtapHidMessage(channel: 0x19, command: CtapHidCommand.cbor, payload: Data(payload)))
    }

    /// Checks that a continuation packet with the wrong sequence number discards the message.
    ///
    /// A listener that attaches in the middle of a message, or misses a report, must not
    /// glue unrelated packets together.
    @Test("an out-of-sequence packet drops the partial message")
    func dropsOutOfSequencePackets() {
        let packets = reports(command: CtapHidCommand.cbor, payload: [UInt8](repeating: 1, count: 150))
        var reassembler = CtapHidReassembler()
        #expect(reassembler.add(packets[0]) == nil)
        #expect(reassembler.add(packets[2]) == nil)
        #expect(reassembler.add(packets[1]) == nil)
    }

    /// Checks that libcbor's output is converted for the CBOR types CTAP2 uses.
    ///
    /// The bytes encode `{1: -7, "a": [true, h'01']}` followed by one stray byte, which must
    /// be left alone and not counted as consumed.
    @Test("CBOR maps, integers, strings, arrays and booleans decode; trailing bytes are ignored")
    func decodesCBOR() {
        let decoded = CBORValue.decode(Data([0xa2, 0x01, 0x26, 0x61, 0x61, 0x82, 0xf5, 0x41, 0x01, 0xff]))
        #expect(decoded?.consumed == 9)
        #expect(decoded?.value[1] == .int(-7))
        #expect(decoded?.value["a"] == .array([.bool(true), .bytes(Data([0x01]))]))
        #expect(CBORValue.decode(Data([0xa2, 0x01])) == nil)
    }

    /// Checks that CTAP2 responses are told apart by the members of their CBOR map.
    ///
    /// An assertion has authenticator data (2) and a signature (3); an attestation has a
    /// format string (1); a non-zero status byte is an error whatever follows.
    @Test("CTAP2 responses are recognised by shape")
    func recognisesCtap2Responses() {
        guard case .assertion(let assertion) = Ctap2Response(Data(assertionPayload(flags: 0x05))) else {
            Issue.record("not recognised as an assertion"); return
        }
        #expect(assertion.authenticatorData.userPresent && assertion.authenticatorData.userVerified)
        #expect(assertion.authenticatorData.signCount == 5)
        #expect(assertion.signature == Data([0xaa, 0xbb]))

        guard case .attestation(let format, _, _) = Ctap2Response(Data(attestationPayload(rpIdHash: Data(repeating: 1, count: 32)))) else {
            Issue.record("not recognised as an attestation"); return
        }
        #expect(format == "none")
        #expect(Ctap2Response(Data([0x2e])) == .error(0x2e))
        #expect(Ctap2Response(Data([0x00])) == .empty)
    }

    /// Checks that attested credential data is split into AAGUID, credential ID and public key.
    ///
    /// The public key is followed by nothing here, but its length is still taken from the
    /// CBOR decoder, which is what keeps extensions out of it on a real key.
    @Test("authenticator data of a registration yields the credential ID and COSE key")
    func parsesAttestedCredentialData() {
        let key: [UInt8] = [0xa2, 0x01, 0x02, 0x03, 0x26]   // {1: 2, 3: -7}
        let bytes = authData(flags: 0x41) + [UInt8](repeating: 0x11, count: 16) + [0x00, 0x02, 0xc1, 0xc2] + key
        let data = AuthenticatorData(Data(bytes))
        #expect(data?.credentialId == Data([0xc1, 0xc2]))
        #expect(data?.aaguid == Data(repeating: 0x11, count: 16))
        #expect(data?.publicKey == Data(key))
        #expect(data?.algorithm == -7)
        #expect(AuthenticatorData(Data(bytes.prefix(40))) == nil)
    }

    /// Checks that U2F responses are recognised from their layout and status word.
    @Test("U2F responses are recognised by shape")
    func recognisesU2fResponses() {
        let signature: [UInt8] = [0x30, 0x02, 0x01, 0x01]
        #expect(U2fResponse(Data([0x01, 0, 0, 0, 9] + signature + [0x90, 0x00]))
            == .authentication(userPresent: true, counter: 9, signature: Data(signature)))
        let point = [UInt8](repeating: 0x04, count: 65)
        #expect(U2fResponse(Data([0x05] + point + [0x02, 0xd1, 0xd2, 0x30, 0x00] + [0x90, 0x00]))
            == .registration(publicKey: Data(point), keyHandle: Data([0xd1, 0xd2])))
        #expect(U2fResponse(Data([0x69, 0x85])) == .status(0x6985))
        #expect(U2fResponse(Data(Array("U2F_V2".utf8) + [0x90, 0x00])) == .version("U2F_V2"))
    }

    /// Checks that an assertion ends the ceremony only when the user was present.
    ///
    /// Browsers first ask the key silently (UP=0) whether it has a credential. That answer is
    /// reported but is not the sign-in; the one with UP=1 is.
    @Test("an assertion with user presence ends the ceremony; a silent check does not")
    func assertionOutcome() {
        var tracker = CeremonyTracker()
        #expect(tracker.observe(message(CtapHidCommand.cbor, assertionPayload(flags: 0x00))).first?.outcome == nil)
        #expect(tracker.observe(message(CtapHidCommand.cbor, assertionPayload(flags: 0x01))).first?.outcome
            == CeremonyOutcome(ceremony: .assertion, succeeded: true))
    }

    /// Checks which CTAP2 errors end the ceremony.
    ///
    /// "No credentials" without a preceding wait for the user is the answer to a silent
    /// check and must not end monitoring, and its repeats must not be logged again. The same
    /// kind of error after the key asked for a touch is the ceremony failing.
    @Test("an error ends the ceremony only after the key waited for the user")
    func errorOutcome() {
        var tracker = CeremonyTracker()
        let noCredentials = message(CtapHidCommand.cbor, [0x2e])
        #expect(tracker.observe(noCredentials).map(\.outcome) == [nil])
        #expect(tracker.observe(noCredentials).isEmpty)

        #expect(tracker.observe(message(CtapHidCommand.keepalive, [0x02])).count == 1)
        #expect(tracker.observe(message(CtapHidCommand.keepalive, [0x02])).isEmpty)
        #expect(tracker.observe(message(CtapHidCommand.cbor, [0x27])).first?.outcome
            == CeremonyOutcome(ceremony: .unknown, succeeded: false))
    }

    /// Checks how registrations are judged, including the browsers' placeholder for `.dummy`.
    ///
    /// A registration for a real relying party succeeded. One for `.dummy` after "no
    /// credentials" means the sign-in found nothing and the browser only waited for a touch;
    /// without that history it is just the user picking a key and monitoring goes on.
    @Test("a placeholder registration is not reported as a registration")
    func registrationOutcome() {
        let real = message(CtapHidCommand.cbor, attestationPayload(rpIdHash: Data(repeating: 1, count: 32)))
        let dummy = message(CtapHidCommand.cbor, attestationPayload(rpIdHash: CeremonyTracker.dummyRpIdHash))

        var tracker = CeremonyTracker()
        #expect(tracker.observe(real).first?.outcome == CeremonyOutcome(ceremony: .registration, succeeded: true))

        tracker = CeremonyTracker()
        #expect(tracker.observe(dummy).first?.outcome == nil)

        tracker = CeremonyTracker()
        _ = tracker.observe(message(CtapHidCommand.cbor, [0x2e]))
        #expect(tracker.observe(dummy).first?.outcome == CeremonyOutcome(ceremony: .assertion, succeeded: false))
    }

    /// Checks the sequence Safari produces when a FIDO2 key has no credential for the site.
    ///
    /// The key answers "no credentials" over CTAP2, Safari falls back to U2F and sends a
    /// placeholder registration to wait for the touch. That registration answer must be
    /// reported as a failed assertion. Without the CTAP2 error before it, the same answer is
    /// taken as a registration.
    @Test("a U2F registration after CTAP2 \"no credentials\" is a failed assertion")
    func u2fPlaceholderAfterNoCredentials() {
        let registration = message(CtapHidCommand.msg, [0x05] + [UInt8](repeating: 0x04, count: 65) + [0x01, 0xd1, 0x90, 0x00])
        var tracker = CeremonyTracker()
        #expect(tracker.observe(registration).first?.outcome == CeremonyOutcome(ceremony: .registration, succeeded: true))

        tracker = CeremonyTracker()
        _ = tracker.observe(message(CtapHidCommand.cbor, [0x2e]))
        _ = tracker.observe(message(CtapHidCommand.msg, [0x6a, 0x80]))
        let events = tracker.observe(registration)
        #expect(events.first?.outcome == CeremonyOutcome(ceremony: .assertion, succeeded: false))
        #expect(events.first?.document == nil)
    }

    /// Checks that `--no-exit` does not let one ceremony colour the next.
    ///
    /// After a sign-in that found no credential, the tracker remembers "no credentials" and
    /// would read a later placeholder registration as that failure. Starting the next
    /// ceremony must clear it, so the same placeholder alone is only a key being selected.
    @Test("starting the next ceremony forgets the previous one's inferences")
    func nextCeremonyStartsClean() {
        let dummy = message(CtapHidCommand.cbor, attestationPayload(rpIdHash: CeremonyTracker.dummyRpIdHash))
        var tracker = CeremonyTracker()
        _ = tracker.observe(message(CtapHidCommand.cbor, [0x2e]))
        tracker.startNextCeremony()
        #expect(tracker.observe(dummy).first?.outcome == nil)
    }

    /// Checks that a U2F request that is polled and then goes silent can be ended.
    ///
    /// U2F has no cancel answer: a browser simply stops asking. The tracker must say that it
    /// is being polled, so the monitor can time the silence, and stop saying so afterwards.
    @Test("a polled U2F request is flagged so that silence can end it")
    func u2fPolling() {
        var tracker = CeremonyTracker()
        #expect(!tracker.pollingU2f)
        #expect(tracker.observe(message(CtapHidCommand.msg, [0x69, 0x85])).count == 1)
        #expect(tracker.observe(message(CtapHidCommand.msg, [0x69, 0x85])).isEmpty)
        #expect(tracker.pollingU2f)
        #expect(tracker.idleExpired().outcome == CeremonyOutcome(ceremony: .unknown, succeeded: false))
        #expect(!tracker.pollingU2f)
    }
}

// The system log is followed on macOS only.
#if os(macOS)
/// Tests for how `monitor` reads the system's log messages about hybrid (QR code) sign-ins.
@Suite("Hybrid log monitoring")
struct HybridLogTests {
    /// Checks a whole ceremony: nothing is shown before the QR code appears, everything
    /// after it is, and the success message ends it.
    @Test("messages are shown from the start of a ceremony and success ends it")
    func successfulCeremony() {
        var tracker = HybridLogTracker()
        #expect(tracker.observe("Changing caBLE client state from bluetoothNotReady to bluetoothOnAndIdle").relevant == false)
        #expect(tracker.observe("Starting caBLE client") == (true, nil))
        #expect(tracker.observe("Connecting to relay at <private>") == (true, nil))
        #expect(tracker.observe("Transaction succeeded.") == (true, CeremonyOutcome(ceremony: .unknown, succeeded: true)))
        #expect(!tracker.active)
    }

    /// Checks that a failure message counts only inside a ceremony.
    ///
    /// The system logs `caBLE transaction failed` every time it discards an unused hybrid
    /// client, for example after a security key sign-in. That must neither be shown nor end
    /// monitoring; the same message after the QR code was shown is the ceremony failing.
    @Test("a failure message outside a ceremony is ignored; inside one it ends it")
    func failureOnlyCountsInsideCeremony() {
        var tracker = HybridLogTracker()
        #expect(tracker.observe("caBLE transaction failed: <private>") == (false, nil))
        _ = tracker.observe("Starting caBLE client")
        #expect(tracker.observe("caBLE transaction failed: <private>") == (true, CeremonyOutcome(ceremony: .unknown, succeeded: false)))
    }

    /// Checks that the system's closing messages are still shown just after the end, and no
    /// longer once that moment has passed.
    @Test("closing messages are shown briefly after the end")
    func trailingMessages() {
        var tracker = HybridLogTracker()
        let end = Date()
        _ = tracker.observe("Starting caBLE client", at: end)
        _ = tracker.observe("caBLE transaction failed: <private>", at: end)
        #expect(tracker.observe("Asked to close socket", at: end.addingTimeInterval(0.2)).relevant)
        #expect(!tracker.observe("Asked to close socket", at: end.addingTimeInterval(5)).relevant)
    }

    /// Checks that a line of `log stream --style ndjson` decodes, and that its header line,
    /// which is not JSON, does not.
    @Test("log stream output decodes into entries")
    func decodesLogStreamLines() throws {
        let line = #"{"eventMessage":"Starting caBLE client","processImagePath":"/System/Library/Frameworks/AuthenticationServices.framework/AuthenticationServicesAgent","subsystem":"com.apple.Safari","category":"Authorization","messageType":"Default","timestamp":"2026-11-19 19:21:47.769480+0100"}"#
        let entry = try JSONDecoder().decode(LogEntry.self, from: Data(line.utf8))
        #expect(entry.eventMessage == "Starting caBLE client")
        #expect(entry.process == "AuthenticationServicesAgent")
        #expect((try? JSONDecoder().decode(LogEntry.self, from: Data("Filtering the log data using".utf8))) == nil)
    }
}
#endif

/// Tests for the argument rules of the `prompt` subcommand that the option types cannot express.
@Suite("prompt arguments")
struct PromptArgumentTests {
    /// Checks that `--rpid`, `--list` and `--info` each work alone and in combination, and
    /// that giving none of them is an error rather than a prompt with nothing to do.
    @Test("at least one of --rpid, --list and --info is required; any combination is accepted")
    func requiresSomethingToDo() throws {
        for arguments in [["-i"], ["-l"], ["-r", "example.com"], ["-i", "-l"], ["-i", "-r", "example.com"],
                          ["-l", "-r", "example.com"], ["-i", "-l", "-r", "example.com"]] {
            _ = try Prompt.parse(arguments)
        }
        #expect(throws: (any Error).self) { try Prompt.parse([]) }
        #expect(throws: (any Error).self) { try Prompt.parse(["--pin", "1234"]) }
    }

    /// Checks that options which only make sense for an assertion are refused without `--rpid`.
    @Test("--challenge, --skip-user-verification and --transport hybrid need --rpid")
    func assertionOptionsNeedRelyingParty() {
        #expect(throws: (any Error).self) { try Prompt.parse(["-i", "--challenge", "AAEC"]) }
        #expect(throws: (any Error).self) { try Prompt.parse(["-l", "--skip-user-verification"]) }
        #expect(throws: (any Error).self) { try Prompt.parse(["-i", "--transport", "hybrid"]) }
    }

    /// Checks the rules of `--skip-user-presence` and `--flood`.
    ///
    /// Skipping user presence is a property of an assertion made by a security key, so it
    /// needs `--rpid` and cannot be combined with a phone. `--flood` only changes what
    /// happens after a cancel, so it is accepted with anything.
    @Test("--skip-user-presence needs --rpid and a security key; --flood goes with anything")
    func presenceAndFloodOptions() throws {
        let skipped = try Prompt.parse(["-r", "example.com", "--skip-user-presence", "--flood"])
        #expect(skipped.skipUserPresence)
        #expect(skipped.flood)
        _ = try Prompt.parse(["-l", "--flood"])
        #expect(try Prompt.parse(["-l", "-f"]).flood)
        #expect(throws: (any Error).self) { try Prompt.parse(["-l", "--skip-user-presence"]) }
        #expect(throws: (any Error).self) {
            try Prompt.parse(["-r", "example.com", "--transport", "hybrid", "--skip-user-presence"])
        }
    }
}

/// Tests for naming the relying party behind an `rpIdHash` (`RelyingParties.swift`).
@Suite("Known relying parties")
struct RelyingPartyTests {
    /// Checks the lookup against a hash that was not computed by this code.
    ///
    /// A security key signing in to webauthn.io reports an `rpIdHash` that starts with
    /// `74 a6 ea 92`, as captured from a real key. The list must turn that hash back into
    /// the name, and must say nothing for a hash of a site it does not know.
    @Test("a known site's hash gives its ID; an unknown hash gives none")
    func looksUpByHash() {
        let hash = Data("webauthn.io".utf8).sha256
        #expect(hash.prefix(4) == Data([0x74, 0xa6, 0xea, 0x92]))
        #expect(KnownRelyingParties.id(forHash: hash) == "webauthn.io")
        #expect(KnownRelyingParties.id(forHash: Data(repeating: 0xab, count: 32)) == nil)
    }

    /// Checks that the monitor names the relying party right after an assertion.
    ///
    /// The assertion event carries the JSON document and the outcome; the event after it
    /// is the extra log line, with the site's name when the hash is known and a plain
    /// statement that it is not when it is unknown.
    @Test("an observed assertion is followed by a line naming the relying party")
    func assertionIsFollowedByRelyingParty() {
        func observe(rpIdHash: Data) -> [MonitorEvent] {
            let payload: [UInt8] = [0x00, 0xa2, 0x02, 0x58, 37] + [UInt8](rpIdHash) + [0x01, 0, 0, 0, 5] + [0x03, 0x41, 0x00]
            var tracker = CeremonyTracker()
            return tracker.observe(CtapHidMessage(channel: 1, command: CtapHidCommand.cbor, payload: Data(payload)))
        }
        let known = observe(rpIdHash: Data("github.com".utf8).sha256)
        #expect(known.count == 2)
        #expect(known.first?.outcome?.succeeded == true)
        #expect(known.last?.message.contains("github.com") == true)
        #expect(known.last?.outcome == nil)
        let unknown = observe(rpIdHash: Data(repeating: 0xab, count: 32))
        #expect(unknown.last?.message.contains("not among") == true)
    }
}
