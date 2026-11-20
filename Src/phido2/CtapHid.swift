import CFido2
import Foundation

// What `monitor` can know comes only from the reports a security key sends to the host: other
// programs' requests are not visible to a second HID client. Everything in this file therefore
// works on responses alone, and recognises each one by its shape.

/// The CTAPHID commands a device answers with.
enum CtapHidCommand {
    static let ping: UInt8 = 0x01
    /// A U2F (CTAP1) APDU response.
    static let msg: UInt8 = 0x03
    static let lock: UInt8 = 0x04
    static let initialize: UInt8 = 0x06
    static let wink: UInt8 = 0x08
    /// A CTAP2 response: a status byte, then CBOR.
    static let cbor: UInt8 = 0x10
    static let cancel: UInt8 = 0x11
    /// Sent about every 100 ms while a CTAP2 request is being worked on.
    static let keepalive: UInt8 = 0x3b
    static let error: UInt8 = 0x3f

    /// A readable name for a command number.
    static func name(_ command: UInt8) -> String {
        switch command {
        case ping: "PING"
        case msg: "MSG"
        case lock: "LOCK"
        case initialize: "INIT"
        case wink: "WINK"
        case cbor: "CBOR"
        case cancel: "CANCEL"
        case keepalive: "KEEPALIVE"
        case error: "ERROR"
        default: "0x" + String(command, radix: 16)
        }
    }
}

/// One complete CTAPHID message from the device, put together from its HID reports.
struct CtapHidMessage: Equatable {
    /// The channel the host and the device agreed on with `INIT`.
    var channel: UInt32
    /// The command, with the "initiation packet" bit removed; see ``CtapHidCommand``.
    var command: UInt8
    var payload: Data
}

/// Joins the input reports of one HID device into CTAPHID messages.
///
/// A message starts with an initiation packet (channel, command, length, 57 bytes of data) and
/// continues in sequence-numbered packets (channel, sequence, 59 bytes of data). Messages on
/// different channels may interleave.
struct CtapHidReassembler {
    private struct Partial {
        var command: UInt8
        var length: Int
        var data: Data
        var nextSequence: UInt8
    }

    private var partial: [UInt32: Partial] = [:]

    /// Adds one input report.
    ///
    /// - Parameter report: The report as received, without a report ID.
    /// - Returns: The message this report completes, or `nil` if more packets are expected or
    ///   the report is malformed or out of sequence (the partial message is then dropped).
    mutating func add(_ report: Data) -> CtapHidMessage? {
        let bytes = [UInt8](report)
        guard bytes.count >= 5 else { return nil }
        let channel = bytes[0..<4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        if bytes[4] & 0x80 != 0 {
            guard bytes.count >= 7 else { return nil }
            let length = Int(bytes[5]) << 8 | Int(bytes[6])
            let state = Partial(command: bytes[4] & 0x7f, length: length,
                                data: Data(bytes[7...].prefix(length)), nextSequence: 0)
            return finish(state, on: channel)
        }
        guard var state = partial[channel], bytes[4] == state.nextSequence else {
            partial[channel] = nil
            return nil
        }
        state.data.append(contentsOf: bytes[5...].prefix(state.length - state.data.count))
        state.nextSequence += 1
        return finish(state, on: channel)
    }

    private mutating func finish(_ state: Partial, on channel: UInt32) -> CtapHidMessage? {
        guard state.data.count >= state.length else {
            partial[channel] = state
            return nil
        }
        partial[channel] = nil
        return CtapHidMessage(channel: channel, command: state.command, payload: state.data)
    }
}

/// WebAuthn authenticator data: the part of an assertion or attestation the key signs.
struct AuthenticatorData: Equatable {
    /// SHA-256 of the relying party ID. The ID itself is never sent back by the key.
    var rpIdHash: Data
    var flags: UInt8
    var signCount: UInt32
    /// The authenticator model. Present in registrations only.
    var aaguid: Data?
    /// Present in registrations only.
    var credentialId: Data?
    /// The new credential's public key as a COSE_Key, CBOR-encoded. Present in registrations only.
    var publicKey: Data?
    /// The COSE algorithm of ``publicKey``, e.g. -7 for ES256.
    var algorithm: Int64?

    /// The user touched the key.
    var userPresent: Bool { flags & 0x01 != 0 }
    /// The key verified the user with a PIN or fingerprint.
    var userVerified: Bool { flags & 0x04 != 0 }

    /// - Parameter data: The `authData` byte string of a CTAP2 response.
    /// - Returns: `nil` if `data` is shorter than its fixed part or its attested credential
    ///   data is truncated.
    init?(_ data: Data) {
        let bytes = [UInt8](data)
        guard bytes.count >= 37 else { return nil }
        rpIdHash = Data(bytes[0..<32])
        flags = bytes[32]
        signCount = bytes[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        // Bit 6 (AT): attested credential data follows.
        guard flags & 0x40 != 0 else { return }
        guard bytes.count >= 55 else { return nil }
        let idLength = Int(bytes[53]) << 8 | Int(bytes[54])
        guard bytes.count >= 55 + idLength else { return nil }
        aaguid = Data(bytes[37..<53])
        credentialId = Data(bytes[55..<55 + idLength])
        // The public key is followed by the extensions, if any; decoding tells where it ends.
        let rest = Data(bytes[(55 + idLength)...])
        if let key = CBORValue.decode(rest) {
            publicKey = rest.prefix(key.consumed)
            algorithm = key.value[3]?.intValue
        }
    }
}

/// A CTAP2 response (`CTAPHID_CBOR`), identified by which members its CBOR map has.
enum Ctap2Response: Equatable {
    /// `authenticatorGetInfo`.
    case info(versions: [String], aaguid: Data?, options: [String: Bool], transports: [String]?)
    /// `authenticatorGetAssertion` or `authenticatorGetNextAssertion`.
    case assertion(Assertion)
    /// `authenticatorMakeCredential`.
    case attestation(format: String, authenticatorData: AuthenticatorData, raw: Data)
    /// `authenticatorClientPIN`.
    case clientPIN(pinRetries: Int64?, uvRetries: Int64?, keyAgreement: Bool, token: Bool)
    /// Success with no data, e.g. for a PIN change or `authenticatorSelection`.
    case empty
    /// Success with data of another command, e.g. credential management.
    case other
    /// A CTAP2 status other than success. The request that caused it cannot be seen.
    case error(UInt8)

    struct Assertion: Equatable {
        var authenticatorData: AuthenticatorData
        var rawAuthenticatorData: Data
        var signature: Data
        /// Absent when the request's allow list had a single entry.
        var credentialId: Data?
        var userId: Data?
        var userName: String?
        var userDisplayName: String?
        /// Sent with the first assertion when the key has several for the relying party.
        var numberOfCredentials: Int64?
    }

    /// - Parameter payload: The payload of a `CTAPHID_CBOR` message from the device.
    init(_ payload: Data) {
        guard let status = payload.first else { self = .other; return }
        guard status == 0 else { self = .error(status); return }
        let body = Data(payload.dropFirst())
        guard !body.isEmpty else { self = .empty; return }
        guard let map = CBORValue.decode(body)?.value, map.mapValue != nil else { self = .other; return }

        if let versions = map[1]?.arrayValue {
            var options: [String: Bool] = [:]
            for (key, value) in map[4]?.mapValue ?? [:] {
                if case .text(let name) = key, let flag = value.boolValue { options[name] = flag }
            }
            self = .info(versions: versions.compactMap(\.textValue), aaguid: map[3]?.bytesValue,
                         options: options, transports: map[9]?.arrayValue?.compactMap(\.textValue))
        } else if let raw = map[2]?.bytesValue, let signature = map[3]?.bytesValue,
                  let authData = AuthenticatorData(raw) {
            let user = map[4]
            self = .assertion(Assertion(
                authenticatorData: authData, rawAuthenticatorData: raw, signature: signature,
                credentialId: map[1]?["id"]?.bytesValue, userId: user?["id"]?.bytesValue,
                userName: user?["name"]?.textValue, userDisplayName: user?["displayName"]?.textValue,
                numberOfCredentials: map[5]?.intValue))
        } else if let format = map[1]?.textValue, let raw = map[2]?.bytesValue,
                  let authData = AuthenticatorData(raw) {
            self = .attestation(format: format, authenticatorData: authData, raw: raw)
        } else if (map[3]?.intValue != nil && map[1] == nil && map[2] == nil)
                    // A fingerprint sensor's description also has an integer under 3, next to
                    // one under 2; a retry counter comes without either of the other members.
                    || (map[1]?.mapValue != nil && map[2] == nil && map[3] == nil)
                    || (map[2]?.bytesValue != nil && map[1] == nil && map[3] == nil) {
            self = .clientPIN(pinRetries: map[3]?.intValue, uvRetries: map[5]?.intValue,
                              keyAgreement: map[1] != nil, token: map[2] != nil)
        } else {
            self = .other
        }
    }
}

/// A U2F (CTAP1) response (`CTAPHID_MSG`): data followed by a two-byte status word.
enum U2fResponse: Equatable {
    case registration(publicKey: Data, keyHandle: Data)
    case authentication(userPresent: Bool, counter: UInt32, signature: Data)
    /// The answer to a version request, `U2F_V2`.
    case version(String)
    /// A status word other than 0x9000.
    case status(UInt16)
    case other

    static let conditionsNotSatisfied: UInt16 = 0x6985
    static let wrongData: UInt16 = 0x6a80

    /// - Parameter payload: The payload of a `CTAPHID_MSG` message from the device.
    init(_ payload: Data) {
        let bytes = [UInt8](payload)
        guard bytes.count >= 2 else { self = .other; return }
        let status = UInt16(bytes[bytes.count - 2]) << 8 | UInt16(bytes[bytes.count - 1])
        guard status == 0x9000 else { self = .status(status); return }
        let body = Array(bytes.dropLast(2))
        if body.count >= 7, body[5] == 0x30, body.count == 7 + Int(body[6]) {
            // Presence byte, 4-byte counter, then an ECDSA signature: a DER SEQUENCE to the end.
            self = .authentication(userPresent: body[0] & 0x01 != 0,
                                   counter: body[1..<5].reduce(UInt32(0)) { $0 << 8 | UInt32($1) },
                                   signature: Data(body[5...]))
        } else if body.count >= 67, body[0] == 0x05, body[1] == 0x04, body.count >= 67 + Int(body[66]) {
            // Reserved byte 0x05, a 65-byte uncompressed P-256 point, then the key handle.
            self = .registration(publicKey: Data(body[1..<66]), keyHandle: Data(body[67..<67 + Int(body[66])]))
        } else if let text = String(bytes: body, encoding: .ascii), text.hasPrefix("U2F_") {
            self = .version(text)
        } else {
            self = .other
        }
    }

    /// A readable name for a status word.
    static func name(_ status: UInt16) -> String {
        switch status {
        case conditionsNotSatisfied: "conditions not satisfied"
        case wrongData: "wrong data"
        case 0x6700: "wrong length"
        case 0x6d00: "instruction not supported"
        case 0x6e00: "class not supported"
        default: "status"
        }
    }
}

/// How a WebAuthn ceremony that `monitor` watched ended.
struct CeremonyOutcome: Equatable {
    enum Ceremony: String {
        case assertion
        case registration
        /// A failed request: the key's error does not say which kind it was.
        case unknown
    }

    var ceremony: Ceremony
    var succeeded: Bool
}

/// One thing `monitor` has to say about a message: a log line, optionally a JSON document,
/// and the ceremony's outcome if this message ended it.
struct MonitorEvent {
    enum Severity { case debug, info, warning }

    var severity: Severity = .info
    var message: String
    var document: (any Encodable)?
    var outcome: CeremonyOutcome?
}

/// Turns the device's messages into observations and decides when a ceremony is over.
///
/// Because only responses are visible, some conclusions are inferences:
/// - "No credentials" ends the ceremony as a failed assertion, unless another key is in
///   use. The browser's placeholder request that follows it is not a ceremony of its own.
/// - Any other CTAP2 error ends the ceremony only if the key had been waiting for the user
///   (a keepalive with status "user presence needed").
/// - Even after such a wait, "PIN required" and its relatives do not end it: the browser
///   sent the request without a PIN to have the key touched, and asks for the PIN next.
/// - With several keys attached, the browser asks all of them and cancels the rest once one
///   is touched. A cancelled request ends the ceremony only if no key was picked and none is
///   still waiting.
/// - An assertion without the user-present flag is such a silent check that found a match.
/// - A registration for the relying party `.dummy` is not a real one: browsers send it to
///   wait for a touch before they report that no credential matched, or that the credential
///   is already registered.
/// - A U2F registration right after a CTAP2 "no credentials" is the same placeholder, sent
///   after the browser fell back to U2F.
/// - U2F has no keepalives; a browser polls until the key is touched. When the polling just
///   stops, ``idleExpired()`` reports the request as abandoned.
struct CeremonyTracker {
    /// Errors a key gives after a touch when the request carried no PIN or a placeholder one.
    static let pinStepErrors: Set<Int32> = [FIDO_ERR_PIN_REQUIRED, FIDO_ERR_PIN_INVALID, FIDO_ERR_PIN_NOT_SET, FIDO_ERR_PIN_AUTH_INVALID]

    /// SHA-256 of `.dummy`, the relying party of browsers' placeholder registrations.
    static let dummyRpIdHash = Data(".dummy".utf8).sha256

    /// Whether a U2F request is being polled, so that silence means it was given up.
    private(set) var pollingU2f = false
    /// The security keys that are waiting for their user right now.
    private var waiting: Set<AnyHashable> = []
    /// The key the user picked by touching it, once one has been picked.
    private var chosen: AnyHashable?
    private var noCredentialsSeen = false
    private var silentMatchSeen = false
    /// Identifies the last line of a kind that repeats many times a second.
    private var repeatKey: String?
    /// Whether the previous ceremony ended with "no credentials", so that the browser's
    /// placeholder request for it may still arrive.
    private var placeholderExpected = false
    /// The authenticator documents already printed, one per security key.
    private var printedInfo: Set<Data> = []

    /// Handles one message.
    ///
    /// - Parameters:
    ///   - message: A message from the device.
    ///   - manufacturer: The device's USB manufacturer string, for the authenticator document.
    ///   - product: The device's USB product string.
    /// - Returns: What to report; empty for repeats of the previous polling answer.
    mutating func observe(_ message: CtapHidMessage, from device: AnyHashable = 0, manufacturer: String? = nil, product: String? = nil) -> [MonitorEvent] {
        switch message.command {
        case CtapHidCommand.keepalive: return keepalive(message.payload.first ?? 0, device)
        case CtapHidCommand.cbor: return ctap2(Ctap2Response(message.payload), device, manufacturer, product)
        case CtapHidCommand.msg: return u2f(U2fResponse(message.payload))
        case CtapHidCommand.initialize:
            return [MonitorEvent(severity: .debug, message: "A program opened a channel to the security key")]
        case CtapHidCommand.error:
            repeatKey = nil
            let code = message.payload.first ?? 0
            return [MonitorEvent(severity: .warning, message: "CTAPHID error 0x\(String(code, radix: 16)): \(Self.hidErrorName(code))")]
        default:
            return [MonitorEvent(severity: .debug, message: "CTAPHID \(CtapHidCommand.name(message.command)) response, \(message.payload.count) bytes")]
        }
    }

    /// Forgets what was inferred about the ceremony that just ended, so that the next one is
    /// judged on its own. The authenticator details already printed are remembered.
    mutating func startNextCeremony() {
        let printed = printedInfo
        // After "no credentials" the browser still sends its placeholder request; that
        // belongs to the ceremony that has just been reported, not to a new one.
        let placeholder = noCredentialsSeen
        self = CeremonyTracker()
        printedInfo = printed
        placeholderExpected = placeholder
    }

    /// Call when a polled U2F request has had no answer for a few seconds.
    ///
    /// - Returns: The observation that ends the ceremony as unsuccessful.
    mutating func idleExpired() -> MonitorEvent {
        pollingU2f = false
        repeatKey = nil
        return MonitorEvent(severity: .warning,
                           message: "Ceremony failed: the U2F request stopped before the key was touched (cancelled or timed out)",
                           outcome: CeremonyOutcome(ceremony: .unknown, succeeded: false))
    }

    // MARK: CTAP2

    private mutating func keepalive(_ status: UInt8, _ device: AnyHashable) -> [MonitorEvent] {
        // 1: processing, 2: user presence needed.
        if status == 2 { waiting.insert(device) }
        guard isNew("keepalive-\(status)") else { return [] }
        return [status == 2
            ? MonitorEvent(message: "The security key is waiting for the user (touch or fingerprint)")
            : MonitorEvent(severity: .debug, message: "The security key is processing a request")]
    }

    private mutating func ctap2(_ response: Ctap2Response, _ device: AnyHashable, _ manufacturer: String?, _ product: String?) -> [MonitorEvent] {
        // A response ends the request the keepalives belonged to.
        let wasWaiting = waiting.remove(device) != nil
        if case .error = response {} else { repeatKey = nil }

        switch response {
        case .info(let versions, let aaguid, let options, let transports):
            // A browser asks for this at the start of a ceremony; whatever was left over
            // from the previous one is not coming any more.
            placeholderExpected = false
            let document = AuthenticatorInfo(
                transport: .usb, manufacturer: manufacturer, product: product,
                aaguid: aaguid.flatMap(formatAAGUID), versions: versions, transports: transports,
                pinSet: options["clientPin"], builtInUserVerification: options["uv"])
            // Browsers ask for this several times per ceremony; print it once.
            // Sorted keys, so that equal documents encode to equal bytes.
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            guard let encoded = try? encoder.encode(document), printedInfo.insert(encoded).inserted else {
                return [MonitorEvent(severity: .debug, message: "authenticatorGetInfo response (unchanged)")]
            }
            return [MonitorEvent(message: "authenticatorGetInfo response: \(versions.joined(separator: ", "))", document: document)]

        case .assertion(let assertion):
            let data = assertion.authenticatorData
            let document = ObservedAssertion(
                protocol: "ctap2", credentialId: assertion.credentialId?.base64URL,
                rpIdHash: data.rpIdHash.base64URL, userPresent: data.userPresent, userVerified: data.userVerified,
                signCount: data.signCount, authenticatorData: assertion.rawAuthenticatorData.base64URL,
                signature: assertion.signature.base64URL,
                user: assertion.userId == nil && assertion.userName == nil ? nil
                    : .init(id: assertion.userId?.base64URL, name: assertion.userName, displayName: assertion.userDisplayName),
                numberOfCredentials: assertion.numberOfCredentials.map(Int.init))
            guard data.userPresent else {
                silentMatchSeen = true
                return [MonitorEvent(message: "Silent check: the security key has a matching credential (UP=0, nothing signed for the site yet)",
                                    document: document),
                        MonitorEvent(message: KnownRelyingParties.describe(hash: data.rpIdHash))]
            }
            let more = (assertion.numberOfCredentials ?? 1) > 1 ? ", \(assertion.numberOfCredentials!) credentials" : ""
            return [MonitorEvent(message: "Assertion succeeded: UP=1 UV=\(data.userVerified ? 1 : 0) signCount=\(data.signCount)\(more)",
                                document: document, outcome: CeremonyOutcome(ceremony: .assertion, succeeded: true)),
                    // After the document, so that the name follows the hash it explains.
                    MonitorEvent(message: KnownRelyingParties.describe(hash: data.rpIdHash))]

        case .attestation(let format, let data, let raw):
            if data.rpIdHash == Self.dummyRpIdHash {
                if placeholderExpected {
                    placeholderExpected = false
                    return [MonitorEvent(message: "Placeholder registration answered: the browser had the key touched before reporting that nothing matched")]
                }
                if noCredentialsSeen {
                    return [MonitorEvent(severity: .warning,
                                        message: "Assertion failed: no matching credential on this security key (inferred: the browser used a placeholder registration to wait for the touch)",
                                        outcome: CeremonyOutcome(ceremony: .assertion, succeeded: false))]
                }
                if silentMatchSeen {
                    return [MonitorEvent(severity: .warning,
                                        message: "Registration failed: the credential is already on this security key (inferred: the browser used a placeholder registration to wait for the touch)",
                                        outcome: CeremonyOutcome(ceremony: .registration, succeeded: false))]
                }
                return [MonitorEvent(message: "Placeholder registration answered: the user touched this security key to select it")]
            }
            let document = ObservedRegistration(
                protocol: "ctap2", format: format, rpIdHash: data.rpIdHash.base64URL,
                aaguid: data.aaguid.flatMap(formatAAGUID), credentialId: data.credentialId?.base64URL,
                algorithm: data.algorithm.map(Int.init), publicKey: data.publicKey?.base64URL,
                userPresent: data.userPresent, userVerified: data.userVerified, signCount: data.signCount,
                authenticatorData: raw.base64URL)
            return [MonitorEvent(message: "Registration succeeded: UP=\(data.userPresent ? 1 : 0) UV=\(data.userVerified ? 1 : 0) attestation format \(format)",
                                document: document, outcome: CeremonyOutcome(ceremony: .registration, succeeded: true)),
                    MonitorEvent(message: KnownRelyingParties.describe(hash: data.rpIdHash))]

        case .clientPIN(let pinRetries, let uvRetries, let keyAgreement, let token):
            if let pinRetries { return [MonitorEvent(message: "clientPIN response: \(pinRetries) PIN attempts left")] }
            if let uvRetries { return [MonitorEvent(message: "clientPIN response: \(uvRetries) built-in verification attempts left")] }
            if token { return [MonitorEvent(message: "clientPIN response: the PIN or fingerprint was accepted (token issued)")] }
            return [MonitorEvent(severity: .debug, message: "clientPIN response" + (keyAgreement ? ": key agreement" : ""))]

        case .empty:
            return [MonitorEvent(severity: .debug, message: "CTAP2 success without data")]

        case .other:
            return [MonitorEvent(severity: .debug, message: "CTAP2 response of an unrecognised command")]

        case .error(let code):
            let name = String(cString: fido_strerr(Int32(code))) + " (0x" + String(code, radix: 16) + ")"
            if code == UInt8(FIDO_ERR_NO_CREDENTIALS) {
                // Said once per ceremony; a browser may ask again for each entry of an allow
                // list, and goes on to a placeholder request that only waits for a touch.
                guard !noCredentialsSeen, !placeholderExpected else { return [] }
                noCredentialsSeen = true
                repeatKey = nil
                // With several keys, the sign-in can still succeed on another one.
                if !waiting.isEmpty || (chosen != nil && chosen != device) {
                    return [MonitorEvent(message: "This security key has no matching credential (\(name)); another key is in use")]
                }
                return [MonitorEvent(severity: .warning, message: "Assertion failed: no matching credential on this security key (\(name))",
                                    outcome: CeremonyOutcome(ceremony: .assertion, succeeded: false))]
            }
            if wasWaiting, Self.pinStepErrors.contains(Int32(code)) {
                // With a PIN-protected key, a browser first sends a request without a PIN.
                // The key waits for a touch, which also tells the browser which of several
                // keys the user picked, and then answers with one of these errors. The
                // browser goes on to ask for the PIN; nothing has failed.
                chosen = device
                repeatKey = nil
                return [MonitorEvent(message: "The security key was touched and wants a PIN (\(name)); the ceremony goes on")]
            }
            if wasWaiting, code == UInt8(FIDO_ERR_KEEPALIVE_CANCEL), (chosen != nil && chosen != device) || !waiting.isEmpty {
                // A browser asks every attached key and cancels the others once the user
                // has touched one. Only when no key is left waiting and none was picked did
                // the user cancel the ceremony itself.
                repeatKey = nil
                return [MonitorEvent(message: "The request to this security key was cancelled; another key is in use")]
            }
            // A mismatched fingerprint is retried by the browser within the same ceremony.
            if wasWaiting && code != UInt8(FIDO_ERR_UV_INVALID) {
                repeatKey = nil
                return [MonitorEvent(severity: .warning, message: "Ceremony failed: \(name)",
                                    outcome: CeremonyOutcome(ceremony: .unknown, succeeded: false))]
            }
            guard isNew("ctap2-error-\(code)") else { return [] }
            return [MonitorEvent(severity: .warning, message: "CTAP2 error: \(name)")]
        }
    }

    // MARK: U2F

    private mutating func u2f(_ response: U2fResponse) -> [MonitorEvent] {
        if case .status = response {} else { repeatKey = nil }
        switch response {
        case .authentication(let userPresent, let counter, let signature):
            pollingU2f = false
            let document = ObservedAssertion(protocol: "u2f", userPresent: userPresent, signCount: counter,
                                             signature: signature.base64URL)
            return [MonitorEvent(message: "Assertion succeeded (U2F): UP=\(userPresent ? 1 : 0) signCount=\(counter)",
                                document: document, outcome: CeremonyOutcome(ceremony: .assertion, succeeded: true))]

        case .registration(let publicKey, let keyHandle):
            pollingU2f = false
            // Safari's sequence when a FIDO2 key has nothing for the site: CTAP2 "no
            // credentials", a fall-back to U2F, then a placeholder registration that only
            // waits for the touch. A real registration on such a key would use CTAP2.
            if placeholderExpected {
                placeholderExpected = false
                return [MonitorEvent(message: "Placeholder registration answered (U2F): the browser had the key touched before reporting that nothing matched")]
            }
            if noCredentialsSeen {
                return [MonitorEvent(severity: .warning,
                                     message: "Assertion failed: no matching credential on this security key (inferred: after \"no credentials\" the browser fell back to U2F and used a placeholder registration to wait for the touch)",
                                     outcome: CeremonyOutcome(ceremony: .assertion, succeeded: false))]
            }
            let document = ObservedRegistration(protocol: "u2f", credentialId: keyHandle.base64URL,
                                                algorithm: -7, publicKey: publicKey.base64URL, userPresent: true)
            // U2F responses do not name the relying party, so a placeholder registration
            // cannot be told from a real one.
            return [MonitorEvent(message: "Registration answered (U2F) after a touch. A browser also sends a placeholder registration like this to wait for a touch when no credential matched; the two cannot be told apart",
                                document: document, outcome: CeremonyOutcome(ceremony: .registration, succeeded: true))]

        case .version(let version):
            return [MonitorEvent(severity: .debug, message: "U2F version response: \(version)")]

        case .status(let status):
            // Polling for the placeholder of a ceremony already reported is not watched.
            pollingU2f = !placeholderExpected && (status == U2fResponse.conditionsNotSatisfied || status == U2fResponse.wrongData)
            guard isNew("u2f-\(status)") else { return [] }
            let code = "0x" + String(status, radix: 16)
            switch status {
            case U2fResponse.conditionsNotSatisfied:
                return [MonitorEvent(message: "U2F: the security key is waiting for a touch (\(code))")]
            case U2fResponse.wrongData:
                return [MonitorEvent(message: "U2F: a key handle was offered that this security key does not own (\(code))")]
            default:
                return [MonitorEvent(severity: .warning, message: "U2F error: \(U2fResponse.name(status)) (\(code))")]
            }

        case .other:
            return [MonitorEvent(severity: .debug, message: "U2F response of an unrecognised command")]
        }
    }

    // MARK: Helpers

    /// Returns whether `key` differs from the previous polling answer, and remembers it.
    private mutating func isNew(_ key: String) -> Bool {
        defer { repeatKey = key }
        return repeatKey != key
    }

    private static func hidErrorName(_ code: UInt8) -> String {
        switch code {
        case 0x01: "invalid command"
        case 0x02: "invalid parameter"
        case 0x03: "invalid length"
        case 0x04: "invalid sequence"
        case 0x05: "message timeout"
        case 0x06: "channel busy"
        case 0x0a: "lock required"
        case 0x0b: "invalid channel"
        default: "other"
        }
    }
}

/// Formats a 16-byte AAGUID as a lowercase UUID string.
///
/// - Returns: `nil` if `aaguid` is not 16 bytes long.
func formatAAGUID(_ aaguid: Data) -> String? {
    guard aaguid.count == 16 else { return nil }
    // Written out by hand: NSUUID's initialiser takes a non-optional pointer on Linux, and its
    // formatting is not the same on every platform.
    let hex = aaguid.map { String(format: "%02x", $0) }
    return [hex[0..<4], hex[4..<6], hex[6..<8], hex[8..<10], hex[10..<16]]
        .map { $0.joined() }
        .joined(separator: "-")
}
