import CFido2
import Foundation

/// A failed libfido2 call or an unusable security key.
struct FidoError: Error, CustomStringConvertible {
    /// The libfido2 / CTAP status code (`FIDO_ERR_*`), or 0 when the failure has no code.
    var code: Int32
    /// What was being attempted, in words fit for the user.
    var operation: String

    /// The error a session ends with after ``FidoSession/cancel()``.
    static let cancelled = FidoError(code: FIDO_ERR_KEEPALIVE_CANCEL, operation: "Cancelled")

    var description: String {
        code == 0 ? operation : "\(operation): \(String(cString: fido_strerr(code))) (0x\(String(code, radix: 16)))"
    }
}

/// The parameters of one assertion ceremony.
struct Request {
    /// Relying party ID, e.g. `login.microsoft.com`. `nil` to make no assertion: the request
    /// then only lists every credential on the security key (``discover``), prints the key's
    /// details (``info``), or both.
    var rpId: String?
    /// The client data to sign; see ``makeClientDataJSON(challenge:origin:)``.
    var clientDataJSON: Data
    /// A PIN known in advance. When `nil`, the user is asked only if the key needs one.
    var pin: String?
    /// Whether to list every credential on the key, of all relying parties.
    var discover: Bool
    /// Whether to print the authenticator's details.
    var info = false
    /// Whether to leave user verification out of the assertion request, so that only a touch
    /// is needed and the result has the UV flag unset. Listing credentials still verifies the
    /// user, because credential management cannot work without it.
    var skipUserVerification = false
    /// Whether to request the assertion without user presence, so that the key answers
    /// without a touch. Keys may refuse this for discoverable credentials.
    var skipUserPresence = false
    /// Whether to start again instead of giving up when the user cancels or the key times
    /// out, for repeated troubleshooting. It never uses up the last PIN attempt.
    var flood = false
}

/// What has already been done for a request, kept across the sessions that flood mode starts
/// one after another, so that a new session does not repeat it: the key's details and the
/// credential list are printed once, and a PIN the key has accepted is not asked for again.
///
/// Used only by the session that has the security key open, so by one thread at a time.
final class SessionProgress {
    /// Whether the authenticator's details have been printed.
    var infoEmitted = false
    /// Whether the credential list has been printed, or found to be unavailable.
    var credentialsEmitted = false
    /// A PIN that the security key accepted.
    var acceptedPIN: String?
}

/// What a ``FidoSession`` needs from the user interface.
///
/// Every method is called on the session's worker thread, never on the main thread.
protocol SessionUI: AnyObject {
    /// Tells the user to insert the key or to touch it (or its fingerprint sensor).
    ///
    /// Until this or ``requestPIN(incorrect:retries:)`` is called, no prompt needs to be on
    /// screen: a request that asks nothing of the user never calls either.
    ///
    /// - Parameter afterPIN: `true` when the user has just entered a PIN, so the wording
    ///   should ask them to activate the key "again".
    func showActivate(afterPIN: Bool)

    /// Asks the user for the key's PIN and blocks until they submit one.
    ///
    /// - Parameters:
    ///   - incorrect: `true` when the previous PIN was rejected.
    ///   - retries: How many attempts the key still allows, if it said so.
    /// - Returns: The PIN the user entered, or `nil` if the user went back instead.
    func requestPIN(incorrect: Bool, retries: Int?) -> String?
}

/// Runs an assertion ceremony against the first FIDO HID device, using libfido2.
///
/// libfido2 reaches the key through IOKit's IOHIDManager on macOS and through hidraw on
/// Linux; neither needs special rights.
/// Its calls block (device polling, waiting for touch), so ``run(_:ui:)`` must not be called
/// on the main thread.
final class FidoSession {
    /// How the user is verified in one attempt.
    private enum Verification {
        case none
        case builtIn
        case pin(String)

        var pin: String? {
            if case .pin(let pin) = self { return pin }
            return nil
        }

        var reported: UserVerification {
            switch self {
            case .none: .none
            case .builtIn: .builtIn
            case .pin: .pin
            }
        }
    }

    private struct FoundDevice {
        var path: String
        var manufacturer: String?
        var product: String?
    }

    /// Held by the session that has the security key open.
    private static let deviceGate = NSLock()

    private let lock = NSLock()
    private var device: OpaquePointer?
    private var cancelled = false
    private let progress: SessionProgress

    /// - Parameter progress: What earlier sessions for the same request have already done.
    ///   A session that is the only one for its request needs none.
    init(progress: SessionProgress = SessionProgress()) {
        self.progress = progress
    }

    /// Whether ``cancel()`` has been called.
    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    /// Ends the session: stops waiting for a key, and cancels a request waiting for touch.
    ///
    /// May be called from any thread. ``run(_:ui:)`` then throws ``FidoError/cancelled``.
    func cancel() {
        lock.lock()
        cancelled = true
        if let device { fido_dev_cancel(device) }
        lock.unlock()
    }

    /// Waits for a security key, verifies the user, and gets the assertion.
    ///
    /// User verification is chosen in this order: the PIN from `request`, the key's built-in
    /// verification (fingerprint) if enrolled, a PIN asked through `ui`, or none if the key
    /// has neither. If built-in verification gets blocked, the PIN is used as the fallback.
    /// With `request.skipUserVerification`, none is chosen outright unless credentials are to
    /// be listed, and the assertion itself is always requested without verification.
    ///
    /// - Parameters:
    ///   - request: What to sign and for which relying party.
    ///   - ui: Receives prompts for touch and PIN.
    /// Results are printed with ``emit(_:)`` as they become available: the authenticator's
    /// details once it is open (if requested), then the credentials, then the assertions.
    ///
    /// - Throws: ``FidoError`` if the session is cancelled, or the key cannot be opened, is
    ///   U2F-only, has no matching credential, has its PIN blocked, or fails in any other way.
    ///   A wrong PIN does not throw; the user is asked again.
    func run(_ request: Request, ui: SessionUI) throws {
        let found = try waitForDevice(ui)
        logger.info("Using \(found.product ?? "security key") at \(found.path)")

        // One session at a time has the key open. A session that was cancelled lets go of it
        // a moment later, on its own thread, and the key cannot be opened twice: without this
        // wait, a session started right after a cancel (flood mode) fails to open it.
        Self.deviceGate.lock()
        defer { Self.deviceGate.unlock() }
        if isCancelled { throw FidoError.cancelled }

        guard let dev = fido_dev_new() else { throw FidoError(code: 0, operation: "fido_dev_new failed") }
        defer {
            var d: OpaquePointer? = dev
            fido_dev_free(&d)
        }
        try check(fido_dev_open(dev, found.path), "Opening the security key")
        lock.lock(); device = dev; lock.unlock()
        defer {
            lock.lock(); device = nil; lock.unlock()
            fido_dev_close(dev)
        }
        guard fido_dev_is_fido2(dev) else {
            throw FidoError(code: 0, operation: "This security key supports only U2F, not FIDO2")
        }

        let pinSet = fido_dev_has_pin(dev)
        let builtInUV = fido_dev_has_uv(dev)
        var info = AuthenticatorInfo(transport: .usb, manufacturer: found.manufacturer, product: found.product,
                                     pinSet: pinSet, builtInUserVerification: builtInUV)
        if request.info, !progress.infoEmitted {
            readAuthenticatorDetails(dev, into: &info)
            emit(info)
            progress.infoEmitted = true
        }
        // Printing the key's details needs neither the user nor a credential.
        guard request.rpId != nil || request.discover else { return }
        if request.pin != nil && !pinSet { logger.warning("The security key has no PIN set; ignoring --pin") }

        var enteredPIN: String?
        var verification: Verification
        if request.skipUserVerification && !request.discover {
            if request.pin != nil { logger.warning("User verification is skipped; ignoring --pin") }
            verification = .none
        } else if pinSet, let pin = request.pin ?? progress.acceptedPIN {
            // Also a PIN that an earlier session of this request asked for and the key accepted.
            verification = .pin(pin)
        } else if builtInUV {
            verification = .builtIn
        } else if pinSet {
            enteredPIN = try askPIN(dev, request, ui, incorrect: false)
            verification = .pin(enteredPIN!)
        } else {
            verification = .none
        }

        while true {
            do {
                // A session cancelled in the meantime must not start waiting for a touch.
                if isCancelled { throw FidoError.cancelled }
                // The prompt is shown only when the user has something to do: touch the key
                // for the assertion, or put a finger on its sensor. Listing credentials with
                // a PIN, for example, needs neither.
                if (request.rpId != nil && !request.skipUserPresence) || verification.reported == .builtIn {
                    ui.showActivate(afterPIN: enteredPIN != nil)
                }
                return try attempt(dev, request, verification)
            } catch let error as FidoError where request.flood && error.code == FIDO_ERR_ACTION_TIMEOUT {
                logger.warning("The security key timed out; flood mode asks again")
            } catch let error as FidoError where error.code == FIDO_ERR_PIN_INVALID {
                progress.acceptedPIN = nil
                var retries: Int32 = 0
                if fido_dev_get_retry_count(dev, &retries) == FIDO_OK {
                    logger.warning("Incorrect PIN, \(retries) attempts left")
                }
                enteredPIN = try askPIN(dev, request, ui, incorrect: true)
                verification = .pin(enteredPIN!)
            } catch let error as FidoError where error.code == FIDO_ERR_UV_INVALID && verification.pin == nil {
                // The fingerprint did not match; the key counts down its own retries.
                var retries: Int32 = 0
                if fido_dev_get_uv_retry_count(dev, &retries) == FIDO_OK {
                    logger.warning("Built-in user verification failed, \(retries) attempts left")
                }
            } catch let error as FidoError
                where pinSet && verification.pin == nil
                && (error.code == FIDO_ERR_UV_BLOCKED || error.code == FIDO_ERR_PIN_REQUIRED) {
                logger.warning("Built-in user verification is unavailable (\(error)); falling back to the PIN")
                enteredPIN = try askPIN(dev, request, ui, incorrect: false)
                verification = .pin(enteredPIN!)
            }
        }
    }

    /// Asks for the PIN through the UI and logs it at once, before the key has checked it.
    ///
    /// In flood mode a dismissed PIN prompt is shown again, and nothing is asked once only
    /// one attempt is left, so that the key can never end up blocked.
    ///
    /// - Throws: ``FidoError/cancelled`` if the user went back instead of entering one, or a
    ///   ``FidoError`` without a code when flood mode stops to keep the last attempt.
    private func askPIN(_ dev: OpaquePointer, _ request: Request, _ ui: SessionUI, incorrect: Bool) throws -> String {
        while true {
            var count: Int32 = 0
            let retries = fido_dev_get_retry_count(dev, &count) == FIDO_OK ? Int(count) : nil
            if request.flood, let retries, retries <= 1 {
                throw FidoError(code: 0, operation: "Flood mode stops here to preserve the last PIN attempt")
            }
            if let pin = ui.requestPIN(incorrect: incorrect, retries: retries) {
                logger.info("PIN entered: \(pin)")
                return pin
            }
            // A session that was cancelled as a whole must not ask again.
            guard request.flood, !isCancelled else { throw FidoError.cancelled }
        }
    }

    /// Performs discovery (if requested) and the assertion once, with a fixed verification
    /// method, printing each result as it arrives.
    ///
    /// - Throws: ``FidoError`` with the CTAP status, including `FIDO_ERR_PIN_INVALID` and the
    ///   `FIDO_ERR_UV_*` codes that ``run(_:ui:)`` recovers from.
    private func attempt(_ dev: OpaquePointer, _ request: Request, _ verification: Verification) throws {
        // Credential management needs a PIN/UV token, so it is unavailable on keys without either.
        let canManage = fido_dev_supports_credman(dev) && verification.reported != .none
        let unavailable = fido_dev_supports_credman(dev)
            ? "Listing credentials needs a PIN or fingerprint, and this security key has neither set"
            : "This security key does not support credential management, so its credentials cannot be listed"
        guard let rpId = request.rpId else {
            // Nothing else was asked of the key, so this is a failure.
            guard canManage else { throw FidoError(code: 0, operation: unavailable) }
            emit(try discoverAll(dev, pin: verification.pin))
            return
        }
        // A retry after a fingerprint mismatch, or the next session in flood mode, must not
        // print the list a second time.
        if request.discover, !progress.credentialsEmitted {
            if canManage {
                emit(try discoverAll(dev, pin: verification.pin))
                // Listing with a PIN proves that the key accepts it.
                if let pin = verification.pin { progress.acceptedPIN = pin }
            } else {
                // The assertion is still made; only the list is left out.
                logger.warning("\(unavailable); --list is ignored")
            }
            progress.credentialsEmitted = true
        }
        do {
            try assert(dev, request, rpId: rpId, request.skipUserVerification ? .none : verification).forEach { emit($0) }
        } catch let error as FidoError
            where error.code == FIDO_ERR_KEEPALIVE_CANCEL || error.code == FIDO_ERR_ACTION_TIMEOUT {
            // The key checks the PIN before it waits for the touch, so a wait that was
            // cancelled or timed out means the PIN was right.
            if !request.skipUserVerification, let pin = verification.pin { progress.acceptedPIN = pin }
            throw error
        }
    }

    /// Polls until a FIDO HID device is attached.
    ///
    /// - Parameter ui: Asked to tell the user to insert a key, if none is attached.
    /// - Returns: The first device found. With several attached, the rest are ignored.
    /// - Throws: ``FidoError/cancelled`` if the session is cancelled while waiting.
    private func waitForDevice(_ ui: SessionUI) throws -> FoundDevice {
        var announced = false
        while true {
            if isCancelled { throw FidoError.cancelled }
            var list = fido_dev_info_new(8)
            defer { fido_dev_info_free(&list, 8) }
            var count = 0
            if fido_dev_info_manifest(list, 8, &count) == FIDO_OK, count > 0,
               let entry = fido_dev_info_ptr(list, 0), let path = string(fido_dev_info_path(entry)) {
                if count > 1 { logger.warning("\(count) security keys found; using the first one") }
                return FoundDevice(path: path,
                                   manufacturer: string(fido_dev_info_manufacturer_string(entry)),
                                   product: string(fido_dev_info_product_string(entry)))
            }
            if !announced {
                logger.info("Waiting for a security key…")
                ui.showActivate(afterPIN: false)
                announced = true
            }
            Thread.sleep(forTimeInterval: 0.3)
        }
    }

    /// Lists every resident credential on the key: first the relying parties, then the
    /// credentials of each.
    ///
    /// - Parameters:
    ///   - dev: An open device that supports credential management.
    ///   - pin: The PIN, or `nil` to have the key verify the user itself (a fingerprint touch).
    ///
    /// The user is verified once: a single token with the credential management permission is
    /// obtained and used for every query. Left to itself, libfido2 would obtain a new one for
    /// each query, which with a fingerprint means a touch for each relying party. That is
    /// also what happens with a libfido2 too old to hand out tokens; see `CFido2.h`.
    /// - Returns: The credentials of all relying parties; empty if the key holds none.
    /// - Throws: ``FidoError`` if the key rejects the PIN, the verification, or the command.
    private func discoverAll(_ dev: OpaquePointer, pin: String?) throws -> [DiscoveredCredential] {
        try check(phido2_get_credman_token(dev, pin), "Verifying the user to list credentials")
        // The token is of no use to the assertion, which needs its own permission.
        defer { phido2_clear_token(dev) }
        var rp = fido_credman_rp_new()
        defer { fido_credman_rp_free(&rp) }
        let r = fido_credman_get_dev_rp(dev, rp, pin)
        if r == FIDO_ERR_NO_CREDENTIALS { return [] }
        try check(r, "Listing relying parties")
        let rpIds = (0..<fido_credman_rp_count(rp)).compactMap { string(fido_credman_rp_id(rp, $0)) }
        logger.info("Found \(rpIds.count) relying parties on the security key")
        return try rpIds.flatMap { try discover(dev, rpId: $0, pin: pin) }
    }

    /// Lists the resident credentials for a relying party with `authenticatorCredentialManagement`.
    ///
    /// - Parameters:
    ///   - dev: An open device that supports credential management.
    ///   - rpId: The relying party to list credentials for.
    ///   - pin: The PIN, or `nil` to have the key verify the user itself (a fingerprint touch).
    /// - Returns: The credentials; empty if the key has none for `rpId`.
    /// - Throws: ``FidoError`` if the key rejects the PIN, the verification, or the command.
    private func discover(_ dev: OpaquePointer, rpId: String, pin: String?) throws -> [DiscoveredCredential] {
        var rk = fido_credman_rk_new()
        defer { fido_credman_rk_free(&rk) }
        let r = fido_credman_get_dev_rk(dev, rpId, rk, pin)
        if r == FIDO_ERR_NO_CREDENTIALS { return [] }
        try check(r, "Listing credentials")
        return (0..<fido_credman_rk_count(rk)).compactMap { i in
            guard let cred = fido_credman_rk(rk, i),
                  let id = Data(fido_cred_id_ptr(cred), fido_cred_id_len(cred)) else { return nil }
            return DiscoveredCredential(
                id: id.base64URL,
                rpId: rpId,
                user: .init(id: Data(fido_cred_user_id_ptr(cred), fido_cred_user_id_len(cred))?.base64URL,
                            name: string(fido_cred_user_name(cred)),
                            displayName: string(fido_cred_display_name(cred))),
                algorithm: fido_cred_type(cred),
                publicKey: Data(fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred))?.base64URL,
                credProtect: fido_cred_prot(cred))
        }
    }

    /// Sends `authenticatorGetAssertion` and blocks until the key is touched.
    ///
    /// No allow list is sent, so only discoverable credentials (passkeys) can answer.
    /// User presence is requested unless the request says to skip it, and user verification whenever the key has a PIN or
    /// built-in verification; the resulting UP and UV flags are logged.
    ///
    /// With a PIN, libfido2 first obtains a PIN token, so a wrong PIN fails before any touch
    /// is requested.
    ///
    /// - Returns: The assertions in WebAuthn form.
    /// - Throws: ``FidoError`` with the CTAP status, e.g. `FIDO_ERR_NO_CREDENTIALS`.
    private func assert(_ dev: OpaquePointer, _ request: Request, rpId: String,
                        _ verification: Verification) throws
        -> [PublicKeyCredential] {
        var a = fido_assert_new()
        defer { fido_assert_free(&a) }
        try check(fido_assert_set_rp(a, rpId), "Setting the RP ID")
        try request.clientDataJSON.withUnsafeBytes {
            try check(fido_assert_set_clientdata(a, $0.bindMemory(to: UInt8.self).baseAddress, $0.count),
                      "Setting the client data")
        }
        try check(fido_assert_set_up(a, request.skipUserPresence ? FIDO_OPT_FALSE : FIDO_OPT_TRUE),
                  "Setting the user presence option")
        // Ask for user verification whenever the key can do it. With a PIN (or a UV token)
        // libfido2 proves verification through pinUvAuthParam and leaves "uv" out of the
        // options map, as CTAP requires; either way the signed flags come back with UV set.
        // A key with neither a PIN nor a fingerprint would reject uv=true, so it is not asked.
        if verification.reported != .none {
            try check(fido_assert_set_uv(a, FIDO_OPT_TRUE), "Requesting user verification")
        }
        try check(fido_dev_get_assert(dev, a, verification.pin), "Getting the assertion")
        for i in 0..<fido_assert_count(a) {
            let flags = fido_assert_flags(a, i)
            logger.info("Assertion \(i + 1) flags: UP=\(flags & 0x01 != 0 ? 1 : 0) UV=\(flags & 0x04 != 0 ? 1 : 0)")
        }

        var credentials: [PublicKeyCredential] = []
        for i in 0..<fido_assert_count(a) {
            guard let id = Data(fido_assert_id_ptr(a, i), fido_assert_id_len(a, i)),
                  let authData = Data(fido_assert_authdata_raw_ptr(a, i), fido_assert_authdata_raw_len(a, i)),
                  let signature = Data(fido_assert_sig_ptr(a, i), fido_assert_sig_len(a, i)) else { continue }
            let userId = Data(fido_assert_user_id_ptr(a, i), fido_assert_user_id_len(a, i))?.base64URL
            credentials.append(PublicKeyCredential(
                id: id.base64URL, rawId: id.base64URL,
                response: .init(clientDataJSON: request.clientDataJSON.base64URL,
                                authenticatorData: authData.base64URL,
                                signature: signature.base64URL,
                                userHandle: userId)))
        }
        return credentials
    }
}

// MARK: - Enumeration

/// Lists every FIDO authenticator attached over USB and reads each one's details, for the
/// `enum` subcommand.
///
/// Each key is opened read-only to ask it `authenticatorGetInfo`; nothing is signed, no
/// credential is listed, and the user is never prompted, so no PIN or touch is needed. A key
/// that cannot be opened, or that speaks only U2F, is still reported with the identity its USB
/// descriptors give (manufacturer and product); the CTAP2 details are then left `nil`.
///
/// - Returns: One ``AuthenticatorInfo`` per attached authenticator, in the order libfido2
///   reports them. Empty when none is attached.
func enumerateAuthenticators() -> [AuthenticatorInfo] {
    // 64 is far more security keys than anyone plugs in at once; extras would simply be ignored.
    let capacity = 64
    var list = fido_dev_info_new(capacity)
    defer { fido_dev_info_free(&list, capacity) }
    var count = 0
    guard fido_dev_info_manifest(list, capacity, &count) == FIDO_OK, count > 0 else { return [] }

    var result: [AuthenticatorInfo] = []
    for i in 0..<count {
        guard let entry = fido_dev_info_ptr(list, i), let path = string(fido_dev_info_path(entry)) else { continue }
        var info = AuthenticatorInfo(
            transport: .usb,
            manufacturer: string(fido_dev_info_manufacturer_string(entry)),
            product: string(fido_dev_info_product_string(entry)))
        readOpenedAuthenticator(path, into: &info)
        result.append(info)
    }
    return result
}

/// Opens one authenticator by its HID path and fills in what CTAP2 reveals: whether a PIN is
/// set, whether built-in verification is enrolled, and the AAGUID, versions and transports.
///
/// Failures are ignored on purpose: a key that will not open, or is U2F-only, keeps the USB
/// identity already in `info` and leaves the CTAP2 fields `nil`.
private func readOpenedAuthenticator(_ path: String, into info: inout AuthenticatorInfo) {
    guard let dev = fido_dev_new() else { return }
    defer {
        var d: OpaquePointer? = dev
        fido_dev_free(&d)
    }
    guard fido_dev_open(dev, path) == FIDO_OK else { return }
    defer { fido_dev_close(dev) }
    guard fido_dev_is_fido2(dev) else { return }
    info.pinSet = fido_dev_has_pin(dev)
    info.builtInUserVerification = fido_dev_has_uv(dev)
    readAuthenticatorDetails(dev, into: &info)
}

/// Fills in the AAGUID, protocol versions and transports from `authenticatorGetInfo`.
///
/// Failures are ignored: the information is diagnostic only.
private func readAuthenticatorDetails(_ dev: OpaquePointer, into info: inout AuthenticatorInfo) {
    var ci = fido_cbor_info_new()
    defer { fido_cbor_info_free(&ci) }
    guard fido_dev_get_cbor_info(dev, ci) == FIDO_OK else { return }
    if let aaguid = Data(fido_cbor_info_aaguid_ptr(ci), fido_cbor_info_aaguid_len(ci)), aaguid.count == 16 {
        info.aaguid = formatAAGUID(aaguid)
    }
    if let versions = fido_cbor_info_versions_ptr(ci) {
        info.versions = (0..<fido_cbor_info_versions_len(ci)).compactMap { string(versions[$0]) }
    }
    if let transports = fido_cbor_info_transports_ptr(ci) {
        info.transports = (0..<fido_cbor_info_transports_len(ci)).compactMap { string(transports[$0]) }
    }
}

// MARK: - C interop helpers

/// Converts a libfido2 status code into a thrown error.
///
/// - Parameters:
///   - code: The value a libfido2 function returned.
///   - operation: What was being attempted, for the error message.
/// - Throws: ``FidoError`` unless `code` is `FIDO_OK`.
private func check(_ code: Int32, _ operation: String) throws {
    if code != FIDO_OK { throw FidoError(code: code, operation: operation) }
}

/// Copies a C string owned by libfido2. Returns `nil` for a null pointer.
private func string(_ pointer: UnsafePointer<CChar>?) -> String? {
    pointer.map { String(cString: $0) }
}

private extension Data {
    /// Copies a buffer owned by libfido2. Returns `nil` for a null pointer or zero length.
    init?(_ pointer: UnsafePointer<UInt8>?, _ count: Int) {
        guard let pointer, count > 0 else { return nil }
        self.init(bytes: pointer, count: count)
    }
}
