import CoreBluetooth
import Foundation
import ObjectiveC

/// A failure of the hybrid (QR code) flow.
struct HybridError: Error, CustomStringConvertible {
    var description: String
}

/// What the system client's delegate returns for a CTAP command: a stand-in for the system's
/// `WBSPair<NSData, NSData>`, of which the client only uses these two accessors.
private final class CommandPair: NSObject {
    /// The client data JSON the command's hash was computed from. The client keeps it for
    /// the credential object it returns.
    @objc let first: NSData
    /// The encoded CTAP command, which the client sends to the phone.
    @objc let second: NSData

    init(first: NSData, second: NSData) {
        self.first = first
        self.second = second
    }
}

/// Gets an assertion from a phone over hybrid transport (caBLE), using the system's own client.
///
/// Nothing of the protocol is implemented here. The private class `ASCABLEClient` in
/// AuthenticationServicesCore.framework generates the QR code, scans Bluetooth for the phone's
/// advertisement, opens the tunnel and runs the encrypted handshake; WebKit's private
/// `_WKWebAuthenticationPanel` encodes the CTAP command. Both run inside this process, so
/// neither needs an entitlement. They are reached through the Objective-C runtime because
/// they have no public headers, and may change or disappear in any macOS update; every
/// class and selector is therefore checked before use.
///
/// All methods must be called on the main thread; callbacks arrive on the main thread.
final class HybridSession: NSObject {
    /// What the system client reports while the phone is being reached.
    enum Progress {
        /// The phone was found over Bluetooth and the tunnel is being opened.
        case connecting
        /// The encrypted channel is up and the phone is asking its user.
        case authenticating
    }

    /// `ASCABLEClient.OperationType.authentication`, as the system's own agent passes it.
    private static let authenticationOperation = 1
    /// `_WKUserVerificationRequirementRequired`.
    private static let userVerificationRequired = 0
    /// `_WKUserVerificationRequirementDiscouraged`.
    private static let userVerificationDiscouraged = 2

    private static let clientClassName = "AuthenticationServicesCore.ASCABLEClient"
    private static let delegateProtocolName = "_TtP26AuthenticationServicesCore21ASCABLEClientDelegate_"
    private static let initSelector = NSSelectorFromString("initWithDelegate:isRegistrationRequest:")
    private static let qrSelector = NSSelectorFromString("qrCodeURL")
    private static let performSelector = NSSelectorFromString(
        "performAuthenticationOperation:forRelyingPartyIdentifier:completionHandler:")
    private static let cancelSelector = NSSelectorFromString("cancelIfNecessary")
    private static let encodeSelector = NSSelectorFromString(
        "encodeGetAssertionCommandWithClientDataJSON:options:userVerificationAvailability:authenticatorSupportedExtensions:")

    private let rpId: String
    private let clientDataJSON: Data
    private let skipUserVerification: Bool
    private var client: NSObject?
    private var cancelled = false

    /// Called when the system client moves to a new phase.
    var onProgress: (Progress) -> Void = { _ in }

    /// Loads the system components and creates a client with a fresh QR code.
    ///
    /// - Parameters:
    ///   - rpId: The relying party ID the phone is asked to sign in to.
    ///   - clientDataJSON: The client data to sign; see ``makeClientDataJSON(challenge:origin:)``.
    ///   - skipUserVerification: `true` to ask the phone not to verify its user. A phone may
    ///     verify anyway; iPhones always do.
    /// - Throws: ``HybridError`` if this macOS version lacks the expected private classes, or
    ///   Bluetooth access has been denied to this tool.
    init(rpId: String, clientDataJSON: Data, skipUserVerification: Bool = false) throws {
        self.rpId = rpId
        self.clientDataJSON = clientDataJSON
        self.skipUserVerification = skipUserVerification
        super.init()

        if CBCentralManager.authorization == .denied || CBCentralManager.authorization == .restricted {
            throw HybridError(description: "Bluetooth access is denied for phido2. "
                + "Allow it in System Settings › Privacy & Security › Bluetooth.")
        }
        dlopen("/System/Library/PrivateFrameworks/AuthenticationServicesCore.framework/AuthenticationServicesCore", RTLD_NOW)
        dlopen("/System/Library/Frameworks/WebKit.framework/WebKit", RTLD_NOW)
        guard let clientClass = NSClassFromString(Self.clientClassName),
              [Self.initSelector, Self.qrSelector, Self.performSelector, Self.cancelSelector]
                  .allSatisfy({ class_getInstanceMethod(clientClass, $0) != nil }),
              let panelClass = NSClassFromString("_WKWebAuthenticationPanel"),
              class_getClassMethod(panelClass, Self.encodeSelector) != nil,
              NSClassFromString("_WKPublicKeyCredentialRequestOptions") != nil else {
            throw HybridError(description: "This macOS version does not have the system hybrid client this tool relies on.")
        }
        // The client's delegate is typed as this protocol; declare conformance at runtime.
        if let delegateProtocol = objc_getProtocol(Self.delegateProtocolName) {
            class_addProtocol(HybridSession.self, delegateProtocol)
        }

        typealias Initializer = @convention(c) (AnyObject, Selector, AnyObject, Bool) -> NSObject?
        let allocated = (clientClass as AnyObject).perform(NSSelectorFromString("alloc")).takeUnretainedValue()
        let initialize = unsafeBitCast(class_getMethodImplementation(clientClass, Self.initSelector), to: Initializer.self)
        guard let client = initialize(allocated, Self.initSelector, self, false) else {
            throw HybridError(description: "The system hybrid client could not be created.")
        }
        self.client = client
    }

    /// The `FIDO:/…` text to show as a QR code. It is valid only for this session.
    var qrCodeText: String {
        (client?.perform(Self.qrSelector)?.takeUnretainedValue() as? NSURL)?.absoluteString ?? ""
    }

    /// Starts scanning for the phone and reports the outcome once.
    ///
    /// - Parameter completion: Receives the assertion, or the error the system client reported.
    ///   Not called after ``cancel()``.
    func start(completion: @escaping (Result<PublicKeyCredential, Error>) -> Void) {
        guard let client else { return }
        logger.info("Hybrid: waiting for a phone to scan the QR code (Bluetooth authorization: \(Self.authorizationName))")
        let handler: @convention(block) (NSObject?, NSError?) -> Void = { [weak self] credential, error in
            DispatchQueue.main.async {
                guard let self, !self.cancelled else { return }
                if let credential, let assertion = self.assertion(from: credential) {
                    completion(.success(assertion))
                } else {
                    completion(.failure(Self.describe(error)))
                }
            }
        }
        typealias Perform = @convention(c) (AnyObject, Selector, Int, NSString, Any) -> Void
        let perform = unsafeBitCast(class_getMethodImplementation(type(of: client), Self.performSelector), to: Perform.self)
        perform(client, Self.performSelector, Self.authenticationOperation, rpId as NSString, handler)
    }

    /// Stops the scan or the running exchange. The completion handler will not be called.
    func cancel() {
        cancelled = true
        _ = client?.perform(Self.cancelSelector)
        client = nil
    }

    // MARK: ASCABLEClientDelegate (called by the system client)

    @objc(cableClientWillConnect:)
    private func cableClientWillConnect(_ client: AnyObject) {
        logger.info("Hybrid: phone found, connecting through the tunnel")
        DispatchQueue.main.async { if !self.cancelled { self.onProgress(.connecting) } }
    }

    @objc(cableClientWillAuthenticate:)
    private func cableClientWillAuthenticate(_ client: AnyObject) {
        logger.info("Hybrid: connected, waiting for the phone")
        DispatchQueue.main.async { if !self.cancelled { self.onProgress(.authenticating) } }
    }

    /// Returns the CTAP `authenticatorGetAssertion` command for the phone, encoded by WebKit.
    ///
    /// The system client expects a pair object (the system's own agent returns a `WBSPair`)
    /// and reads it with `first` and `second`: the client data, and the command built from it
    /// (the order was established by disassembling the client).
    ///
    /// - Parameters:
    ///   - availability: The phone's user verification capability, as a
    ///     `_WKWebAuthenticationUserVerificationAvailability` value; passed through unchanged.
    ///   - extensions: The extensions the phone supports; passed through unchanged.
    /// - Returns: The client data paired with the command bytes (`0x02` followed by CBOR), or
    ///   `nil` if encoding failed.
    @objc(encodeGetAssertionCTAPCommandForAuthenticatorWithUserVerificationAvailability:authenticatorSupportedExtensions:)
    private func encodeGetAssertionCommand(_ availability: UInt, _ extensions: AnyObject?) -> CommandPair? {
        guard let panelClass = NSClassFromString("_WKWebAuthenticationPanel"),
              let optionsClass = NSClassFromString("_WKPublicKeyCredentialRequestOptions") as? NSObject.Type,
              let method = class_getClassMethod(panelClass, Self.encodeSelector) else { return nil }
        let options = optionsClass.init()
        options.setValue(rpId, forKey: "relyingPartyIdentifier")
        options.setValue(skipUserVerification ? Self.userVerificationDiscouraged : Self.userVerificationRequired,
                         forKey: "userVerification")
        typealias Encode = @convention(c) (AnyClass, Selector, NSData, AnyObject, Int, AnyObject?) -> NSData?
        let encode = unsafeBitCast(method_getImplementation(method), to: Encode.self)
        guard let command = encode(panelClass, Self.encodeSelector, clientDataJSON as NSData, options,
                                   Int(availability), extensions) else { return nil }
        logger.debug("Hybrid: sending the assertion request (\(command.length) bytes)")
        return CommandPair(first: clientDataJSON as NSData, second: command)
    }

    // MARK: Helpers

    /// Converts the system's credential object (an `ASC…PublicKeyCredentialAssertion`) into
    /// the WebAuthn JSON shape.
    ///
    /// - Returns: `nil` if the object lacks the credential ID, authenticator data or signature.
    private func assertion(from credential: NSObject) -> PublicKeyCredential? {
        func data(_ key: String) -> Data? {
            guard credential.responds(to: NSSelectorFromString(key)) else { return nil }
            return credential.value(forKey: key) as? Data
        }
        guard let id = data("credentialID"), let authenticatorData = data("authenticatorData"),
              let signature = data("signature") else { return nil }
        if authenticatorData.count > 32 {
            let flags = authenticatorData[authenticatorData.startIndex + 32]
            logger.info("Assertion 1 flags: UP=\(flags & 0x01 != 0 ? 1 : 0) UV=\(flags & 0x04 != 0 ? 1 : 0)")
        }
        return PublicKeyCredential(
            id: id.base64URL, rawId: id.base64URL,
            response: .init(clientDataJSON: clientDataJSON.base64URL,
                            authenticatorData: authenticatorData.base64URL,
                            signature: signature.base64URL,
                            userHandle: data("userHandle")?.base64URL))
    }

    /// Turns the system client's error into something readable.
    ///
    /// The client reports a private Swift error type whose default description is useless, so
    /// the bridged `NSError` domain and code are shown instead.
    private static func describe(_ error: NSError?) -> HybridError {
        guard let error else { return HybridError(description: "The phone returned no usable assertion.") }
        var text = "The phone sign-in failed (\(error.domain) error \(error.code))"
        if !error.userInfo.isEmpty { text += " \(error.userInfo)" }
        return HybridError(description: text + ".")
    }

    private static var authorizationName: String {
        switch CBCentralManager.authorization {
        case .allowedAlways: "allowed"
        case .denied: "denied"
        case .restricted: "restricted"
        case .notDetermined: "not yet asked"
        @unknown default: "unknown"
        }
    }
}
