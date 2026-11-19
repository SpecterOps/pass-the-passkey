import Foundation

/// Runs the prompt: starts the transport the user chose and ends the process when it is done.
///
/// Main-thread only. Exactly one of the two sessions is active at a time; going back to the
/// chooser ends it.
final class Coordinator {
    private let request: Request
    private let model: PromptModel
    private var fido: FidoSession?
    private var bridge: SessionPromptBridge?
    private var hybrid: HybridSession?

    /// - Parameters:
    ///   - request: What to sign and for which relying party.
    ///   - model: The prompt to drive; its action callbacks are taken over.
    init(request: Request, model: PromptModel) {
        self.request = request
        self.model = model
        model.onContinue = { [unowned self] in start($0) }
        model.onBack = { [unowned self] in back() }
        model.onCancel = { [unowned self] in cancel() }
        model.onSubmitPIN = { [unowned self] in bridge?.submit(pin: $0) }
    }

    /// Starts a transport.
    ///
    /// - Parameters:
    ///   - method: The transport to use.
    ///   - fixed: `true` when the transport was set on the command line: the chooser is never
    ///     shown, so the back chevron cancels instead.
    func start(_ method: SignInMethod, fixed: Bool = false) {
        if fixed { model.canGoBack = false }
        switch method {
        case .securityKey: startSecurityKey()
        case .qrCode: startHybrid()
        }
    }

    /// Runs a ``FidoSession`` on a worker thread, because libfido2 calls block.
    private func startSecurityKey() {
        let session = FidoSession()
        let bridge = SessionPromptBridge(model: model)
        fido = session
        self.bridge = bridge
        model.showActivate(afterPIN: false)
        let request = request
        Thread.detachNewThread {
            do {
                try session.run(request, ui: bridge)
                DispatchQueue.main.async { self.finish() }
            } catch {
                // A session the user backed out of ends quietly.
                guard !session.isCancelled else { return }
                DispatchQueue.main.async { self.fail(error) }
            }
        }
    }

    /// Shows the QR code and lets the system's hybrid client wait for the phone.
    private func startHybrid() {
        do {
            guard let rpId = request.rpId else {
                throw HybridError(description: "A phone can only make assertions; a relying party ID is needed.")
            }
            let session = try HybridSession(rpId: rpId, clientDataJSON: request.clientDataJSON,
                                            skipUserVerification: request.skipUserVerification)
            hybrid = session
            session.onProgress = { [unowned self] progress in
                model.showPhoneProgress(connected: progress == .authenticating)
            }
            model.showQRCode(session.qrCodeText)
            session.start { [unowned self] result in
                switch result {
                case .success(let assertion):
                    emitHybridResult(assertion)
                    finish()
                case .failure(let error): fail(error)
                }
            }
        } catch {
            fail(error)
        }
    }

    /// Prints the documents for an assertion that came from a phone.
    ///
    /// A phone exposes neither authenticator details nor credential management, so the
    /// authenticator document (with `--info`) carries only the transport, and with `--list`
    /// the only credential that can be reported is the one that signed.
    private func emitHybridResult(_ assertion: PublicKeyCredential) {
        if request.info { emit(AuthenticatorInfo(transport: .hybrid)) }
        if request.discover {
            let credential = DiscoveredCredential(id: assertion.id, rpId: request.rpId ?? "",
                                                  user: .init(id: assertion.response.userHandle))
            emit(CredentialsDocument(credentials: [credential], credentialSource: .assertion))
        }
        emit(assertion)
    }

    /// Ends the active session and returns to the chooser.
    private func back() {
        stopSessions()
        model.showChooser()
    }

    /// Ends everything and exits with status 1.
    private func cancel() {
        stopSessions()
        if model.stage != .failed { logger.info("Cancelled.") }
        exit(1)
    }

    private func stopSessions() {
        bridge?.deactivate()
        fido?.cancel()
        hybrid?.cancel()
        bridge = nil
        fido = nil
        hybrid = nil
    }

    /// Exits with status 0; the session has already printed its results.
    private func finish() {
        exit(0)
    }

    /// Reports a failure on stderr and in the prompt; the process exits when it is dismissed.
    private func fail(_ error: Error) {
        logger.error("\(error)")
        model.showFailure(error)
    }
}
