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
    /// What the security key sessions of this request have done so far; see ``SessionProgress``.
    private let progress = SessionProgress()
    /// The transport set on the command line, if any; flood mode starts it again.
    private var fixedMethod: SignInMethod?

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
        if fixed {
            model.canGoBack = false
            fixedMethod = method
        }
        switch method {
        case .securityKey: startSecurityKey()
        case .qrCode: startHybrid()
        }
    }

    /// Runs a ``FidoSession`` on a worker thread, because libfido2 calls block.
    private func startSecurityKey() {
        let session = FidoSession(progress: progress)
        let bridge = SessionPromptBridge(model: model)
        fido = session
        self.bridge = bridge
        // After the chooser, the prompt moves on at once. Without a chooser it stays hidden
        // until the session has something to ask of the user.
        if model.isPresented { model.showActivate(afterPIN: false) }
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
            if request.skipUserPresence {
                logger.warning("A phone always asks its user; --skip-user-presence is ignored")
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
    /// authenticator document (with `--info`) carries only the transport, and `--list` only
    /// produces a warning.
    private func emitHybridResult(_ assertion: PublicKeyCredential) {
        if request.info { emit(AuthenticatorInfo(transport: .hybrid)) }
        if request.discover {
            logger.warning("A phone cannot list its credentials, so --list is ignored")
        }
        emit(assertion)
    }

    /// Ends the active session and returns to the chooser.
    private func back() {
        stopSessions()
        model.showChooser()
    }

    /// Ends everything and exits with status 1. In flood mode the prompt starts again
    /// instead, unless it is an error that is being dismissed; Ctrl-C still ends the tool.
    private func cancel() {
        stopSessions()
        if request.flood, model.stage != .failed {
            logger.info("Cancelled; flood mode starts again")
            if let fixedMethod { start(fixedMethod, fixed: true) } else { model.showChooser() }
            return
        }
        if model.stage != .failed { logger.info("Cancelled.") }
        exit(1)
    }

    private func stopSessions() {
        // Cancelled first, so that a worker released from the PIN prompt sees it and stops.
        fido?.cancel()
        bridge?.deactivate()
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
        // A request that never needed the prompt does not open it for the error either.
        guard model.isPresented else { exit(1) }
        model.showFailure(error)
    }
}
