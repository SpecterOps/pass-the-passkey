import AppKit

extension TransportOption {
    /// The method to start with, or `nil` to show the chooser.
    var method: SignInMethod? {
        switch self {
        case .usb: .securityKey
        case .hybrid: .qrCode
        case .any: nil
        }
    }
}

/// Shows the macOS prompt and runs the AppKit event loop.
///
/// Never returns: the ``Coordinator`` exits the process on success or when the prompt is
/// dismissed.
///
/// - Parameters:
///   - request: What to sign, list or print.
///   - transport: The transport set on the command line.
func runPrompt(_ request: Request, transport: TransportOption) -> Never {
    // Needed for the Bluetooth permission of the QR code flow; see the function's comment.
    // Nothing has been printed yet, so starting over in a child process repeats nothing.
    relaunchAsResponsibleProcess()
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let model = PromptModel(rpId: request.rpId)
    let coordinator = Coordinator(request: request, model: model)
    showPromptPanel(model)
    if request.rpId == nil {
        coordinator.start(.securityKey, fixed: true)
    } else if let method = transport.method {
        coordinator.start(method, fixed: true)
    }
    withExtendedLifetime(coordinator) { app.run() }
    exit(0)
}
