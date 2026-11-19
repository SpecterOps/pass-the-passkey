import AppKit
import AuthenticationServices
import CFido2
import CoreImage.CIFilterBuiltins
import Observation

/// Texts and artwork read at runtime from the system's AuthenticationServices framework.
///
/// Using the system's own resources keeps the prompt identical to the native sign-in
/// sheet, including its localisation, without copying Apple's assets into this project.
enum SystemResources {
    /// The resource bundle of AuthenticationServices.framework.
    static let bundle = Bundle(for: ASAuthorizationController.self)

    /// Looks up a localised string of the system sheet.
    ///
    /// - Parameter key: A key from the framework's `Localizable.strings`.
    /// - Returns: The localised text, or `key` itself if the system no longer has it.
    static func text(_ key: String) -> String {
        bundle.localizedString(forKey: key, value: key, table: nil)
    }

    /// Looks up a localised format string of the system sheet and fills in one argument.
    static func text(_ key: String, _ argument: String) -> String {
        String(format: text(key), argument)
    }

    /// The colour the system sheet draws QR code modules in.
    static let qrCodeColor: NSColor = NSColor(named: "CABLEQRCodeContentsColor", bundle: bundle)?
        .usingColorSpace(.sRGB) ?? NSColor(white: 0.17, alpha: 1)

    /// The icon of the system's Passwords app, which the sheet shows while a phone is in use.
    static let passwordsIcon = NSWorkspace.shared.icon(forFile: "/System/Applications/Passwords.app")

    /// The security key glyph of the system sheet, as a template image.
    ///
    /// - Parameter pointSize: The symbol size; 50 for the large artwork, about 17 in a list row.
    static func keyIcon(pointSize: CGFloat) -> NSImage {
        let image = bundle.image(forResource: "security.key")
            ?? NSImage(systemSymbolName: "key.horizontal.fill", accessibilityDescription: nil)!
        return image.withSymbolConfiguration(.init(pointSize: pointSize, weight: .regular)) ?? image
    }
}

/// How the user chose to sign in on the first screen.
enum SignInMethod {
    /// A phone scans a QR code (hybrid transport).
    case qrCode
    /// A USB security key.
    case securityKey
}

/// The state behind ``PromptView``. Main-thread only.
@Observable
final class PromptModel {
    /// Which screen of the prompt is showing.
    enum Stage {
        /// Choosing between QR code and security key.
        case choose
        /// Showing the QR code for a phone to scan.
        case qrCode
        /// The phone has scanned the code; waiting for it to finish.
        case phone
        /// Waiting for the security key to be inserted or touched.
        case activate
        /// Asking for the security key's PIN.
        case pin
        /// Showing an error until the user dismisses the prompt.
        case failed
    }

    var stage = Stage.choose
    /// The bold heading.
    var title = SystemResources.text("Sign In")
    /// The text under the heading.
    var message: String
    /// The selected row on the first screen.
    var method = SignInMethod.qrCode
    /// The QR code on the ``Stage/qrCode`` screen.
    var qrImage: NSImage?
    /// The contents of the PIN field.
    var pin = ""
    /// Whether the chevron returns to the chooser. `false` when the transport was fixed on the
    /// command line, so there is no chooser to return to.
    var canGoBack = true

    /// Called when the user confirms the choice on the first screen.
    var onContinue: (SignInMethod) -> Void = { _ in }
    /// Called when the user goes back to the first screen.
    var onBack: () -> Void = {}
    /// Called when the user dismisses the prompt.
    var onCancel: () -> Void = {}
    /// Called when the user submits the PIN field.
    var onSubmitPIN: (String) -> Void = { _ in }

    /// The relying party ID shown in the texts. Empty when only listing credentials, in which
    /// case the chooser and phone screens, which name it, are never shown.
    let rpId: String

    /// Creates a model that starts on the method chooser.
    ///
    /// - Parameter rpId: The relying party ID shown to the user, or `nil` when the tool only
    ///   lists the credentials of a security key.
    init(rpId: String?) {
        self.rpId = rpId ?? ""
        message = SystemResources.text("Choose how you’d like to sign in to “%@”. (website)", self.rpId)
    }

    // MARK: Screens

    /// Returns to the method chooser.
    func showChooser() {
        stage = .choose
        title = SystemResources.text("Sign In")
        message = SystemResources.text("Choose how you’d like to sign in to “%@”. (website)", rpId)
        qrImage = nil
        pin = ""
    }

    /// Shows a QR code for a phone to scan.
    ///
    /// - Parameter text: The `FIDO:/…` payload.
    func showQRCode(_ text: String) {
        stage = .qrCode
        title = SystemResources.text("Scan QR Code (CABLE title)")
        message = SystemResources.text("Scan this QR code with a compatible device to sign in to “%@”. (website)", rpId)
        qrImage = Self.qrImage(for: text)
    }

    /// Shows progress after the phone has scanned the code.
    ///
    /// As in the system sheet, this screen has only a bold line of text under the Passwords
    /// icon, and no way back.
    ///
    /// - Parameter connected: `false` while the tunnel is being opened, `true` once the phone
    ///   is asking its user.
    func showPhoneProgress(connected: Bool) {
        stage = .phone
        title = connected
            ? SystemResources.text("Use your other device to choose a passkey for “%@”. (website)", rpId)
            : SystemResources.text("Connecting…")
        message = ""
    }

    /// Tells the user to insert or touch the security key.
    ///
    /// - Parameter afterPIN: `true` when the user has just entered a PIN.
    func showActivate(afterPIN: Bool) {
        stage = .activate
        title = SystemResources.text("Use Security Key")
        if afterPIN {
            message = SystemResources.text("To finish, insert and activate your security key again.")
        } else if rpId.isEmpty {
            // The system sheet has no text for this step that does not name a site.
            message = "To continue, insert and activate your security key."
        } else {
            message = SystemResources.text("To continue with “%@”, insert and activate your security key. (website)", rpId)
        }
    }

    /// Asks for the security key's PIN.
    ///
    /// - Parameter incorrect: `true` when the previous PIN was rejected.
    func showPIN(incorrect: Bool) {
        pin = ""
        stage = .pin
        title = SystemResources.text("Use Security Key")
        message = SystemResources.text(incorrect
            ? "The PIN you entered was incorrect. Please try again."
            : "Enter the PIN to unlock your security key.")
    }

    /// Replaces the prompt's text with an error and leaves it up until dismissed.
    ///
    /// - Parameter error: The failure. A missing credential gets the system sheet's wording;
    ///   anything else is shown by its description.
    func showFailure(_ error: Error) {
        if let fido = error as? FidoError, fido.code == FIDO_ERR_NO_CREDENTIALS, !rpId.isEmpty {
            message = SystemResources.text(
                "No credentials were found for “%@” on this security key. Try again with a different security key.", rpId)
        } else if let hybrid = error as? HybridError {
            message = hybrid.description
        } else if error is FidoError {
            message = "\(error)"
        } else {
            message = (error as NSError).localizedDescription
        }
        stage = .failed
    }

    // MARK: User actions

    /// Hands the typed PIN to ``onSubmitPIN``. Does nothing unless the PIN screen is showing
    /// and the field is not empty.
    func submitPIN() {
        guard stage == .pin, !pin.isEmpty else { return }
        onSubmitPIN(pin)
    }

    /// The chevron: back to the chooser from a later screen, otherwise the same as Cancel.
    func goBack() {
        guard stage != .phone else { return }
        if stage == .choose || stage == .failed || !canGoBack { onCancel() } else { onBack() }
    }

    // MARK: Helpers

    /// Renders a QR code with Core Image.
    ///
    /// - Parameter text: The payload to encode.
    /// - Returns: A crisp image in the system sheet's dark grey on white, or `nil` if Core
    ///   Image could not encode it.
    private static func qrImage(for text: String) -> NSImage? {
        let generator = CIFilter.qrCodeGenerator()
        generator.message = Data(text.utf8)
        // Level M gives the same 37-module code as the system sheet. It tolerates 15 % damage;
        // the badge hides about half of that, and the result was checked to decode.
        generator.correctionLevel = "M"
        let tint = CIFilter.falseColor()
        tint.inputImage = generator.outputImage
        tint.color0 = CIColor(color: SystemResources.qrCodeColor) ?? .black
        tint.color1 = .white
        guard let output = tint.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cgImage = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
}

/// Connects one ``FidoSession`` on its worker thread to the ``PromptModel`` on the main thread.
///
/// A new bridge is made for every security-key attempt. When the user goes back to the
/// chooser, ``deactivate()`` releases a worker waiting for the PIN and makes every later call
/// from that worker a no-op, so an abandoned session can never change the screen.
final class SessionPromptBridge: SessionUI {
    private let model: PromptModel
    private let pinSubmitted = DispatchSemaphore(value: 0)
    // Main-thread state.
    private var active = true
    private var waitingForPIN = false
    private var pinResult: String?

    /// - Parameter model: The prompt to drive. Must be created on the main thread.
    init(model: PromptModel) {
        self.model = model
    }

    // MARK: SessionUI (worker thread)

    func showActivate(afterPIN: Bool) {
        DispatchQueue.main.async {
            guard self.active else { return }
            self.model.showActivate(afterPIN: afterPIN)
        }
    }

    func requestPIN(incorrect: Bool) -> String? {
        DispatchQueue.main.async {
            guard self.active else {
                self.pinSubmitted.signal()
                return
            }
            self.pinResult = nil
            self.waitingForPIN = true
            self.model.showPIN(incorrect: incorrect)
        }
        pinSubmitted.wait()
        return DispatchQueue.main.sync { self.pinResult }
    }

    // MARK: Main thread

    /// Delivers the PIN the user typed to the waiting worker.
    func submit(pin: String) {
        guard active, waitingForPIN else { return }
        waitingForPIN = false
        pinResult = pin
        model.showActivate(afterPIN: true)
        pinSubmitted.signal()
    }

    /// Detaches the worker from the prompt; a pending PIN request returns `nil`.
    func deactivate() {
        active = false
        if waitingForPIN {
            waitingForPIN = false
            pinResult = nil
            pinSubmitted.signal()
        }
    }
}
