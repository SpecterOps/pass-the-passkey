import ArgumentParser
import CFido2
import Foundation

/// The values of `--transport`.
enum TransportOption: String, ExpressibleByArgument, CaseIterable {
    /// A USB security key; the chooser is skipped.
    case usb
    /// A phone scanning a QR code; the chooser is skipped.
    case hybrid
    /// Let the user choose in the prompt. On Linux, where only USB is available, the same
    /// as ``usb``.
    case any
}

/// The command-line entry point. It has no options of its own; the work is done by the
/// subcommands ``Prompt`` and ``Monitor``.
@main
struct Phido2: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "phido2",
        abstract: "Gets WebAuthn assertions from security keys and phones, and watches other programs use a security key.",
        subcommands: [Prompt.self, Monitor.self])
}

/// `phido2 prompt`: parses arguments, shows the prompt, prints the JSON result.
///
/// Exit status is 0 on success, 1 on a failed or cancelled ceremony, and 64 on invalid arguments.
struct Prompt: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "prompt",
        abstract: "Gets a WebAuthn assertion from a USB security key or, on macOS, a phone.",
        discussion: """
            Shows sign-in prompts in the style of the system (macOS) or of Chromium (Linux): a \
            security key is reached over USB HID with CTAP2, a phone by scanning a QR code \
            (hybrid transport, macOS only). At least one of --rpid, --list and \
            --info is required; they can be combined freely. Each result is printed on stdout as \
            a JSON document: the authenticator's details (--info), the credentials found \
            (--list) and the assertion(s) (--rpid). Diagnostics go to stderr.
            """)

    @Option(name: [.customShort("r"), .customLong("rpid")],
            help: "Relying party ID to get an assertion for, e.g. login.microsoft.com. The signed origin is https://<rpid>. Without it no assertion is made.")
    var rpId: String?

    @Option(name: .shortAndLong,
            help: "Challenge to sign, base64url or base64. A random one is generated if omitted.")
    var challenge: String?

    @Option(name: .shortAndLong, help: "Security key PIN. If omitted, the key's fingerprint sensor is used when enrolled; otherwise a prompt asks for the PIN. Not used with a phone.")
    var pin: String?

    @Option(name: .shortAndLong,
            help: "How to reach the authenticator: usb (security key), hybrid (phone scans a QR code, macOS only), or any to choose in the prompt.")
    var transport: TransportOption = .any

    @Flag(name: .shortAndLong, help: "List all credentials on the security key, of every relying party.")
    var list = false

    @Flag(name: .shortAndLong, help: "Print the authenticator's details: product, AAGUID, CTAP versions, transports, PIN and fingerprint state. Alone, it needs no PIN and no touch.")
    var info = false

    @Flag(name: [.customShort("s"), .customLong("skip-user-verification")],
          help: "Do not request user verification for the assertion: no PIN or fingerprint, only a touch. The result has the UV flag unset.")
    var skipUserVerification = false

    @Flag(name: .customLong("skip-user-presence"),
          help: "Request the assertion without user presence, so that the security key answers without a touch. The result has the UP flag unset. Keys may refuse this.")
    var skipUserPresence = false

    @Flag(name: .shortAndLong,
          help: "Start again instead of exiting when the prompt is cancelled or the security key times out, until interrupted. Stops before the last PIN attempt, so the key is never blocked.")
    var flood = false

    @Flag(name: .shortAndLong, help: "Print debug-level messages and libfido2's CTAP/HID trace to stderr.")
    var debug = false

    /// Checks the combinations of options that the types alone cannot express.
    ///
    /// - Throws: `ValidationError` if none of `--rpid`, `--list` and `--info` is given, or if
    ///   an option that needs a relying party is given without `--rpid`.
    func validate() throws {
        guard rpId != nil || list || info else {
            throw ValidationError("Nothing to do. Give at least one of --rpid, --list and --info.")
        }
        #if !os(macOS)
        if transport == .hybrid {
            throw ValidationError("--transport hybrid is available on macOS only; here only a USB security key can be used.")
        }
        #endif
        if transport == .hybrid && skipUserPresence {
            throw ValidationError("--skip-user-presence applies to USB security keys, not to --transport hybrid: a phone always asks its user.")
        }
        guard rpId == nil else { return }
        if skipUserPresence {
            throw ValidationError("--skip-user-presence applies to assertions and needs --rpid.")
        }
        if skipUserVerification {
            throw ValidationError("--skip-user-verification applies to assertions and needs --rpid; listing credentials always requires verification.")
        }
        if challenge != nil { throw ValidationError("--challenge needs --rpid; without it nothing is signed.") }
        if transport == .hybrid {
            throw ValidationError("Without --rpid only a USB security key can be used, not --transport hybrid: a phone neither lists credentials nor describes itself.")
        }
    }

    /// Shows the prompt and runs the platform's event loop. Never returns normally: the
    /// process exits on success or when the prompt is dismissed.
    ///
    /// - Throws: `ValidationError` if `--challenge` cannot be decoded.
    func run() throws {
        let challengeData: Data
        if let challenge {
            guard let decoded = Data(base64URLOrBase64: challenge), !decoded.isEmpty else {
                throw ValidationError("--challenge is not valid base64url or base64.")
            }
            challengeData = decoded
        } else {
            challengeData = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        }
        // Without a relying party there is nothing to sign: the request only lists credentials
        // or prints the key's details.
        let request = Request(
            rpId: rpId,
            clientDataJSON: rpId.map { makeClientDataJSON(challenge: challengeData, origin: "https://\($0)") } ?? Data(),
            pin: pin,
            discover: list,
            info: info,
            skipUserVerification: skipUserVerification,
            skipUserPresence: skipUserPresence,
            flood: flood)

        bootstrapLogging(debug: debug, subcommand: Self.configuration.commandName!)
        fido_init(debug ? FIDO_DEBUG : 0)
        // The user interface is the platform's: AppKit and SwiftUI on macOS, GTK on Linux.
        runPrompt(request, transport: transport)
    }
}
