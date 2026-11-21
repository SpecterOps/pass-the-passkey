import ArgumentParser
import CFido2
import Foundation

/// `phido2 enum`: lists the FIDO security keys attached to the computer and prints each one's
/// details.
///
/// Unlike ``Prompt`` and ``Monitor``, this subcommand shows no user interface and runs no
/// platform event loop: it only asks libfido2 which authenticators are attached, queries each
/// over USB HID with `authenticatorGetInfo`, and prints the result. No PIN, touch or special
/// rights are needed.
///
/// Exit status is 0 when the enumeration ran, whether or not any key was found, and 64 on
/// invalid arguments.
struct Enum: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enum",
        abstract: "Lists the FIDO security keys attached over USB and prints each one's details.",
        discussion: """
            For every attached key a JSON document is printed on stdout with its product, \
            AAGUID, CTAP versions, transports, and whether a PIN and built-in verification are \
            set. Needs no PIN and no touch.
            """)

    @Flag(name: .shortAndLong, help: "Print debug-level messages and libfido2's CTAP/HID trace to stderr.")
    var debug = false

    /// Enumerates the attached authenticators and prints one JSON document per key. Returns
    /// normally, so the process exits 0; no event loop is entered.
    func run() throws {
        bootstrapLogging(debug: debug, subcommand: Self.configuration.commandName!)
        fido_init(debug ? FIDO_DEBUG : 0)
        let authenticators = enumerateAuthenticators()
        if authenticators.isEmpty {
            logger.warning("No FIDO security keys found.")
        } else {
            logger.info("Found \(authenticators.count) FIDO security key(s).")
        }
        for info in authenticators { emit(info) }
    }
}
