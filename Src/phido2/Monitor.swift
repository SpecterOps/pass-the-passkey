import ArgumentParser
import Foundation

/// `phido2 monitor`: watches what FIDO security keys answer to other programs.
///
/// Exit status is 0 when the watched ceremony succeeded, 1 when it failed, and 64 on invalid
/// arguments. With `--no-exit` it runs until interrupted.
struct Monitor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "monitor",
        abstract: "Watches a USB security key or a phone (QR code) being used by another program, until one assertion or registration is done.",
        discussion: """
            Opens every FIDO HID device for reading only, also those attached later, \
            and reads the reports the key sends to whichever program is talking to it, such as \
            a browser. Requests are not visible, only the key's answers, so the relying party \
            appears as a hash and a failure does not always say what was attempted. Events are \
            logged on stderr; authenticator details, assertions and registrations are also \
            printed on stdout as JSON documents. Needs no administrator rights.

            On macOS, when the system log is readable, which it is for administrators, \
            sign-ins with a phone that scans a QR code (hybrid transport) are followed as \
            well: the system's own log messages about them are shown as they are, from the QR \
            code appearing to the success or failure. Otherwise only security keys are monitored.
            """)

    @Flag(name: .customLong("no-exit"), help: "Keep monitoring after an assertion or registration has succeeded or failed, until interrupted. By default the tool exits after the first one.")
    var noExit = false

    /// Starts monitoring and runs the main loop. Never returns normally: ``MonitorSession``
    /// exits the process when a ceremony is over, unless `--no-exit` is given.
    func run() throws {
        bootstrapLogging(debug: false, subcommand: Self.configuration.commandName!)
        // Where the reports come from is the platform's: IOHIDManager on macOS, hidraw on Linux.
        runMonitor(MonitorSession(exitAfterOutcome: !noExit))
    }
}

/// Turns the reports of the watched security keys into log lines and JSON documents, and
/// decides when the tool is done.
///
/// Where the reports come from is not its concern: the platform's listener calls
/// ``attached(_:description:)``, ``received(_:from:manufacturer:product:)`` and
/// ``removed(_:description:)``. Main-thread only.
final class MonitorSession {
    /// How long a polled U2F request may stay unanswered before it counts as given up.
    private static let u2fIdleLimit: TimeInterval = 3
    /// How long to keep listening after the outcome, for the remaining assertions of a key
    /// that has several credentials for the relying party.
    private static let lingerAfterOutcome: TimeInterval = 0.5

    private let exitAfterOutcome: Bool
    private var tracker = CeremonyTracker()
    private var reassemblers: [AnyHashable: CtapHidReassembler] = [:]
    private var lastReport = Date.distantPast
    private var exitAt: Date?
    private var exitStatus: Int32 = 0
    private var timer: DispatchSourceTimer?

    /// - Parameter exitAfterOutcome: `true` to exit the process once a ceremony has ended,
    ///   `false` to go on with the next one.
    init(exitAfterOutcome: Bool) {
        self.exitAfterOutcome = exitAfterOutcome
    }

    /// Starts the timer that ends the process after an outcome and notices abandoned U2F
    /// requests. It fires on the main queue, so the platform must run the main loop.
    func start() {
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 0.25, repeating: 0.25)
        timer.setEventHandler { [unowned self] in tick() }
        timer.resume()
        self.timer = timer
    }

    /// A security key appeared.
    ///
    /// - Parameters:
    ///   - device: Anything that identifies the device to the listener.
    ///   - description: The device in words, for the log.
    func attached(_ device: AnyHashable, description: String) {
        reassemblers[device] = CtapHidReassembler()
        logger.info("Monitoring \(description)")
    }

    /// A security key was unplugged.
    func removed(_ device: AnyHashable, description: String) {
        reassemblers[device] = nil
        logger.info("Removed: \(description)")
    }

    /// One input report arrived from a security key.
    ///
    /// - Parameters:
    ///   - packet: The report, without a report ID.
    ///   - device: The device it came from, as given to ``attached(_:description:)``.
    ///   - manufacturer: The device's USB manufacturer string, for the authenticator document.
    ///   - product: The device's USB product string.
    func received(_ packet: Data, from device: AnyHashable, manufacturer: String?, product: String?) {
        lastReport = Date()
        guard let message = reassemblers[device, default: CtapHidReassembler()].add(packet) else { return }
        for event in tracker.observe(message, manufacturer: manufacturer, product: product) {
            report(event)
        }
    }

    /// Logs an event, prints its document, and, if it has an outcome, schedules the exit or
    /// gets ready for the next ceremony.
    func report(_ event: MonitorEvent) {
        switch event.severity {
        // Repeats and events that carry no information; not shown.
        case .debug: break
        case .info: logger.info("\(event.message)")
        case .warning: logger.warning("\(event.message)")
        }
        if let document = event.document { emit(document) }
        guard let outcome = event.outcome else { return }
        if !exitAfterOutcome {
            tracker.startNextCeremony()
        } else {
            // The first outcome decides the status; later assertions only extend the wait.
            if exitAt == nil { exitStatus = outcome.succeeded ? 0 : 1 }
            exitAt = Date().addingTimeInterval(Self.lingerAfterOutcome)
        }
    }

    private func tick() {
        if let exitAt {
            if Date() >= exitAt { exit(exitStatus) }
        } else if tracker.pollingU2f, Date().timeIntervalSince(lastReport) > Self.u2fIdleLimit {
            report(tracker.idleExpired())
        }
    }
}
