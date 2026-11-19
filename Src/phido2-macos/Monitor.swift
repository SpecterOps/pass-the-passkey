import ArgumentParser
import Foundation
import IOKit
import IOKit.hid

/// `phido2 monitor`: watches what FIDO security keys answer to other programs.
///
/// Exit status is 0 when the watched ceremony succeeded, 1 when it failed, and 64 on invalid
/// arguments. With `--no-exit` it runs until interrupted.
struct Monitor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "monitor",
        abstract: "Watches a USB security key or a phone (QR code) being used by another program, until one assertion or registration is done.",
        discussion: """
            Opens every FIDO HID device without exclusive access, also those attached later, \
            and reads the reports the key sends to whichever program is talking to it, such as \
            a browser. Requests are not visible, only the key's answers, so the relying party \
            appears as a hash and a failure does not always say what was attempted. Events are \
            logged on stderr; authenticator details, assertions and registrations are also \
            printed on stdout as JSON documents. Needs no administrator rights.

            When the system log is readable, which it is for administrators, sign-ins with a \
            phone that scans a QR code (hybrid transport) are followed as well: the system's \
            own log messages about them are shown as they are, from the QR code appearing to \
            the success or failure. Otherwise only security keys are monitored.
            """)

    @Flag(name: .customLong("no-exit"), help: "Keep monitoring after an assertion or registration has succeeded or failed, until interrupted. By default the tool exits after the first one.")
    var noExit = false

    /// Starts monitoring and runs the main run loop. Never returns normally: ``HidMonitor``
    /// exits the process when a ceremony is over, unless `--no-exit` is given.
    func run() throws {
        bootstrapLogging(debug: false, subcommand: Self.configuration.commandName!)
        HidMonitor(exitAfterOutcome: !noExit).run()
    }
}

/// Listens to all FIDO HID devices through IOHIDManager and reports what they send; also
/// follows the system log for hybrid ceremonies when it is readable (``HybridLogStream``).
///
/// Main-thread only: the manager's callbacks and the timer are scheduled on the main run loop.
final class HidMonitor {
    /// The HID usage page and usage the FIDO Alliance registered for CTAPHID devices.
    private static let fidoUsagePage = 0xF1D0
    private static let fidoUsage = 0x01
    /// How long a polled U2F request may stay unanswered before it counts as given up.
    private static let u2fIdleLimit: TimeInterval = 3
    /// How long to keep listening after the outcome, for the remaining assertions of a key
    /// that has several credentials for the relying party.
    private static let lingerAfterOutcome: TimeInterval = 0.5

    private let exitAfterOutcome: Bool
    private let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
    private var tracker = CeremonyTracker()
    private var hybridTracker = HybridLogTracker()
    private let hybridLog = HybridLogStream()
    private var reassemblers: [IOHIDDevice: CtapHidReassembler] = [:]
    private var lastReport = Date.distantPast
    private var exitAt: Date?
    private var exitStatus: Int32 = 0

    /// - Parameter exitAfterOutcome: `true` to exit the process once a ceremony has ended,
    ///   `false` to go on with the next one.
    init(exitAfterOutcome: Bool) {
        self.exitAfterOutcome = exitAfterOutcome
    }

    /// Opens the devices and processes their reports until a ceremony ends.
    ///
    /// IOHIDManager calls back for the devices already attached and for every one attached
    /// later, so nothing is polled and no key needs to be present at the start.
    func run() -> Never {
        let context = Unmanaged.passUnretained(self).toOpaque()
        let matching: [String: Any] = [kIOHIDDeviceUsagePageKey: Self.fidoUsagePage, kIOHIDDeviceUsageKey: Self.fidoUsage]
        IOHIDManagerSetDeviceMatching(manager, matching as CFDictionary)
        IOHIDManagerRegisterDeviceMatchingCallback(manager, { context, _, _, device in
            Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue().attached(device)
        }, context)
        IOHIDManagerRegisterDeviceRemovalCallback(manager, { context, _, _, device in
            Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue().removed(device)
        }, context)
        IOHIDManagerRegisterInputReportCallback(manager, { context, _, sender, _, _, report, length in
            guard let sender else { return }
            let device = Unmanaged<IOHIDDevice>.fromOpaque(sender).takeUnretainedValue()
            Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue()
                .received(Data(bytes: report, count: length), from: device)
        }, context)
        IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetMain(), CFRunLoopMode.defaultMode.rawValue)

        // Not kIOHIDOptionsTypeSeizeDevice: the point is to listen without disturbing anyone.
        let status = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        if status != kIOReturnSuccess {
            logger.warning("Opening the HID devices returned 0x\(String(UInt32(bitPattern: status), radix: 16)); some security keys may not be readable")
        }
        if (IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice>)?.isEmpty ?? true {
            logger.info("No FIDO security key is attached; waiting for one")
        }
        hybridLog.start(
            onReady: { logger.info("Also following the system log for sign-ins with a phone (QR code)") },
            onEntry: { [unowned self] in logged($0) },
            onUnavailable: { logger.info("Not following the system log for sign-ins with a phone (QR code); only security keys are monitored. Reason: \($0)") })
        Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [unowned self] _ in tick() }
        CFRunLoopRun()
        exit(0)
    }

    private func attached(_ device: IOHIDDevice) {
        reassemblers[device] = CtapHidReassembler()
        logger.info("Monitoring \(describe(device))")
    }

    private func removed(_ device: IOHIDDevice) {
        reassemblers[device] = nil
        logger.info("Removed: \(describe(device))")
    }

    private func received(_ packet: Data, from device: IOHIDDevice) {
        lastReport = Date()
        guard let message = reassemblers[device, default: CtapHidReassembler()].add(packet) else { return }
        for observation in tracker.observe(message, manufacturer: string(device, kIOHIDManufacturerKey),
                                           product: string(device, kIOHIDProductKey)) {
            report(observation)
        }
    }

    /// Shows a system log message if it belongs to a hybrid ceremony, unchanged, and reports
    /// the ceremony's end.
    private func logged(_ entry: LogEntry) {
        guard let message = entry.eventMessage else { return }
        let (relevant, outcome) = hybridTracker.observe(message)
        guard relevant else { return }
        let failure = entry.messageType == "Error" || entry.messageType == "Fault"
        report(MonitorEvent(severity: failure ? .warning : .info, message: "System log, \(entry.process): \(message)"))
        if let outcome {
            report(MonitorEvent(severity: outcome.succeeded ? .info : .warning,
                                message: outcome.succeeded ? "Hybrid (QR code) ceremony succeeded" : "Hybrid (QR code) ceremony failed",
                                outcome: outcome))
        }
    }

    /// Logs an observation, prints its document, and, if it has an outcome, schedules the
    /// exit or gets ready for the next ceremony.
    private func report(_ observation: MonitorEvent) {
        switch observation.severity {
        // Repeats and events that carry no information; not shown.
        case .debug: break
        case .info: logger.info("\(observation.message)")
        case .warning: logger.warning("\(observation.message)")
        }
        if let document = observation.document { emit(document) }
        guard let outcome = observation.outcome else { return }
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

    private func string(_ device: IOHIDDevice, _ key: String) -> String? {
        IOHIDDeviceGetProperty(device, key as CFString) as? String
    }

    private func describe(_ device: IOHIDDevice) -> String {
        let name = [string(device, kIOHIDManufacturerKey), string(device, kIOHIDProductKey)]
            .compactMap { $0 }.joined(separator: " ")
        let vendor = IOHIDDeviceGetProperty(device, kIOHIDVendorIDKey as CFString) as? Int ?? 0
        let product = IOHIDDeviceGetProperty(device, kIOHIDProductIDKey as CFString) as? Int ?? 0
        return "\(name.isEmpty ? "security key" : name) (USB \(String(format: "%04x:%04x", vendor, product)))"
    }
}
