import Foundation
import IOKit
import IOKit.hid

/// Listens to every FIDO security key and to the system log, and runs the main run loop.
///
/// Never returns: the session exits the process when a ceremony is over, and otherwise the
/// tool runs until it is interrupted.
///
/// - Parameter session: Receives what the security keys send.
func runMonitor(_ session: MonitorSession) -> Never {
    let monitor = HidMonitor(session: session)
    monitor.start()
    session.start()
    withExtendedLifetime(monitor) { CFRunLoopRun() }
    exit(0)
}

/// Listens to all FIDO HID devices through IOHIDManager and passes what they send to a
/// ``MonitorSession``; also follows the system log for hybrid ceremonies when it is readable
/// (``HybridLogStream``).
///
/// Main-thread only: the manager's callbacks are scheduled on the main run loop.
final class HidMonitor {
    /// The HID usage page and usage the FIDO Alliance registered for CTAPHID devices.
    private static let fidoUsagePage = 0xF1D0
    private static let fidoUsage = 0x01

    private let session: MonitorSession
    private let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
    private var hybridTracker = HybridLogTracker()
    private let hybridLog = HybridLogStream()

    /// - Parameter session: Receives the devices' reports and the hybrid ceremonies' outcomes.
    init(session: MonitorSession) {
        self.session = session
    }

    /// Opens the devices and starts following the system log.
    ///
    /// IOHIDManager calls back for the devices already attached and for every one attached
    /// later, so nothing is polled and no key needs to be present at the start.
    func start() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        let matching: [String: Any] = [kIOHIDDeviceUsagePageKey: Self.fidoUsagePage, kIOHIDDeviceUsageKey: Self.fidoUsage]
        IOHIDManagerSetDeviceMatching(manager, matching as CFDictionary)
        IOHIDManagerRegisterDeviceMatchingCallback(manager, { context, _, _, device in
            let monitor = Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue()
            monitor.session.attached(device, description: monitor.describe(device))
        }, context)
        IOHIDManagerRegisterDeviceRemovalCallback(manager, { context, _, _, device in
            let monitor = Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue()
            monitor.session.removed(device, description: monitor.describe(device))
        }, context)
        IOHIDManagerRegisterInputReportCallback(manager, { context, _, sender, _, _, report, length in
            guard let sender else { return }
            let device = Unmanaged<IOHIDDevice>.fromOpaque(sender).takeUnretainedValue()
            let monitor = Unmanaged<HidMonitor>.fromOpaque(context!).takeUnretainedValue()
            monitor.session.received(Data(bytes: report, count: length), from: device,
                                     manufacturer: monitor.string(device, kIOHIDManufacturerKey),
                                     product: monitor.string(device, kIOHIDProductKey))
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
    }

    /// Shows a system log message if it belongs to a hybrid ceremony, unchanged, and reports
    /// the ceremony's end.
    private func logged(_ entry: LogEntry) {
        guard let message = entry.eventMessage else { return }
        let (relevant, outcome) = hybridTracker.observe(message)
        guard relevant else { return }
        let failure = entry.messageType == "Error" || entry.messageType == "Fault"
        session.report(MonitorEvent(severity: failure ? .warning : .info, message: "System log, \(entry.process): \(message)"))
        if let outcome {
            session.report(MonitorEvent(severity: outcome.succeeded ? .info : .warning,
                                        message: outcome.succeeded ? "Hybrid (QR code) ceremony succeeded" : "Hybrid (QR code) ceremony failed",
                                        outcome: outcome))
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
