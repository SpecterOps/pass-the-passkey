import Foundation

// On Linux a security key is reached through a hidraw node, /dev/hidrawN. The kernel hands a
// copy of every input report to each program that has the node open, so a second program that
// opens it for reading only sees what the key answers to the first one, a browser for
// instance, without taking anything away from it. This file finds those nodes and reads them.
//
// Nothing here is specific to Linux as far as the compiler is concerned: it uses only POSIX
// calls and plain files, so it is built and unit-tested on macOS as well, where it simply
// finds no devices.

/// What a HID report descriptor says about FIDO: whether the device is a security key and
/// which of its input reports belong to the FIDO collection.
struct HidReportDescriptor: Equatable {
    /// The HID usage page the FIDO Alliance registered for CTAPHID devices.
    static let fidoUsagePage: UInt32 = 0xF1D0

    /// A descriptor that cannot be understood.
    struct Malformed: Error, CustomStringConvertible, Equatable {
        var description: String
    }

    /// Whether a top-level collection has the FIDO usage page.
    var fido = false
    /// Whether the device numbers its reports, in which case every report read from hidraw
    /// starts with the report ID.
    var numbered = false
    /// The IDs of the input reports inside the FIDO collection; 0 for unnumbered reports.
    var inputIDs: Set<UInt8> = []
    /// The IDs of the input reports of all other collections.
    var otherInputIDs: Set<UInt8> = []

    /// Why the FIDO reports of this device cannot be told from its other reports, if so.
    ///
    /// Such a device is not monitored: bytes of, say, its keyboard collection could be taken
    /// for CTAP traffic.
    var ambiguity: String? {
        if !inputIDs.isDisjoint(with: otherInputIDs) { return "a non-FIDO collection shares an input report ID with the FIDO one" }
        if numbered && inputIDs.contains(0) { return "it mixes numbered and unnumbered FIDO reports" }
        return nil
    }

    /// Reads a report descriptor as the kernel exposes it in sysfs.
    ///
    /// Only what is needed is interpreted: the usage page of each top-level collection, and
    /// the report ID in force at each input item. Nested collections belong to their parent.
    ///
    /// - Parameter data: The descriptor's bytes.
    /// - Throws: ``Malformed`` if an item is cut short or the collections do not balance.
    init(_ data: Data) throws {
        let bytes = [UInt8](data)
        var usagePage: UInt32 = 0
        var reportID: UInt8 = 0
        var saved: [(UInt32, UInt8)] = []
        // For each open collection, whether it is (inside) a FIDO one.
        var collections: [Bool] = []
        // The usage page of the first usage since the last main item.
        var pendingUsagePage: UInt32?
        var offset = 0

        while offset < bytes.count {
            let prefix = bytes[offset]
            offset += 1
            if prefix == 0xFE {
                // A long item: a size byte, a tag byte, then the data. None are defined.
                guard bytes.count - offset >= 2 else { throw Malformed(description: "truncated long HID item") }
                let size = Int(bytes[offset])
                offset += 2
                guard bytes.count - offset >= size else { throw Malformed(description: "truncated long HID item data") }
                offset += size
                continue
            }
            let size = prefix & 3 == 3 ? 4 : Int(prefix & 3)
            let type = (prefix >> 2) & 3
            let tag = (prefix >> 4) & 15
            guard bytes.count - offset >= size else { throw Malformed(description: "truncated HID item") }
            var value: UInt32 = 0
            for i in 0..<size { value |= UInt32(bytes[offset + i]) << (8 * UInt32(i)) }
            offset += size

            switch (type, tag) {
            case (1, 0): usagePage = value                       // Usage Page
            case (1, 8):                                         // Report ID
                guard value >= 1, value <= 255 else { throw Malformed(description: "invalid HID report ID") }
                reportID = UInt8(value)
                numbered = true
            case (1, 10): saved.append((usagePage, reportID))    // Push
            case (1, 11):                                        // Pop
                guard let last = saved.popLast() else { throw Malformed(description: "HID global stack underflow") }
                (usagePage, reportID) = last
            case (2, 0), (2, 1):                                 // Usage, Usage Minimum
                // A four-byte usage carries its own page in the upper half.
                if pendingUsagePage == nil { pendingUsagePage = size == 4 ? value >> 16 : usagePage }
            case (0, _):                                         // Main items
                switch tag {
                case 10:                                         // Collection
                    let isFido = collections.last ?? (pendingUsagePage == Self.fidoUsagePage)
                    collections.append(isFido)
                    if isFido { fido = true }
                case 12:                                         // End Collection
                    guard collections.popLast() != nil else { throw Malformed(description: "HID collection stack underflow") }
                case 8:                                          // Input
                    if let isFido = collections.last {
                        if isFido { inputIDs.insert(reportID) } else { otherInputIDs.insert(reportID) }
                    }
                default: break
                }
                pendingUsagePage = nil
            default: break
            }
        }
        guard collections.isEmpty else { throw Malformed(description: "unterminated HID collection") }
        guard saved.isEmpty else { throw Malformed(description: "unterminated HID global stack") }
    }
}

/// A FIDO security key found in sysfs.
struct HidrawDevice: Equatable {
    /// The kernel's name of the node, e.g. `hidraw3`.
    var name: String
    /// The device node to read, e.g. `/dev/hidraw3`.
    var node: String
    /// The device's name as the kernel reports it, usually manufacturer and product.
    var product: String?
    /// USB vendor and product ID, if known.
    var vendorID: UInt32?
    var productID: UInt32?
    var descriptor: HidReportDescriptor

    /// The device in words, for the log.
    var description: String {
        let ids = vendorID.flatMap { vendor in productID.map { String(format: "USB %04x:%04x, ", vendor, $0) } } ?? ""
        return "\(product ?? "security key") (\(ids)\(name))"
    }

    /// Lists the FIDO devices among the system's hidraw nodes.
    ///
    /// - Parameters:
    ///   - classDirectory: Where the kernel lists hidraw devices; a parameter for tests.
    ///   - deviceDirectory: Where the device nodes are.
    /// - Returns: The security keys, sorted by name. Devices that are not FIDO, or whose
    ///   descriptor cannot be read, are left out.
    static func scan(classDirectory: String = "/sys/class/hidraw", deviceDirectory: String = "/dev") -> [HidrawDevice] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: classDirectory)) ?? []
        return names.filter { $0.hasPrefix("hidraw") }.sorted().compactMap { name in
            // <class>/hidrawN/device is the HID device the node belongs to.
            let device = "\(classDirectory)/\(name)/device"
            guard let data = FileManager.default.contents(atPath: "\(device)/report_descriptor"),
                  let descriptor = try? HidReportDescriptor(data), descriptor.fido else { return nil }
            var found = HidrawDevice(name: name, node: "\(deviceDirectory)/\(name)", descriptor: descriptor)
            // uevent has lines such as HID_ID=0003:00001050:00000407 and HID_NAME=Yubico YubiKey.
            let uevent = FileManager.default.contents(atPath: "\(device)/uevent").map { String(decoding: $0, as: UTF8.self) } ?? ""
            for line in uevent.split(separator: "\n") {
                if line.hasPrefix("HID_NAME=") {
                    let text = line.dropFirst("HID_NAME=".count).filter { !$0.isNewline && $0 != "\u{1B}" }
                    if !text.isEmpty { found.product = String(text) }
                } else if line.hasPrefix("HID_ID=") {
                    let parts = line.dropFirst("HID_ID=".count).split(separator: ":")
                    if parts.count == 3 {
                        found.vendorID = UInt32(parts[1], radix: 16)
                        found.productID = UInt32(parts[2], radix: 16)
                    }
                }
            }
            return found
        }
    }

    /// Takes the CTAPHID packet out of one report read from the node.
    ///
    /// - Parameter report: The bytes of one `read` call.
    /// - Returns: The packet, or `nil` if the report belongs to another collection of a
    ///   device that numbers its reports.
    func packet(from report: Data) -> Data? {
        guard descriptor.numbered else { return report }
        guard let id = report.first, descriptor.inputIDs.contains(id) else { return nil }
        return Data(report.dropFirst())
    }
}

/// Reads every FIDO hidraw node, also those of keys plugged in later.
///
/// The nodes are opened for reading only and nothing is ever written to them, so no command
/// reaches a key. A worker thread does the reading; the callbacks are delivered on the main
/// queue.
final class HidrawWatcher {
    /// How often sysfs is looked at for keys that were plugged in or removed.
    private static let rescanInterval: TimeInterval = 1

    private let onAttached: (HidrawDevice) -> Void
    private let onRemoved: (HidrawDevice) -> Void
    private let onPacket: (Data, HidrawDevice) -> Void
    private let onWaiting: () -> Void

    // Worker-thread state.
    private var opened: [(device: HidrawDevice, descriptor: Int32)] = []
    /// Devices already complained about, so that each complaint is logged once.
    private var skipped: [String: String] = [:]
    private var waitingReported = false

    /// - Parameters:
    ///   - onAttached: A key was found and opened.
    ///   - onRemoved: A key was unplugged, or can no longer be read.
    ///   - onPacket: A CTAPHID packet arrived from a key.
    ///   - onWaiting: No key is attached; called once each time that becomes true.
    init(onAttached: @escaping (HidrawDevice) -> Void, onRemoved: @escaping (HidrawDevice) -> Void,
         onPacket: @escaping (Data, HidrawDevice) -> Void, onWaiting: @escaping () -> Void) {
        self.onAttached = onAttached
        self.onRemoved = onRemoved
        self.onPacket = onPacket
        self.onWaiting = onWaiting
    }

    /// Starts the worker thread. It runs until the process exits.
    func start() {
        Thread.detachNewThread { [self] in
            var nextScan = Date.distantPast
            while true {
                if Date() >= nextScan {
                    rescan()
                    nextScan = Date().addingTimeInterval(Self.rescanInterval)
                }
                readAvailable(timeoutMilliseconds: 250)
            }
        }
    }

    /// Opens the keys that appeared and closes those that are gone.
    private func rescan() {
        let present = HidrawDevice.scan()
        for entry in opened where !present.contains(entry.device) { forget(entry.device, "unplugged") }
        skipped = skipped.filter { name, _ in present.contains { $0.name == name } }
        for device in present where !opened.contains(where: { $0.device == device }) {
            if let reason = device.descriptor.ambiguity {
                skip(device, "its FIDO reports cannot be told apart: \(reason)")
                continue
            }
            let descriptor = open(device.node, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY)
            guard descriptor >= 0 else {
                let code = errno
                skip(device, code == EACCES || code == EPERM
                    ? "permission denied; the udev uaccess ACL for security keys is missing"
                    : String(cString: strerror(code)))
                continue
            }
            opened.append((device, descriptor))
            skipped[device.name] = nil
            DispatchQueue.main.async { self.onAttached(device) }
        }
        if opened.isEmpty {
            if !waitingReported {
                waitingReported = true
                DispatchQueue.main.async { self.onWaiting() }
            }
        } else {
            waitingReported = false
        }
    }

    private func skip(_ device: HidrawDevice, _ reason: String) {
        guard skipped[device.name] != reason else { return }
        skipped[device.name] = reason
        DispatchQueue.main.async { logger.warning("Not monitoring \(device.description): \(reason)") }
    }

    private func forget(_ device: HidrawDevice, _ reason: String) {
        guard let index = opened.firstIndex(where: { $0.device == device }) else { return }
        close(opened[index].descriptor)
        opened.remove(at: index)
        DispatchQueue.main.async {
            logger.debug("Closing \(device.name): \(reason)")
            self.onRemoved(device)
        }
    }

    /// Waits for reports on the open nodes and passes them on.
    private func readAvailable(timeoutMilliseconds: Int32) {
        guard !opened.isEmpty else {
            Thread.sleep(forTimeInterval: Double(timeoutMilliseconds) / 1000)
            return
        }
        var descriptors = opened.map { pollfd(fd: $0.descriptor, events: Int16(POLLIN), revents: 0) }
        guard poll(&descriptors, nfds_t(descriptors.count), timeoutMilliseconds) > 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 4096)
        // `opened` changes when a device is closed, so work from a copy.
        for (entry, polled) in zip(opened, descriptors) where polled.revents != 0 {
            // Each read returns one report; drain what has queued up.
            while true {
                let count = read(entry.descriptor, &buffer, buffer.count)
                if count > 0 {
                    guard let packet = entry.device.packet(from: Data(buffer[0..<count])) else { continue }
                    DispatchQueue.main.async { self.onPacket(packet, entry.device) }
                } else if count < 0 && errno == EINTR {
                    continue
                } else if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break
                } else {
                    // End of file or an error such as ENODEV: the key is gone.
                    forget(entry.device, count == 0 ? "end of file" : String(cString: strerror(errno)))
                    break
                }
            }
        }
    }
}
