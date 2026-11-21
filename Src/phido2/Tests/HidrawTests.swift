import Foundation
import Testing
@testable import phido2

/// Tests for finding security keys among Linux hidraw devices (`Hidraw.swift`).
///
/// The monitor must open only FIDO devices and must read their reports correctly, or it
/// would either miss keys or take a keyboard's keystrokes for CTAP traffic. The code uses
/// only files and POSIX calls, so these tests run on macOS too, against made-up sysfs trees.
@Suite("Linux hidraw discovery")
struct HidrawTests {
    /// The report descriptor nearly every security key has: one FIDO collection with a
    /// 64-byte input and a 64-byte output report, no report IDs.
    static let fidoDescriptor = Data([
        0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
        0x09, 0x01,        // Usage (U2F Authenticator Device)
        0xA1, 0x01,        // Collection (Application)
        0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x81, 0x02,        //   Input
        0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x91, 0x02,        //   Output
        0xC0,              // End Collection
    ])

    /// A boot keyboard, cut down to one input report.
    static let keyboardDescriptor = Data([
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
        0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
    ])

    /// A device with a keyboard collection (report ID 1) and a FIDO collection (report ID 2).
    static let compositeDescriptor = Data([
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
        0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
        0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x02,
        0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0xC0,
    ])

    /// Checks that the usual security key descriptor is recognised as FIDO, without report IDs.
    ///
    /// Its single input report is then unnumbered (ID 0), and a report read from the node
    /// is the CTAPHID packet as it is.
    @Test("a plain security key is recognised and its reports are passed on unchanged")
    func recognisesPlainSecurityKey() throws {
        let descriptor = try HidReportDescriptor(Self.fidoDescriptor)
        #expect(descriptor.fido)
        #expect(!descriptor.numbered)
        #expect(descriptor.inputIDs == [0])
        #expect(descriptor.ambiguity == nil)
        let device = HidrawDevice(name: "hidraw0", node: "/dev/hidraw0", descriptor: descriptor)
        #expect(device.packet(from: Data([1, 2, 3])) == Data([1, 2, 3]))
    }

    /// Checks that a keyboard is not taken for a security key.
    @Test("a keyboard is not FIDO")
    func ignoresKeyboard() throws {
        #expect(try !HidReportDescriptor(Self.keyboardDescriptor).fido)
    }

    /// Checks a device that numbers its reports: only reports with the FIDO collection's ID
    /// are passed on, and the ID byte is removed.
    ///
    /// hidraw puts the report ID in front of each report of such a device. Passing the
    /// keyboard's reports on, or leaving the ID in place, would corrupt CTAPHID reassembly.
    @Test("with report IDs, only the FIDO collection's reports are passed on, without the ID")
    func filtersNumberedReports() throws {
        let descriptor = try HidReportDescriptor(Self.compositeDescriptor)
        #expect(descriptor.fido)
        #expect(descriptor.numbered)
        #expect(descriptor.inputIDs == [2])
        #expect(descriptor.otherInputIDs == [1])
        #expect(descriptor.ambiguity == nil)
        let device = HidrawDevice(name: "hidraw0", node: "/dev/hidraw0", descriptor: descriptor)
        #expect(device.packet(from: Data([2, 0xAA, 0xBB])) == Data([0xAA, 0xBB]))
        #expect(device.packet(from: Data([1, 0xAA, 0xBB])) == nil)
    }

    /// Checks that a device whose FIDO and other collections share a report ID is flagged.
    ///
    /// Here neither collection sets a report ID, so both use ID 0 and their reports cannot
    /// be told apart; the monitor refuses such a device instead of guessing.
    @Test("a device whose collections share a report ID is flagged as ambiguous")
    func flagsSharedReportID() throws {
        let descriptor = try HidReportDescriptor(Self.keyboardDescriptor + Self.fidoDescriptor)
        #expect(descriptor.fido)
        #expect(descriptor.ambiguity != nil)
    }

    /// Checks that a damaged descriptor is rejected instead of being read past its end.
    ///
    /// The descriptor comes from the device, so it is untrusted input. One cut off in the
    /// middle of an item, and one whose collection is never closed, must both throw.
    @Test("a truncated or unbalanced descriptor is rejected")
    func rejectsMalformedDescriptors() {
        #expect(throws: HidReportDescriptor.Malformed.self) { try HidReportDescriptor(Data([0x06, 0xD0])) }
        #expect(throws: HidReportDescriptor.Malformed.self) { try HidReportDescriptor(Self.fidoDescriptor.dropLast()) }
        #expect(throws: HidReportDescriptor.Malformed.self) { try HidReportDescriptor(Data([0xC0])) }
    }

    /// Checks the scan of a sysfs tree: FIDO devices are found with their name and USB IDs,
    /// other devices and unreadable entries are left out.
    ///
    /// The tree is built in a temporary folder in the layout the kernel uses:
    /// `<class>/hidrawN/device/report_descriptor` and `…/uevent`.
    @Test("scanning sysfs finds the security keys and reads their names and USB IDs")
    func scansSysfs() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("phido2-hidraw-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        func add(_ name: String, _ descriptor: Data?, uevent: String = "") throws {
            let device = root.appendingPathComponent("\(name)/device")
            try FileManager.default.createDirectory(at: device, withIntermediateDirectories: true)
            try descriptor?.write(to: device.appendingPathComponent("report_descriptor"))
            try Data(uevent.utf8).write(to: device.appendingPathComponent("uevent"))
        }
        try add("hidraw0", Self.keyboardDescriptor)
        try add("hidraw1", Self.fidoDescriptor,
                uevent: "DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\n")
        try add("hidraw2", nil)
        try add("event5", Self.fidoDescriptor)

        let found = HidrawDevice.scan(classDirectory: root.path, deviceDirectory: "/dev")
        #expect(found.map(\.name) == ["hidraw1"])
        #expect(found.first?.node == "/dev/hidraw1")
        #expect(found.first?.product == "Yubico YubiKey OTP+FIDO+CCID")
        #expect(found.first?.vendorID == 0x1050)
        #expect(found.first?.productID == 0x0407)
        #expect(found.first?.description == "Yubico YubiKey OTP+FIDO+CCID (USB 1050:0407, hidraw1)")
    }
}
