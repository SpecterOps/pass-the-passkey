import Foundation

// A hybrid ("scan the QR code with your phone") ceremony never touches a USB device, so the
// HID monitor cannot see it. The system component that runs it, AuthenticationServicesCore,
// writes its progress to the unified log. `monitor` follows that log with `/usr/bin/log
// stream`, which macOS allows only for members of the admin group; for anyone else this part
// is skipped and only security keys are monitored.

/// Decides which of the system's hybrid log messages belong to a ceremony and when it ends.
///
/// The messages are not parsed beyond their first words:
/// - `Starting caBLE client` (the QR code is shown) or `Connecting to relay` (a phone scanned
///   it) starts a ceremony. Until then nothing is relevant: the system also logs
///   `caBLE transaction failed` whenever it tears down a hybrid client that was never used,
///   which happens at the end of every security key sign-in.
/// - `Transaction succeeded.` or `caBLE transaction failed` ends it.
/// - Messages in between, and for a moment after the end, are shown as they are.
struct HybridLogTracker {
    /// How long after the end the system's closing messages are still shown.
    static let trailingInterval: TimeInterval = 1

    /// Whether a ceremony has started and not yet ended.
    private(set) var active = false
    private var showUntil = Date.distantPast

    /// Handles one log message.
    ///
    /// - Parameters:
    ///   - message: The message text.
    ///   - now: The current time; a parameter so that tests can control it.
    /// - Returns: Whether to show the message, and the ceremony's outcome if this message
    ///   ended it. Whether it was an assertion or a registration is not logged.
    mutating func observe(_ message: String, at now: Date = Date()) -> (relevant: Bool, outcome: CeremonyOutcome?) {
        guard active else {
            if message.hasPrefix("Starting caBLE client") || message.hasPrefix("Connecting to relay") {
                active = true
                return (true, nil)
            }
            return (now < showUntil, nil)
        }
        let succeeded = message.hasPrefix("Transaction succeeded")
        guard succeeded || message.hasPrefix("caBLE transaction failed") else { return (true, nil) }
        active = false
        showUntil = now.addingTimeInterval(Self.trailingInterval)
        return (true, CeremonyOutcome(ceremony: .unknown, succeeded: succeeded))
    }
}

/// One event of the unified log, as `log stream --style ndjson` prints it.
struct LogEntry: Decodable {
    var eventMessage: String?
    var processImagePath: String?
    var subsystem: String?
    var category: String?
    /// `Default`, `Info`, `Debug`, `Error` or `Fault`.
    var messageType: String?

    /// The name of the process that logged the event.
    var process: String { processImagePath.map { ($0 as NSString).lastPathComponent } ?? "?" }
}

/// Follows the unified log for hybrid transport messages by running `/usr/bin/log stream`.
///
/// Callbacks arrive on the main queue.
final class HybridLogStream {
    /// Selects the messages of the hybrid client and its WebSocket tunnel, plus the two kinds
    /// of message the passkey agent logs about it under Safari's subsystem. "caBLE" is the
    /// protocol's original name and is matched with its exact capitalisation.
    static let predicate = """
        (subsystem == "com.apple.AuthenticationServicesCore" AND category IN {"Authorization", "WebSocket"}) \
        OR (subsystem == "com.apple.Safari" AND category == "Authorization" \
        AND (eventMessage CONTAINS "caBLE" OR eventMessage BEGINSWITH "Completing authorization"))
        """

    private static let lock = NSLock()
    private static var children: [Process] = []
    private static var cleanupRegistered = false
    private static var signalSources: [DispatchSourceSignal] = []

    private let process = Process()
    private let output = Pipe()
    private let errors = Pipe()
    private var buffer = Data()
    private var ready = false

    /// Starts following the log.
    ///
    /// - Parameters:
    ///   - onReady: Called once the log is being read.
    ///   - onEntry: Called for every matching log event.
    ///   - onUnavailable: Called with the reason if the log cannot be read, typically because
    ///     the user is not an administrator, or if reading stops later.
    func start(onReady: @escaping () -> Void, onEntry: @escaping (LogEntry) -> Void,
               onUnavailable: @escaping (String) -> Void) {
        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        // Without --level info the client's state changes, which are logged at that level,
        // are left out.
        process.arguments = ["stream", "--level", "info", "--style", "ndjson", "--predicate", Self.predicate]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = errors
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { handle.readabilityHandler = nil; return }
            DispatchQueue.main.async { self?.received(data, onReady, onEntry) }
        }
        process.terminationHandler = { [errors] _ in
            let text = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async { onUnavailable(text.isEmpty ? "log stream ended" : text) }
        }
        do {
            try process.run()
            Self.terminateAtExit(process)
        } catch {
            DispatchQueue.main.async { onUnavailable("\(error.localizedDescription)") }
        }
    }

    /// Splits the output into lines and decodes those that are log events.
    private func received(_ data: Data, _ onReady: () -> Void, _ onEntry: (LogEntry) -> Void) {
        // Anything on standard output, even the header line, shows that the log is open.
        if !ready {
            ready = true
            onReady()
        }
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0a) {
            let line = buffer[buffer.startIndex..<newline]
            buffer = Data(buffer[buffer.index(after: newline)...])
            if let entry = try? JSONDecoder().decode(LogEntry.self, from: line) { onEntry(entry) }
        }
    }

    /// Makes sure the child does not outlive this process when it calls `exit` or is
    /// interrupted or terminated by a signal.
    private static func terminateAtExit(_ process: Process) {
        lock.lock()
        children.append(process)
        let register = !cleanupRegistered
        cleanupRegistered = true
        lock.unlock()
        guard register else { return }
        atexit {
            HybridLogStream.lock.lock()
            HybridLogStream.children.filter(\.isRunning).forEach { $0.terminate() }
            HybridLogStream.lock.unlock()
        }
        // A signal's default action ends the process without running `atexit`, so the
        // common ones are turned into a normal exit with the conventional status.
        for number in [SIGINT, SIGTERM, SIGHUP] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { exit(128 + number) }
            source.resume()
            signalSources.append(source)
        }
    }
}
