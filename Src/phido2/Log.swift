import Logging

/// The tool's logger, from Apple's swift-log package.
///
/// Diagnostics go to standard error so that standard output carries only the JSON result.
/// ``bootstrapLogging(debug:subcommand:)`` replaces it with one labelled after the running
/// subcommand; it must have run before the first message, or swift-log's default handler is
/// used instead.
var logger = Logger(label: "phido2")

/// Installs the console log handler. Call once, before the first log message.
///
/// Every line then starts with a timestamp, the level and the label
/// `phido2.<subcommand>`, which tells the output of `prompt` and `monitor` apart.
///
/// - Parameters:
///   - debug: `true` to also print messages below the `info` level.
///   - subcommand: The name of the running subcommand, e.g. `monitor`.
func bootstrapLogging(debug: Bool, subcommand: String) {
    LoggingSystem.bootstrap { label in
        var handler = StreamLogHandler.standardError(label: label)
        handler.logLevel = debug ? .debug : .info
        return handler
    }
    logger = Logger(label: "phido2.\(subcommand)")
}
