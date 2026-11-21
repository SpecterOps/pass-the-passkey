import Foundation

/// Listens to every FIDO security key through hidraw and runs the main dispatch loop.
///
/// Never returns: the session exits the process when a ceremony is over, and otherwise the
/// tool runs until it is interrupted. Sign-ins with a phone are not followed on Linux.
///
/// - Parameter session: Receives what the security keys send.
func runMonitor(_ session: MonitorSession) -> Never {
    let watcher = HidrawWatcher(
        onAttached: { session.attached($0.name, description: $0.description) },
        onRemoved: { session.removed($0.name, description: $0.description) },
        // The kernel's device name holds manufacturer and product in one string.
        onPacket: { session.received($0, from: $1.name, manufacturer: nil, product: $1.product) },
        onWaiting: { logger.info("No FIDO security key is attached; waiting for one") })
    watcher.start()
    session.start()
    withExtendedLifetime(watcher) { dispatchMain() }
}
