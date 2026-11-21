import Foundation

/// Private libsystem call that makes a spawned child its own "responsible process".
/// Browsers and debuggers use it for the same purpose.
@_silgen_name("responsibility_spawnattrs_setdisclaim")
private func responsibility_spawnattrs_setdisclaim(
    _ attributes: UnsafeMutablePointer<posix_spawnattr_t?>, _ disclaim: Int32) -> Int32

/// Re-launches this executable as its own responsible process, then exits with its status.
///
/// macOS attributes privacy permissions to the *responsible* process, which for a command-line
/// tool is the terminal that started it. Terminal has no Bluetooth usage description, so a
/// Bluetooth scan from a tool started there is killed. After this call the tool itself is
/// responsible: macOS reads the usage description embedded in this executable and asks the
/// user to allow Bluetooth for "phido2".
///
/// Returns normally in the re-launched child (and if spawning fails); never returns in the
/// parent, which waits for the child and forwards its exit status.
func relaunchAsResponsibleProcess() {
    let marker = "PHIDO2_RESPONSIBLE"
    guard getenv(marker) == nil, let path = Bundle.main.executablePath else { return }
    setenv(marker, "1", 1)

    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    defer { posix_spawnattr_destroy(&attributes) }
    guard responsibility_spawnattrs_setdisclaim(&attributes, 1) == 0 else { return }

    var pid: pid_t = 0
    guard posix_spawn(&pid, path, nil, &attributes, CommandLine.unsafeArgv, environ) == 0 else { return }
    // Leave Ctrl-C to the child, which shares the terminal's process group.
    signal(SIGINT, SIG_IGN)
    var status: Int32 = 0
    while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
    let signalNumber = status & 0x7f
    exit(signalNumber == 0 ? (status >> 8) & 0xff : 128 + signalNumber)
}
