# phido2 for macOS

PoC command-line tool that gets a WebAuthn assertion from a USB security key
(YubiKey or any FIDO2 key) or from a phone that scans a QR code, **without**
the AuthenticationServices API and therefore without any entitlement. It shows
prompts that mimic the native macOS sign-in sheet; the icons and texts are
loaded at runtime from the system's AuthenticationServices framework.

It has two subcommands: `prompt` gets an assertion, and `monitor` watches a
security key being used by another program (see "Monitor").

- **USB security key:** CTAP2 over HID through
  [libfido2](https://github.com/Yubico/libfido2) (IOHIDManager underneath).
- **Phone (hybrid transport):** the system's own, private hybrid client; see
  "Hybrid transport" below.

## Build

Needs macOS 26.4, the Xcode Command Line Tools and Homebrew's libfido2; no Xcode,
no cmake.

The Command Line Tools provide the Swift compiler, `make` and `codesign`.
Homebrew's own installer normally sets them up; if they are missing:

```bash
xcode-select --install
```

Then install libfido2 (this also pulls in libcbor and OpenSSL):

```bash
brew install libfido2
```

Build from the repository root:

```bash
make
```

The result is `Build/bin/phido2-macos/release/phido2`: one ad-hoc signed
executable with libfido2, libcbor and libcrypto linked statically (it depends
only on system libraries). The examples below call it `phido2`.

| Command | Effect |
|---|---|
| `make` | Build and ad-hoc sign the executable. |
| `make test` | Run the unit tests. |
| `make clean` | Remove the build products. |
| `make distclean` | Also remove the prepared dependencies. |

The root `Makefile` passes these goals to `Src/phido2-macos/Makefile`, which
can also be used directly. Neither touches the .NET projects.

## Layout

The build writes nothing into `Src`. All output goes to the repository's
`Build` folder, next to the output of the .NET projects.

| Path | Contents |
|---|---|
| `Src/phido2-macos/Package.swift` | Swift Package Manager manifest. |
| `Src/phido2-macos/Makefile` | Prepares the static libraries, builds, signs, tests. |
| `Src/phido2-macos/*.swift` | The tool. The sources lie directly in the project folder, like those of the .NET projects. |
| `Src/phido2-macos/Info.plist` | Embedded into the executable; carries the Bluetooth usage description. |
| `Src/phido2-macos/CFido2/` | A header and module map that expose the libfido2 and libcbor C headers to Swift as the module `CFido2`. |
| `Src/phido2-macos/Tests/` | Unit tests (Swift Testing). |
| `.github/workflows/autobuild.yml` | CI: the `Build macOS` job tests, builds, signs, verifies and uploads. |
| `Build/bin/phido2-macos/release/` | The final executable (ignored). |
| `Build/obj/phido2-macos/swiftpm/` | SwiftPM's intermediate files (ignored). |
| `Build/obj/phido2-macos/deps/` | Prepared headers and static libraries (ignored). |
| `Build/obj/phido2-macos/vscode/` | The VS Code Swift extension's own build folder (ignored); kept apart from the Makefile's so the two do not collide. |

## Use

```bash
phido2 prompt --rpid login.microsoft.com --challenge AAECAwQFBgc --list --info
```

At least one of `--rpid`, `--list` and `--info` is required. They can be
combined freely, and each adds one kind of result.

| Option | Meaning |
|---|---|
| `-r`, `--rpid` | Get an assertion for this relying party ID. The signed origin is `https://<rpid>`. |
| `-l`, `--list` | List the key's credentials: with `--rpid` those of that RP, without it all of them. |
| `-i`, `--info` | Print the authenticator's details. Alone, it needs no PIN and no touch. |
| `-c`, `--challenge` | Challenge, base64url or base64. Random if omitted. Needs `--rpid`. |
| `-p`, `--pin` | PIN. See "User verification" for what happens without it. |
| `-t`, `--transport` | `usb`, `hybrid`, or `any` (default). `any` shows a chooser; the others skip it. |
| `-s`, `--skip-user-verification` | Do not request user verification for the assertion; only a touch is needed. Needs `--rpid`. |
| `-d`, `--debug` | Debug-level messages and libfido2's CTAP/HID trace on stderr. |

Without `--rpid` nothing is signed and only a USB security key can be used.
To list every credential on a key, give `--list` (optionally with `--pin`);
this needs a key with credential management. To only identify the key:

```bash
phido2 prompt --info
```

JSON goes to stdout. Diagnostics go to stderr through
[swift-log](https://github.com/apple/swift-log), one line per message with a
timestamp, the level and the label `phido2.prompt` or
`phido2.monitor`, which names the subcommand that wrote it. Exit
status is 0 on success, 1 on failure or cancel, 64 on invalid arguments.

Results are printed on stdout as standalone JSON
documents that follow one another:

1. **Authenticator** (with `--info`), once the key is opened: `transport` (`usb` or `hybrid`),
   product, AAGUID, CTAP versions, supported transports, whether a PIN is set
   and whether built-in user verification is enrolled. A phone reports only
   `transport`.
2. **Credentials** (with `--list`): `credentials` plus `credentialSource`, from
   credential management when the key supports it, otherwise from the assertion
   response.
3. **Assertion**, once per credential the authenticator answered with: a bare
   WebAuthn `AuthenticationResponseJSON` object.

`jq` reads such a stream directly. The documents are told apart by their
members, for example `jq 'select(.type == "public-key")'` for assertions,
`select(.credentials)` for the list and `select(.transport)` for the
authenticator.

A PIN typed into the prompt is logged on stderr the
moment it is entered (`PIN entered: …`), before the key has checked it, as are
the UP and UV flags of each assertion.

### Hybrid transport

Choosing "Scan QR Code" (or `--transport hybrid`) shows a QR code. A phone
scans it, announces itself over Bluetooth, and the assertion travels through
the phone vendor's tunnel server.

None of that protocol is implemented here. The tool loads two private system
components into its own process:

- `ASCABLEClient` from AuthenticationServicesCore.framework: QR code,
  Bluetooth scan, tunnel and encrypted handshake.
- `_WKWebAuthenticationPanel` from WebKit: encodes the CTAP command.

Consequences:

- **Private API.** These classes have no public headers and can change in any
  macOS update. The tool checks for them and reports a clear error if they are
  gone. Verified on macOS 26.6.
- **Bluetooth permission.** macOS asks once to allow Bluetooth for
  "phido2". To make that possible for a single-file executable, the
  tool embeds an `Info.plist` and re-launches itself as
  its own "responsible process"; otherwise the permission would be attributed
  to the terminal, and Terminal cannot hold it.
- **No PIN, no credential list.** The phone verifies its user itself, so
  `--pin` is ignored, and `--list` reports only the credential that signed.

### User verification

This section applies to USB security keys.

The first that applies is used:

1. `--pin`, if given and the key has a PIN.
2. The key's built-in verification (fingerprint), if enrolled. No PIN prompt is
   shown; the user touches the sensor. With `--list` this takes two touches:
   one to list the credentials, one for the assertion.
3. A PIN prompt, if the key has a PIN.
4. Touch only, if the key has neither.

If the fingerprint is blocked after too many mismatches, the PIN prompt is the
fallback.

With `--skip-user-verification` none of the above is used for the assertion:
the request carries no user verification, only a touch is needed, and the
signed flags have UV unset. Credentials the key protects with user
verification are then not offered, so the key may report that it has none.
Combined with `--list`, the listing still asks for the PIN or fingerprint,
because credential management cannot work without it; only the assertion
skips verification. A phone is merely asked not to verify and may do so anyway.

User presence (UP) is always requested. User verification (UV) is requested in
cases 1–3, so the signed authenticator data carries both flags; in case 4 only
UP is possible. The flags of each assertion are printed on stderr.

## Monitor

```bash
phido2 monitor
```

Watches every FIDO security key on USB while another program, such as Safari,
uses it, and exits as soon as one assertion or registration is done:
status 0 if it succeeded, 1 if it failed. With `--no-exit` it keeps
monitoring one ceremony after another until interrupted.

- **How it listens.** The keys are opened through IOHIDManager without
  exclusive access, and macOS delivers a key's input reports to every program
  that has it open. IOHIDManager also announces keys attached later, so no key
  needs to be present at the start and nothing is polled. No administrator
  rights are needed.
- **Only answers are visible.** What the other program sends to the key is not
  delivered to a second listener. The relying party therefore appears only as
  its SHA-256 hash, and each answer is recognised by its shape.
- **Output.** Every event is one log line on stderr. Complex results are also
  printed on stdout as JSON documents: the authenticator (as with
  `prompt --info`), and documents with `"event": "assertion"` or
  `"event": "registration"` that carry the credential ID, RP ID hash, flags,
  counter, signature and, for registrations, the AAGUID and public key.
  libcbor, which libfido2 already brings in, decodes the CTAP2 answers.

Deciding that a ceremony is over is partly inference:

| Observed | Reported as |
|---|---|
| Assertion with the user-present flag | Assertion succeeded. |
| Assertion without it | A browser's silent check for a credential; monitoring continues. |
| Registration answer | Registration succeeded. |
| Registration for the RP `.dummy` after "no credentials" | Assertion failed: browsers send this placeholder to wait for a touch before reporting that nothing matched. |
| U2F registration answer after a CTAP2 "no credentials" | Assertion failed: the same placeholder, sent after the browser fell back to U2F. |
| Error after the key waited for the user | Ceremony failed; the error does not say whether it was an assertion or a registration. |
| Error without such a wait | The answer to a silent check; monitoring continues. |
| U2F polling that stops for 3 seconds | Ceremony failed (cancelled or timed out). |

### Phones (hybrid transport)

A sign-in with a phone that scans a QR code never touches a USB device. The
system component that runs it writes its progress to the unified log, which
`monitor` follows through `/usr/bin/log stream`, limited to those messages.

- **Needs an administrator account.** macOS lets only members of the admin
  group read the log; no password prompt is involved. For anyone else this
  part is skipped, a log line says so, and security keys are still monitored.
- **Shown as they are.** From the QR code appearing (`Starting caBLE client`)
  to the end, each of the system's messages is logged unchanged, prefixed
  with `System log, <process>:`. This includes the phone being found
  (`Connecting to relay`) and the tunnel's errors.
- **End.** `Transaction succeeded.` ends the ceremony successfully,
  `caBLE transaction failed` unsuccessfully, for example when the prompt is
  cancelled. `monitor` then exits as it does for a security key. The log does
  not say whether it was an assertion or a registration, and no JSON is
  printed.
- **Redacted.** The system hides the relying party and the tunnel's address
  (`<private>`).

A U2F registration answer does not name the relying party, so on a U2F-only
key a placeholder cannot be told from a real registration; the log line says so.

Verified with Safari on macOS 26.6. A program that opens the key exclusively
hides its traffic: nothing is seen while a libfido2-based tool uses the key,
which includes this tool's own `prompt` subcommand. Browsers with their own
USB code have not been tried.

## Running a downloaded build

The binary is ad-hoc signed, not notarised. A copy downloaded with a browser
is quarantined, and Gatekeeper will refuse it until the attribute is removed:

```bash
xattr -d com.apple.quarantine phido2
```

Builds are distributed as `phido2-macos-arm64.tar.gz`, both as the CI
workflow's artifact and as a release asset. The tarball keeps the executable
permission, which the zip that GitHub wraps around artifacts would drop.

## Limits

- Only discoverable credentials (passkeys) are used; no allow list is sent.
- With several keys attached, `prompt` uses the first one found.
- The prompt shows the RP ID as given, while the system sheet shortens it to
  the registrable domain.
- Apple silicon only as built (Homebrew's libraries are single-architecture).
