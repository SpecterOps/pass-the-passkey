# Changelog

All notable changes to Pass-the-Passkey are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.8.0] - 2026-09-14

### Added

- **`whfb` command** in the [SharpPasskeys CLI](SharpPasskeys.md) — signs a
  Microsoft Entra ID (`login.microsoft.com`) WebAuthn assertion directly with a
  locally unlocked Windows Hello for Business key, with matching support added to
  the Passkey Injector C2 command generation.
- New [browser bookmarks](../Src/SpecterOps.Passkeys.Injector/MenuItems/Bookmarks.json)
  in the Passkey Injector: Binance and Telegram.

### Fixed

- **`list authenticators` command** in the [SharpPasskeys CLI](SharpPasskeys.md)
  now correctly decodes the authenticator **AAGUID**.

## [2.7.0] - 2026-07-22

### Added

- Initial public release ("Black Hat Edition") of Pass-the-Passkey, comprising
  the Passkey Injector (WPF payload), the [SharpPasskeys CLI](SharpPasskeys.md),
  the native [WebAuthn hook DLL](WebAuthnHook.md), and the supporting
  [PowerShell scripts](../Src/Scripts).

_Versions prior to 2.7.0 predate the public release and are not tracked here._

[2.8.0]: https://github.com/SpecterOps/pass-the-passkey/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/SpecterOps/pass-the-passkey/releases/tag/v2.7.0
