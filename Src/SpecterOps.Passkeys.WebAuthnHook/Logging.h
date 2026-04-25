#pragma once

#include <Windows.h>
#include <webauthn.h>

#include <string>
#include <string_view>
#include <vector>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    /// Formats the current local time for log output.
    std::wstring Timestamp();

    /// Returns the current process image name without the .exe suffix.
    std::wstring GetCurrentProcessName();

    /// Returns the user name associated with the current process token.
    std::wstring GetCurrentUserName();

    /// Writes a single log line to OutputDebugString.
    void AppendLog(std::wstring_view message);

    /// Decodes a UTF-8 buffer and truncates it to the configured log budget.
    std::wstring ReadUtf8(const BYTE* buffer, DWORD length);

    /// Formats a binary buffer as uppercase hexadecimal and truncates it if needed.
    std::wstring ToHex(const BYTE* buffer, DWORD length);

    /// Converts a Win32 BOOL to a stable log string.
    std::wstring AsBool(BOOL value);

    /// Appends a summary entry when a logged collection was truncated.
    void AppendCollectionTruncation(std::vector<std::wstring>& parts, DWORD originalCount);

    /// Formats the classic allow-credential array from the WebAuthn request.
    std::wstring DescribeCredentials(const WEBAUTHN_CREDENTIALS& credentials);

    /// Formats the extended allow-credential list, including transport flags.
    std::wstring DescribeCredentialList(const WEBAUTHN_CREDENTIAL_LIST* credentialList);

    /// Summarizes extension identifiers and payload sizes.
    std::wstring DescribeExtensions(const WEBAUTHN_EXTENSIONS& extensions);

    /// Formats the credential hint string array.
    std::wstring DescribeHints(LPCWSTR const* hints, DWORD count);

    /// Maps the native attachment enum to a readable string.
    std::wstring DescribeAuthenticatorAttachment(DWORD value);

    /// Maps the native user-verification enum to a readable string.
    std::wstring DescribeUserVerification(DWORD value);

    /// Flattens a WebAuthn assertion request into a human-readable log entry.
    std::wstring FormatAssertionRequest(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options);
}
