#pragma once

#include <Windows.h>
#include <webauthn.h>

#include <string>
#include <string_view>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    constexpr const wchar_t* WebAuthnHookPipeName = LR"(\\.\pipe\WebAuthnHook)";

    /// Writes a message atomically to a PIPE_TYPE_MESSAGE pipe handle.
    /// Each WriteFile call creates one discrete message that the server reads as a unit.
    bool WritePipeMessage(HANDLE pipe, std::string_view message);

    /// Builds the "AssertionStarted" JSON pipe message.
    /// <paramref name="processName"/>, <paramref name="userName"/>, and <paramref name="pid"/> are
    /// retrieved once by the caller so the OS lookups are not repeated for every message.
    std::string BuildAssertionStartedMessage(
        LPCWSTR rpId,
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid);

    /// Builds the "AssertionCompleted" JSON pipe message containing the serialized assertion.
    /// Returns an empty string when <paramref name="clientData"/> or <paramref name="assertion"/>
    /// lack required fields.
    std::string BuildAssertionCompletedMessage(
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid,
        const WEBAUTHN_CLIENT_DATA* clientData,
        const WEBAUTHN_ASSERTION* assertion);

    /// Builds the "AssertionError" JSON pipe message carrying the HRESULT and the relying party ID.
    std::string BuildAssertionErrorMessage(
        LPCWSTR rpId,
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid,
        HRESULT hresult);
}
