#pragma once

#include <Windows.h>
#include <webauthn.h>
#include <rapidjson/fwd.h>

#include <optional>
#include <string>
#include <string_view>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    constexpr const wchar_t* WebAuthnHookPipeName = LR"(\\.\pipe\WebAuthnHook)";
    constexpr DWORD DefaultPipeResponseTimeoutMs = 1000;
    constexpr DWORD WaitPipeResponseTimeoutMs = 60000;
    constexpr size_t MaxPipeResponseBytes = 5 * 1024;

    enum class HookPipeAction
    {
        Unknown,
        Continue,
        Capture,
        Inject,
        Wait,
    };

    /// Parses a UTF-8 JSON object into a RapidJSON DOM.
    bool TryParseJsonObject(const std::string_view json, rapidjson::Document& document);

    /// Opens the hook named pipe, writes a message atomically, reads an optional response, and closes the handle.
    /// Returns the response JSON when one is received within the timeout; otherwise returns std::nullopt.
    std::optional<std::string> SendPipeMessage(
        const std::string_view message,
        const DWORD timeoutMs = DefaultPipeResponseTimeoutMs);

    /// Parses the action from an incoming hook response JSON message.
    HookPipeAction ParsePipeMessageAction(const std::string_view message);

    /// Builds a replacement clientDataJSON buffer with an injected base64url challenge.
    std::optional<std::string> BuildClientDataJsonWithChallenge(
        const WEBAUTHN_CLIENT_DATA* clientData,
        const std::string_view challenge);

    /// Builds the "AssertionStarted" JSON pipe message.
    /// <paramref name="processName"/>, <paramref name="userName"/>, and <paramref name="pid"/> are
    /// retrieved once by the caller so the OS lookups are not repeated for every message.
    std::string BuildAssertionStartedMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const HookPipeAction previousAction = HookPipeAction::Unknown);

    /// Builds the "AssertionCompleted" JSON pipe message containing the serialized assertion.
    std::string BuildAssertionCompletedMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const WEBAUTHN_CLIENT_DATA* clientData,
        const WEBAUTHN_ASSERTION* assertion,
        const HookPipeAction previousAction = HookPipeAction::Unknown);

    /// Builds the "AssertionError" JSON pipe message carrying the HRESULT and the relying party ID.
    std::string BuildAssertionErrorMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const HRESULT hresult,
        const HookPipeAction previousAction = HookPipeAction::Unknown);
}
