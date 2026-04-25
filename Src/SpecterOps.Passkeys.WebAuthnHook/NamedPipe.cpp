#include "NamedPipe.h"

#include <cstdio>
#include <string>
#include <string_view>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    namespace
    {
        constexpr size_t SerializedAssertionJsonOverhead = 256;

        // Returns the current UTC time formatted as an ISO 8601 timestamp (e.g. "2026-04-25T10:18:30.224Z").
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

        std::string WideToUtf8(std::wstring_view wide)
        {
            if (wide.empty())
            {
                return {};
            }

            const int length = ::WideCharToMultiByte(
                CP_UTF8, 0,
                wide.data(), static_cast<int>(wide.size()),
                nullptr, 0, nullptr, nullptr);

            if (length <= 0)
            {
                return {};
            }

            std::string utf8(static_cast<size_t>(length), '\0');
            ::WideCharToMultiByte(
                CP_UTF8, 0,
                wide.data(), static_cast<int>(wide.size()),
                utf8.data(), length, nullptr, nullptr);
            return utf8;
        }

        std::string JsonEscapeString(std::string_view str)
        {
            std::string result;
            result.reserve(str.size());
            for (const unsigned char c : str)
            {
                switch (c)
                {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n";  break;
                case '\r': result += "\\r";  break;
                case '\t': result += "\\t";  break;
                default:
                    if (c < 0x20)
                    {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned>(c));
                        result += buf;
                    }
                    else
                    {
                        result += static_cast<char>(c);
                    }
                    break;
                }
            }
            return result;
        }

        std::string Base64UrlEncode(const BYTE* buffer, DWORD length)
        {
            if (buffer == nullptr || length == 0)
            {
                return {};
            }

            constexpr char Base64Alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

            std::string encoded;
            encoded.reserve(((static_cast<size_t>(length) + 2) / 3) * 4);

            for (DWORD index = 0; index < length; index += 3)
            {
                const DWORD remaining = length - index;
                const BYTE byte0 = buffer[index];
                const BYTE byte1 = remaining > 1 ? buffer[index + 1] : 0;
                const BYTE byte2 = remaining > 2 ? buffer[index + 2] : 0;

                encoded.push_back(Base64Alphabet[(byte0 >> 2) & 0x3F]);
                encoded.push_back(Base64Alphabet[((byte0 & 0x03) << 4) | ((byte1 >> 4) & 0x0F)]);

                if (remaining > 1)
                {
                    encoded.push_back(Base64Alphabet[((byte1 & 0x0F) << 2) | ((byte2 >> 6) & 0x03)]);
                }

                if (remaining > 2)
                {
                    encoded.push_back(Base64Alphabet[byte2 & 0x3F]);
                }
            }

            return encoded;
        }

        std::string SerializeAssertionResponse(
            const WEBAUTHN_CLIENT_DATA* clientData,
            const WEBAUTHN_ASSERTION* assertion)
        {
            const std::string credentialId = (assertion != nullptr && assertion->Credential.pbId != nullptr && assertion->Credential.cbId > 0)
                ? Base64UrlEncode(assertion->Credential.pbId, assertion->Credential.cbId)
                : std::string{};
            const std::string clientDataJson = (clientData != nullptr && clientData->pbClientDataJSON != nullptr && clientData->cbClientDataJSON > 0)
                ? Base64UrlEncode(clientData->pbClientDataJSON, clientData->cbClientDataJSON)
                : std::string{};
            const std::string authenticatorData = (assertion != nullptr && assertion->pbAuthenticatorData != nullptr && assertion->cbAuthenticatorData > 0)
                ? Base64UrlEncode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData)
                : std::string{};
            const std::string signature = (assertion != nullptr && assertion->pbSignature != nullptr && assertion->cbSignature > 0)
                ? Base64UrlEncode(assertion->pbSignature, assertion->cbSignature)
                : std::string{};
            const std::string userHandle = (assertion != nullptr && assertion->pbUserId != nullptr && assertion->cbUserId > 0)
                ? Base64UrlEncode(assertion->pbUserId, assertion->cbUserId)
                : std::string{};

            std::string json;
            json.reserve(
                credentialId.size() * 2
                + clientDataJson.size()
                + authenticatorData.size()
                + signature.size()
                + userHandle.size()
                + SerializedAssertionJsonOverhead);

            json += R"({"id":")";
            json += credentialId;
            json += R"(","rawId":")";
            json += credentialId;
            json += R"(","type":"public-key","response":{"clientDataJSON":")";
            json += clientDataJson;
            json += R"(","authenticatorData":")";
            json += authenticatorData;
            json += R"(","signature":")";
            json += signature;
            json += R"(","userHandle":)";

            if (assertion == nullptr || assertion->cbUserId == 0 || assertion->pbUserId == nullptr)
            {
                json += "null";
            }
            else
            {
                json += '"';
                json += userHandle;
                json += '"';
            }

            json += R"(},"clientExtensionResults":{}})";
            return json;
        }

        // Appends the common fields shared by all pipe messages: type discriminator, timestamp,
        // pid, processName, and userName.  The caller appends any type-specific fields and the
        // closing brace.
        void AppendCommonFields(
            std::string& msg,
            const char* type,
            const std::string& timestamp,
            std::wstring_view processName,
            std::wstring_view userName,
            DWORD pid)
        {
            const std::string processNameEscaped = JsonEscapeString(WideToUtf8(processName));
            const std::string userNameEscaped    = JsonEscapeString(WideToUtf8(userName));

            msg += R"({"type":")";
            msg += type;
            msg += R"(","timestamp":")";
            msg += timestamp;
            msg += R"(","pid":)";
            msg += std::to_string(pid);
            msg += R"(,"processName":")";
            msg += processNameEscaped;
            msg += R"(","userName":")";
            msg += userNameEscaped;
            msg += '"';
        }
    }

    HANDLE OpenHookPipe()
    {
        return ::CreateFileW(
            WebAuthnHookPipeName,
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    bool WritePipeMessage(HANDLE pipe, std::string_view message)
    {
        DWORD bytesWritten = 0;
        return ::WriteFile(
                   pipe,
                   message.data(),
                   static_cast<DWORD>(message.size()),
                   &bytesWritten,
                   nullptr)
            && bytesWritten == message.size();
    }

    std::string BuildAssertionStartedMessage(
        LPCWSTR rpId,
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid)
    {
        const std::string timestamp   = IsoTimestampUtc();
        const std::string rpIdEscaped = JsonEscapeString(WideToUtf8(rpId ? rpId : L""));

        std::string msg;
        AppendCommonFields(msg, "AssertionStarted", timestamp, processName, userName, pid);
        msg += R"(,"rpId":")";
        msg += rpIdEscaped;
        msg += R"("})";
        return msg;
    }

    std::string BuildAssertionCompletedMessage(
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid,
        const WEBAUTHN_CLIENT_DATA* clientData,
        const WEBAUTHN_ASSERTION* assertion)
    {
        const std::string payload = SerializeAssertionResponse(clientData, assertion);
        const std::string timestamp = IsoTimestampUtc();

        std::string msg;
        AppendCommonFields(msg, "AssertionCompleted", timestamp, processName, userName, pid);
        msg += R"(,"payload":)";
        msg += payload;
        msg += '}';
        return msg;
    }

    std::string BuildAssertionErrorMessage(
        LPCWSTR rpId,
        std::wstring_view processName,
        std::wstring_view userName,
        DWORD pid,
        HRESULT hresult)
    {
        const std::string timestamp   = IsoTimestampUtc();
        const std::string rpIdEscaped = JsonEscapeString(WideToUtf8(rpId ? rpId : L""));

        std::string msg;
        AppendCommonFields(msg, "AssertionError", timestamp, processName, userName, pid);
        msg += R"(,"rpId":")";
        msg += rpIdEscaped;
        msg += R"(","hresult":)";
        msg += std::to_string(static_cast<uint32_t>(hresult));
        msg += '}';
        return msg;
    }
}
