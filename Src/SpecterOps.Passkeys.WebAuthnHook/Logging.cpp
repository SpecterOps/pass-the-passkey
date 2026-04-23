#include "Logging.h"

#include <algorithm>
#include <cwchar>
#include <sstream>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    // Cap collection logging so a malformed request cannot explode log volume.
    constexpr DWORD MaxLoggedCollectionItems = 16;

    // Limit copied UTF-8 payloads such as clientDataJSON and requestOptions JSON.
    constexpr DWORD MaxLoggedUtf8Bytes = 4096;

    // Limit copied binary blobs such as credential IDs and authenticator IDs.
    constexpr DWORD MaxLoggedBinaryBytes = 256;

    // Timestamp each event so multi-process hook output can be correlated later.
    std::wstring Timestamp()
    {
        SYSTEMTIME localTime{};
        ::GetLocalTime(&localTime);

        wchar_t buffer[32]{};
        swprintf_s(
            buffer,
            L"%02u:%02u:%02u.%03u",
            localTime.wHour,
            localTime.wMinute,
            localTime.wSecond,
            localTime.wMilliseconds);

        return buffer;
    }

    std::wstring GetCurrentProcessName()
    {
        wchar_t path[MAX_PATH]{};
        const DWORD length = ::GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (length == 0 || length >= std::size(path))
        {
            return L"<unknown>";
        }

        const wchar_t* fileName = wcsrchr(path, L'\\');
        fileName = fileName == nullptr ? path : fileName + 1;

        std::wstring processName(fileName);
        const size_t extensionIndex = processName.rfind(L'.');
        if (extensionIndex != std::wstring::npos)
        {
            processName.resize(extensionIndex);
        }

        return processName;
    }

    std::wstring GetCurrentUserName()
    {
        wchar_t userName[256]{};
        DWORD length = static_cast<DWORD>(std::size(userName));
        if (!::GetUserNameW(userName, &length) || length <= 1)
        {
            return L"<unknown>";
        }

        return std::wstring(userName, length - 1);
    }

    std::wstring GetLogPath()
    {
        wchar_t tempPath[MAX_PATH]{};
        const DWORD pathLength = ::GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
        if (pathLength == 0 || pathLength >= std::size(tempPath))
        {
            return L"SpecterOps.Passkeys.WebAuthnHook.log";
        }

        std::wstring path(tempPath, pathLength);
        path += L"SpecterOps.Passkeys.WebAuthnHook.log";
        return path;
    }

    // Write to both the debugger and a temp-file log so the hook is observable
    // even when the target browser was started outside Visual Studio.
    void AppendLog(std::wstring_view message)
    {
        std::wstring line(message);
        line.append(L"\r\n");

        ::OutputDebugStringW(line.c_str());

        const std::wstring path = GetLogPath();
        HANDLE file = ::CreateFileW(
            path.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        const int utf8Length = ::WideCharToMultiByte(
            CP_UTF8,
            0,
            line.c_str(),
            static_cast<int>(line.size()),
            nullptr,
            0,
            nullptr,
            nullptr);

        if (utf8Length > 0)
        {
            std::string utf8(static_cast<size_t>(utf8Length), '\0');
            ::WideCharToMultiByte(
                CP_UTF8,
                0,
                line.c_str(),
                static_cast<int>(line.size()),
                utf8.data(),
                utf8Length,
                nullptr,
                nullptr);

            DWORD bytesWritten = 0;
            ::WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &bytesWritten, nullptr);
        }

        ::CloseHandle(file);
    }

    std::wstring ReadUtf8(const BYTE* buffer, DWORD length)
    {
        if (buffer == nullptr || length == 0)
        {
            return L"";
        }

        const DWORD bytesToCopy = std::min(length, MaxLoggedUtf8Bytes);
        const int wideLength = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(buffer),
            static_cast<int>(bytesToCopy),
            nullptr,
            0);

        std::wstring text;
        if (wideLength > 0)
        {
            text.resize(static_cast<size_t>(wideLength));
            ::MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                reinterpret_cast<const char*>(buffer),
                static_cast<int>(bytesToCopy),
                text.data(),
                wideLength);
        }

        if (length > bytesToCopy)
        {
            text += L"... <truncated ";
            text += std::to_wstring(length - bytesToCopy);
            text += L" bytes>";
        }

        return text;
    }

    std::wstring ToHex(const BYTE* buffer, DWORD length)
    {
        if (buffer == nullptr || length == 0)
        {
            return L"";
        }

        const DWORD bytesToCopy = std::min(length, MaxLoggedBinaryBytes);
        std::wstringstream stream;
        stream.setf(std::ios::uppercase);
        stream.fill(L'0');

        for (DWORD index = 0; index < bytesToCopy; ++index)
        {
            stream.width(2);
            stream << std::hex << static_cast<unsigned>(buffer[index]);
        }

        if (length > bytesToCopy)
        {
            stream << L"...<truncated " << (length - bytesToCopy) << L" bytes>";
        }

        return stream.str();
    }

    std::wstring AsBool(BOOL value)
    {
        return value ? L"True" : L"False";
    }

    void AppendCollectionTruncation(std::vector<std::wstring>& parts, DWORD originalCount)
    {
        if (originalCount > MaxLoggedCollectionItems)
        {
            parts.push_back(L"... (" + std::to_wstring(originalCount - MaxLoggedCollectionItems) + L" more)");
        }
    }

    std::wstring DescribeCredentials(const WEBAUTHN_CREDENTIALS& credentials)
    {
        if (credentials.cCredentials == 0 || credentials.pCredentials == nullptr)
        {
            return L"<none>";
        }

        const DWORD itemsToCopy = std::min(credentials.cCredentials, MaxLoggedCollectionItems);
        std::vector<std::wstring> parts;
        parts.reserve(itemsToCopy);

        for (DWORD index = 0; index < itemsToCopy; ++index)
        {
            const auto& credential = credentials.pCredentials[index];
            parts.push_back(
                std::wstring(credential.pwszCredentialType ? credential.pwszCredentialType : L"<null>")
                + L":" + ToHex(credential.pbId, credential.cbId));
        }

        AppendCollectionTruncation(parts, credentials.cCredentials);

        std::wstringstream stream;
        for (size_t index = 0; index < parts.size(); ++index)
        {
            if (index > 0)
            {
                stream << L", ";
            }

            stream << parts[index];
        }

        return stream.str();
    }

    std::wstring DescribeCredentialList(const WEBAUTHN_CREDENTIAL_LIST* credentialList)
    {
        if (credentialList == nullptr || credentialList->cCredentials == 0 || credentialList->ppCredentials == nullptr)
        {
            return L"<none>";
        }

        const DWORD itemsToCopy = std::min(credentialList->cCredentials, MaxLoggedCollectionItems);
        std::vector<std::wstring> parts;
        parts.reserve(itemsToCopy);

        for (DWORD index = 0; index < itemsToCopy; ++index)
        {
            const auto credential = credentialList->ppCredentials[index];
            if (credential == nullptr)
            {
                continue;
            }

            parts.push_back(
                std::wstring(credential->pwszCredentialType ? credential->pwszCredentialType : L"<null>")
                + L":" + ToHex(credential->pbId, credential->cbId)
                + L" transport=0x" + [&credential]()
                {
                    std::wstringstream stream;
                    stream << std::hex << std::uppercase << credential->dwTransports;
                    return stream.str();
                }());
        }

        AppendCollectionTruncation(parts, credentialList->cCredentials);

        if (parts.empty())
        {
            return L"<none>";
        }

        std::wstringstream stream;
        for (size_t index = 0; index < parts.size(); ++index)
        {
            if (index > 0)
            {
                stream << L", ";
            }

            stream << parts[index];
        }

        return stream.str();
    }

    std::wstring DescribeExtensions(const WEBAUTHN_EXTENSIONS& extensions)
    {
        if (extensions.cExtensions == 0 || extensions.pExtensions == nullptr)
        {
            return L"<none>";
        }

        const DWORD itemsToCopy = std::min(extensions.cExtensions, MaxLoggedCollectionItems);
        std::vector<std::wstring> parts;
        parts.reserve(itemsToCopy);

        for (DWORD index = 0; index < itemsToCopy; ++index)
        {
            const auto& extension = extensions.pExtensions[index];
            parts.push_back(
                std::wstring(extension.pwszExtensionIdentifier ? extension.pwszExtensionIdentifier : L"<null>")
                + L" (" + std::to_wstring(extension.cbExtension) + L" bytes)");
        }

        AppendCollectionTruncation(parts, extensions.cExtensions);

        std::wstringstream stream;
        for (size_t index = 0; index < parts.size(); ++index)
        {
            if (index > 0)
            {
                stream << L", ";
            }

            stream << parts[index];
        }

        return stream.str();
    }

    std::wstring DescribeHints(LPCWSTR const* hints, DWORD count)
    {
        if (hints == nullptr || count == 0)
        {
            return L"<none>";
        }

        const DWORD itemsToCopy = std::min(count, MaxLoggedCollectionItems);
        std::vector<std::wstring> parts;
        parts.reserve(itemsToCopy);

        for (DWORD index = 0; index < itemsToCopy; ++index)
        {
            parts.push_back(hints[index] ? hints[index] : L"<null>");
        }

        AppendCollectionTruncation(parts, count);

        std::wstringstream stream;
        for (size_t index = 0; index < parts.size(); ++index)
        {
            if (index > 0)
            {
                stream << L", ";
            }

            stream << parts[index];
        }

        return stream.str();
    }

    std::wstring DescribeAuthenticatorAttachment(DWORD value)
    {
        switch (value)
        {
        case WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM:
            return L"platform";
        case WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM:
            return L"cross-platform";
        case WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2:
            return L"cross-platform-u2f-v2";
        case WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY:
        default:
            return L"any";
        }
    }

    std::wstring DescribeUserVerification(DWORD value)
    {
        switch (value)
        {
        case WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED:
            return L"required";
        case WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED:
            return L"preferred";
        case WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED:
            return L"discouraged";
        case WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY:
        default:
            return L"any";
        }
    }

    // Flatten the native WebAuthn request into readable text before forwarding
    // to the original API.
    std::wstring FormatAssertionRequest(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options)
    {
        std::wstringstream builder;

        builder << L"[" << Timestamp() << L"] [pid=" << ::GetCurrentProcessId()
                << L" tid=" << ::GetCurrentThreadId() << L"] WebAuthNAuthenticatorGetAssertion\r\n";
        builder << L"  hwnd: 0x" << std::hex << reinterpret_cast<UINT_PTR>(hwnd) << std::dec << L"\r\n";
        builder << L"  rpId: " << (rpId ? rpId : L"<null>") << L"\r\n";

        if (clientData != nullptr)
        {
            builder << L"  clientData.hashAlg: "
                    << (clientData->pwszHashAlgId ? clientData->pwszHashAlgId : L"<null>") << L"\r\n";
            builder << L"  clientData.json: " << ReadUtf8(clientData->pbClientDataJSON, clientData->cbClientDataJSON) << L"\r\n";
        }

        if (options == nullptr)
        {
            builder << L"  options: <null>";
            return builder.str();
        }

        builder << L"  options.version: " << options->dwVersion << L"\r\n";
        builder << L"  options.timeoutMs: " << options->dwTimeoutMilliseconds << L"\r\n";
        builder << L"  options.attachment: " << DescribeAuthenticatorAttachment(options->dwAuthenticatorAttachment)
                << L" (" << options->dwAuthenticatorAttachment << L")\r\n";
        builder << L"  options.userVerification: " << DescribeUserVerification(options->dwUserVerificationRequirement)
                << L" (" << options->dwUserVerificationRequirement << L")\r\n";
        builder << L"  options.flags: 0x" << std::hex << options->dwFlags << std::dec << L"\r\n";
        builder << L"  options.inPrivate: " << AsBool(options->bBrowserInPrivateMode) << L"\r\n";
        builder << L"  options.autoFill: " << AsBool(options->bAutoFill) << L"\r\n";
        builder << L"  options.allowCredentials: " << DescribeCredentials(options->CredentialList) << L"\r\n";
        builder << L"  options.extensions: " << DescribeExtensions(options->Extensions) << L"\r\n";

        if (options->pAllowCredentialList != nullptr)
        {
            builder << L"  options.allowCredentialListEx: " << DescribeCredentialList(options->pAllowCredentialList) << L"\r\n";
        }

        if (options->pwszU2fAppId != nullptr)
        {
            builder << L"  options.u2fAppId: " << options->pwszU2fAppId << L"\r\n";
        }

        if (options->pwszRemoteWebOrigin != nullptr)
        {
            builder << L"  options.remoteWebOrigin: " << options->pwszRemoteWebOrigin << L"\r\n";
        }

        if (options->cCredentialHints > 0 && options->ppwszCredentialHints != nullptr)
        {
            builder << L"  options.credentialHints: " << DescribeHints(options->ppwszCredentialHints, options->cCredentialHints) << L"\r\n";
        }

        if (options->cbPublicKeyCredentialRequestOptionsJSON > 0 && options->pbPublicKeyCredentialRequestOptionsJSON != nullptr)
        {
            builder << L"  options.requestOptionsJson: "
                    << ReadUtf8(options->pbPublicKeyCredentialRequestOptionsJSON, options->cbPublicKeyCredentialRequestOptionsJSON) << L"\r\n";
        }

        if (options->cbAuthenticatorId > 0 && options->pbAuthenticatorId != nullptr)
        {
            builder << L"  options.authenticatorId: " << ToHex(options->pbAuthenticatorId, options->cbAuthenticatorId) << L"\r\n";
        }

        return builder.str();
    }
}
