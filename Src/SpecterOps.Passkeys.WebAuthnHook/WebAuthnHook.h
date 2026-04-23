#pragma once

#include <Windows.h>
#include <webauthn.h>

namespace SpecterOps::Passkeys::WebAuthnHook
{
    /// Detour entrypoint that logs the request before calling the original API.
    HRESULT WINAPI HookWebAuthNAuthenticatorGetAssertion(
        HWND hwnd,
        LPCWSTR rpId,
        WEBAUTHN_CLIENT_DATA* clientData,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
        WEBAUTHN_ASSERTION** assertion);

    /// Watches LoadLibraryW so the assertion hook can be armed after lazy DLL loads.
    HMODULE WINAPI HookLoadLibraryW(LPCWSTR fileName);

    /// Watches LoadLibraryExW so the assertion hook can be armed after lazy DLL loads.
    HMODULE WINAPI HookLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags);

    /// Installs the WebAuthNAuthenticatorGetAssertion detour when webauthn.dll is available.
    bool AttachAssertionHook();

    /// Installs bootstrap detours on LoadLibrary entrypoints during DLL attach.
    bool AttachBootstrapHooks();

    /// Removes any installed detours before the hook DLL unloads.
    void DetachHooks();
}
