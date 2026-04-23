#include "WebAuthnHook.h"
#include "Logging.h"
#include <detours.h>
#include <string>

using namespace SpecterOps::Passkeys::WebAuthnHook;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(instance);
        DetourRestoreAfterWith();

        // Only fall back to LoadLibrary bootstrap hooks when webauthn.dll is not
        // yet loaded — the common case under early injection.
        if (!AttachAssertionHook() && !AttachBootstrapHooks())
        {
            AppendLog(
                L"[" + Timestamp() + L"] " + GetCurrentProcessName()
                + L" (pid " + std::to_wstring(::GetCurrentProcessId())
                + L", user " + GetCurrentUserName()
                + L") Failed to arm bootstrap Detours hooks.");
            return FALSE;
        }

        break;

    case DLL_PROCESS_DETACH:
        // Only detach on a dynamic FreeLibrary unload.
        if (reserved == nullptr)
        {
            DetachHooks();
        }
        break;
    }

    return TRUE;
}
