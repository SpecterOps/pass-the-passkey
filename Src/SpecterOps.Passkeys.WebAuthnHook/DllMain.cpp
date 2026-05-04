#include "WebAuthnHook.h"
#include <detours/detours.h>

using namespace SpecterOps::Passkeys::WebAuthnHook;

/// Initializes or detaches WebAuthn detours as the hook DLL is loaded or unloaded.
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
