using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.System.Memory;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Owns memory allocated inside a remote process and releases it with <c>VirtualFreeEx</c>.
/// </summary>
internal sealed unsafe class RemoteAllocationSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private readonly SafeProcessHandle _processHandle;

    private RemoteAllocationSafeHandle(SafeProcessHandle processHandle, IntPtr allocationHandle)
        : base(ownsHandle: true)
    {
        _processHandle = processHandle;
        handle = allocationHandle;
    }

    public static RemoteAllocationSafeHandle Allocate(SafeProcessHandle processHandle, nuint byteCount)
    {
        return new RemoteAllocationSafeHandle(
            processHandle,
            (IntPtr)PInvoke.VirtualAllocEx(
                processHandle,
                null,
                byteCount,
                VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                PAGE_PROTECTION_FLAGS.PAGE_READWRITE));
    }

    protected override bool ReleaseHandle()
        => PInvoke.VirtualFreeEx(_processHandle, (void*)handle, 0, VIRTUAL_FREE_TYPE.MEM_RELEASE);
}
