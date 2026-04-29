using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.Threading;

namespace SpecterOps.Passkeys.Mythic;

internal static unsafe class SafeProcessHandleExtensions
{
    extension(SafeProcessHandle)
    {
        public static SafeProcessHandle OpenProcess(
            PROCESS_ACCESS_RIGHTS desiredAccess,
            bool inheritHandle,
            int pid)
        {
            var handle = PInvoke.OpenProcess(desiredAccess, inheritHandle, (uint)pid);
            return new SafeProcessHandle((IntPtr)handle.Value, ownsHandle: true);
        }
    }

    extension(SafeProcessHandle processHandle)
    {
        public bool IsWow64Process(out IMAGE_FILE_MACHINE processMachine, out IMAGE_FILE_MACHINE nativeMachine)
            => PInvoke.IsWow64Process2(processHandle, out processMachine, out nativeMachine);

        public bool WriteProcessMemory(RemoteAllocationSafeHandle allocation, ReadOnlySpan<byte> buffer)
            => PInvoke.WriteProcessMemory(processHandle, (void*)allocation.DangerousGetHandle(), buffer);

        public bool TryRunRemoteThread(
            IntPtr startAddress,
            RemoteAllocationSafeHandle parameter,
            string routineName,
            int pid,
            ILogger logger,
            out uint exitCode)
        {
            if (parameter is null)
            {
                throw new ArgumentNullException(nameof(parameter));
            }

            return RunRemoteThread(
                processHandle,
                startAddress,
                (void*)parameter.DangerousGetHandle(),
                routineName,
                pid,
                logger,
                out exitCode);
        }

        public bool TryRunRemoteThread(
            IntPtr startAddress,
            ProcessModule parameter,
            string routineName,
            int pid,
            ILogger logger,
            out uint exitCode)
        {
            if (parameter is null)
            {
                throw new ArgumentNullException(nameof(parameter));
            }

            return RunRemoteThread(
                processHandle,
                startAddress,
                (void*)parameter.BaseAddress,
                routineName,
                pid,
                logger,
                out exitCode);
        }
    }

    private static bool RunRemoteThread(
        SafeProcessHandle processHandle,
        IntPtr startAddress,
        void* parameter,
        string routineName,
        int pid,
        ILogger logger,
        out uint exitCode)
    {
        // TODO: Reject or support cross-bitness attach/detach; local kernel32 export addresses are not safe for different-bitness targets.
        exitCode = 0;
        if (startAddress == IntPtr.Zero)
        {
            return false;
        }

        var startRoutine = Marshal.GetDelegateForFunctionPointer<LPTHREAD_START_ROUTINE>(startAddress);

        using var threadHandle = PInvoke.CreateRemoteThread(
            processHandle,
            null,
            0,
            startRoutine,
            parameter,
            0,
            out _);

        if (threadHandle.IsInvalid)
        {
            PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.CreateRemoteThread), pid);
            return false;
        }

        var waitResult = PInvoke.WaitForSingleObject(threadHandle, PInvoke.INFINITE);
        if (waitResult == WAIT_EVENT.WAIT_FAILED)
        {
            PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.WaitForSingleObject), pid);
            return false;
        }

        if (!PInvoke.GetExitCodeThread(threadHandle, out exitCode))
        {
            PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.GetExitCodeThread), pid);
            return false;
        }

        return true;
    }

}
