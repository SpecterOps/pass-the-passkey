using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.Threading;

namespace SpecterOps.Passkeys.SharpPasskeys;

internal static unsafe class SafeProcessHandleExtensions
{
    extension(SafeProcessHandle)
    {
        /// <summary>
        /// Opens a handle to the specified process with the desired access rights and inheritance option.
        /// </summary>
        /// <param name="desiredAccess">The access rights requested for the process handle.</param>
        /// <param name="inheritHandle">Indicates whether the handle is inheritable.</param>
        /// <param name="pid">The process ID of the target process.</param>
        /// <returns>A SafeProcessHandle representing the opened process.</returns>
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
        /// <summary>
        /// Determines whether the specified process is running under WOW64 (Windows 32-bit on Windows 64-bit) and retrieves the machine types of the process and the native system.
        /// </summary>
        /// <param name="processMachine">The machine type of the process.</param>
        /// <param name="nativeMachine">The machine type of the native system.</param>
        /// <returns>True if the process is running under WOW64, otherwise false.</returns>
        public bool IsWow64Process(out IMAGE_FILE_MACHINE processMachine, out IMAGE_FILE_MACHINE nativeMachine)
            => PInvoke.IsWow64Process2(processHandle, out processMachine, out nativeMachine);

        public bool WriteProcessMemory(RemoteAllocationSafeHandle allocation, ReadOnlySpan<byte> buffer)
            => PInvoke.WriteProcessMemory(processHandle, (void*)allocation.DangerousGetHandle(), buffer);

        /// <summary>
        /// Runs a remote thread in the target process at the specified start address with the given parameter, and waits for it to complete.
        /// </summary>
        /// <param name="startAddress">The starting address of the remote thread.</param>
        /// <param name="parameter">The parameter to pass to the remote thread.</param>
        /// <param name="routineName">The name of the routine being executed.</param>
        /// <param name="pid">The process ID of the target process.</param>
        /// <param name="logger">The logger to use for logging errors.</param>
        /// <param name="exitCode">The exit code of the remote thread.</param>
        /// <returns>True if the remote thread was successfully created and executed, otherwise false.</returns>
        /// <exception cref="ArgumentNullException"></exception>
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

        /// <summary>
        /// Runs a remote thread in the target process at the specified start address with the given parameter, and waits for it to complete.
        /// </summary>
        /// <param name="startAddress">The starting address of the remote thread.</param>
        /// <param name="parameter">The parameter to pass to the remote thread.</param>
        /// <param name="routineName">The name of the routine being executed.</param>
        /// <param name="pid">The process ID of the target process.</param>
        /// <param name="logger">The logger to use for logging errors.</param>
        /// <param name="exitCode">The exit code of the remote thread.</param>
        /// <returns>True if the remote thread was successfully created and executed, otherwise false.</returns>
        /// <exception cref="ArgumentNullException"></exception>
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

    /// <summary>
    /// Runs a remote thread in the target process at the specified start address with the given parameter, and waits for it to complete.
    /// </summary>
    /// <param name="processHandle">The handle to the target process.</param>
    /// <param name="startAddress">The starting address of the remote thread.</param>
    /// <param name="parameter">The parameter to pass to the remote thread.</param>
    /// <param name="routineName">The name of the routine being executed.</param>
    /// <param name="pid">The process ID of the target process.</param>
    /// <param name="logger">The logger to use for logging errors.</param>
    /// <param name="exitCode">The exit code of the remote thread.</param>
    /// <returns>True if the remote thread was successfully created and executed, otherwise false.</returns>
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

        // Successfully ran the remote thread and obtained an exit code.
        return true;
    }

}
