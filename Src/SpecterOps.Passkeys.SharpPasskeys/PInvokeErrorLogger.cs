using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SpecterOps.Passkeys.SharpPasskeys;

internal static class PInvokeErrorLogger
{
    /// <summary>
    /// Logs the most recent Win32 error (retrieved via <see cref="Marshal.GetLastWin32Error"/>) together with its system message.
    /// </summary>
    public static void LogLastPInvokeError(ILogger logger, string operation, int pid)
    {
        int error = Marshal.GetLastWin32Error();
        logger.LogError(
            "{Operation} failed for pid {Pid} ({Code}: {Message}).",
            operation,
            pid,
            error,
            new Win32Exception(error).Message);
    }
}
