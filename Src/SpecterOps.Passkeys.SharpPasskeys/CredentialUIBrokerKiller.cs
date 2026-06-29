using System.Diagnostics;

namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Terminates running CredentialUIBroker processes to dismiss any active Windows Security prompt.
/// </summary>
internal static class CredentialUIBrokerKiller
{
    private const string ProcessName = "CredentialUIBroker";
    private const int DoubleTapAttempts = 2;
    private static readonly TimeSpan RespawnDelay = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan ExitTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Kills all running CredentialUIBroker processes. Retries after a brief pause to handle respawns.
    /// Returns the PIDs of processes that were successfully killed.
    /// </summary>
    public static List<int> Kill(bool doubletap = true)
    {
        var killedPids = new List<int>();
        int maxAttempts = doubletap ? DoubleTapAttempts : 1;

        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            Process[] processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length == 0)
            {
                break;
            }

            foreach (Process process in processes)
            {
                try
                {
                    int pid = process.Id;
                    process.Kill();
                    process.WaitForExit((int)ExitTimeout.TotalMilliseconds);
                    killedPids.Add(pid);
                }
                catch
                {
                    // Process may have already exited
                }
                finally
                {
                    process.Dispose();
                }
            }

            if (attempt < maxAttempts)
            {
                Thread.Sleep(RespawnDelay);
            }
        }

        return killedPids;
    }
}
