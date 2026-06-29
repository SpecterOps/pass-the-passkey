using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security.Principal;

namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Defines the <c>wait</c> subcommand that monitors the Microsoft-Windows-WebAuthN/Operational event log
/// for an incoming assertion (authentication) request and reports the relying party ID, timestamp, and Windows user.
/// </summary>
internal static class WaitCommand
{
    private const string WebAuthnLogPath = "Microsoft-Windows-WebAuthN/Operational";
    private const int GetAssertionRequestEventId = 1103;
    private const int RpIdPropertyIndex = 1;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Creates the <c>wait</c> command with optional <c>--timeout</c> and <c>--kill</c> parameters.
    /// </summary>
    public static Command Create(ILogger logger)
    {
        var timeoutOption = new Option<int?>("--timeout", "-t")
        {
            Description = $"Timeout in seconds (default: {DefaultTimeout.TotalSeconds:0})"
        };

        var killOption = new Option<bool>("--kill", "-k")
        {
            Description = "Kill the CredentialUIBroker.exe process when an assertion request is detected"
        };

        var command = new Command("wait", "Wait for a WebAuthn assertion request and report the relying party ID")
        {
            timeoutOption,
            killOption
        };

        command.SetAction(parseResult =>
        {
            int? timeoutSeconds = parseResult.GetValue(timeoutOption);
            TimeSpan timeout = timeoutSeconds.HasValue
                ? TimeSpan.FromSeconds(timeoutSeconds.Value)
                : DefaultTimeout;
            bool kill = parseResult.GetValue(killOption);

            WaitForAssertionRequest(logger, timeout, kill);
        });

        return command;
    }

    /// <summary>
    /// Subscribes to the WebAuthN event log via <see cref="EventLogWatcher"/> for event ID 1103
    /// (GetAssertion request). Blocks until an event arrives or the timeout expires, then extracts
    /// the relying party ID, timestamp, and Windows user from the event and writes them to stdout.
    /// </summary>
    private static void WaitForAssertionRequest(ILogger logger, TimeSpan timeout, bool kill)
    {
        using var eventArrived = new ManualResetEventSlim(false);
        string? rpId = null;
        DateTime? timeCreated = null;
        string? userName = null;

        var query = new EventLogQuery(
            WebAuthnLogPath,
            PathType.LogName,
            $"*[System[EventID={GetAssertionRequestEventId}]]"
        );

        using var watcher = new EventLogWatcher(query);

        watcher.EventRecordWritten += (_, args) =>
        {
            using EventRecord? eventRecord = args.EventRecord;
            if (eventRecord is not null)
            {
                // RpId is the second EventData field (index 1) in event ID 1103
                rpId = eventRecord.Properties.Count > RpIdPropertyIndex
                    ? eventRecord.Properties[RpIdPropertyIndex].Value?.ToString()
                    : null;
                timeCreated = eventRecord.TimeCreated;
                userName = ResolveUserName(eventRecord.UserId);
                eventArrived.Set();
            }
        };

        try
        {
            watcher.Enabled = true;
        }
        catch (UnauthorizedAccessException)
        {
            logger.LogError("Access denied to the Microsoft-Windows-WebAuthN/Operational event log.");
            return;
        }
        catch (EventLogNotFoundException)
        {
            logger.LogError("The Microsoft-Windows-WebAuthN/Operational event log was not found.");
            return;
        }

        logger.LogInformation("Waiting for WebAuthn assertion request (timeout: {Timeout:0}m)...", timeout.TotalMinutes);

        if (eventArrived.Wait(timeout))
        {
            if (kill)
            {
                List<int> killedPids = CredentialUIBrokerKiller.Kill(doubletap: true);
                if (killedPids.Count > 0)
                {
                    logger.LogInformation("Killed CredentialUIBroker (PID {Pids}).", string.Join(", ", killedPids));
                }
            }

            string time = timeCreated?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? string.Empty;
            Console.WriteLine($"Time: {time}");
            Console.WriteLine($"User: {userName ?? string.Empty}");
            Console.WriteLine($"Relying Party: {rpId ?? string.Empty}");
        }
        else
        {
            logger.LogWarning("Timeout expired. No assertion request detected.");
        }
    }

    /// <summary>
    /// Translates a <see cref="SecurityIdentifier"/> (SID) into a human-readable domain\user name.
    /// Returns the SID string if the account cannot be resolved.
    /// </summary>
    private static string? ResolveUserName(SecurityIdentifier? sid)
    {
        if (sid is null)
        {
            return null;
        }

        try
        {
            var account = (NTAccount)sid.Translate(typeof(NTAccount));
            return account.Value;
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }
}
