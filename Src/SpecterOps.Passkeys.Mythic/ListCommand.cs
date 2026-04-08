using System.Buffers.Text;
using System.CommandLine;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using DSInternals.Win32.WebAuthn;
using DSInternals.Win32.WebAuthn.Events;
using Microsoft.Extensions.Logging;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Defines the <c>list</c> subcommand tree for enumerating WebAuthn authenticators, plugins,
/// stored credentials, and authentication event history from the Windows event log.
/// </summary>
internal static class ListCommand
{
    /// <summary>
    /// Creates the <c>list</c> command with subcommands: all, authenticators, plugins, hello, and events.
    /// </summary>
    public static Command Create(ILogger logger)
    {
        var allCommand = new Command("all", "List all authenticators, plugins, credentials, and event history");
        allCommand.SetAction(_ =>
        {
            ListPlatformAuthenticators(logger);
            ListAuthenticatorPlugins(logger);
            ListWindowsHelloCredentials(logger);
            ListEventHistory(logger);
        });

        var authenticatorsCommand = new Command("authenticators", "List platform authenticators");
        authenticatorsCommand.SetAction(_ => ListPlatformAuthenticators(logger));

        var pluginsCommand = new Command("plugins", "List authenticator plugins");
        pluginsCommand.SetAction(_ => ListAuthenticatorPlugins(logger));

        var helloCommand = new Command("hello", "List Windows Hello credentials");
        helloCommand.SetAction(_ => ListWindowsHelloCredentials(logger));

        var eventsCommand = new Command("events", "List WebAuthn authentication event history");
        eventsCommand.SetAction(_ => ListEventHistory(logger));

        var hwndCommand = new Command("hwnd", "List processes with window handles");
        hwndCommand.SetAction(_ => ListWindowHandles(logger));

        var command = new Command("list", "List authenticators, plugins, credentials, and event history")
        {
            allCommand,
            authenticatorsCommand,
            pluginsCommand,
            helloCommand,
            eventsCommand,
            hwndCommand
        };

        return command;
    }

    /// <summary>
    /// Enumerates platform authenticators registered with the Windows WebAuthn API (e.g., TPM, Windows Hello).
    /// </summary>
    private static void ListPlatformAuthenticators(ILogger logger)
    {
        logger.LogInformation("Enumerating platform authenticators...");

        try
        {
            var authenticators = WebAuthnApi.GetAuthenticatorList();
            if (authenticators is null || authenticators.Count == 0)
            {
                logger.LogWarning("No platform authenticators found.");
            }
            else
            {
                var table = new AsciiTable("ID", "Name", "Locked");
                foreach (var auth in authenticators)
                {
                    table.AddRow(
                        auth.AuthenticatorId is not null ? Base64Url.EncodeToString(auth.AuthenticatorId) : string.Empty,
                        auth.AuthenticatorName ?? string.Empty,
                        auth.Locked ? "Yes" : "No"
                    );
                }

                table.Print(Console.Out);

                logger.LogInformation("Total platform authenticators discovered: {Count}", authenticators.Count);
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to enumerate platform authenticators: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Enumerates third-party passkey provider plugins (e.g., 1Password, Bitwarden) registered in the Windows registry.
    /// </summary>
    private static void ListAuthenticatorPlugins(ILogger logger)
    {
        logger.LogInformation("Enumerating authenticator plugins from the registry...");

        try
        {
            var plugins = WebAuthnApi.GetPluginAuthenticators();
            if (plugins is null || plugins.Count == 0)
            {
                logger.LogWarning("No authenticator plugins found.");
            }
            else
            {
                var table = new AsciiTable("Name", "Publisher", "User", "Algorithm");
                foreach (var plugin in plugins)
                {
                    table.AddRow(
                        plugin.Name ?? string.Empty,
                        plugin.PublisherDisplayName ?? string.Empty,
                        plugin.UserName ?? string.Empty,
                        plugin.SigningKeyAlgorithm ?? string.Empty
                    );
                }

                table.Print(Console.Out);

                logger.LogInformation("Total plugins discovered: {Count}", plugins.Count);
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to enumerate authenticator plugins: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Lists discoverable (resident) credentials stored by Windows Hello for all relying parties.
    /// </summary>
    private static void ListWindowsHelloCredentials(ILogger logger)
    {
        logger.LogInformation("Enumerating Windows Hello credentials...");

        try
        {
            var credentials = WebAuthnApi.GetPlatformCredentialList(null, false);
            if (credentials is null || credentials.Count == 0)
            {
                logger.LogWarning("No Windows Hello credentials found.");
            }
            else
            {
                var table = new AsciiTable("Relying Party", "User", "Credential ID");
                foreach (var cred in credentials)
                {
                    table.AddRow(
                        cred.RelyingPartyInformation?.Id ?? string.Empty,
                        cred.UserInformation?.Name ?? string.Empty,
                        cred.CredentialId is not null ? Base64Url.EncodeToString(cred.CredentialId) : string.Empty
                    );
                }

                table.Print(Console.Out);

                logger.LogInformation("Total credentials discovered: {Count}", credentials.Count);
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to enumerate Windows Hello credentials: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Reads the Microsoft-Windows-WebAuthN/Operational event log, aggregates registration and authentication
    /// operations, deduplicates by relying party and credential ID, and displays a summary table.
    /// </summary>
    private static void ListEventHistory(ILogger logger)
    {
        logger.LogInformation("Fetching passkey use history from the Microsoft-Windows-WebAuthN/Operational event log...");

        try
        {
            var events = WebAuthnEventReader.ReadEvents();
            var operations = WebAuthnOperationBuilder.Build(events);

            if (operations.Count == 0)
            {
                logger.LogWarning("No events found.");
            }
            else
            {
                // Group all operations (registrations + authentications) by RP + Credential ID
                var grouped = operations
                    .GroupBy(op => (
                        op.RpId,
                        CredId: op.CredentialId is not null ? Base64Url.EncodeToString(op.CredentialId) : string.Empty
                    ))
                    .Select(g =>
                    {
                        var latest = g.OrderByDescending(op => op.TimeCompleted ?? op.TimeStarted).First();
                        // UserName is typically only in registration events; pick the first non-empty value
                        string userName = g.Select(op => op.UserName).FirstOrDefault(n => !string.IsNullOrEmpty(n)) ?? string.Empty;
                        // Product/Manufacturer may be missing on some events; pick from the first record that has them
                        var withProduct = g.FirstOrDefault(op => !string.IsNullOrEmpty(op.Product));
                        return new
                        {
                            Latest = latest,
                            Count = g.Count(),
                            UserName = userName,
                            Authenticator = FormatAuthenticatorName(
                                latest.ProviderName,
                                withProduct?.Manufacturer ?? latest.Manufacturer,
                                withProduct?.Product ?? latest.Product)
                        };
                    })
                    .OrderByDescending(x => x.Latest.TimeCompleted ?? x.Latest.TimeStarted)
                    .ToList();

                var table = new AsciiTable("Last Used", "Use Count", "Relying Party", "User", "Credential ID", "Authenticator");
                foreach (var entry in grouped)
                {
                    var op = entry.Latest;
                    string lastUsed = (op.TimeCompleted ?? op.TimeStarted)?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? string.Empty;
                    string credId = op.CredentialId is not null ? Base64Url.EncodeToString(op.CredentialId) : string.Empty;

                    table.AddRow(
                        lastUsed,
                        entry.Count.ToString(CultureInfo.InvariantCulture),
                        op.RpId ?? string.Empty,
                        entry.UserName,
                        credId,
                        entry.Authenticator
                    );
                }

                table.Print(Console.Out);

                logger.LogInformation("Total unique credentials discovered: {Count}", grouped.Count);
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to read the WebAuthn event log: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Enumerates processes in the current user's session that have a visible main window handle.
    /// </summary>
    private static void ListWindowHandles(ILogger logger)
    {
        logger.LogInformation("Enumerating processes with window handles...");

        try
        {
            var entries = new List<(string Handle, string ProcessName, string WindowTitle)>();

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.MainWindowHandle != IntPtr.Zero)
                    {
                        entries.Add((
                            process.MainWindowHandle.ToInt64().ToString(CultureInfo.InvariantCulture).PadLeft(10),
                            process.ProcessName ?? string.Empty,
                            process.MainWindowTitle ?? string.Empty
                        ));
                    }
                }
                catch (InvalidOperationException)
                {
                    // Process exited before we could inspect it.
                }
                finally
                {
                    process.Dispose();
                }
            }

            if (entries.Count == 0)
            {
                logger.LogWarning("No processes with window handles found.");
            }
            else
            {
                entries.Sort((a, b) => string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase));

                var table = new AsciiTable("Process Name", "Handle", "Window Title");
                foreach (var entry in entries)
                {
                    table.AddRow(entry.ProcessName, entry.Handle, entry.WindowTitle);
                }

                table.Print(Console.Out);
                logger.LogInformation("Total processes with window handles: {Count}", entries.Count);
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to enumerate window handles: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Builds a human-readable authenticator label from event log fields.
    /// Returns "Windows Hello" for the platform provider, or manufacturer/product for external security keys.
    /// </summary>
    private static string FormatAuthenticatorName(string? providerName, string? manufacturer, string? product)
    {
        if (string.Equals(providerName, "MicrosoftPlatformProvider", StringComparison.OrdinalIgnoreCase))
        {
            return "Windows Hello";
        }

        if (manufacturer is not null && product is not null)
        {
            return $"{manufacturer} {product}";
        }

        return manufacturer ?? product ?? providerName ?? string.Empty;
    }
}
