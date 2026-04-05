using System.Buffers.Text;
using System.CommandLine;
using System.Globalization;
using DSInternals.Win32.WebAuthn;
using DSInternals.Win32.WebAuthn.Events;

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
    public static Command Create()
    {
        var allCommand = new Command("all", "List all authenticators, plugins, credentials, and event history");
        allCommand.SetAction(_ =>
        {
            ListPlatformAuthenticators();
            ListAuthenticatorPlugins();
            ListWindowsHelloCredentials();
            ListEventHistory();
        });

        var authenticatorsCommand = new Command("authenticators", "List platform authenticators");
        authenticatorsCommand.SetAction(_ => ListPlatformAuthenticators());

        var pluginsCommand = new Command("plugins", "List authenticator plugins");
        pluginsCommand.SetAction(_ => ListAuthenticatorPlugins());

        var helloCommand = new Command("hello", "List Windows Hello credentials");
        helloCommand.SetAction(_ => ListWindowsHelloCredentials());

        var eventsCommand = new Command("events", "List WebAuthn authentication event history");
        eventsCommand.SetAction(_ => ListEventHistory());

        var command = new Command("list", "List authenticators, plugins, credentials, and event history")
        {
            allCommand,
            authenticatorsCommand,
            pluginsCommand,
            helloCommand,
            eventsCommand
        };

        return command;
    }

    /// <summary>
    /// Enumerates platform authenticators registered with the Windows WebAuthn API (e.g., TPM, Windows Hello).
    /// </summary>
    private static void ListPlatformAuthenticators()
    {
        Console.WriteLine("Platform Authenticators:");
        Console.WriteLine();

        try
        {
            var authenticators = WebAuthnApi.GetAuthenticatorList();
            if (authenticators is null || authenticators.Count == 0)
            {
                Console.WriteLine("  No platform authenticators found.");
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
            }
        }
        catch (NotSupportedException)
        {
            Console.WriteLine("  Not supported on this Windows version.");
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Enumerates third-party passkey provider plugins (e.g., 1Password, Bitwarden) registered in the Windows registry.
    /// </summary>
    private static void ListAuthenticatorPlugins()
    {
        Console.WriteLine("Authenticator Plugins:");
        Console.WriteLine();

        try
        {
            var plugins = WebAuthnApi.GetPluginAuthenticators();
            if (plugins is null || plugins.Count == 0)
            {
                Console.WriteLine("  No authenticator plugins registered.");
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
            }
        }
        catch (NotSupportedException)
        {
            Console.WriteLine("  Not supported on this Windows version.");
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Lists discoverable (resident) credentials stored by Windows Hello for all relying parties.
    /// </summary>
    private static void ListWindowsHelloCredentials()
    {
        Console.WriteLine("Windows Hello Credentials:");
        Console.WriteLine();

        try
        {
            var credentials = WebAuthnApi.GetPlatformCredentialList(null, false);
            if (credentials is null || credentials.Count == 0)
            {
                Console.WriteLine("  No Windows Hello credentials found.");
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
            }
        }
        catch (NotSupportedException)
        {
            Console.WriteLine("  Not supported on this Windows version.");
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Reads the Microsoft-Windows-WebAuthN/Operational event log, aggregates registration and authentication
    /// operations, deduplicates by relying party and credential ID, and displays a summary table.
    /// </summary>
    private static void ListEventHistory()
    {
        Console.WriteLine("WebAuthn Authentication Event History:");
        Console.WriteLine();

        try
        {
            var events = WebAuthnEventReader.ReadEvents();
            var operations = WebAuthnOperationBuilder.Build(events);

            if (operations.Count == 0)
            {
                Console.WriteLine("  No events found.");
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
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("  Access denied. Run as administrator to read the WebAuthn event log.");
        }
        catch (NotSupportedException)
        {
            Console.WriteLine("  Not supported on this Windows version.");
        }

        Console.WriteLine();
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
