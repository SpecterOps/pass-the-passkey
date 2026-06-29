using DSInternals.Win32.WebAuthn;

namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Defines the <c>apiversion</c> subcommand that reports the version of the Windows WebAuthn API
/// available on the current host and whether a user-verifying platform authenticator (e.g., Windows Hello)
/// is available.
/// </summary>
internal static class ApiVersionCommand
{
    /// <summary>
    /// Creates the <c>apiversion</c> command.
    /// </summary>
    public static Command Create(ILogger logger)
    {
        var command = new Command("apiversion", "Show the Windows WebAuthn API version and platform authenticator availability");

        command.SetAction(_ => ShowApiVersion(logger));

        return command;
    }

    /// <summary>
    /// Queries <see cref="WebAuthnApi"/> for the API version and platform authenticator status and
    /// prints the results as a table.
    /// </summary>
    private static void ShowApiVersion(ILogger logger)
    {
        try
        {
            if (!WebAuthnApi.IsAvailable)
            {
                logger.LogWarning("The Windows WebAuthn API is not available on this host.");
                return;
            }

            string apiVersion = WebAuthnApi.ApiVersion is { } v
                ? ((uint)v).ToString(System.Globalization.CultureInfo.InvariantCulture)
                : "Unknown";
            bool platformAuthenticatorAvailable = WebAuthnApi.IsUserVerifyingPlatformAuthenticatorAvailable;

            var table = new AsciiTable("Property", "Value");
            table.AddRow("API Version", apiVersion);
            table.AddRow("Platform Authenticator Available", platformAuthenticatorAvailable ? "Yes" : "No");
            table.Print(Console.Out);
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to query the WebAuthn API: {Message}", ex.Message);
        }
    }
}
