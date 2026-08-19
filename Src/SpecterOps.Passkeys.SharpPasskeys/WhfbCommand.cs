using DSInternals.Win32.WebAuthn;
using DSInternals.Win32.WebAuthn.Cryptography;

namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Defines the <c>whfb</c> subcommand that signs a Microsoft Entra ID assertion with a local
/// Windows Hello for Business key without invoking the native WebAuthn prompt.
/// </summary>
internal static class WhfbCommand
{
    /// <summary>
    /// Creates the <c>whfb</c> command with options for challenge, signature counter,
    /// and private-browser mode.
    /// </summary>
    public static Command Create(ILogger logger)
    {
        var challengeOption = new Option<string>("--challenge", "-c")
        {
            Description = "Base64url-encoded challenge from login.microsoft.com",
            Required = true
        };

        var signatureCounterOption = new Option<uint>("--signature-counter", "--counter", "-s")
        {
            Description = "Signature counter value to embed in authenticator data (default: 0)"
        };

        var privateOption = new Option<bool>("--private", "-p")
        {
            Description = "Indicate that the browser is in private mode; skips WebAuthn event log entries (OPSEC)"
        };

        var command = new Command("whfb", "Sign an Entra ID assertion with a local Windows Hello for Business key")
        {
            challengeOption,
            signatureCounterOption,
            privateOption
        };

        command.SetAction(parseResult =>
        {
            string challenge = parseResult.GetValue(challengeOption)!;
            uint signatureCounter = parseResult.GetValue(signatureCounterOption);
            bool browserInPrivateMode = parseResult.GetValue(privateOption);

            SignAssertions(logger, challenge, signatureCounter, browserInPrivateMode);
        });

        return command;
    }

    /// <summary>
    /// Signs the supplied challenge with every locally resolvable WHfB passkey and writes each
    /// JSON assertion to stdout.
    /// </summary>
    private static void SignAssertions(
        ILogger logger,
        string challenge,
        uint signatureCounter,
        bool browserInPrivateMode)
    {
        try
        {
            byte[] challengeBytes = Base64UrlConverter.FromBase64UrlString(challenge);

            logger.LogInformation(
                "Signing challenge for relying party '{RpId}' with local Windows Hello for Business keys...",
                WindowsHelloForBusinessSigner.RelyingPartyId);

            IReadOnlyList<AssertionPublicKeyCredential> assertions = WindowsHelloForBusinessSigner.GetAssertions(
                challengeBytes,
                signatureCounter,
                browserInPrivateMode);

            int count = 0;
            foreach (AssertionPublicKeyCredential assertion in assertions)
            {
                Console.WriteLine(assertion.ToString());
                count++;
            }

            if (count == 0)
            {
                logger.LogWarning("No locally resolvable Windows Hello for Business assertions were found.");
                return;
            }

            logger.LogInformation("Generated {Count} Windows Hello for Business assertion(s).", count);
        }
        catch (Exception ex)
        {
            logger.LogError("WHfB signing failed: {Message}", ex.Message);
        }
    }
}
