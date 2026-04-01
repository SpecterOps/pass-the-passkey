using System.CommandLine;
using DSInternals.Win32.WebAuthn;

namespace SpecterOps.Passkeys.Mythic;

public class Program
{
    public static int Main(string[] args)
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

        var assertionCommand = new Command("assertion", "Perform a WebAuthn assertion (authentication)")
        {
            relyingPartyOption,
            challengeOption,
            credentialIdOption
        };

        assertionCommand.SetAction(parseResult =>
        {
            string relyingParty = parseResult.GetValue(relyingPartyOption)!;
            string challenge = parseResult.GetValue(challengeOption)!;
            string? credentialId = parseResult.GetValue(credentialIdOption);

            byte[] challengeBytes = Base64UrlConverter.FromBase64UrlString(challenge);

            List<PublicKeyCredentialDescriptor>? allowedCredentials = null;
            if (credentialId is not null)
            {
                byte[] credentialIdBytes = Base64UrlConverter.FromBase64UrlString(credentialId);
                allowedCredentials = [new PublicKeyCredentialDescriptor(credentialIdBytes)];
            }

            var api = new WebAuthnApi();
            var response = api.AuthenticatorGetAssertion(
                rpId: relyingParty,
                challenge: challengeBytes,
                userVerificationRequirement: UserVerificationRequirement.Preferred,
                authenticatorAttachment: AuthenticatorAttachment.Any,
                timeoutMilliseconds: 60000,
                allowCredentials: allowedCredentials,
                extensions: null,
                largeBlobOperation: CredentialLargeBlobOperation.None,
                largeBlob: null,
                browserInPrivateMode: false,
                linkedDevice: null,
                windowHandle: WindowHandle.ConsoleWindow
            );

            string authenticatorData = Base64UrlConverter.ToBase64UrlString(response.AuthenticatorData);
            string signature = Base64UrlConverter.ToBase64UrlString(response.Signature);
            string clientDataJson = Base64UrlConverter.ToBase64UrlString(response.ClientDataJson);
            string? userHandle = response.UserHandle is not null
                ? Base64UrlConverter.ToBase64UrlString(response.UserHandle)
                : null;

            Console.WriteLine($"{{\"authenticatorData\":\"{authenticatorData}\",\"signature\":\"{signature}\",\"clientDataJSON\":\"{clientDataJson}\",\"userHandle\":{(userHandle is not null ? $"\"{userHandle}\"" : "null")}}}");
        });

        var rootCommand = new RootCommand("SpecterOps Passkeys Mythic CLI")
        {
            assertionCommand
        };

        var config = new CommandLineConfiguration(rootCommand);
        return config.Invoke(args);
    }
}
