using CommunityToolkit.Mvvm.ComponentModel;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the C2 Commands dialog. Generates CLI commands from assertion request options.
/// </summary>
public partial class C2CommandsDialogViewModel : ObservableObject
{
    /// <summary>
    /// Gets the list of Mythic CLI commands to display.
    /// </summary>
    public IReadOnlyList<string> MythicCommands { get; }

    public C2CommandsDialogViewModel(PublicKeyCredentialRequestOptions assertionOptions)
    {
        MythicCommands = BuildMythicCommands(assertionOptions);
    }

    private static List<string> BuildMythicCommands(PublicKeyCredentialRequestOptions options)
    {
        string rpId = options.RpId ?? string.Empty;
        string challenge = options.Challenge ?? string.Empty;

        string baseCommand = $"passkeys assertion --relying-party {rpId} --challenge {challenge}";

        if (options.AllowCredentials is null or { Length: 0 })
        {
            return [baseCommand];
        }

        var credentialCommands = options.AllowCredentials.Select(c => $"passkeys assertion --relying-party {rpId} --credential-id {c.Id} --challenge {challenge}");

        return [baseCommand, .. credentialCommands];
    }
}
