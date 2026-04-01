using CommunityToolkit.Mvvm.ComponentModel;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the C2 Commands dialog. Generates CLI commands from assertion request options.
/// </summary>
public partial class C2CommandsDialogViewModel : ObservableObject
{
    public static IReadOnlyList<PublicKeyCredentialHint> AuthenticatorTypeHints { get; } =
        Enum.GetValues<PublicKeyCredentialHint>();

    private static readonly Dictionary<string, PublicKeyCredentialHint> s_webAuthnHintMap = new()
    {
        ["client-device"] = PublicKeyCredentialHint.ClientDevice,
        ["security-key"] = PublicKeyCredentialHint.SecurityKey,
        ["hybrid"] = PublicKeyCredentialHint.Hybrid
    };

    /// <summary>
    /// Gets or sets the selected authenticator type hint.
    /// </summary>
    [ObservableProperty]
    private PublicKeyCredentialHint _selectedAuthenticatorTypeHint;

    /// <summary>
    /// Gets the list of Mythic CLI commands to display.
    /// </summary>
    public IReadOnlyList<string> MythicCommands { get; }

    public C2CommandsDialogViewModel(PublicKeyCredentialRequestOptions assertionOptions)
    {
        _selectedAuthenticatorTypeHint = ResolveDefaultHint(assertionOptions.Hints);
        MythicCommands = BuildMythicCommands(assertionOptions);
    }

    private static PublicKeyCredentialHint ResolveDefaultHint(string[]? hints)
    {
        if (hints is { Length: > 0 } && s_webAuthnHintMap.TryGetValue(hints[0], out var mapped))
        {
            return mapped;
        }

        return PublicKeyCredentialHint.None;
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
