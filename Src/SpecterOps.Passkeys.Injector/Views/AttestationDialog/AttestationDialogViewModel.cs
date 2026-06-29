using System.ComponentModel.DataAnnotations;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the AttestationDialog.
/// </summary>
public partial class AttestationDialogViewModel : ObservableValidator, IAttestationDialogViewModel
{
    private readonly IClipboardService _clipboardService;

    /// <summary>
    /// Gets or sets the relying party identifier.
    /// </summary>
    [ObservableProperty]
    private string _rpId = string.Empty;

    /// <summary>
    /// Gets or sets the relying party name.
    /// </summary>
    [ObservableProperty]
    private string _rpName = string.Empty;

    /// <summary>
    /// Gets or sets the user id.
    /// </summary>
    [ObservableProperty]
    private byte[] _userId = [];

    /// <summary>
    /// Gets or sets the user name.
    /// </summary>
    [ObservableProperty]
    private string _userName = string.Empty;

    /// <summary>
    /// Gets or sets the user display name.
    /// </summary>
    [ObservableProperty]
    private string _userDisplayName = string.Empty;

    /// <summary>
    /// Gets or sets the challenge value.
    /// </summary>
    [ObservableProperty]
    private byte[] _challenge = [];

    /// <summary>
    /// Gets or sets the timeout value in milliseconds.
    /// </summary>
    [ObservableProperty]
    private uint? _timeout;

    /// <summary>
    /// Gets or sets the attestation conveyance preference.
    /// </summary>
    [ObservableProperty]
    private string _attestation = string.Empty;

    /// <summary>
    /// Gets or sets the authenticator attachment.
    /// </summary>
    [ObservableProperty]
    private string _authenticatorAttachment = string.Empty;

    /// <summary>
    /// Gets or sets the resident key requirement.
    /// </summary>
    [ObservableProperty]
    private string _residentKey = string.Empty;

    /// <summary>
    /// Gets or sets whether a resident key is required.
    /// </summary>
    [ObservableProperty]
    private bool? _requireResidentKey;

    /// <summary>
    /// Gets or sets the user verification requirement.
    /// </summary>
    [ObservableProperty]
    private string _userVerification = string.Empty;

    /// <summary>
    /// Gets the credential parameters collection for DataGrid binding.
    /// </summary>
    public ObservableCollection<PublicKeyCredentialParameter> PubKeyCredParams { get; } = [];

    /// <summary>
    /// Gets or sets the preferred algorithm names for display.
    /// </summary>
    [ObservableProperty]
    private string[]? _credentialAlgorithms;

    /// <summary>
    /// Gets the excluded credentials collection for DataGrid binding.
    /// </summary>
    public ObservableCollection<PublicKeyCredentialDescriptor> ExcludeCredentials { get; } = [];

    /// <summary>
    /// Gets or sets the extensions as a compressed JSON string.
    /// </summary>
    [ObservableProperty]
    private string _extensions = string.Empty;

    /// <summary>
    /// Gets or sets UI hints for authenticator selection.
    /// </summary>
    [ObservableProperty]
    private string[]? _hints;

    /// <summary>
    /// Gets or sets preferred attestation formats.
    /// </summary>
    [ObservableProperty]
    private string[]? _attestationFormats;

    /// <summary>
    /// Gets the credential mediation requirement.
    /// </summary>
    public string? Mediation { get; init; }

    /// <summary>
    /// Gets the current browser address.
    /// </summary>
    public string CurrentAddress { get; init; } = string.Empty;

    /// <summary>
    /// Gets or sets the JSON response text.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitCommand))]
    [NotifyDataErrorInfo]
    [CustomValidation(typeof(AttestationDialogViewModel), nameof(ValidatePublicKeyCredentialJson))]
    private string? _publicKeyCredentialJson;

    /// <summary>
    /// Gets or sets the raw JSON request text.
    /// </summary>
    [ObservableProperty]
    private string _attestationOptionsJson = string.Empty;

    /// <summary>
    /// Gets or sets the absolute time at which the WebAuthn request times out (start time + request timeout).
    /// </summary>
    [ObservableProperty]
    private DateTime? _requestExpiration;

    /// <summary>
    /// Gets or sets the absolute time at which the challenge expires, parsed from its JWT <c>exp</c> claim when available.
    /// </summary>
    [ObservableProperty]
    private DateTime? _challengeExpiration;

    public AttestationDialogViewModel()
        : this(string.Empty, null, string.Empty, new ClipboardService())
    {
    }

    public AttestationDialogViewModel(
        string attestationOptionsJson,
        string? mediation,
        string currentAddress,
        IClipboardService clipboardService)
    {
        _clipboardService = clipboardService;
        Mediation = mediation;
        CurrentAddress = currentAddress;
        AttestationOptionsJson = attestationOptionsJson;
    }

    /// <summary>
    /// Validates the JSON response text.
    /// </summary>
    public static ValidationResult ValidatePublicKeyCredentialJson(string? value, ValidationContext _)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new ValidationResult("Value cannot be empty");
        }

        try
        {
            var parsedCredential = AttestationPublicKeyCredential.FromJson(value);
            return parsedCredential?.Response is AuthenticatorAttestationResponse
                ? ValidationResult.Success!
                : new ValidationResult("Invalid JSON");
        }
        catch (JsonException)
        {
            return new ValidationResult("Invalid JSON");
        }
    }

    partial void OnAttestationOptionsJsonChanged(string value)
    {
        AttestationOptionsJson = JsonNormalizer.NormalizeJson(value, indented: true, removePastedWhitespace: false);

        PublicKeyCredentialCreationOptions? options = PublicKeyCredentialCreationOptions.FromJson(value);
        if (options is null)
        {
            return;
        }

        RpId = options.RelyingParty?.Id ?? string.Empty;
        RpName = options.RelyingParty?.Name ?? string.Empty;
        UserId = options.User.Id;
        UserName = options.User?.Name ?? string.Empty;
        UserDisplayName = options.User?.DisplayName ?? string.Empty;
        Challenge = options.Challenge;
        Timeout = options.TimeoutMilliseconds;
        Attestation = options.Attestation.ToString();

        AuthenticatorAttachment = options.AuthenticatorSelection?.AuthenticatorAttachment.ToString() ?? string.Empty;
        ResidentKey = options.AuthenticatorSelection?.ResidentKey.ToString() ?? string.Empty;
        RequireResidentKey = options.AuthenticatorSelection?.RequireResidentKey;
        UserVerification = options.AuthenticatorSelection?.UserVerificationRequirement.ToString() ?? string.Empty;

        PubKeyCredParams.Clear();
        if (options.PublicKeyCredentialParameters != null)
        {
            foreach (var param in options.PublicKeyCredentialParameters)
            {
                PubKeyCredParams.Add(param);
            }
        }

        CredentialAlgorithms = BuildAlgorithmNames(options.PublicKeyCredentialParameters);

        ExcludeCredentials.Clear();
        if (options.ExcludeCredentials != null)
        {
            foreach (var cred in options.ExcludeCredentials)
            {
                ExcludeCredentials.Add(cred);
            }
        }

        Extensions = JsonNormalizer.NormalizeJson(
                options.Extensions?.ToString(),
                indented: false,
                removePastedWhitespace: false);

        Hints = options.Hints?.ToArray();
        AttestationFormats = options.AttestationFormats?.ToArray();

        // Timer anchors: record when the dialog was populated and compute expiration endpoints.
        DateTime startTime = DateTime.Now;
        RequestExpiration = options.TimeoutMilliseconds.HasValue
            ? startTime.AddMilliseconds(options.TimeoutMilliseconds.Value)
            : null;
        ChallengeExpiration = ChallengeJwtExpiration.TryGet(Challenge);
    }

    /// <summary>
    /// Pastes and normalizes JSON from the clipboard into the response field.
    /// </summary>
    [RelayCommand]
    private void PasteResponse()
    {
        PublicKeyCredentialJson = JsonNormalizer.NormalizeJson(
            _clipboardService.GetText(),
            indented: true,
            removePastedWhitespace: true);
    }

    /// <summary>
    /// Submits the credential response if valid.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSubmit))]
    private void Submit(Action? onSubmit)
    {
        onSubmit?.Invoke();
    }

    private bool CanSubmit()
    {
        return !string.IsNullOrWhiteSpace(PublicKeyCredentialJson) && !HasErrors;
    }

    /// <summary>
    /// Called when PublicKeyCredentialJson changes to validate the JSON.
    /// </summary>
    partial void OnPublicKeyCredentialJsonChanged(string? value)
    {
        ValidateProperty(value, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
    }

    private static string[]? BuildAlgorithmNames(IReadOnlyList<PublicKeyCredentialParameter>? parameters)
    {
        if (parameters == null || parameters.Count == 0)
        {
            return null;
        }

        return [.. parameters.Select(param => param.Algorithm.ToString())];
    }
}
