using System.ComponentModel.DataAnnotations;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the AssertionDialog.
/// </summary>
public partial class AssertionDialogViewModel : ObservableValidator, IAssertionDialogViewModel
{
    private readonly IClipboardService _clipboardService;
    private readonly IC2CommandsDialogService _c2CommandsDialogService;
    private readonly ISoftwareSigningDialogService _softwareSigningDialogService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogViewModel"/> class for design-time support.
    /// </summary>
    public AssertionDialogViewModel()
        : this(
            string.Empty,
            null,
            string.Empty,
            new ClipboardService(),
            new SoftwareSigningDialogService(
                new PasskeyFileDialogService(new OwnerWindowService()),
                new DecryptionPasswordDialogService(new OwnerWindowService()),
                new MessageBoxService(new OwnerWindowService()),
                new OwnerWindowService()),
            new C2CommandsDialogService(new OwnerWindowService()))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogViewModel"/> class.
    /// </summary>
    public AssertionDialogViewModel(
        string assertionOptionsJson,
        string? mediation,
        string currentAddress,
        IClipboardService clipboardService,
        ISoftwareSigningDialogService softwareSigningDialogService,
        IC2CommandsDialogService c2CommandsDialogService)
    {
        _clipboardService = clipboardService;
        _softwareSigningDialogService = softwareSigningDialogService;
        _c2CommandsDialogService = c2CommandsDialogService;
        Mediation = mediation;
        CurrentAddress = currentAddress;
        AssertionOptionsJson = assertionOptionsJson;
    }

    /// <summary>
    /// Gets or sets the relying party identifier.
    /// </summary>
    [ObservableProperty]
    private string? _rpId;

    /// <summary>
    /// Gets or sets the challenge value.
    /// </summary>
    [ObservableProperty]
    private byte[]? _challenge;

    /// <summary>
    /// Gets the mediation value.
    /// </summary>
    public string? Mediation { get; init; }

    /// <summary>
    /// Gets the current browser address.
    /// </summary>
    public string CurrentAddress { get; init; } = string.Empty;

    /// <summary>
    /// Gets the allowed credentials collection for DataGrid binding.
    /// </summary>
    public ObservableCollection<PublicKeyCredentialDescriptor> AllowCredentials { get; } = [];

    /// <summary>
    /// Gets or sets the extensions as a compressed JSON string.
    /// </summary>
    [ObservableProperty]
    private string _extensions = string.Empty;

    /// <summary>
    /// Gets or sets the hints for authenticator selection.
    /// </summary>
    [ObservableProperty]
    private string[]? _hints;

    /// <summary>
    /// Gets or sets the timeout value in milliseconds.
    /// </summary>
    [ObservableProperty]
    private uint? _timeout;

    /// <summary>
    /// Gets or sets the user verification requirement.
    /// </summary>
    [ObservableProperty]
    private string _userVerification = string.Empty;

    /// <summary>
    /// Gets or sets the JSON response text.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitCommand))]
    [NotifyDataErrorInfo]
    [CustomValidation(typeof(AssertionDialogViewModel), nameof(ValidatePublicKeyCredentialJson))]
    private string? _publicKeyCredentialJson;

    /// <summary>
    /// Gets or sets the raw JSON request text.
    /// </summary>
    [ObservableProperty]
    private string _assertionOptionsJson = string.Empty;

    /// <summary>
    /// Gets or sets the request options and populates the view model properties.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ShowC2CommandsCommand))]
    [NotifyCanExecuteChangedFor(nameof(SignWithSoftwareSignerCommand))]
    private PublicKeyCredentialRequestOptions? _assertionOptions;

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
            var parsedCredential = AssertionPublicKeyCredential.FromJson(value);
            return parsedCredential != null ? ValidationResult.Success! : new ValidationResult("Invalid JSON");
        }
        catch (JsonException)
        {
            return new ValidationResult("Invalid JSON");
        }
    }

    partial void OnAssertionOptionsJsonChanged(string value)
    {
        AssertionOptionsJson = JsonNormalizer.NormalizeJson(value, indented: true, removePastedWhitespace: true);
        AssertionOptions = PublicKeyCredentialRequestOptions.FromJson(value);
    }

    partial void OnAssertionOptionsChanged(PublicKeyCredentialRequestOptions? value)
    {
        if (value is null)
        {
            return;
        }

        RpId = value.RpId ?? RpId;
        Challenge = value.Challenge;
        Hints = value.Hints?.ToArray();
        Timeout = value.Timeout;
        UserVerification = value.UserVerification.ToString();

        // Populate AllowCredentials collection
        AllowCredentials.Clear();
        if (value.AllowCredentials != null)
        {
            foreach (var cred in value.AllowCredentials)
            {
                AllowCredentials.Add(cred);
            }
        }

        Extensions = JsonNormalizer.NormalizeJson(
                value.Extensions?.ToString(),
                indented: false,
                removePastedWhitespace: false);

        // If the RP ID is not set in the options, use the current address to resolve it.
        if (RpId is null && !string.IsNullOrWhiteSpace(CurrentAddress))
        {
            RpId = new UriBuilder(CurrentAddress).Host;
        }

        // Timer anchors: record when the dialog was populated and compute expiration endpoints.
        DateTime startTime = DateTime.Now;
        RequestExpiration = value.Timeout.HasValue
            ? startTime.AddMilliseconds(value.Timeout.Value)
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

    [RelayCommand(CanExecute = nameof(CanRunCommands))]
    private void SignWithSoftwareSigner()
    {
        string? signedCredentialJson = _softwareSigningDialogService.SignCredential(
            AssertionOptions!, // Null test is done by the CanExecute method
            CurrentAddress);

        if (signedCredentialJson != null)
        {
            PublicKeyCredentialJson = JsonNormalizer.NormalizeJson(signedCredentialJson, indented: true, removePastedWhitespace: true);
        }
    }

    [RelayCommand(CanExecute = nameof(CanRunCommands))]
    private void ShowC2Commands()
    {
        // Null test is done by the CanExecute method
        _c2CommandsDialogService.Show(AssertionOptions!, CurrentAddress);
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

    private bool CanRunCommands()
    {
        return AssertionOptions is { Challenge.Length: > 0 } &&
            !string.IsNullOrWhiteSpace(CurrentAddress);
    }

    /// <summary>
    /// Called when PublicKeyCredentialJson changes to validate the JSON.
    /// </summary>
    partial void OnPublicKeyCredentialJsonChanged(string? value)
    {
        ValidateProperty(value, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
    }

}
