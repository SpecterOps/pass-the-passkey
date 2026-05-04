using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SpecterOps.Passkeys.Injector.Cryptography;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the AssertionDialog.
/// </summary>
public partial class AssertionDialogViewModel : ObservableValidator, IAssertionDialogViewModel
{
    private readonly IClipboardService _clipboardService;
    private readonly IC2CommandsDialogService _c2CommandsDialogService;
    private readonly IKeepassXCSigningDialogService _keepassXCSigningDialogService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogViewModel"/> class.
    /// </summary>
    public AssertionDialogViewModel()
        : this(
            new ClipboardService(),
            new KeepassXCSigningDialogService(
                new PasskeyFileDialogService(new OwnerWindowService()),
                new MessageBoxService(new OwnerWindowService()),
                new OwnerWindowService()),
            new C2CommandsDialogService(new OwnerWindowService()))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogViewModel"/> class.
    /// </summary>
    public AssertionDialogViewModel(
        IClipboardService clipboardService,
        IKeepassXCSigningDialogService keepassXCSigningDialogService,
        IC2CommandsDialogService c2CommandsDialogService)
    {
        _clipboardService = clipboardService;
        _keepassXCSigningDialogService = keepassXCSigningDialogService;
        _c2CommandsDialogService = c2CommandsDialogService;
    }

    /// <summary>
    /// Gets or sets the relying party identifier.
    /// </summary>
    [ObservableProperty]
    private string _rpId = string.Empty;

    /// <summary>
    /// Gets or sets the challenge value.
    /// </summary>
    [ObservableProperty]
    private string _challenge = string.Empty;

    /// <summary>
    /// Gets or sets the mediation value.
    /// </summary>
    [ObservableProperty]
    private string _mediation = string.Empty;

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
    /// Gets or sets the timeout value.
    /// </summary>
    [ObservableProperty]
    private string _timeout = string.Empty;

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
    private PublicKeyCredentialRequestOptions? _assertionOptions;

    /// <summary>
    /// Gets or sets the time at which the assertion dialog was populated.
    /// </summary>
    [ObservableProperty]
    private DateTime? _assertionStartTime;

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

    private static readonly JsonSerializerOptions s_jsonSerializerOptions = new()
    {
        WriteIndented = true
    };

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
            var parsedCredential = PublicKeyCredential.FromJson(value);
            return parsedCredential != null ? ValidationResult.Success! : new ValidationResult("Invalid JSON");
        }
        catch (JsonException)
        {
            return new ValidationResult("Invalid JSON");
        }
    }

    partial void OnAssertionOptionsJsonChanged(string value)
    {
        AssertionOptionsJson = NormalizeJson(value);
        AssertionOptions = PublicKeyCredentialRequestOptions.FromJson(value);
    }

    partial void OnAssertionOptionsChanged(PublicKeyCredentialRequestOptions? value)
    {
        if (value == null)
        {
            ClearAssertionOptions();
            return;
        }

        RpId = value.RpId ?? string.Empty;
        Challenge = value.Challenge ?? string.Empty;
        Hints = value.Hints;
        Timeout = value.Timeout.HasValue ? value.Timeout.Value.ToString(CultureInfo.InvariantCulture) : string.Empty;
        UserVerification = value.UserVerification ?? string.Empty;

        // Populate AllowCredentials collection
        AllowCredentials.Clear();
        if (value.AllowCredentials != null)
        {
            foreach (var cred in value.AllowCredentials)
            {
                AllowCredentials.Add(cred);
            }
        }

        // Serialize Extensions to compressed JSON string
        Extensions = value.Extensions.HasValue
            ? value.Extensions.Value.GetRawText()
            : string.Empty;

        // Timer anchors: record when the dialog was populated and compute expiration endpoints.
        AssertionStartTime = DateTime.Now;
        RequestExpiration = value.Timeout.HasValue
            ? AssertionStartTime.Value.AddMilliseconds(value.Timeout.Value)
            : null;
        ChallengeExpiration = ChallengeJwtExpiration.TryGet(Challenge);
    }

    /// <summary>
    /// Pastes and normalizes JSON from the clipboard into the response field.
    /// </summary>
    [RelayCommand]
    private void PasteResponse()
    {
        string? pastedText = _clipboardService.GetText();
        if (!string.IsNullOrEmpty(pastedText))
        {
            PublicKeyCredentialJson = NormalizeJson(pastedText);
        }
    }

    [RelayCommand]
    private void SignWithKeepassXC()
    {
        string? signedCredentialJson = _keepassXCSigningDialogService.SignCredential(
            Challenge,
            RpId,
            string.IsNullOrEmpty(UserVerification) ? null : UserVerification,
            AllowCredentials.Count > 0 ? [.. AllowCredentials] : null);

        if (signedCredentialJson != null)
        {
            PublicKeyCredentialJson = NormalizeJson(signedCredentialJson);
        }
    }

    [RelayCommand(CanExecute = nameof(CanShowC2Commands))]
    private void ShowC2Commands()
    {
        if (AssertionOptions == null)
        {
            return;
        }

        _c2CommandsDialogService.Show(AssertionOptions);
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

    private bool CanShowC2Commands()
    {
        return AssertionOptions != null;
    }

    /// <summary>
    /// Called when PublicKeyCredentialJson changes to validate the JSON.
    /// </summary>
    partial void OnPublicKeyCredentialJsonChanged(string? value)
    {
        ValidateProperty(value, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Normalizes a JSON string by removing whitespace and formatting it.
    /// </summary>
    public static string NormalizeJson(string value)
    {
        // Pasted strings might contain spaces or new lines, making them invalid JSON. Remove those first.
        // When copied from the event log, they might be partially surrounded by <Data Name="Value">{...}</Data>, from which 2 characters tend to be copied by mistake.
        string trimmed = value.Trim().Replace(" ", null).Replace("\r\n", null).TrimStart('"', '>').TrimEnd('<', '/');

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(trimmed);
            return JsonSerializer.Serialize(doc.RootElement, s_jsonSerializerOptions);
        }
        catch (JsonException)
        {
            // Return the original trimmed string if parsing fails (the user might still be editing it)
            return trimmed;
        }
    }

    private void ClearAssertionOptions()
    {
        RpId = string.Empty;
        Challenge = string.Empty;
        AllowCredentials.Clear();
        Extensions = string.Empty;
        Hints = null;
        Timeout = string.Empty;
        UserVerification = string.Empty;
        AssertionStartTime = null;
        RequestExpiration = null;
        ChallengeExpiration = null;
        PublicKeyCredentialJson = null;
        ValidateProperty(PublicKeyCredentialJson, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
    }
}
