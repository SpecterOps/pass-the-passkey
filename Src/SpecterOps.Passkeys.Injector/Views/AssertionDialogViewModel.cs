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
    /// <summary>
    /// Event raised when the user submits a valid response.
    /// </summary>
    public event EventHandler? OnSubmit;

    /// <summary>
    /// Callback invoked to retrieve the current clipboard text. Returns null if the clipboard contains no text.
    /// </summary>
    public Func<string?>? GetClipboardText { get; set; }

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
            // Set all bound properties to default values
            Reset();
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
    /// Resets the view model to its initial state.
    /// </summary>
    public void Reset()
    {
        RpId = string.Empty;
        Challenge = string.Empty;
        Mediation = string.Empty;
        AllowCredentials.Clear();
        Extensions = string.Empty;
        Hints = null;
        Timeout = string.Empty;
        UserVerification = string.Empty;
        AssertionOptionsJson = string.Empty;
        AssertionOptions = null;
        AssertionStartTime = null;
        RequestExpiration = null;
        ChallengeExpiration = null;
        PublicKeyCredentialJson = null;
        ValidateProperty(PublicKeyCredentialJson, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Pastes and normalizes JSON from the clipboard into the response field.
    /// </summary>
    [RelayCommand]
    private void PasteResponse()
    {
        string? pastedText = GetClipboardText?.Invoke();
        if (!string.IsNullOrEmpty(pastedText))
        {
            PublicKeyCredentialJson = NormalizeJson(pastedText);
        }
    }

    /// <summary>
    /// Submits the credential response if valid.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSubmit))]
    private void Submit()
    {
        OnSubmit?.Invoke(this, EventArgs.Empty);
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
}
