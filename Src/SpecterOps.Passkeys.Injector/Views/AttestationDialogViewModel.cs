using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the AttestationDialog.
/// </summary>
public partial class AttestationDialogViewModel : ObservableValidator
{
    /// <summary>
    /// Event raised when the user submits a valid response.
    /// </summary>
    public event EventHandler? OnSubmit;

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
    private string _userId = string.Empty;

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
    private string _challenge = string.Empty;

    /// <summary>
    /// Gets or sets the timeout value.
    /// </summary>
    [ObservableProperty]
    private string _timeout = string.Empty;

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
    public ObservableCollection<PublicKeyCredentialParameters> PubKeyCredParams { get; } = [];

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
    /// Gets or sets the creation options and populates the view model properties.
    /// </summary>
    [ObservableProperty]
    private PublicKeyCredentialCreationOptions? _attestationOptions;

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
        AttestationOptionsJson = PrettyPrintJson(value);
        AttestationOptions = PublicKeyCredentialCreationOptions.FromJson(value);
    }

    partial void OnAttestationOptionsChanged(PublicKeyCredentialCreationOptions? value)
    {
        if (value == null)
        {
            // Set all bound properties to default values
            Reset();
            return;
        }

        RpId = value.RelyingParty?.Id ?? string.Empty;
        RpName = value.RelyingParty?.Name ?? string.Empty;
        UserId = value.User?.Id ?? string.Empty;
        UserName = value.User?.Name ?? string.Empty;
        UserDisplayName = value.User?.DisplayName ?? string.Empty;
        Challenge = value.Challenge ?? string.Empty;
        Timeout = value.Timeout.HasValue ? value.Timeout.Value.ToString(CultureInfo.InvariantCulture) : string.Empty;
        Attestation = value.Attestation ?? string.Empty;

        AuthenticatorAttachment = value.AuthenticatorSelection?.AuthenticatorAttachment ?? string.Empty;
        ResidentKey = value.AuthenticatorSelection?.ResidentKey ?? string.Empty;
        RequireResidentKey = value.AuthenticatorSelection?.RequireResidentKey;
        UserVerification = value.AuthenticatorSelection?.UserVerification ?? string.Empty;

        PubKeyCredParams.Clear();
        if (value.PubKeyCredParams != null)
        {
            foreach (var param in value.PubKeyCredParams)
            {
                PubKeyCredParams.Add(param);
            }
        }

        CredentialAlgorithms = BuildAlgorithmNames(value.PubKeyCredParams);

        ExcludeCredentials.Clear();
        if (value.ExcludeCredentials != null)
        {
            foreach (var cred in value.ExcludeCredentials)
            {
                ExcludeCredentials.Add(cred);
            }
        }

        Extensions = value.Extensions.HasValue
            ? value.Extensions.Value.GetRawText()
            : string.Empty;

        Hints = value.Hints;
        AttestationFormats = value.AttestationFormats;
    }

    /// <summary>
    /// Resets the view model to its initial state.
    /// </summary>
    public void Reset()
    {
        RpId = string.Empty;
        RpName = string.Empty;
        UserId = string.Empty;
        UserName = string.Empty;
        UserDisplayName = string.Empty;
        Challenge = string.Empty;
        Timeout = string.Empty;
        Attestation = string.Empty;
        AuthenticatorAttachment = string.Empty;
        ResidentKey = string.Empty;
        RequireResidentKey = null;
        UserVerification = string.Empty;
        PubKeyCredParams.Clear();
        CredentialAlgorithms = null;
        ExcludeCredentials.Clear();
        Extensions = string.Empty;
        Hints = null;
        AttestationFormats = null;
        AttestationOptionsJson = string.Empty;
        AttestationOptions = null;
        PublicKeyCredentialJson = null;
        ValidateProperty(PublicKeyCredentialJson, nameof(PublicKeyCredentialJson));
        SubmitCommand.NotifyCanExecuteChanged();
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
    /// Pretty prints a JSON string if valid.
    /// </summary>
    public static string PrettyPrintJson(string value)
    {
        string trimmed = value.Trim();

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
            return trimmed;
        }
    }

    private static string[]? BuildAlgorithmNames(PublicKeyCredentialParameters[]? parameters)
    {
        if (parameters == null || parameters.Length == 0)
        {
            return null;
        }

        List<string> names = [];

        foreach (var param in parameters)
        {
            if (!param.Algorithm.HasValue)
            {
                continue;
            }

            int value = param.Algorithm.Value;
            if (Enum.IsDefined(typeof(Algorithm), value))
            {
                names.Add(((Algorithm)value).ToString());
            }
            else
            {
                names.Add(value.ToString(CultureInfo.InvariantCulture));
            }
        }

        return names.Count > 0 ? [.. names] : null;
    }
}
