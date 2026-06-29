using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography;

namespace SpecterOps.Passkeys.Injector;

public partial class SoftwareSigningDialogViewModel : ObservableValidator, ISoftwareSigningDialogViewModel
{
    private readonly PublicKeyCredentialRequestOptions _assertionOptions;
    private readonly string _rpId;
    private readonly string _hostName;
    private readonly IPasskeyFileDialogService _passkeyFileDialogService;
    private readonly IDecryptionPasswordDialogService _decryptionPasswordDialogService;
    private readonly IMessageBoxService _messageBoxService;

    private AuthenticatorAttachment _authenticatorAttachment = AuthenticatorAttachment.Platform;

    public string? SignedCredentialJson { get; private set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    [NotifyDataErrorInfo]
    [Required(ErrorMessage = "Passkey file is required.")]
    private string _passkeyFilePath = string.Empty;

    public ObservableCollection<ExportedPasskey> AvailablePasskeys { get; } = [];

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    private ExportedPasskey? _selectedPasskey;

    [ObservableProperty] private string? _signatureAlgorithm;
    [ObservableProperty] private string? _keyType;
    [ObservableProperty] private int? _keyLength;
    [ObservableProperty] private string? _hashFunction;

    [ObservableProperty] private uint _counter = 0;
    [ObservableProperty] private bool _userVerified = true;
    [ObservableProperty] private bool _userPresent = true;

    [ObservableProperty] private byte[]? _credentialId;
    [ObservableProperty] private string _userName = string.Empty;
    [ObservableProperty] private byte[]? _userHandle;

    public SoftwareSigningDialogViewModel(
        PublicKeyCredentialRequestOptions assertionOptions,
        string currentAddress,
        IPasskeyFileDialogService passkeyFileDialogService,
        IDecryptionPasswordDialogService decryptionPasswordDialogService,
        IMessageBoxService messageBoxService)
    {
        ArgumentNullException.ThrowIfNull(assertionOptions);
        ArgumentNullException.ThrowIfNull(currentAddress);

        _hostName = new UriBuilder(currentAddress).Host;
        _rpId = assertionOptions.RpId ?? _hostName;
        _assertionOptions = assertionOptions;
        _userVerified = assertionOptions.UserVerification is UserVerificationRequirement.Required or UserVerificationRequirement.Preferred;
        _passkeyFileDialogService = passkeyFileDialogService;
        _decryptionPasswordDialogService = decryptionPasswordDialogService;
        _messageBoxService = messageBoxService;
    }

    [RelayCommand]
    private void BrowsePasskeyFile()
    {
        string? path = _passkeyFileDialogService.BrowseForPasskeyFile();
        if (path != null)
            LoadPasskeyFile(path);
    }

    [RelayCommand]
    private void IncrementCounter()
    {
        if (Counter < uint.MaxValue) Counter++;
    }

    [RelayCommand]
    private void DecrementCounter()
    {
        if (Counter > 0u) Counter--;
    }

    [RelayCommand(CanExecute = nameof(CanSign))]
    private void Sign(Action? onSubmit)
    {
        if (SelectedPasskey == null) return;

        try
        {
            var flags = AuthenticatorFlags.BackupEligible | AuthenticatorFlags.BackedUp;
            if (UserPresent) flags |= AuthenticatorFlags.UserPresent;
            if (UserVerified) flags |= AuthenticatorFlags.UserVerified;

            AssertionPublicKeyCredential credential = SoftwareAuthenticator.GetAssertion(
                _hostName,
                _assertionOptions.RpId,
                _assertionOptions.Challenge,
                SelectedPasskey.KeyAlgorithm,
                Counter,
                flags,
                SelectedPasskey.CredentialId,
                SelectedPasskey.UserHandle,
                SelectedPasskey.PrivateKey,
                _authenticatorAttachment);

            SignedCredentialJson = credential.ToString();
            onSubmit?.Invoke();
        }
        catch (Exception ex)
        {
            _messageBoxService.ShowError($"Signing failed: {ex.Message}", "Error");
        }
    }

    private bool CanSign() => SelectedPasskey != null;

    partial void OnSelectedPasskeyChanged(ExportedPasskey? value)
    {
        if (value == null)
        {
            ClearCredentialFields();
            return;
        }

        CredentialId = value.CredentialId;
        UserName = value.Username ?? string.Empty;
        UserHandle = value.UserHandle;
        Counter = value.SignatureCounter;
        PopulateAlgorithmFields(value.KeyAlgorithm);

        // Determine authenticator attachment from matched allow-credential descriptor
        PublicKeyCredentialDescriptor? matchedDescriptor = _assertionOptions.AllowCredentials?.FirstOrDefault(c =>
            c.Id.SequenceEqual(value.CredentialId));

        _authenticatorAttachment = matchedDescriptor?.Transports is { } transports
            && transports != AuthenticatorTransport.NoRestrictions
            && !transports.HasFlag(AuthenticatorTransport.Internal)
            ? AuthenticatorAttachment.CrossPlatform
            : AuthenticatorAttachment.Platform;

        SignCommand.NotifyCanExecuteChanged();
    }

    private void LoadPasskeyFile(string path)
    {
        ClearAllFields();

        try
        {
            IReadOnlyList<ExportedPasskey> passkeys = LoadPasskeysFromFile(path);

            if (passkeys.Count == 0)
            {
                _messageBoxService.ShowError("No passkeys found in the selected file.", "No Passkeys");
                return;
            }

            PasskeyFilePath = path;

            // Filter to passkeys matching the relying party
            var matchingPasskeys = passkeys
                .Where(p => string.Equals(p.RelyingParty, _rpId, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchingPasskeys.Count == 0)
            {
                _messageBoxService.ShowError(
                    $"No passkeys for '{_rpId}' found in the selected file.",
                    "No Matching Passkeys");
                return;
            }

            // If allowCredentials is provided, filter to matching credential IDs
            if (_assertionOptions.AllowCredentials?.Count > 0)
            {
                matchingPasskeys = [.. matchingPasskeys.Where(p => _assertionOptions.AllowCredentials.Any(c => c.Id.SequenceEqual(p.CredentialId)))];

                if (matchingPasskeys.Count == 0)
                {
                    _messageBoxService.ShowError(
                        "None of the passkeys match the allowed credentials list.",
                        "No Matching Passkeys");
                    return;
                }
            }

            foreach (var passkey in matchingPasskeys)
            {
                AvailablePasskeys.Add(passkey);
            }

            SelectedPasskey = AvailablePasskeys.FirstOrDefault();
        }
        catch (OperationCanceledException)
        {
            // User cancelled file selection or decryption, no need to show an error
        }
        catch (Exception ex)
        {
            _messageBoxService.ShowError($"Failed to load passkey file: {ex.Message}", "Error");
        }
    }

    private IReadOnlyList<ExportedPasskey> LoadPasskeysFromFile(string path)
    {
        string extension = Path.GetExtension(path);

        if (string.Equals(extension, ".passkey", StringComparison.OrdinalIgnoreCase))
        {
            return KeePassXCPasskey.LoadFromFile(path).GetPasskeys();
        }

        if (string.Equals(extension, ".cxf", StringComparison.OrdinalIgnoreCase))
        {
            return CredentialExchangeFile.LoadFromFile(path).GetPasskeys();
        }

        if (string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
        {
            string json = File.ReadAllText(path);

            // Both Bitwarden and CXF use .json; pick the parser by sniffing a CXF-specific root property.
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("exporterRpId", out _))
            {
                return CredentialExchangeFile.LoadFromJson(json).GetPasskeys();
            }

            return LoadPasskeysFromBitwardenExport(json);
        }

        throw new NotSupportedException($"Unsupported passkey file format: {extension}");
    }

    private IReadOnlyList<ExportedPasskey> LoadPasskeysFromBitwardenExport(string json)
    {
        var header = JsonSerializer.Deserialize(json, WebAuthnJsonContext.Default.BitwardenVaultExportHeader);
        if (header is null)
        {
            throw new JsonException("Failed to parse Bitwarden export header.");
        }

        if (header.Encrypted)
        {
            if (!header.PasswordProtected)
            {
                throw new JsonException("Only password-protected Bitwarden encrypted exports are supported.");
            }

            var encrypted = BitwardenEncryptedVaultExport.LoadFromJson(json);

            string? password = null;
            string? errorMessage = null;

            while (true)
            {
                password = _decryptionPasswordDialogService.PromptForPassword(
                    "Decrypt Bitwarden Export",
                    password,
                    errorMessage);

                if (password is null)
                {
                    throw new OperationCanceledException("Decryption cancelled by user.");
                }

                try
                {
                    BitwardenCleartextVaultExport decrypted = encrypted.Decrypt(password);
                    return decrypted.GetPasskeys();
                }
                catch (CryptographicException ex)
                {
                    errorMessage = ex.Message;
                }
            }
        }
        else
        {
            // Must be an unencrypted export
            return BitwardenCleartextVaultExport.LoadFromJson(json).GetPasskeys();
        }
    }

    private void ClearAllFields()
    {
        SelectedPasskey = null;
        AvailablePasskeys.Clear();
        PasskeyFilePath = string.Empty;
        ClearCredentialFields();
    }

    private void ClearCredentialFields()
    {
        _authenticatorAttachment = AuthenticatorAttachment.Platform;
        CredentialId = null;
        UserName = string.Empty;
        UserHandle = null;
        Counter = 0;
        SignatureAlgorithm = string.Empty;
        KeyType = string.Empty;
        KeyLength = null;
        HashFunction = string.Empty;
        SignCommand.NotifyCanExecuteChanged();
    }

    private void PopulateAlgorithmFields(Algorithm algorithm)
    {
        SignatureAlgorithm = algorithm.AlgorithmName;
        KeyType = algorithm.KeyTypeName;
        KeyLength = algorithm.KeyLength;
        HashFunction = algorithm.HashAlgorithm?.Name;
    }
}
