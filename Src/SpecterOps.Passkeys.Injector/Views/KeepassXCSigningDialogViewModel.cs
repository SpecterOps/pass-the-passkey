using System.Buffers.Text;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SpecterOps.Passkeys.Injector.Cryptography;

namespace SpecterOps.Passkeys.Injector;

public partial class KeepassXCSigningDialogViewModel : ObservableValidator
{
    private readonly string _challenge;
    private readonly string _rpId;
    private readonly PublicKeyCredentialDescriptor[]? _allowCredentials;

    private KeePassXCPasskey? _loadedPasskey;
    private Algorithm _detectedAlgorithm;
    private byte[]? _credentialIdBytes;
    private byte[]? _userHandleBytes;

    public event EventHandler<string>? OnSigned;

    /// <summary>
    /// Callback invoked to browse for a passkey file. Returns the selected path, or null if cancelled.
    /// </summary>
    public Func<string?>? BrowseForPasskeyFile { get; set; }

    /// <summary>
    /// Callback invoked to display an error message. Parameters are (message, title).
    /// </summary>
    public Action<string, string>? ShowError { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    [NotifyDataErrorInfo]
    [Required(ErrorMessage = "Passkey file is required.")]
    private string _passkeyFilePath = string.Empty;

    [ObservableProperty] private string? _signatureAlgorithm;
    [ObservableProperty] private string? _keyType;
    [ObservableProperty] private int? _keyLength;
    [ObservableProperty] private string? _hashFunction;

    [ObservableProperty] private int _counter = 0;
    [ObservableProperty] private bool _userVerified = true;
    [ObservableProperty] private bool _userPresent = true;

    [ObservableProperty] private string _credentialId = string.Empty;
    [ObservableProperty] private string _userName = string.Empty;
    [ObservableProperty] private string _userHandle = string.Empty;

    public KeepassXCSigningDialogViewModel(
        string challenge,
        string rpId,
        string? userVerification = null,
        PublicKeyCredentialDescriptor[]? allowCredentials = null)
    {
        _challenge = challenge;
        _rpId = rpId;
        _allowCredentials = allowCredentials;
        _userVerified = userVerification is not "discouraged";
    }

    [RelayCommand]
    private void BrowsePasskeyFile()
    {
        string? path = BrowseForPasskeyFile?.Invoke();
        if (path != null)
            LoadPasskeyFile(path);
    }

    [RelayCommand]
    private void IncrementCounter() => Counter++;

    [RelayCommand]
    private void DecrementCounter()
    {
        if (Counter > 0) Counter--;
    }

    [RelayCommand(CanExecute = nameof(CanSign))]
    private void Sign()
    {
        if (_loadedPasskey == null) return;

        try
        {
            using AsymmetricAlgorithm privateKey = _loadedPasskey.LoadPrivateKey();

            var flags = AuthenticatorFlags.UP;
            if (UserVerified) flags |= AuthenticatorFlags.UV;

            byte[] challengeBytes = Base64Url.DecodeFromChars(_challenge.AsSpan());

            PublicKeyCredential credential = SoftwareAuthenticator.GetAssertion(
                _rpId,
                challengeBytes,
                _detectedAlgorithm,
                (uint)Counter,
                flags,
                _credentialIdBytes!,
                _userHandleBytes,
                privateKey);

            OnSigned?.Invoke(this, credential.ToString());
        }
        catch (Exception ex)
        {
            ShowError?.Invoke($"Signing failed: {ex.Message}", "Error");
        }
    }

    private bool CanSign() => _loadedPasskey != null;

    private void LoadPasskeyFile(string path)
    {
        ClearPasskeyFields();

        try
        {
            KeePassXCPasskey passkey = KeePassXCPasskey.LoadFromFile(path);

            if (!string.Equals(passkey.RelyingParty, _rpId, StringComparison.OrdinalIgnoreCase))
            {
                ShowError?.Invoke(
                    $"This passkey is for '{passkey.RelyingParty}', not '{_rpId}'.",
                    "Invalid Passkey");
                return;
            }

            if (_allowCredentials?.Length > 0)
            {
                string? encodedId = passkey.CredentialId != null
                    ? Base64Url.EncodeToString(passkey.CredentialId)
                    : null;
                bool found = _allowCredentials.Any(c =>
                    string.Equals(c.Id, encodedId, StringComparison.Ordinal));
                if (!found)
                {
                    ShowError?.Invoke(
                        "The passkey's credential ID is not in the allowed credentials list.",
                        "Invalid Passkey");
                    return;
                }
            }

            using AsymmetricAlgorithm key = passkey.LoadPrivateKey();
            _detectedAlgorithm = SoftwareAuthenticator.DetectAlgorithm(key);

            _credentialIdBytes = passkey.CredentialId;
            _userHandleBytes = passkey.UserHandle;

            PasskeyFilePath = path;
            CredentialId = passkey.CredentialId != null ? Base64Url.EncodeToString(passkey.CredentialId) : string.Empty;
            UserName = passkey.Username ?? string.Empty;
            UserHandle = passkey.UserHandle != null ? Base64Url.EncodeToString(passkey.UserHandle) : string.Empty;
            PopulateAlgorithmFields(_detectedAlgorithm);

            _loadedPasskey = passkey;
            SignCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            ShowError?.Invoke($"Failed to load passkey file: {ex.Message}", "Error");
        }
    }

    private void ClearPasskeyFields()
    {
        _loadedPasskey = null;
        _credentialIdBytes = null;
        _userHandleBytes = null;
        CredentialId = string.Empty;
        UserName = string.Empty;
        UserHandle = string.Empty;
        SignatureAlgorithm = string.Empty;
        KeyType = string.Empty;
        KeyLength = null;
        HashFunction = string.Empty;
        SignCommand.NotifyCanExecuteChanged();
    }

    private void PopulateAlgorithmFields(Algorithm algorithm)
    {
        SignatureAlgorithm = SoftwareAuthenticator.GetAlgorithmName(algorithm);
        KeyType = SoftwareAuthenticator.GetKeyType(algorithm);
        KeyLength = SoftwareAuthenticator.GetKeyLength(algorithm);
        HashFunction = SoftwareAuthenticator.GetHashAlgorithm(algorithm).Name;
    }
}
