
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the software signing dialog view model.
/// </summary>
public interface ISoftwareSigningDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets the serialized credential JSON produced by signing.</summary>
    string? SignedCredentialJson { get; }

    /// <summary>Gets the selected passkey file path.</summary>
    string PasskeyFilePath { get; }

    /// <summary>Gets the collection of passkeys loaded from the file.</summary>
    ObservableCollection<ExportedPasskey> AvailablePasskeys { get; }

    /// <summary>Gets or sets the currently selected passkey.</summary>
    ExportedPasskey? SelectedPasskey { get; set; }

    /// <summary>Gets the signature algorithm name.</summary>
    string? SignatureAlgorithm { get; }

    /// <summary>Gets the key type.</summary>
    string? KeyType { get; }

    /// <summary>Gets the key length.</summary>
    int? KeyLength { get; }

    /// <summary>Gets the hash function name.</summary>
    string? HashFunction { get; }

    /// <summary>Gets or sets the signature counter.</summary>
    uint Counter { get; set; }

    /// <summary>Gets or sets whether user verification is asserted.</summary>
    bool UserVerified { get; set; }

    /// <summary>Gets or sets whether user presence is asserted.</summary>
    bool UserPresent { get; set; }

    /// <summary>Gets the credential identifier.</summary>
    byte[]? CredentialId { get; }

    /// <summary>Gets the user name.</summary>
    string UserName { get; }

    /// <summary>Gets the user handle.</summary>
    byte[]? UserHandle { get; }

    /// <summary>Gets the command that opens passkey file browsing.</summary>
    IRelayCommand BrowsePasskeyFileCommand { get; }

    /// <summary>Gets the command that increments the signature counter.</summary>
    IRelayCommand IncrementCounterCommand { get; }

    /// <summary>Gets the command that decrements the signature counter.</summary>
    IRelayCommand DecrementCounterCommand { get; }

    /// <summary>Gets the command that signs the assertion.</summary>
    IRelayCommand<Action?> SignCommand { get; }
}
