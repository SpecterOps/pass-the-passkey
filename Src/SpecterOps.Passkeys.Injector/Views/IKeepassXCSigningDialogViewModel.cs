using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the KeepassXC signing dialog view model.
/// </summary>
public interface IKeepassXCSigningDialogViewModel : INotifyPropertyChanged
{
    /// <summary>
    /// Occurs when a signed credential has been produced.
    /// </summary>
    event EventHandler<string>? OnSigned;

    /// <summary>Gets or sets the callback used to browse for a passkey file.</summary>
    Func<string?>? BrowseForPasskeyFile { get; set; }

    /// <summary>Gets or sets the callback used to display an error.</summary>
    Action<string, string>? ShowError { get; set; }

    /// <summary>Gets or sets the selected passkey file path.</summary>
    string PasskeyFilePath { get; set; }

    /// <summary>Gets or sets the signature algorithm name.</summary>
    string? SignatureAlgorithm { get; set; }

    /// <summary>Gets or sets the key type.</summary>
    string? KeyType { get; set; }

    /// <summary>Gets or sets the key length.</summary>
    int? KeyLength { get; set; }

    /// <summary>Gets or sets the hash function name.</summary>
    string? HashFunction { get; set; }

    /// <summary>Gets or sets the signature counter.</summary>
    uint Counter { get; set; }

    /// <summary>Gets or sets whether user verification is asserted.</summary>
    bool UserVerified { get; set; }

    /// <summary>Gets or sets whether user presence is asserted.</summary>
    bool UserPresent { get; set; }

    /// <summary>Gets or sets the credential identifier.</summary>
    string CredentialId { get; set; }

    /// <summary>Gets or sets the user name.</summary>
    string UserName { get; set; }

    /// <summary>Gets or sets the user handle.</summary>
    string UserHandle { get; set; }

    /// <summary>Gets the command that opens passkey file browsing.</summary>
    IRelayCommand BrowsePasskeyFileCommand { get; }

    /// <summary>Gets the command that increments the signature counter.</summary>
    IRelayCommand IncrementCounterCommand { get; }

    /// <summary>Gets the command that decrements the signature counter.</summary>
    IRelayCommand DecrementCounterCommand { get; }

    /// <summary>Gets the command that signs the assertion.</summary>
    IRelayCommand SignCommand { get; }
}
