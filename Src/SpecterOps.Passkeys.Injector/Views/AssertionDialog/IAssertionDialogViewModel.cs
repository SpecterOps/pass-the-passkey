
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the assertion dialog view model.
/// </summary>
public interface IAssertionDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets the relying party identifier.</summary>
    string RpId { get; }

    /// <summary>Gets the challenge value.</summary>
    byte[]? Challenge { get; }

    /// <summary>Gets the mediation preference.</summary>
    string? Mediation { get; }

    /// <summary>Gets the current browser address.</summary>
    string CurrentAddress { get; }

    /// <summary>Gets the allowed credentials collection.</summary>
    ObservableCollection<PublicKeyCredentialDescriptor> AllowCredentials { get; }

    /// <summary>Gets the request extensions JSON.</summary>
    string Extensions { get; }

    /// <summary>Gets authenticator selection hints.</summary>
    string[]? Hints { get; }

    /// <summary>Gets the timeout value in milliseconds.</summary>
    uint? Timeout { get; }

    /// <summary>Gets the user verification requirement.</summary>
    string UserVerification { get; }

    /// <summary>Gets or sets the serialized credential response.</summary>
    string? PublicKeyCredentialJson { get; set; }

    /// <summary>Gets the raw assertion options JSON.</summary>
    string AssertionOptionsJson { get; }

    /// <summary>Gets the parsed assertion options.</summary>
    PublicKeyCredentialRequestOptions? AssertionOptions { get; }

    /// <summary>Gets when the request expires.</summary>
    DateTime? RequestExpiration { get; }

    /// <summary>Gets when the challenge expires.</summary>
    DateTime? ChallengeExpiration { get; }

    /// <summary>Gets the command that pastes a response from the clipboard.</summary>
    IRelayCommand PasteResponseCommand { get; }

    /// <summary>Gets the command that opens the software signing dialog.</summary>
    IRelayCommand SignWithSoftwareSignerCommand { get; }

    /// <summary>Gets the command that opens the C2 commands dialog.</summary>
    IRelayCommand ShowC2CommandsCommand { get; }

    /// <summary>Gets the command that submits the dialog.</summary>
    IRelayCommand<Action?> SubmitCommand { get; }
}
