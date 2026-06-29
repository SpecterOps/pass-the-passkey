
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the attestation dialog view model.
/// </summary>
public interface IAttestationDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets the relying party identifier.</summary>
    string RpId { get; }

    /// <summary>Gets the relying party name.</summary>
    string RpName { get; }

    /// <summary>Gets the user identifier.</summary>
    byte[] UserId { get; }

    /// <summary>Gets the user name.</summary>
    string UserName { get; }

    /// <summary>Gets the user display name.</summary>
    string UserDisplayName { get; }

    /// <summary>Gets the challenge value.</summary>
    byte[] Challenge { get; }

    /// <summary>Gets the timeout value in milliseconds.</summary>
    uint? Timeout { get; }

    /// <summary>Gets the attestation conveyance preference.</summary>
    string Attestation { get; }

    /// <summary>Gets the authenticator attachment.</summary>
    string AuthenticatorAttachment { get; }

    /// <summary>Gets the resident key preference.</summary>
    string ResidentKey { get; }

    /// <summary>Gets whether a resident key is required.</summary>
    bool? RequireResidentKey { get; }

    /// <summary>Gets the user verification requirement.</summary>
    string UserVerification { get; }

    /// <summary>Gets the credential parameter collection.</summary>
    ObservableCollection<PublicKeyCredentialParameter> PubKeyCredParams { get; }

    /// <summary>Gets the credential algorithm names.</summary>
    string[]? CredentialAlgorithms { get; }

    /// <summary>Gets the excluded credentials collection.</summary>
    ObservableCollection<PublicKeyCredentialDescriptor> ExcludeCredentials { get; }

    /// <summary>Gets the request extensions JSON.</summary>
    string Extensions { get; }

    /// <summary>Gets authenticator selection hints.</summary>
    string[]? Hints { get; }

    /// <summary>Gets preferred attestation formats.</summary>
    string[]? AttestationFormats { get; }

    /// <summary>Gets the credential mediation requirement.</summary>
    string? Mediation { get; }

    /// <summary>Gets the current browser address.</summary>
    string CurrentAddress { get; }

    /// <summary>Gets or sets the serialized credential response.</summary>
    string? PublicKeyCredentialJson { get; set; }

    /// <summary>Gets the raw attestation options JSON.</summary>
    string AttestationOptionsJson { get; }

    /// <summary>Gets when the request expires.</summary>
    DateTime? RequestExpiration { get; }

    /// <summary>Gets when the challenge expires.</summary>
    DateTime? ChallengeExpiration { get; }

    /// <summary>Gets the command that submits the dialog.</summary>
    IRelayCommand<Action?> SubmitCommand { get; }

}
