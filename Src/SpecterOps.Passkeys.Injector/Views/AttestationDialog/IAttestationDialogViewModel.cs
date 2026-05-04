using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the attestation dialog view model.
/// </summary>
public interface IAttestationDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets or sets the relying party identifier.</summary>
    string RpId { get; set; }

    /// <summary>Gets or sets the relying party name.</summary>
    string RpName { get; set; }

    /// <summary>Gets or sets the user identifier.</summary>
    string UserId { get; set; }

    /// <summary>Gets or sets the user name.</summary>
    string UserName { get; set; }

    /// <summary>Gets or sets the user display name.</summary>
    string UserDisplayName { get; set; }

    /// <summary>Gets or sets the challenge value.</summary>
    string Challenge { get; set; }

    /// <summary>Gets or sets the timeout value.</summary>
    string Timeout { get; set; }

    /// <summary>Gets or sets the attestation conveyance preference.</summary>
    string Attestation { get; set; }

    /// <summary>Gets or sets the authenticator attachment.</summary>
    string AuthenticatorAttachment { get; set; }

    /// <summary>Gets or sets the resident key preference.</summary>
    string ResidentKey { get; set; }

    /// <summary>Gets or sets whether a resident key is required.</summary>
    bool? RequireResidentKey { get; set; }

    /// <summary>Gets or sets the user verification requirement.</summary>
    string UserVerification { get; set; }

    /// <summary>Gets the credential parameter collection.</summary>
    ObservableCollection<PublicKeyCredentialParameters> PubKeyCredParams { get; }

    /// <summary>Gets or sets the credential algorithm names.</summary>
    string[]? CredentialAlgorithms { get; set; }

    /// <summary>Gets the excluded credentials collection.</summary>
    ObservableCollection<PublicKeyCredentialDescriptor> ExcludeCredentials { get; }

    /// <summary>Gets or sets the request extensions JSON.</summary>
    string Extensions { get; set; }

    /// <summary>Gets or sets authenticator selection hints.</summary>
    string[]? Hints { get; set; }

    /// <summary>Gets or sets preferred attestation formats.</summary>
    string[]? AttestationFormats { get; set; }

    /// <summary>Gets or sets the credential mediation requirement.</summary>
    string Mediation { get; set; }

    /// <summary>Gets or sets the serialized credential response.</summary>
    string? PublicKeyCredentialJson { get; set; }

    /// <summary>Gets or sets the raw attestation options JSON.</summary>
    string AttestationOptionsJson { get; set; }

    /// <summary>Gets or sets the parsed attestation options.</summary>
    PublicKeyCredentialCreationOptions? AttestationOptions { get; set; }

    /// <summary>Gets or sets when the attestation flow started.</summary>
    DateTime? AttestationStartTime { get; set; }

    /// <summary>Gets or sets when the request expires.</summary>
    DateTime? RequestExpiration { get; set; }

    /// <summary>Gets or sets when the challenge expires.</summary>
    DateTime? ChallengeExpiration { get; set; }

    /// <summary>Gets the command that submits the dialog.</summary>
    IRelayCommand<Action?> SubmitCommand { get; }

}
