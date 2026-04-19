using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the assertion dialog view model.
/// </summary>
public interface IAssertionDialogViewModel : INotifyPropertyChanged
{
    /// <summary>
    /// Occurs when the user submits a valid assertion response.
    /// </summary>
    event EventHandler? OnSubmit;

    /// <summary>
    /// Gets or sets the callback used to read text from the clipboard.
    /// </summary>
    Func<string?>? GetClipboardText { get; set; }

    /// <summary>Gets or sets the relying party identifier.</summary>
    string RpId { get; set; }

    /// <summary>Gets or sets the challenge value.</summary>
    string Challenge { get; set; }

    /// <summary>Gets or sets the mediation preference.</summary>
    string Mediation { get; set; }

    /// <summary>Gets the allowed credentials collection.</summary>
    ObservableCollection<PublicKeyCredentialDescriptor> AllowCredentials { get; }

    /// <summary>Gets or sets the request extensions JSON.</summary>
    string Extensions { get; set; }

    /// <summary>Gets or sets authenticator selection hints.</summary>
    string[]? Hints { get; set; }

    /// <summary>Gets or sets the timeout value.</summary>
    string Timeout { get; set; }

    /// <summary>Gets or sets the user verification requirement.</summary>
    string UserVerification { get; set; }

    /// <summary>Gets or sets the serialized credential response.</summary>
    string? PublicKeyCredentialJson { get; set; }

    /// <summary>Gets or sets the raw assertion options JSON.</summary>
    string AssertionOptionsJson { get; set; }

    /// <summary>Gets or sets the parsed assertion options.</summary>
    PublicKeyCredentialRequestOptions? AssertionOptions { get; set; }

    /// <summary>Gets or sets when the assertion flow started.</summary>
    DateTime? AssertionStartTime { get; set; }

    /// <summary>Gets or sets when the request expires.</summary>
    DateTime? RequestExpiration { get; set; }

    /// <summary>Gets or sets when the challenge expires.</summary>
    DateTime? ChallengeExpiration { get; set; }

    /// <summary>Gets the command that pastes a response from the clipboard.</summary>
    IRelayCommand PasteResponseCommand { get; }

    /// <summary>Gets the command that submits the dialog.</summary>
    IRelayCommand SubmitCommand { get; }

    /// <summary>
    /// Resets the view model to its initial state.
    /// </summary>
    void Reset();
}
