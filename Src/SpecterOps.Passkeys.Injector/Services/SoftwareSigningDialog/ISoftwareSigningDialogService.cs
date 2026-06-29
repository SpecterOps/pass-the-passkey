namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the software signing dialog for a WebAuthn assertion request.
/// </summary>
public interface ISoftwareSigningDialogService
{
    /// <summary>
    /// Displays the signing dialog for the provided assertion details.
    /// </summary>
    /// <param name="assertionOptions">The assertion options to sign.</param>
    /// <param name="currentAddress">The current browser address used for collected client data.</param>
    /// <returns>The signed credential JSON, or <see langword="null"/> when the dialog is cancelled.</returns>
    string? SignCredential(
        PublicKeyCredentialRequestOptions assertionOptions,
        string currentAddress);
}
