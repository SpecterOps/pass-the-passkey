namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the KeepassXC signing dialog for a WebAuthn assertion request.
/// </summary>
public interface IKeepassXCSigningDialogService
{
    /// <summary>
    /// Displays the signing dialog for the provided assertion details.
    /// </summary>
    /// <param name="challenge">The assertion challenge to sign.</param>
    /// <param name="rpId">The relying party identifier for the assertion.</param>
    /// <param name="userVerification">The optional user verification preference.</param>
    /// <param name="allowCredentials">The optional list of allowed credentials.</param>
    /// <returns>The signed credential JSON, or <see langword="null"/> when the dialog is cancelled.</returns>
    string? SignCredential(
        string challenge,
        string rpId,
        string? userVerification = null,
        PublicKeyCredentialDescriptor[]? allowCredentials = null);
}
