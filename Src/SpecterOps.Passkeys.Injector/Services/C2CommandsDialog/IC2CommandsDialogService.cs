namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the C2 commands dialog for a WebAuthn assertion request.
/// </summary>
public interface IC2CommandsDialogService
{
    /// <summary>
    /// Displays the dialog for the provided assertion options.
    /// </summary>
    void Show(PublicKeyCredentialRequestOptions assertionOptions);
}
