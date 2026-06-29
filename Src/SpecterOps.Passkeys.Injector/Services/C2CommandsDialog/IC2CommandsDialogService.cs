namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the C2 commands dialog for a WebAuthn assertion request.
/// </summary>
public interface IC2CommandsDialogService
{
    /// <summary>
    /// Displays the dialog for the provided assertion options.
    /// </summary>
    /// <param name="currentAddress">The current browser address at the time of the request, or an empty string when unavailable.</param>
    void Show(PublicKeyCredentialRequestOptions assertionOptions, string currentAddress);
}
