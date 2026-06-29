namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the WebAuthn attestation dialog.
/// </summary>
public interface IAttestationDialogService
{
    /// <summary>
    /// Displays the attestation dialog for the provided request.
    /// </summary>
    /// <param name="optionsJson">The credential creation options JSON.</param>
    /// <param name="mediation">The optional mediation preference.</param>
    /// <param name="currentAddress">The current browser address at the time of the request.</param>
    /// <returns>The submitted credential JSON, or <see langword="null"/> when cancelled.</returns>
    string? Show(string optionsJson, string? mediation, string currentAddress);
}
