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
    /// <returns>The submitted credential JSON, or <see langword="null"/> when cancelled.</returns>
    string? Show(string optionsJson);
}
