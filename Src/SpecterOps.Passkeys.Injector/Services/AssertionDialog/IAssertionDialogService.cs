namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the WebAuthn assertion dialog.
/// </summary>
public interface IAssertionDialogService
{
    /// <summary>
    /// Displays the assertion dialog for the provided request.
    /// </summary>
    /// <param name="optionsJson">The credential request options JSON.</param>
    /// <param name="mediation">The mediation preference.</param>
    /// <param name="currentAddress">The current browser address at the time of the request.</param>
    /// <returns>The submitted credential JSON, or <see langword="null"/> when cancelled.</returns>
    string? Show(string optionsJson, string? mediation, string currentAddress);
}
