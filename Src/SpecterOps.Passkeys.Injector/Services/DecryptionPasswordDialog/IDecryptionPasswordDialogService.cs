namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows a password dialog for decrypting encrypted vault exports.
/// </summary>
public interface IDecryptionPasswordDialogService
{
    /// <summary>
    /// Prompts the user for a decryption password.
    /// </summary>
    /// <param name="title">The dialog title describing the vault format.</param>
    /// <param name="initialPassword">An optional password to pre-fill, e.g., after a failed decryption attempt.</param>
    /// <param name="errorMessage">An optional error message to display, e.g., from a previous decryption failure.</param>
    /// <returns>The entered password, or <see langword="null"/> when the dialog is cancelled.</returns>
    string? PromptForPassword(string title, string? initialPassword = null, string? errorMessage = null);
}
