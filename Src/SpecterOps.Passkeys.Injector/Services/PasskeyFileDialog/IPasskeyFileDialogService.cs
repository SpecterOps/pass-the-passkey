namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows a file picker for selecting exported passkey files.
/// </summary>
public interface IPasskeyFileDialogService
{
    /// <summary>
    /// Opens the passkey file picker dialog.
    /// </summary>
    /// <returns>The selected passkey file path, or <see langword="null"/> when no file is selected.</returns>
    string? BrowseForPasskeyFile();
}
