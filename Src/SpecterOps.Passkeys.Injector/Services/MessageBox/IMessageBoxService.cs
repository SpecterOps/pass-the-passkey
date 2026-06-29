namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows application message boxes.
/// </summary>
public interface IMessageBoxService
{
    /// <summary>
    /// Displays an error message dialog.
    /// </summary>
    /// <param name="message">The error message to display.</param>
    /// <param name="title">The dialog title.</param>
    void ShowError(string message, string title);
}
