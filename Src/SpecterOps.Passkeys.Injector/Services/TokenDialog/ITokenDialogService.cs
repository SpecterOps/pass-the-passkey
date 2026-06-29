namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Shows the token dialog.
/// </summary>
public interface ITokenDialogService
{
    /// <summary>
    /// Displays the token dialog.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="tokenResponse">The token response payload.</param>
    void Show(string title, string tokenResponse);
}
