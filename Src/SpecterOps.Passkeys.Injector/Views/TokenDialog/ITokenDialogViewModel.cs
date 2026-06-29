
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the token dialog view model.
/// </summary>
public interface ITokenDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets the dialog title.</summary>
    string Title { get; }

    /// <summary>Gets the access token.</summary>
    string? AccessToken { get; }

    /// <summary>Gets the ID token.</summary>
    string? IdToken { get; }

    /// <summary>Gets the refresh token.</summary>
    string? RefreshToken { get; }

    /// <summary>Gets a value indicating whether an access token is available.</summary>
    bool IsAccessTokenPresent { get; }

    /// <summary>Gets a value indicating whether an ID token is available.</summary>
    bool IsIdTokenPresent { get; }

    /// <summary>Gets a value indicating whether a refresh token is available.</summary>
    bool IsRefreshTokenPresent { get; }

    /// <summary>Gets the command that copies the access token to the clipboard.</summary>
    IRelayCommand CopyAccessTokenCommand { get; }

    /// <summary>Gets the command that copies the refresh token to the clipboard.</summary>
    IRelayCommand CopyRefreshTokenCommand { get; }

    /// <summary>Gets the command that copies the ID token to the clipboard.</summary>
    IRelayCommand CopyIdTokenCommand { get; }

    /// <summary>Gets the raw token response.</summary>
    string TokenResponse { get; }
}
