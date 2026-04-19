using System.ComponentModel;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the token dialog view model.
/// </summary>
public interface ITokenDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets or sets the dialog title.</summary>
    string Title { get; set; }

    /// <summary>Gets or sets the access token.</summary>
    string? AccessToken { get; set; }

    /// <summary>Gets or sets the ID token.</summary>
    string? IdToken { get; set; }

    /// <summary>Gets or sets the refresh token.</summary>
    string? RefreshToken { get; set; }

    /// <summary>Gets a value indicating whether an access token is available.</summary>
    bool IsAccessTokenPresent { get; }

    /// <summary>Gets a value indicating whether an ID token is available.</summary>
    bool IsIdTokenPresent { get; }

    /// <summary>Gets a value indicating whether a refresh token is available.</summary>
    bool IsRefreshTokenPresent { get; }

    /// <summary>Gets or sets the raw token response.</summary>
    string TokenResponse { get; set; }
}
