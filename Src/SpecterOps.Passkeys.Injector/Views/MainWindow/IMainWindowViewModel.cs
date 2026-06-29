
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the main injector window view model.
/// </summary>
public interface IMainWindowViewModel : INotifyPropertyChanged
{
    /// <summary>Gets the default browser URL.</summary>
    string DefaultBrowserUrl { get; }

    /// <summary>Gets the default address bar text.</summary>
    string DefaultAddressBarText { get; }

    /// <summary>Gets the saved bookmarks.</summary>
    ObservableCollection<Bookmark> Bookmarks { get; }

    /// <summary>Gets or sets the active Microsoft redirect listener.</summary>
    MicrosoftApp? ActiveMicrosoftRedirectListener { get; set; }

    /// <summary>Gets or sets the current browser address.</summary>
    string? CurrentAddress { get; set; }

    /// <summary>Gets the available Microsoft application profiles.</summary>
    ObservableCollection<MicrosoftApp> MicrosoftApps { get; }

    /// <summary>
    /// Attempts to handle an OAuth redirect and extract tokens.
    /// </summary>
    /// <param name="uri">The redirect URI to inspect.</param>
    /// <param name="cancelNavigation">An optional callback that cancels navigation once a match is found.</param>
    /// <returns><see langword="true"/> when the redirect was handled; otherwise <see langword="false"/>.</returns>
    Task<bool> TryHandleOAuthRedirectAsync(string uri, Action? cancelNavigation = null);

    /// <summary>
    /// Loads the embedded JavaScript injected into the WebView.
    /// </summary>
    string LoadEmbeddedScript();
}
