using System.IO;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.DependencyInjection;
using Microsoft.Web.WebView2.Core;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private const string WebView2ProfileName = "PasskeyInjector";
    private const string WebAuthnBridgeObjectName = "webAuthnBridge";
    private readonly MainWindowViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        _viewModel = Ioc.Default.GetRequiredService<MainWindowViewModel>();
        DataContext = _viewModel;
        _viewModel.CredentialRequested += ShowAssertionDialog;
        _viewModel.CredentialCreationRequested += ShowAttestationDialog;

        Closed += OnWindowClosed;
        InitializeAsync();
    }

    private async void InitializeAsync()
    {
        // Configure WebView2 with a custom profile directory
        string userDataFolder = Path.Combine(Path.GetTempPath(), WebView2ProfileName);
        CoreWebView2Environment webView2Environment = await CoreWebView2Environment.CreateAsync(null, userDataFolder);

        await webView.EnsureCoreWebView2Async(webView2Environment);
        webView.CoreWebView2.SourceChanged += OnSourceChanged;
        webView.CoreWebView2.NavigationStarting += OnNavigationStarting;

        // Register the JavaScript-C# bridge
        WebAuthnBridge webAuthnBridge = Ioc.Default.GetRequiredService<WebAuthnBridge>();
        webView.CoreWebView2.AddHostObjectToScript(WebAuthnBridgeObjectName, webAuthnBridge);

        // Inject the JavaScript code from the embedded resource
        await webView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(_viewModel.LoadEmbeddedScript());

        // Enable navigation now that WebView2 is ready
        goButton.IsEnabled = true;
    }

    private void OnNavigateClick(object sender, RoutedEventArgs e)
    {
        // When the GO button is clicked, navigate to the selected URL
        Navigate(addressBar.Text);
    }

    private void OnAddressBarSuggestionsClosed(object sender, EventArgs e)
    {
        // When the suggestions dropdown closes, navigate to the selected URL
        if (addressBar.SelectedItem is Bookmark selectedBookmark)
        {
            Navigate(selectedBookmark.Url);
        }
    }

    private void Navigate(string url, bool resetRedirectListener = true)
    {
        if (resetRedirectListener)
        {
            // Reset any previous redirect listeners before navigating
            _viewModel.ActiveMicrosoftRedirectListener = null;
        }

        try
        {
            webView.CoreWebView2.Navigate(url);
        }
        catch (ArgumentException)
        {
            // Suppress invalid URL exceptions
        }
    }

    private void OnSourceChanged(object? sender, CoreWebView2SourceChangedEventArgs e)
    {
        // Sync the address bar with the current URL, with the exception of about:blank
        string newAddress = webView.CoreWebView2.Source;
        addressBar.Text = newAddress == _viewModel.DefaultBrowserUrl ?
            _viewModel.DefaultAddressBarText :
            newAddress;
    }

    private async void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        // Try to capture redirects for OAuth2/OIDC flows
        if (!e.IsRedirected)
        {
            return;
        }

        bool showDialog = await _viewModel.TryHandleOAuthRedirectAsync(e.Uri, () => e.Cancel = true);

        if (showDialog)
        {
            ShowTokenDialog();
        }
    }

    private void ShowTokenDialog()
    {
        TokenDialog dialog = new() { Owner = this };
        dialog.ShowDialog();
    }

    private void ShowAssertionDialog(object? sender, EventArgs e)
    {
        AssertionDialog dialog = new() { Owner = this };
        dialog.ShowDialog();
    }

    private void ShowAttestationDialog(object? sender, EventArgs e)
    {
        AttestationDialog dialog = new() { Owner = this };
        dialog.ShowDialog();
    }

    private async void OnWindowClosed(object? sender, EventArgs e)
    {
        // Clear all browsing data on close
        if (webView.CoreWebView2 != null)
        {
            await webView.CoreWebView2.Profile.ClearBrowsingDataAsync();
        }
    }

    private async void OnClearBrowsingDataClick(object sender, RoutedEventArgs e)
    {
        if (webView.CoreWebView2 != null)
        {
            webView.CoreWebView2.Navigate(_viewModel.DefaultBrowserUrl);
            await webView.CoreWebView2.Profile.ClearBrowsingDataAsync();
        }
    }

    private void OnMenuButtonClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button menuButton && menuButton.ContextMenu is ContextMenu contextMenu)
        {
            contextMenu.PlacementTarget = menuButton;
            contextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            contextMenu.IsOpen = true;
        }
    }

    private void OnBookmarkClick(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem menuItem || menuItem.DataContext is not Bookmark bookmark)
        {
            return;
        }

        Navigate(bookmark.Url);
    }

    private void OnAuthenticateAsClick(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem menuItem || menuItem.DataContext is not MicrosoftApp profile)
        {
            return;
        }

        // Set the active Microsoft app profile to start capturing redirects
        _viewModel.ActiveMicrosoftRedirectListener = profile;
        Navigate(profile.AuthorizeUrl, resetRedirectListener: false);
    }

    private void OnOpenDevToolsClick(object sender, RoutedEventArgs e)
    {
        webView.CoreWebView2?.OpenDevToolsWindow();
    }
}
