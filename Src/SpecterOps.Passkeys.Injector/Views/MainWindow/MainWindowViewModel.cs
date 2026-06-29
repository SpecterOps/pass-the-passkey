using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Web;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// ViewModel for the MainWindow.
/// </summary>
public partial class MainWindowViewModel : ObservableObject, IMainWindowViewModel
{
    private static readonly HttpClient s_httpClient = new();
    private readonly IAssertionDialogService _assertionDialogService;
    private readonly IAttestationDialogService _attestationDialogService;
    private readonly ITokenDialogService _tokenDialogService;

    /// <inheritdoc />
    public string DefaultBrowserUrl { get; } = "about:blank";

    /// <inheritdoc />
    public string DefaultAddressBarText { get; } = "https://";

    /// <inheritdoc />
    public ObservableCollection<Bookmark> Bookmarks { get; } = Bookmark.LoadBookmarks();

    /// <inheritdoc />
    public MicrosoftApp? ActiveMicrosoftRedirectListener { get; set; }

    /// <inheritdoc />
    public string? CurrentAddress { get; set; }

    /// <inheritdoc />
    public ObservableCollection<MicrosoftApp> MicrosoftApps { get; } = MicrosoftApp.LoadMicrosoftApps();

    public MainWindowViewModel(
        IWebAuthnBridge bridge,
        IAssertionDialogService assertionDialogService,
        IAttestationDialogService attestationDialogService,
        ITokenDialogService tokenDialogService)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(assertionDialogService);
        ArgumentNullException.ThrowIfNull(attestationDialogService);
        ArgumentNullException.ThrowIfNull(tokenDialogService);

        _assertionDialogService = assertionDialogService;
        _attestationDialogService = attestationDialogService;
        _tokenDialogService = tokenDialogService;

        // Register for credential requests from the WebAuthn bridge
        bridge.CredentialRequested += (_, e) => e.PublicKeyCredential = this.HandleCredentialRequest(e.OptionsJson, e.Mediation);
        bridge.CredentialCreationRequested += (_, e) => e.PublicKeyCredential = this.HandleCredentialCreation(e.OptionsJson, e.Mediation);
    }

    /// <summary>
    /// Handles a credential request from the WebAuthn bridge.
    /// </summary>
    /// <param name="optionsJson">The credential request options JSON.</param>
    /// <param name="mediation">The mediation value.</param>
    /// <returns>The credential JSON if successful, null otherwise.</returns>
    private string? HandleCredentialRequest(string optionsJson, string? mediation)
    {
        if (string.IsNullOrWhiteSpace(CurrentAddress))
        {
            // This should be a rare occurrence since the address bar is pre-populated and users are likely to enter an address before attempting WebAuthn, but this is a safeguard against potential confusion
            return null;
        }

        return _assertionDialogService.Show(optionsJson, mediation, CurrentAddress);
    }

    /// <summary>
    /// Handles a credential creation request from the WebAuthn bridge.
    /// </summary>
    /// <param name="optionsJson">The credential creation options JSON.</param>
    /// <param name="mediation">The mediation value.</param>
    /// <returns>The credential JSON if successful, null otherwise.</returns>
    private string? HandleCredentialCreation(string optionsJson, string? mediation)
    {
        if (string.IsNullOrWhiteSpace(CurrentAddress))
        {
            // This should be a rare occurrence since the address bar is pre-populated and users are likely to enter an address before attempting WebAuthn, but this is a safeguard against potential confusion
            return null;
        }

        return _attestationDialogService.Show(optionsJson, mediation, CurrentAddress);
    }

    /// <inheritdoc />
    public async Task<bool> TryHandleOAuthRedirectAsync(string uri, Action? cancelNavigation = null)
    {
        if (ActiveMicrosoftRedirectListener is null)
        {
            return false;
        }

        bool isAuthorizationRedirect = TryGetAuthorizationCode(uri, ActiveMicrosoftRedirectListener.RedirectUri, out string? code, out string? error, out string? errorDescription);

        if (!isAuthorizationRedirect)
        {
            return false;
        }

        // Do not continue with redirects
        // Note: This must be done before any awaits
        cancelNavigation?.Invoke();

        // Clear the active listener to stop capturing further redirects
        var activeListenerCached = ActiveMicrosoftRedirectListener;
        ActiveMicrosoftRedirectListener = null;

        if (!string.IsNullOrWhiteSpace(error))
        {
            _tokenDialogService.Show("Authorization Error", $$"""
{
  "error": "{{error}}",
  "error_description": "{{errorDescription}}"
}
""");
        }
        else if (!string.IsNullOrWhiteSpace(code))
        {
            string tokensJson = await ExchangeCodeForTokensAsync(code, activeListenerCached);
            _tokenDialogService.Show($"Token Response for {activeListenerCached.DisplayName}", tokensJson);
        }
        return true;
    }

    private static bool TryGetAuthorizationCode(string uriString, string expectedRedirectUri, out string? code, out string? error, out string? errorDescription)
    {
        // Initialize out parameters
        code = null;
        error = null;
        errorDescription = null;

        if (!Uri.TryCreate(uriString, UriKind.Absolute, out Uri? uri) ||
            !Uri.TryCreate(expectedRedirectUri, UriKind.Absolute, out Uri? expectedUri))
        {
            // Invalid URIs
            return false;
        }

        bool isMatch =
            string.Equals(uri.Scheme, expectedUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(uri.Host, expectedUri.Host, StringComparison.OrdinalIgnoreCase) &&
            uri.Port == expectedUri.Port &&
            string.Equals(uri.AbsolutePath.TrimEnd('/'), expectedUri.AbsolutePath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

        if (!isMatch)
        {
            return false;
        }

        var query = HttpUtility.ParseQueryString(uri.Query);
        error = query.Get(OpenIdConnectParameterNames.Error);
        errorDescription = query.Get(OpenIdConnectParameterNames.ErrorDescription);
        code = query.Get(OpenIdConnectParameterNames.Code);
        return true;
    }

    /// <inheritdoc />
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Allow override through inheritance.")]
    public string LoadEmbeddedScript()
    {
        using Stream? javaScriptStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SpecterOps.Passkeys.Injector.Services.WebAuthnBridge.WebAuthnBridge.js");
        using StreamReader javaScriptReader = new(javaScriptStream ?? throw new InvalidOperationException("Could not find the embedded JavaScript."), Encoding.UTF8);
        return javaScriptReader.ReadToEnd();
    }

    private static async Task<string> ExchangeCodeForTokensAsync(string code, MicrosoftApp request)
    {
        string tokenEndpoint = request.UseV1Endpoint
            ? "https://login.microsoftonline.com/common/oauth2/token"
            : "https://login.microsoftonline.com/common/oauth2/v2.0/token";

        var formFields = new Dictionary<string, string>
        {
            [OpenIdConnectParameterNames.ClientId] = request.ClientId,
            [OpenIdConnectParameterNames.GrantType] = OpenIdConnectGrantTypes.AuthorizationCode,
            [OpenIdConnectParameterNames.RedirectUri] = request.RedirectUri,
            [OpenIdConnectParameterNames.Code] = code
        };

        if (request.UseV1Endpoint)
        {
            if (!string.IsNullOrWhiteSpace(request.Resource))
            {
                formFields[OpenIdConnectParameterNames.Resource] = request.Resource;
            }
        }
        else if (!string.IsNullOrWhiteSpace(request.Scope))
        {
            formFields[OpenIdConnectParameterNames.Scope] = request.Scope;
        }

        using FormUrlEncodedContent content = new(formFields);
        using HttpRequestMessage message = new(HttpMethod.Post, tokenEndpoint)
        {
            Content = content
        };

        if (!string.IsNullOrWhiteSpace(request.UserAgent))
        {
            // Optionally override the User-Agent header
            message.Headers.UserAgent.ParseAdd(request.UserAgent);
        }

        using HttpResponseMessage response = await s_httpClient.SendAsync(message);
        return await response.Content.ReadAsStringAsync();
    }
}
