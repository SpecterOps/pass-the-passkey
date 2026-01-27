using System.Collections.ObjectModel;
using System.Collections.Specialized;
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
public partial class MainWindowViewModel : ObservableObject
{
    private static readonly HttpClient s_httpClient = new();
    private readonly AssertionDialogViewModel _assertionViewModel;
    private readonly TokenDialogViewModel _tokenViewModel;
    public string DefaultBrowserUrl { get; } = "about:blank";
    public string DefaultAddressBarText { get; } = "https://";

    /// <summary>
    /// Callback to show the assertion dialog.
    /// </summary>
    public EventHandler? CredentialRequested { get; set; }

    public sealed record Bookmark(string Name, string Url);

    public ObservableCollection<Bookmark> Bookmarks { get; } =
    [
        new("Microsoft Entra Portal", "https://entra.microsoft.com"),
        new("Microsoft Entra Device Authentication", "https://login.microsoftonline.com/common/oauth2/deviceauth"),
        new("GitHub", "https://github.com/login"),
        new("Nintendo", "https://accounts.nintendo.com/login"),
        new("Nvidia", "https://www.nvidia.com/account"),
        new("Atlassian", "https://id.atlassian.com/login"),
        new("Tencent Cloud", "https://www.tencentcloud.com/account/login")
    ];

    public sealed record MicrosoftApp(
        string IconGlyph,
        string DisplayName,
        string AuthorizeUrl,
        string ClientId,
        string RedirectUri,
        string? Resource = null,
        string? Scope = null,
        bool UseV1Endpoint = false,
        string? UserAgent = null
        );

    public MicrosoftApp? ActiveMicrosoftRedirectListener { get; set; }

    public ObservableCollection<MicrosoftApp> MicrosoftApps { get; } =
    [
        CreateMicrosoftApp(
            "\uE902",
            "Microsoft Teams",
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            ),
        CreateMicrosoftApp(
            "\uE774",
            "Microsoft Edge",
            "ecd6b820-32c2-49b6-98a6-444530e5a77a"
            ),
        CreateMicrosoftApp(
            "\uE756",
            "Microsoft Graph Command Line Tools",
            "14d82eec-204b-4c2f-b7e8-296a70dab67e",
            "http://localhost"
            ),
        CreateMicrosoftApp(
            "\uE756",
            "Microsoft Azure PowerShell",
            "1950a258-227b-4e31-a9cf-717495945fc2"
            ),
        CreateMicrosoftApp(
            "\uE756",
            "Microsoft Azure CLI",
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
            ),
        CreateMicrosoftApp(
            "\uE975",
            "Microsoft Intune Company Portal",
            "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
            "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="
            ),
        CreateMicrosoftApp(
            "\uE912",
            "Office 365 Management",
            "00b41c95-dab0-4487-9791-b9d2c32c80f2"
            ),
        CreateMicrosoftApp(
            "\uE8A5",
            "Microsoft Office",
            "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "launch-word://com.microsoft.Office.Word"
            ),
        CreateMicrosoftApp(
            "\uE753",
            "OneDrive",
            "b26aadf8-566f-4478-926f-589f601d9c74",
            "msauth://com.microsoft.skydrive/gSoqzhbCjkyvI/l7kC7IdG7KbPU="
            )
    ];

    public MainWindowViewModel(AssertionDialogViewModel assertionViewModel, TokenDialogViewModel tokenViewModel, WebAuthnBridge bridge)
    {
        ArgumentNullException.ThrowIfNull(assertionViewModel);
        ArgumentNullException.ThrowIfNull(tokenViewModel);

        _assertionViewModel = assertionViewModel;
        _tokenViewModel = tokenViewModel;

        // Register for credential requests from the WebAuthn bridge
        bridge.CredentialRequested += (_, e) => e.PublicKeyCredential = this.HandleCredentialRequest(e.Options, e.Mediation);
    }

    private static MicrosoftApp CreateMicrosoftApp(
        string iconGlyph,
        string displayName,
        string clientId,
        string redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient",
        string? scope = "openid offline_access",
        string? resource = null,
        bool useV1Endpoint = false,
        string? userAgent = null
        )
    {
        string authorizeUrl = BuildAuthorizeUrl(clientId, resource, scope, redirectUri, useV1Endpoint);
        return new MicrosoftApp(iconGlyph, displayName, authorizeUrl, clientId, redirectUri, resource, scope, useV1Endpoint, userAgent);
    }

    private static string BuildAuthorizeUrl(
        string clientId,
        string? resource,
        string? scope,
        string redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient",
        bool useV1Endpoint = false)
    {
        // TODO: Add support for sovereign clouds
        string baseUri = useV1Endpoint
            ? "https://login.microsoftonline.com/common/oauth2/authorize"
            : "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";

        NameValueCollection queryString = HttpUtility.ParseQueryString(string.Empty);

        queryString.Add(OpenIdConnectParameterNames.ResponseType, OpenIdConnectParameterNames.Code);
        queryString.Add(OpenIdConnectParameterNames.ClientId, clientId);
        queryString.Add(OpenIdConnectParameterNames.RedirectUri, redirectUri);
        queryString.Add(OpenIdConnectParameterNames.State, Guid.NewGuid().ToString());

        if (useV1Endpoint)
        {
            if (!string.IsNullOrWhiteSpace(resource))
            {
                queryString.Add(OpenIdConnectParameterNames.Resource, resource);
            }
            if (!string.IsNullOrWhiteSpace(scope))
            {
                queryString.Add(OpenIdConnectParameterNames.Scope, scope);
            }
        }
        else if (!string.IsNullOrWhiteSpace(scope))
        {
            queryString.Add(OpenIdConnectParameterNames.Scope, scope);
        }

        var builder = new UriBuilder(baseUri)
        {
            Query = queryString.ToString()
        };

        return builder.Uri.ToString();
    }

    /// <summary>
    /// Handles a credential request from the WebAuthn bridge.
    /// </summary>
    /// <param name="options">The credential request options.</param>
    /// <param name="mediation">The mediation value.</param>
    /// <returns>The credential JSON if successful, null otherwise.</returns>
    private string? HandleCredentialRequest(PublicKeyCredentialRequestOptions options, string? mediation)
    {
        // Reset and populate the assertion view model
        _assertionViewModel.Reset();
        _assertionViewModel.Options = options;
        _assertionViewModel.Mediation = mediation ?? string.Empty;

        // Show the dialog through the callback
        CredentialRequested?.Invoke(this, EventArgs.Empty);

        // Returns the JSON assertion or null if cancelled
        return _assertionViewModel.PublicKeyCredentialJson;
    }

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
            _tokenViewModel.Title = "Authorization Error";
            _tokenViewModel.TokenResponse = $$"""
{
  "error": "{{error}}",
  "error_description": "{{errorDescription}}"
}
""";
        }
        else if (!string.IsNullOrWhiteSpace(code))
        {
            string tokensJson = await ExchangeCodeForTokensAsync(code, activeListenerCached);
            _tokenViewModel.Title = $"Token Response for {activeListenerCached.DisplayName}";
            _tokenViewModel.TokenResponse = tokensJson;
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

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Allow override through inheritance.")]
    public string LoadEmbeddedScript()
    {
        using Stream? javaScriptStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SpecterOps.Passkeys.Injector.WebAuthnBridge.js");
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
