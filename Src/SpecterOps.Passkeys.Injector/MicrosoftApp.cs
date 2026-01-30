using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SpecterOps.Passkeys.Injector;

public sealed partial class MicrosoftApp
{
    private const string DefaultRedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient";
    private const string DefaultScope = "openid offline_access";

    [JsonPropertyName("iconGlyph")]
    [JsonRequired]
    public string IconGlyph { get; init; }

    [JsonPropertyName("displayName")]
    [JsonRequired]
    public string DisplayName { get; init; }

    [JsonIgnore]
    public string AuthorizeUrl { get; }

    [JsonPropertyName("clientId")]
    [JsonRequired]
    public string ClientId { get; init; }

    [JsonPropertyName("redirectUri")]
    public string RedirectUri { get; init; }

    [JsonPropertyName("resource")]
    public string? Resource { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("useV1Endpoint")]
    public bool UseV1Endpoint { get; init; }

    [JsonPropertyName("userAgent")]
    public string? UserAgent { get; init; }

    [JsonConstructor]
    public MicrosoftApp(
        string iconGlyph,
        string displayName,
        string clientId,
        string? redirectUri = null,
        string? resource = null,
        string? scope = null,
        bool useV1Endpoint = false,
        string? userAgent = null)
    {
        IconGlyph = iconGlyph;
        DisplayName = displayName;
        ClientId = clientId;
        RedirectUri = string.IsNullOrWhiteSpace(redirectUri) ? DefaultRedirectUri : redirectUri;
        Resource = resource;
        Scope = string.IsNullOrWhiteSpace(scope) ? DefaultScope : scope;
        UseV1Endpoint = useV1Endpoint;
        UserAgent = userAgent;
        AuthorizeUrl = BuildAuthorizeUrl(ClientId, Resource, Scope, RedirectUri, UseV1Endpoint);
    }

    public static ObservableCollection<MicrosoftApp> LoadMicrosoftApps()
    {
        const string resourceName = "SpecterOps.Passkeys.Injector.MicrosoftApps.json";
        using Stream? stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return [];
        }

        MicrosoftApp[] apps = JsonSerializer.Deserialize(stream, MicrosoftAppJsonContext.Default.MicrosoftAppArray) ?? [];
        return new ObservableCollection<MicrosoftApp>(apps);
    }

    private static string BuildAuthorizeUrl(
        string clientId,
        string? resource,
        string? scope,
        string redirectUri,
        bool useV1Endpoint)
    {
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

}

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(MicrosoftApp[]))]
internal sealed partial class MicrosoftAppJsonContext : JsonSerializerContext;
