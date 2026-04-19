using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SpecterOps.Passkeys.Injector;

public sealed partial class TokenDialogViewModel : ObservableObject, ITokenDialogViewModel
{
    private static readonly JsonSerializerOptions TokenResponseSerializerOptions = new()
    {
        WriteIndented = true
    };

    [ObservableProperty]
    private string _title = "Token Response";

    [ObservableProperty]
    private string? _accessToken;

    [ObservableProperty]
    private string? _idToken;

    [ObservableProperty]
    private string? _refreshToken;

    public bool IsAccessTokenPresent => !string.IsNullOrWhiteSpace(AccessToken);

    public bool IsIdTokenPresent => !string.IsNullOrWhiteSpace(IdToken);

    public bool IsRefreshTokenPresent => !string.IsNullOrWhiteSpace(RefreshToken);

    public string TokenResponse
    {
        get;
        set
        {
            // Attempt to format the token response as pretty-printed JSON
            if (TryFormatJson(value, out string formattedValue))
            {
                value = formattedValue;
            }

            SetProperty(ref field, value);

            // Extract tokens from the OpenID Connect token response
            OpenIdConnectMessage tokenResponse = new(value);
            (AccessToken, IdToken, RefreshToken) = (tokenResponse.AccessToken, tokenResponse.IdToken, tokenResponse.RefreshToken);
        }
    } = string.Empty;

    partial void OnAccessTokenChanged(string? value) => OnPropertyChanged(nameof(IsAccessTokenPresent));

    partial void OnIdTokenChanged(string? value) => OnPropertyChanged(nameof(IsIdTokenPresent));

    partial void OnRefreshTokenChanged(string? value) => OnPropertyChanged(nameof(IsRefreshTokenPresent));

    private static bool TryFormatJson(string value, out string formatted)
    {
        formatted = string.Empty;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(value);
            formatted = JsonSerializer.Serialize(document.RootElement, TokenResponseSerializerOptions);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
