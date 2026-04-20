using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SpecterOps.Passkeys.Injector;

public sealed partial class TokenDialogViewModel : ObservableObject, ITokenDialogViewModel
{
    private readonly IClipboardService _clipboardService;

    private static readonly JsonSerializerOptions TokenResponseSerializerOptions = new()
    {
        WriteIndented = true
    };

    public TokenDialogViewModel()
        : this(new ClipboardService())
    {
    }

    public TokenDialogViewModel(IClipboardService clipboardService)
    {
        _clipboardService = clipboardService;
    }

    [ObservableProperty]
    private string _title = "Token Response";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CopyAccessTokenCommand))]
    private string? _accessToken;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CopyIdTokenCommand))]
    private string? _idToken;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CopyRefreshTokenCommand))]
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

    [RelayCommand(CanExecute = nameof(IsAccessTokenPresent))]
    private void CopyAccessToken() => _clipboardService.SetText(AccessToken);

    [RelayCommand(CanExecute = nameof(IsRefreshTokenPresent))]
    private void CopyRefreshToken() => _clipboardService.SetText(RefreshToken);

    [RelayCommand(CanExecute = nameof(IsIdTokenPresent))]
    private void CopyIdToken() => _clipboardService.SetText(IdToken);

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
