using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the token dialog.
/// </summary>
public sealed class TokenDialogService : ITokenDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;
    private readonly IClipboardService _clipboardService;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    /// <param name="clipboardService">Service used to copy tokens to the clipboard.</param>
    public TokenDialogService(IOwnerWindowService ownerWindowService, IClipboardService clipboardService)
    {
        _ownerWindowService = ownerWindowService;
        _clipboardService = clipboardService;
    }

    /// <inheritdoc/>
    public void Show(string title, string tokenResponse)
    {
        ArgumentNullException.ThrowIfNull(title);
        ArgumentNullException.ThrowIfNull(tokenResponse);

        ITokenDialogViewModel viewModel = new TokenDialogViewModel(_clipboardService)
        {
            Title = title,
            TokenResponse = tokenResponse
        };

        TokenDialog dialog = new(viewModel);
        Window? owner = _ownerWindowService.GetOwnerWindow();
        if (owner != null)
        {
            dialog.Owner = owner;
        }

        dialog.ShowDialog();
    }
}
