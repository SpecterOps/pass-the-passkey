using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the assertion dialog.
/// </summary>
public sealed class AssertionDialogService : IAssertionDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;
    private readonly IClipboardService _clipboardService;
    private readonly IKeepassXCSigningDialogService _keepassXCSigningDialogService;
    private readonly IC2CommandsDialogService _c2CommandsDialogService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    /// <param name="clipboardService">Service used to paste assertion responses.</param>
    /// <param name="keepassXCSigningDialogService">Service used to sign assertions with KeepassXC.</param>
    /// <param name="c2CommandsDialogService">Service used to display C2 command helpers.</param>
    public AssertionDialogService(
        IOwnerWindowService ownerWindowService,
        IClipboardService clipboardService,
        IKeepassXCSigningDialogService keepassXCSigningDialogService,
        IC2CommandsDialogService c2CommandsDialogService)
    {
        _ownerWindowService = ownerWindowService;
        _clipboardService = clipboardService;
        _keepassXCSigningDialogService = keepassXCSigningDialogService;
        _c2CommandsDialogService = c2CommandsDialogService;
    }

    /// <inheritdoc/>
    public string? Show(string optionsJson, string? mediation)
    {
        ArgumentNullException.ThrowIfNull(optionsJson);

        AssertionDialogViewModel viewModel = new(
            _clipboardService,
            _keepassXCSigningDialogService,
            _c2CommandsDialogService)
        {
            AssertionOptionsJson = optionsJson,
            Mediation = mediation ?? string.Empty
        };

        AssertionDialog dialog = new(viewModel);
        Window? owner = _ownerWindowService.GetOwnerWindow();
        if (owner != null)
        {
            dialog.Owner = owner;
        }

        return dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(viewModel.PublicKeyCredentialJson)
            ? viewModel.PublicKeyCredentialJson
            : null;
    }
}
