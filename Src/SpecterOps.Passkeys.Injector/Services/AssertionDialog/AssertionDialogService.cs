
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the assertion dialog.
/// </summary>
public sealed class AssertionDialogService : IAssertionDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;
    private readonly IClipboardService _clipboardService;
    private readonly ISoftwareSigningDialogService _softwareSigningDialogService;
    private readonly IC2CommandsDialogService _c2CommandsDialogService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AssertionDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    /// <param name="clipboardService">Service used to paste assertion responses.</param>
    /// <param name="softwareSigningDialogService">Service used to sign assertions with software authenticators.</param>
    /// <param name="c2CommandsDialogService">Service used to display C2 command helpers.</param>
    public AssertionDialogService(
        IOwnerWindowService ownerWindowService,
        IClipboardService clipboardService,
        ISoftwareSigningDialogService softwareSigningDialogService,
        IC2CommandsDialogService c2CommandsDialogService)
    {
        _ownerWindowService = ownerWindowService;
        _clipboardService = clipboardService;
        _softwareSigningDialogService = softwareSigningDialogService;
        _c2CommandsDialogService = c2CommandsDialogService;
    }

    /// <inheritdoc/>
    public string? Show(string optionsJson, string? mediation, string currentAddress)
    {
        ArgumentNullException.ThrowIfNull(optionsJson);
        ArgumentNullException.ThrowIfNull(currentAddress);

        AssertionDialogViewModel viewModel = new(
            optionsJson,
            mediation,
            currentAddress,
            _clipboardService,
            _softwareSigningDialogService,
            _c2CommandsDialogService);

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
