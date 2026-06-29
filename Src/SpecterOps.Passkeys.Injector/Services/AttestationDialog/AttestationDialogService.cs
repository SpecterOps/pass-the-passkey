
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the attestation dialog.
/// </summary>
public sealed class AttestationDialogService : IAttestationDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;
    private readonly IClipboardService _clipboardService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AttestationDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    /// <param name="clipboardService">Service used to paste responses from the clipboard.</param>
    public AttestationDialogService(IOwnerWindowService ownerWindowService, IClipboardService clipboardService)
    {
        _ownerWindowService = ownerWindowService;
        _clipboardService = clipboardService;
    }

    /// <inheritdoc/>
    public string? Show(string optionsJson, string? mediation, string currentAddress)
    {
        ArgumentNullException.ThrowIfNull(optionsJson);
        ArgumentNullException.ThrowIfNull(currentAddress);

        AttestationDialogViewModel viewModel = new(
            optionsJson,
            mediation,
            currentAddress,
            _clipboardService);

        AttestationDialog dialog = new(viewModel);
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
