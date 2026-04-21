using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the attestation dialog.
/// </summary>
public sealed class AttestationDialogService : IAttestationDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AttestationDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    public AttestationDialogService(IOwnerWindowService ownerWindowService)
    {
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc/>
    public string? Show(string optionsJson)
    {
        ArgumentNullException.ThrowIfNull(optionsJson);

        AttestationDialogViewModel viewModel = new()
        {
            AttestationOptionsJson = optionsJson
        };

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
