using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default UI service for displaying the C2 commands dialog.
/// </summary>
public sealed class C2CommandsDialogService : IC2CommandsDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;

    /// <summary>
    /// Initializes a new instance of the <see cref="C2CommandsDialogService"/> class.
    /// </summary>
    /// <param name="ownerWindowService">Service used to resolve the owner window.</param>
    public C2CommandsDialogService(IOwnerWindowService ownerWindowService)
    {
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc/>
    public void Show(PublicKeyCredentialRequestOptions assertionOptions)
    {
        ArgumentNullException.ThrowIfNull(assertionOptions);

        IC2CommandsDialogViewModel viewModel = new C2CommandsDialogViewModel()
        {
            AssertionOptions = assertionOptions
        };

        C2CommandsDialog dialog = new(viewModel);
        Window? owner = _ownerWindowService.GetOwnerWindow();
        if (owner != null)
        {
            dialog.Owner = owner;
        }

        dialog.ShowDialog();
    }
}
