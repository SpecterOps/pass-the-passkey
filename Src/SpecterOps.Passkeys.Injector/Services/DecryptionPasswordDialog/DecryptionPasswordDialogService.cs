
namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class DecryptionPasswordDialogService : IDecryptionPasswordDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;

    public DecryptionPasswordDialogService(IOwnerWindowService ownerWindowService)
    {
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc />
    public string? PromptForPassword(string title, string? initialPassword = null, string? errorMessage = null)
    {
        var viewModel = new DecryptionPasswordDialogViewModel(
            title,
            initialPassword,
            errorMessage);

        var dialog = new DecryptionPasswordDialog(viewModel)
        {
            Owner = _ownerWindowService.GetOwnerWindow()
        };

        return dialog.ShowDialog() == true ? viewModel.Password : null;
    }
}
