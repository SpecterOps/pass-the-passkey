namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class MessageBoxService : IMessageBoxService
{
    private readonly IOwnerWindowService _ownerWindowService;

    public MessageBoxService(IOwnerWindowService ownerWindowService)
    {
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc />
    public void ShowError(string message, string title)
    {
        AppErrorDialogViewModel viewModel = new()
        {
            Message = message,
            Title = title
        };

        AppErrorDialog dialog = new(viewModel)
        {
            Owner = _ownerWindowService.GetOwnerWindow()
        };

        dialog.ShowDialog();
    }
}
