using Microsoft.Win32;
using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class PasskeyFileDialogService : IPasskeyFileDialogService
{
    private readonly IOwnerWindowService _ownerWindowService;

    public PasskeyFileDialogService(IOwnerWindowService ownerWindowService)
    {
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc />
    public string? BrowseForPasskeyFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select KeepassXC Exported Passkey File",
            Filter = "KeepassXC Passkey (*.passkey)|*.passkey|All Files (*.*)|*.*",
            CheckFileExists = true
        };

        Window? owner = _ownerWindowService.GetOwnerWindow();
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }
}
