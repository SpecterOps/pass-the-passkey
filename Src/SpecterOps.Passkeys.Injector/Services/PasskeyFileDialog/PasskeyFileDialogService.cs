using Microsoft.Win32;

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
            Title = "Select Exported Passkey File",
            Filter = "All Passkey Files (*.passkey;*.json;*.cxf)|*.passkey;*.json;*.cxf|KeePassXC Passkey (*.passkey)|*.passkey|Bitwarden Export (*.json)|*.json|Credential Exchange Format (*.cxf)|*.cxf|All Files (*.*)|*.*",
            CheckFileExists = true
        };

        Window? owner = _ownerWindowService.GetOwnerWindow();
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }
}
