using System.ComponentModel;
using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class KeepassXCSigningDialogService : IKeepassXCSigningDialogService
{
    private readonly IPasskeyFileDialogService _passkeyFileDialogService;
    private readonly IMessageBoxService _messageBoxService;
    private readonly IOwnerWindowService _ownerWindowService;

    public KeepassXCSigningDialogService(
        IPasskeyFileDialogService passkeyFileDialogService,
        IMessageBoxService messageBoxService,
        IOwnerWindowService ownerWindowService)
    {
        _passkeyFileDialogService = passkeyFileDialogService;
        _messageBoxService = messageBoxService;
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc />
    public string? SignCredential(
        string challenge,
        string rpId,
        string? userVerification = null,
        PublicKeyCredentialDescriptor[]? allowCredentials = null)
    {
        var viewModel = new KeepassXCSigningDialogViewModel(
            challenge,
            rpId,
            _passkeyFileDialogService,
            _messageBoxService,
            userVerification,
            allowCredentials);

        var dialog = new KeepassXCSigningDialog(viewModel)
        {
            Owner = _ownerWindowService.GetOwnerWindow()
        };

        return dialog.ShowDialog() == true ? viewModel.SignedCredentialJson : null;
    }
}
