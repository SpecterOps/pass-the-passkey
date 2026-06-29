
namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class SoftwareSigningDialogService : ISoftwareSigningDialogService
{
    private readonly IPasskeyFileDialogService _passkeyFileDialogService;
    private readonly IDecryptionPasswordDialogService _decryptionPasswordDialogService;
    private readonly IMessageBoxService _messageBoxService;
    private readonly IOwnerWindowService _ownerWindowService;

    public SoftwareSigningDialogService(
        IPasskeyFileDialogService passkeyFileDialogService,
        IDecryptionPasswordDialogService decryptionPasswordDialogService,
        IMessageBoxService messageBoxService,
        IOwnerWindowService ownerWindowService)
    {
        _passkeyFileDialogService = passkeyFileDialogService;
        _decryptionPasswordDialogService = decryptionPasswordDialogService;
        _messageBoxService = messageBoxService;
        _ownerWindowService = ownerWindowService;
    }

    /// <inheritdoc />
    public string? SignCredential(
        PublicKeyCredentialRequestOptions assertionOptions,
        string currentAddress)
    {
        ArgumentNullException.ThrowIfNull(assertionOptions);
        ArgumentNullException.ThrowIfNull(currentAddress);

        if (assertionOptions.Challenge is not { Length: > 0 })
        {
            _messageBoxService.ShowError("Assertion options must include a challenge.", "Invalid Assertion");
            return null;
        }

        var viewModel = new SoftwareSigningDialogViewModel(
            assertionOptions,
            currentAddress,
            _passkeyFileDialogService,
            _decryptionPasswordDialogService,
            _messageBoxService);

        var dialog = new SoftwareSigningDialog(viewModel)
        {
            Owner = _ownerWindowService.GetOwnerWindow()
        };

        return dialog.ShowDialog() == true ? viewModel.SignedCredentialJson : null;
    }
}
