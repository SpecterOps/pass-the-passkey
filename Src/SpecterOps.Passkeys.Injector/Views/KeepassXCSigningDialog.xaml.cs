using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for KeepassXCSigningDialog.xaml
/// </summary>
public partial class KeepassXCSigningDialog : Window
{
    private readonly KeepassXCSigningDialogViewModel _viewModel;

    /// <summary>
    /// The serialized credential JSON produced by signing, available after DialogResult is true.
    /// </summary>
    public string? SignedCredentialJson { get; private set; }

    public KeepassXCSigningDialog(
        string challenge,
        string rpId,
        string? userVerification = null,
        PublicKeyCredentialDescriptor[]? allowCredentials = null)
    {
        _viewModel = new KeepassXCSigningDialogViewModel(challenge, rpId, userVerification, allowCredentials);
        _viewModel.OnSigned += OnSigned;
        _viewModel.BrowseForPasskeyFile = BrowseForPasskeyFile;
        _viewModel.ShowError = ShowError;

        Closed += OnClosed;

        InitializeComponent();
        DataContext = _viewModel;
    }

    private void OnSigned(object? sender, string credentialJson)
    {
        SignedCredentialJson = credentialJson;
        DialogResult = true;
        Close();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _viewModel.OnSigned -= OnSigned;
        _viewModel.BrowseForPasskeyFile = null;
        _viewModel.ShowError = null;
        Closed -= OnClosed;
    }

    private string? BrowseForPasskeyFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select KeepassXC Exported Passkey File",
            Filter = "KeepassXC Passkey (*.passkey)|*.passkey|All Files (*.*)|*.*",
            CheckFileExists = true
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private void ShowError(string message, string title) =>
        AppErrorDialog.Show(message, title, owner: this);

    private void OnCounterPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        e.Handled = !Regex.IsMatch(e.Text, @"^\d+$");
    }
}
