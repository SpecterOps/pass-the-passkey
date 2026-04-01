using System.Windows;
using System.Windows.Input;
using CommunityToolkit.Mvvm.DependencyInjection;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for AssertionDialog.xaml
/// </summary>
public partial class AssertionDialog : Window
{
    private readonly AssertionDialogViewModel? _viewModel;

    /// <summary>
    /// Initializes a new instance of the AssertionDialog.
    /// </summary>
    public AssertionDialog()
    {
        InitializeComponent();

        // Bind the data context to the ViewModel
        _viewModel = Ioc.Default.GetService<AssertionDialogViewModel>();
        if (_viewModel != null)
        {
            _viewModel.OnSubmit += OnSubmit;
            _viewModel.GetClipboardText = () => Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        DataContext = _viewModel;

        DataObject.AddPastingHandler(ResponseTextBox, OnResponseJsonPaste);
    }

    private void OnResponseJsonPaste(object sender, DataObjectPastingEventArgs e)
    {
        // Normalize pasted JSON content
        if (e.DataObject.GetDataPresent(DataFormats.Text))
        {
            string? pastedText = e.DataObject.GetData(DataFormats.Text) as string;
            if (!string.IsNullOrEmpty(pastedText))
            {
                string normalizedJson = AssertionDialogViewModel.NormalizeJson(pastedText);
                // Override the data being pasted with the normalized JSON
                e.DataObject = new DataObject(DataFormats.Text, normalizedJson);
            }
        }
    }

    private void OnSubmit(object? sender, EventArgs e)
    {
        DialogResult = true;
        Close();
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        // Close the dialog on Escape key press
        if (e.Key == Key.Escape)
        {
            DialogResult = false;
            Close();
            e.Handled = true;
            return;
        }

        base.OnPreviewKeyDown(e);
    }

    private void OnSignWithKeepassXC(object sender, RoutedEventArgs e)
    {
        if (_viewModel == null)
        {
            return;
        }

        var dialog = new KeepassXCSigningDialog(
            challenge: _viewModel.Challenge,
            rpId: _viewModel.RpId,
            userVerification: string.IsNullOrEmpty(_viewModel.UserVerification) ? null : _viewModel.UserVerification,
            allowCredentials: _viewModel.AllowCredentials.Count > 0 ? [.. _viewModel.AllowCredentials] : null)
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true && dialog.SignedCredentialJson != null)
        {
            _viewModel.PublicKeyCredentialJson = AssertionDialogViewModel.NormalizeJson(dialog.SignedCredentialJson);
        }
    }

    private void OnShowC2Commands(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.AssertionOptions == null)
        {
            return;
        }

        var dialog = new C2CommandsDialog(_viewModel.AssertionOptions)
        {
            Owner = this
        };
        dialog.ShowDialog();
    }

    private void OnDialogClosed(object? sender, EventArgs e)
    {
        if (_viewModel != null)
        {
            if (DialogResult == false)
            {
                // Clear the credential JSON if the dialog was cancelled
                _viewModel.PublicKeyCredentialJson = string.Empty;
            }

            _viewModel.OnSubmit -= OnSubmit;
            _viewModel.GetClipboardText = null;
        }
    }
}
