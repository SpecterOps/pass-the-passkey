using System.Windows;
using System.Windows.Input;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for AttestationDialog.xaml
/// </summary>
public partial class AttestationDialog : Window
{
    /// <summary>
    /// Initializes a new instance of the AttestationDialog.
    /// </summary>
    public AttestationDialog(IAttestationDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;

        // Handle JSON pasting from clipboard
        DataObject.AddPastingHandler(ResponseTextBox, OnResponseJsonPaste);
    }

    public Action CloseOnSubmit => () =>
    {
        DialogResult = true;
        Close();
    };

    private void OnResponseJsonPaste(object sender, DataObjectPastingEventArgs e)
    {
        // Normalize pasted JSON content
        if (e.DataObject.GetDataPresent(DataFormats.Text))
        {
            string? pastedText = e.DataObject.GetData(DataFormats.Text) as string;
            if (!string.IsNullOrEmpty(pastedText))
            {
                string normalizedJson = AttestationDialogViewModel.PrettyPrintJson(pastedText);
                // Override the data being pasted with the normalized JSON
                e.DataObject = new DataObject(DataFormats.Text, normalizedJson);
            }
        }
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
}
