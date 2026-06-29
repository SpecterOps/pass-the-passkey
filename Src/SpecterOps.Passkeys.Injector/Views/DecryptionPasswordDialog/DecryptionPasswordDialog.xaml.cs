using System.Windows.Input;

namespace SpecterOps.Passkeys.Injector;

public partial class DecryptionPasswordDialog : Window
{
    public DecryptionPasswordDialog(DecryptionPasswordDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        Loaded += (_, _) => PasswordBox.Focus();
    }

    public Action CloseOnSubmit => () =>
    {
        DialogResult = true;
        Close();
    };

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
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
