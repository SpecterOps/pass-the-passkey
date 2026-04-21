using System.Windows;
using System.Windows.Input;

namespace SpecterOps.Passkeys.Injector;

public partial class TokenDialog : Window
{
    public TokenDialog(ITokenDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        // Intercept Escape before the focused control handles it so the dialog
        // always closes as a canceled action.
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
