using System.Windows;
using System.Windows.Input;
using CommunityToolkit.Mvvm.DependencyInjection;

namespace SpecterOps.Passkeys.Injector;

public partial class TokenDialog : Window
{
    public TokenDialog()
    {
        InitializeComponent();
        DataContext = Ioc.Default.GetService<ITokenDialogViewModel>();
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
