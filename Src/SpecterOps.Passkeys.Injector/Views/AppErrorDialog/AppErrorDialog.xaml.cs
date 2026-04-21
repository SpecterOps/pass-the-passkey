using System.Windows;
using System.Windows.Input;

namespace SpecterOps.Passkeys.Injector;

public partial class AppErrorDialog : Window
{
    public AppErrorDialog(AppErrorDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

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
