using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for C2CommandsDialog.xaml
/// </summary>
public partial class C2CommandsDialog : Window
{
    public C2CommandsDialog(IC2CommandsDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
