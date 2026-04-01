using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Interaction logic for C2CommandsDialog.xaml
/// </summary>
public partial class C2CommandsDialog : Window
{
    public C2CommandsDialog(PublicKeyCredentialRequestOptions assertionOptions)
    {
        var viewModel = new C2CommandsDialogViewModel(assertionOptions);

        InitializeComponent();
        DataContext = viewModel;
    }
}
