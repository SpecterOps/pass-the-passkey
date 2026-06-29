using System.Text.RegularExpressions;
using System.Windows.Input;

namespace SpecterOps.Passkeys.Injector;

public partial class SoftwareSigningDialog : Window
{
    public SoftwareSigningDialog(ISoftwareSigningDialogViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
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

    private void OnCounterPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        e.Handled = !IntegerRegex().IsMatch(e.Text);
    }

    [GeneratedRegex(@"^\d+$")]
    private static partial Regex IntegerRegex();
}
