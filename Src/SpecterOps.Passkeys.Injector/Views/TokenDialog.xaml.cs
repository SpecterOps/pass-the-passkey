using System.Windows;
using System.Windows.Input;
using CommunityToolkit.Mvvm.DependencyInjection;

namespace SpecterOps.Passkeys.Injector;

public partial class TokenDialog : Window
{
    private readonly ITokenDialogViewModel? _viewModel;

    public TokenDialog()
    {
        InitializeComponent();
        _viewModel = Ioc.Default.GetService<ITokenDialogViewModel>();
        DataContext = _viewModel;
    }

    private void OnCopyAccessTokenClick(object sender, RoutedEventArgs e) =>
        CopyTokenToClipboard(_viewModel?.AccessToken);

    private void OnCopyRefreshTokenClick(object sender, RoutedEventArgs e) =>
        CopyTokenToClipboard(_viewModel?.RefreshToken);

    private void OnCopyIdTokenClick(object sender, RoutedEventArgs e) =>
        CopyTokenToClipboard(_viewModel?.IdToken);

    private static void CopyTokenToClipboard(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        Clipboard.SetText(token);
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
