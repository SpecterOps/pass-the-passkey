using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// A modern WPF error dialog to replace MessageBox.
/// </summary>
public partial class AppErrorDialog : Window
{
    public AppErrorDialog(string message, string title, Window? owner = null)
    {
        InitializeComponent();
        Title = title;
        MessageText.Text = message;
        Owner = owner;
    }

    public static void Show(string message, string title, Window? owner = null)
    {
        new AppErrorDialog(message, title, owner).ShowDialog();
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
