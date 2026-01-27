using System.Windows;
using System.Windows.Controls;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// A TextBox with an overlay copy button that copies the text to the clipboard.
/// </summary>
public partial class ClipboardEnabledTextBox : UserControl
{
    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(
            nameof(Text),
            typeof(string),
            typeof(ClipboardEnabledTextBox),
            new PropertyMetadata(string.Empty));

    public ClipboardEnabledTextBox()
    {
        InitializeComponent();
    }

    public string? Text
    {
        get => (string?)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(Text))
        {
            try
            {
                Clipboard.SetText(Text);
            }
            catch
            {
                // Ignore clipboard errors
            }
        }
    }
}
