using System.Windows.Controls;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// A password input with a reveal toggle that switches between masked and plaintext display.
/// </summary>
/// <remarks>
/// PasswordBox.Password is intentionally not a dependency property in WPF (to discourage keeping
/// passwords in the binding/data layer), so this control bridges it to a bindable Password DP.
/// While the reveal toggle is on, the password is held as plaintext in the underlying TextBox.
/// </remarks>
public partial class RevealablePasswordBox : UserControl
{
    /// <summary>
    /// Default maximum password length. Matches typical service limits and bounds memory exposure
    /// while in revealed (plaintext) mode.
    /// </summary>
    public const int DefaultMaxLength = 256;

    public static readonly DependencyProperty PasswordProperty =
        DependencyProperty.Register(
            nameof(Password),
            typeof(string),
            typeof(RevealablePasswordBox),
            new FrameworkPropertyMetadata(
                string.Empty,
                FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
                OnPasswordChanged));

    public static readonly DependencyProperty MaxLengthProperty =
        DependencyProperty.Register(
            nameof(MaxLength),
            typeof(int),
            typeof(RevealablePasswordBox),
            new PropertyMetadata(DefaultMaxLength));

    // Guards against the DP -> PasswordBox -> DP feedback loop: setting PasswordBox.Password
    // raises PasswordChanged, which would otherwise write back into the DP and recurse.
    private bool _suppressSync;

    public RevealablePasswordBox()
    {
        InitializeComponent();
    }

    /// <summary>
    /// The current password value. Two-way bindable.
    /// </summary>
    public string Password
    {
        get => (string)GetValue(PasswordProperty);
        set => SetValue(PasswordProperty, value);
    }

    /// <summary>
    /// Maximum allowed password length. Mirrors <see cref="PasswordBox.MaxLength"/>.
    /// </summary>
    public int MaxLength
    {
        get => (int)GetValue(MaxLengthProperty);
        set => SetValue(MaxLengthProperty, value);
    }

    /// <summary>
    /// Focuses the currently visible inner control (PasswordBox or TextBox depending on reveal state).
    /// Hides UserControl.Focus because keyboard focus must land on the actual input element, not the container.
    /// </summary>
    public new void Focus()
    {
        if (RevealToggle.IsChecked == true)
        {
            TextBoxControl.Focus();
            TextBoxControl.SelectAll();
        }
        else
        {
            PasswordBoxControl.Focus();
            PasswordBoxControl.SelectAll();
        }
    }

    // Pushes external DP changes (e.g. initial value from a binding) into the PasswordBox.
    // The TextBox already reflects the DP via its Text binding, so it does not need explicit syncing here.
    private static void OnPasswordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var control = (RevealablePasswordBox)d;
        if (control._suppressSync) return;

        string newValue = (string)e.NewValue ?? string.Empty;
        if (control.PasswordBoxControl.Password != newValue)
        {
            control._suppressSync = true;
            control.PasswordBoxControl.Password = newValue;
            control._suppressSync = false;
        }
    }

    // Pushes user edits in the PasswordBox out to the DP (and through to any consumer binding).
    private void OnPasswordBoxChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressSync) return;

        _suppressSync = true;
        Password = PasswordBoxControl.Password;
        _suppressSync = false;
    }

    // Swaps which inner control is visible and transfers focus so typing continues uninterrupted.
    private void OnRevealToggled(object sender, RoutedEventArgs e)
    {
        bool reveal = RevealToggle.IsChecked == true;
        TextBoxControl.Visibility = reveal ? Visibility.Visible : Visibility.Collapsed;
        PasswordBoxControl.Visibility = reveal ? Visibility.Collapsed : Visibility.Visible;

        if (reveal)
        {
            TextBoxControl.Focus();
            // Place caret at end rather than selecting all, since the user is mid-entry.
            TextBoxControl.CaretIndex = TextBoxControl.Text?.Length ?? 0;
        }
        else
        {
            PasswordBoxControl.Focus();
        }
    }
}
