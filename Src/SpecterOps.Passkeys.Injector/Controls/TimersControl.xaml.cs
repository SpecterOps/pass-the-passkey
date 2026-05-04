using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Displays live mm:ss countdowns for the WebAuthn request and challenge expirations.
/// </summary>
public partial class TimersControl : UserControl
{
    public static readonly DependencyProperty RequestExpirationProperty =
        DependencyProperty.Register(
            nameof(RequestExpiration),
            typeof(DateTime?),
            typeof(TimersControl),
            new PropertyMetadata(null, OnAnyExpirationChanged));

    public static readonly DependencyProperty ChallengeExpirationProperty =
        DependencyProperty.Register(
            nameof(ChallengeExpiration),
            typeof(DateTime?),
            typeof(TimersControl),
            new PropertyMetadata(null, OnAnyExpirationChanged));

    private static readonly Brush s_positiveBrush =
        (Application.Current?.TryFindResource("SystemFillColorSuccessBrush") as Brush)
        ?? new SolidColorBrush(Color.FromRgb(0x0F, 0x7B, 0x0F));

    private static readonly Brush s_negativeBrush =
        (Application.Current?.TryFindResource("SystemFillColorCriticalBrush") as Brush)
        ?? new SolidColorBrush(Color.FromRgb(0xC4, 0x2B, 0x1C));

    private readonly DispatcherTimer _timer;

    public TimersControl()
    {
        InitializeComponent();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _timer.Tick += (_, _) => UpdateDisplay();

        Loaded += (_, _) => { _timer.Start(); UpdateDisplay(); };
        Unloaded += (_, _) => _timer.Stop();
    }

    public DateTime? RequestExpiration
    {
        get => (DateTime?)GetValue(RequestExpirationProperty);
        set => SetValue(RequestExpirationProperty, value);
    }

    public DateTime? ChallengeExpiration
    {
        get => (DateTime?)GetValue(ChallengeExpirationProperty);
        set => SetValue(ChallengeExpirationProperty, value);
    }

    private static void OnAnyExpirationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((TimersControl)d).UpdateDisplay();
    }

    private void UpdateDisplay()
    {
        // Single "now" snapshot so both countdowns are computed against the same instant.
        DateTime now = DateTime.Now;
        SetCountdown(RequestCountdownText, RequestExpiration, now);
        SetCountdown(ChallengeCountdownText, ChallengeExpiration, now);
    }

    private static void SetCountdown(TextBlock target, DateTime? expiration, DateTime now)
    {
        if (!expiration.HasValue)
        {
            target.Text = "N/A";
            target.ClearValue(TextBlock.ForegroundProperty);
            return;
        }

        int totalSeconds = (int)(expiration.Value - now).TotalSeconds;
        int abs = Math.Abs(totalSeconds);
        string sign = totalSeconds < 0 ? "-" : string.Empty;
        target.Text = $"{sign}{abs / 60:D2}:{abs % 60:D2}";
        target.Foreground = totalSeconds > 0 ? s_positiveBrush : s_negativeBrush;
    }
}
