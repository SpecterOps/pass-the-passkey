using System.Globalization;
using System.Windows.Data;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Converts zero/empty count to Visible, non-zero to Collapsed.
/// Used to show placeholder text when a collection is empty.
/// </summary>
public class ZeroToVisibleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int count)
        {
            return count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
