using System.Globalization;
using System.Windows.Data;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Converts a string array to a comma-separated string for display.
/// </summary>
public class StringArrayToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string[] array)
        {
            return string.Join(", ", array);
        }
        return string.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
