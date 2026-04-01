using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;

namespace SpecterOps.Passkeys.Injector;

public class PublicKeyCredentialHintDescriptionConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is PublicKeyCredentialHint hint)
        {
            var field = typeof(PublicKeyCredentialHint).GetField(hint.ToString());
            var attr = field?.GetCustomAttributes(typeof(DescriptionAttribute), false).FirstOrDefault() as DescriptionAttribute;
            return attr?.Description ?? hint.ToString();
        }

        return value?.ToString() ?? string.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
