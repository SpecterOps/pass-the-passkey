using System.Buffers.Text;
using System.Globalization;
using System.Windows.Data;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Converts byte arrays to base64url strings for WebAuthn field display.
/// </summary>
public class ByteArrayToBase64UrlConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is byte[] bytes ? Base64Url.EncodeToString(bytes) : string.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
