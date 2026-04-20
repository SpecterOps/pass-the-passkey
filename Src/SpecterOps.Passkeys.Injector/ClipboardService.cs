using System.Windows;

namespace SpecterOps.Passkeys.Injector;

public sealed class ClipboardService : IClipboardService
{
    public string? GetText()
    {
        try
        {
            return Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        catch
        {
            return null;
        }
    }

    public void SetText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            // Ignore clipboard errors.
        }
    }
}
