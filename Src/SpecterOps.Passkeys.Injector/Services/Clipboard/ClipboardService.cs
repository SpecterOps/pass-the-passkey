using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <inheritdoc />
public sealed class ClipboardService : IClipboardService
{
    /// <inheritdoc />
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

    /// <inheritdoc />
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
