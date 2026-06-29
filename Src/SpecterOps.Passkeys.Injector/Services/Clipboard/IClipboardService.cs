namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Provides clipboard read and write operations for text content.
/// </summary>
public interface IClipboardService
{
    /// <summary>
    /// Gets the current clipboard text.
    /// </summary>
    /// <returns>The clipboard text, or <see langword="null"/> when text is unavailable.</returns>
    string? GetText();

    /// <summary>
    /// Sets the clipboard text when a non-empty value is provided.
    /// </summary>
    /// <param name="text">The text to place on the clipboard.</param>
    void SetText(string? text);
}
