
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Normalizes JSON text for display and paste handling.
/// </summary>
public static class JsonNormalizer
{
    private static readonly JsonSerializerOptions s_indentedJsonSerializerOptions = new()
    {
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions s_compactJsonSerializerOptions = new()
    {
        WriteIndented = false
    };

    /// <summary>
    /// Normalizes a JSON string by removing whitespace and formatting it.
    /// </summary>
    public static string NormalizeJson(string? value, bool indented, bool removePastedWhitespace)
    {
        string trimmed = value?.Trim() ?? string.Empty;

        if (removePastedWhitespace)
        {
            trimmed = CleanPastedJson(trimmed);

        }

        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(trimmed);
            JsonSerializerOptions jsonSerializerOptions = indented
                ? s_indentedJsonSerializerOptions
                : s_compactJsonSerializerOptions;

            return JsonSerializer.Serialize(doc.RootElement, jsonSerializerOptions);
        }
        catch (JsonException)
        {
            // Return the original trimmed string if parsing fails (the user might still be editing it)
            return trimmed;
        }
    }

    private static string CleanPastedJson(string value)
    {
        // Event log copies can include layout whitespace or partial <Data Name="Value"> wrapper characters or the " Value: " prefix.
        return value
            .Replace(" ", string.Empty)
            .Replace("\r\n", string.Empty)
            .TrimStart('"', '>', ':')
            .TrimEnd('<', '/');
    }
}
