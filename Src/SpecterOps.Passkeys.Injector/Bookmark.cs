using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SpecterOps.Passkeys.Injector;

public sealed partial class Bookmark
{
    private const string DefaultGlobeIconBase64 = "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";

    [JsonPropertyName("name")]
    [JsonRequired]
    public string Name { get; init; }

    [JsonPropertyName("url")]
    [JsonRequired]
    public string Url { get; init; }

    [JsonPropertyName("favicon")]
    public string? Favicon { get; init; }

    [JsonIgnore]
    public ImageSource? FaviconImageSource
    {
        get => field ??= CreateImageSource(Favicon);
        private set;
    }

    [JsonConstructor]
    public Bookmark(string name, string url, string? favicon = null)
    {
        Name = name;
        Url = url;
        Favicon = string.IsNullOrWhiteSpace(favicon) ? DefaultGlobeIconBase64 : favicon;
    }

    public static ObservableCollection<Bookmark> LoadBookmarks()
    {
        const string resourceName = "SpecterOps.Passkeys.Injector.Bookmarks.json";
        using Stream? stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return [];
        }

        Bookmark[] bookmarks = JsonSerializer.Deserialize(stream, BookmarkJsonContext.Default.BookmarkArray) ?? [];
        return new ObservableCollection<Bookmark>(bookmarks);
    }

    private static BitmapImage? CreateImageSource(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
        {
            return null;
        }

        byte[] bytes = Convert.FromBase64String(base64);
        using MemoryStream stream = new(bytes);
        BitmapImage image = new();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }
}

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(Bookmark[]))]
internal sealed partial class BookmarkJsonContext : JsonSerializerContext;
