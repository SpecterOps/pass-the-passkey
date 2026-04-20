namespace SpecterOps.Passkeys.Injector;

public interface IClipboardService
{
    string? GetText();

    void SetText(string? text);
}
