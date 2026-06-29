
namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the dialog that generates operator commands from assertion options.
/// </summary>
public interface IC2CommandsDialogViewModel : INotifyPropertyChanged
{
    /// <summary>Gets or sets the selected authenticator type hint.</summary>
    PublicKeyCredentialHint SelectedAuthenticatorTypeHint { get; set; }

    /// <summary>Gets or sets whether the broker kill flag is enabled.</summary>
    bool KillCredentialUIBroker { get; set; }

    /// <summary>Gets or sets whether prompt flooding is enabled.</summary>
    bool PromptFlood { get; set; }

    /// <summary>Gets or sets whether spoofing the window handle is enabled.</summary>
    bool SpoofWindowHandle { get; set; }

    /// <summary>Gets or sets whether the browser-in-private-mode flag is enabled.</summary>
    bool BrowserInPrivateMode { get; set; }

    /// <summary>Gets the standalone SharpPasskeys commands.</summary>
    ObservableCollection<string> StandaloneCommands { get; }

    /// <summary>Gets the Mythic-compatible commands.</summary>
    ObservableCollection<string> MythicCommands { get; }

    /// <summary>Gets the BOF commands (e.g., COFFLoader-compatible).</summary>
    ObservableCollection<string> BofCommands { get; }

    /// <summary>Gets the PowerShell command variants.</summary>
    ObservableCollection<string> PowerShellCommands { get; }
}
