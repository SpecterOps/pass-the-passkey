namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Event arguments for credential creation events.
/// </summary>
public class CredentialCreationEventArgs : EventArgs
{
    /// <summary>
    /// The raw options JSON passed to navigator.credentials.create().
    /// </summary>
    public string OptionsJson { get; }

    /// <summary>
    /// The response to return to JavaScript. Set this property in the event handler.
    /// </summary>
    public string? PublicKeyCredential { get; set; }

    public CredentialCreationEventArgs(string optionsJson)
    {
        OptionsJson = optionsJson;
    }
}
