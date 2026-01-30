namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Event arguments for credential request events.
/// </summary>
public class CredentialRequestEventArgs : EventArgs
{
    /// <summary>
    /// The raw options JSON passed to navigator.credentials.get().
    /// </summary>
    public string OptionsJson { get; }

    /// <summary>
    /// The mediation level for the credential request.
    /// </summary>
    /// <remarks>Can be "conditional", "optional", "required", or "silent". The default value is "optional".</remarks>
    public string? Mediation { get; }

    /// <summary>
    /// The response to return to JavaScript. Set this property in the event handler.
    /// </summary>
    public string? PublicKeyCredential { get; set; }

    public CredentialRequestEventArgs(string optionsJson, string? mediation = null)
    {
        OptionsJson = optionsJson;
        Mediation = mediation;
    }
}
