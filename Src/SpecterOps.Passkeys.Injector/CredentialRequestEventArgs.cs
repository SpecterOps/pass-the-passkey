namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Event arguments for credential request events.
/// </summary>
public class CredentialRequestEventArgs : EventArgs
{
    /// <summary>
    /// The options passed to navigator.credentials.get().
    /// </summary>
    public PublicKeyCredentialRequestOptions Options { get; }

    /// <summary>
    /// The mediation level for the credential request.
    /// </summary>
    /// <remarks>Can be "conditional", "optional", "required", or "silent". The default value is "optional".</remarks>
    public string? Mediation { get; }

    /// <summary>
    /// The response to return to JavaScript. Set this property in the event handler.
    /// </summary>
    public string? PublicKeyCredential { get; set; }

    public CredentialRequestEventArgs(PublicKeyCredentialRequestOptions options, string? mediation = null)
    {
        Options = options;
        Mediation = mediation;
    }
}
