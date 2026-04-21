namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Contract for the WebAuthn bridge that proxies credential operations between JavaScript and the injector UI.
/// </summary>
public interface IWebAuthnBridge
{
    /// <summary>
    /// Occurs when JavaScript requests an assertion credential.
    /// </summary>
    event EventHandler<CredentialRequestEventArgs>? CredentialRequested;

    /// <summary>
    /// Occurs when JavaScript requests creation of a new credential.
    /// </summary>
    event EventHandler<CredentialCreationEventArgs>? CredentialCreationRequested;

    /// <summary>
    /// Handles a JavaScript request for <c>navigator.credentials.get()</c>.
    /// </summary>
    /// <param name="optionsJson">The serialized WebAuthn request options.</param>
    /// <param name="mediation">The optional mediation preference.</param>
    /// <returns>The serialized credential response, or <see langword="null"/> if no response is available.</returns>
    Task<string?> GetCredentialAsync(string optionsJson, string? mediation = null);

    /// <summary>
    /// Handles a JavaScript request for <c>navigator.credentials.create()</c>.
    /// </summary>
    /// <param name="optionsJson">The serialized WebAuthn creation options.</param>
    /// <returns>The serialized credential response, or <see langword="null"/> if no response is available.</returns>
    Task<string?> CreateCredentialAsync(string optionsJson);
}
