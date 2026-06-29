using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// WebAuthn bridge that acts as a proxy between JavaScript in WebView2 and the native WebAuthn implementation.
/// This class is exposed to JavaScript via COM interop.
/// </summary>
[ClassInterface(ClassInterfaceType.AutoDual)]
[ComVisible(true)]
public class WebAuthnBridge : IWebAuthnBridge
{
    /// <summary>
    /// Event raised when a credential is requested from JavaScript.
    /// </summary>
    public event EventHandler<CredentialRequestEventArgs>? CredentialRequested;

    /// <summary>
    /// Event raised when a credential creation is requested from JavaScript.
    /// </summary>
    public event EventHandler<CredentialCreationEventArgs>? CredentialCreationRequested;

    /// <summary>
    /// Handles the navigator.credentials.get() call from JavaScript.
    /// </summary>
    /// <param name="optionsJson">The PublicKeyCredentialRequestOptions from JavaScript as a JSON string.</param>
    /// <returns>A PublicKeyCredential response as a JSON string, or null if the operation fails.</returns>
    public Task<string?> GetCredentialAsync(string optionsJson, string? mediation = null)
    {
        try
        {
            Debug.WriteLine($"WebAuthnBridge.GetCredentialAsync options JSON: {optionsJson}");
            var eventArgs = new CredentialRequestEventArgs(optionsJson, mediation);
            CredentialRequested?.Invoke(this, eventArgs);
            return Task.FromResult(eventArgs.PublicKeyCredential);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WebAuthnBridge.GetCredentialAsync error: {ex.Message}");
            // Return null if the operation fails, so that the native WebAuthn flow can proceed.
            return Task.FromResult<string?>(null);
        }
    }

    /// <summary>
    /// Handles the navigator.credentials.create() call from JavaScript.
    /// </summary>
    /// <param name="optionsJson">The PublicKeyCredentialCreationOptions from JavaScript as a JSON string.</param>
    /// <param name="mediation">The mediation value from JavaScript.</param>
    /// <returns>A PublicKeyCredential response as a JSON string, or null if the operation fails.</returns>
    public Task<string?> CreateCredentialAsync(string optionsJson, string? mediation = null)
    {
        try
        {
            Debug.WriteLine($"WebAuthnBridge.CreateCredentialAsync options JSON: {optionsJson}");
            var eventArgs = new CredentialCreationEventArgs(optionsJson, mediation);
            CredentialCreationRequested?.Invoke(this, eventArgs);
            return Task.FromResult(eventArgs.PublicKeyCredential);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WebAuthnBridge.CreateCredentialAsync error: {ex.Message}");
            // Return null if the operation fails, so that the native WebAuthn flow can proceed.
            return Task.FromResult<string?>(null);
        }
    }
}
