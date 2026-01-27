using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// WebAuthn bridge that acts as a proxy between JavaScript in WebView2 and the native WebAuthn implementation.
/// This class is exposed to JavaScript via COM interop.
/// </summary>
[ClassInterface(ClassInterfaceType.AutoDual)]
[ComVisible(true)]
public class WebAuthnBridge
{
    /// <summary>
    /// Event raised when a credential is requested from JavaScript.
    /// </summary>
    public event EventHandler<CredentialRequestEventArgs>? CredentialRequested;

    /// <summary>
    /// Handles the navigator.credentials.get() call from JavaScript.
    /// </summary>
    /// <param name="optionsJson">The PublicKeyCredentialRequestOptions from JavaScript as a JSON string.</param>
    /// <returns>A PublicKeyCredential response as a JSON string, or null if the operation fails.</returns>
    public async Task<string?> GetCredentialAsync(string optionsJson, string? mediation = null)
    {
        try
        {
            var requestOptions = PublicKeyCredentialRequestOptions.FromJson(optionsJson);

            if (requestOptions != null)
            {
                // Raise the event to notify listeners about the credential request
                var eventArgs = new CredentialRequestEventArgs(requestOptions, mediation);
                CredentialRequested?.Invoke(this, eventArgs);

                // If a response was provided by the event handler, return it as JSON
                if (eventArgs.PublicKeyCredential != null)
                {
                    return eventArgs.PublicKeyCredential;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WebAuthnBridge.GetCredentialAsync error: {ex.Message}");
        }

        // Return null if the operation fails
        return null;
    }
}

