namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Well-known constants for the WebAuthn protocol and related authenticators.
/// </summary>
public static class WebAuthnConstants
{
    /// <summary>
    /// The credential type for public-key credentials.
    /// </summary>
    public const string PublicKeyCredentialType = "public-key";

    /// <summary>
    /// The client data type for WebAuthn assertion (authentication) operations.
    /// </summary>
    public const string ClientDataTypeGet = "webauthn.get";

    /// <summary>
    /// The authenticator attachment value for platform authenticators.
    /// </summary>
    public const string AuthenticatorAttachmentPlatform = "platform";

    /// <summary>
    /// The authenticator attachment value for cross-platform (roaming) authenticators.
    /// </summary>
    public const string AuthenticatorAttachmentCrossPlatform = "cross-platform";

    /// <summary>
    /// The transport value indicating a platform (internal) authenticator.
    /// </summary>
    public const string AuthenticatorTransportInternal = "internal";

    /// <summary>
    /// The AAGUID of the KeePassXC authenticator.
    /// </summary>
    public static readonly Guid KeePassXCAaGuid = new("fdb141b2-5d84-443e-8a35-4698c205a502");
}
