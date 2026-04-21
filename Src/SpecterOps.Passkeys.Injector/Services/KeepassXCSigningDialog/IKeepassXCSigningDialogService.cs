namespace SpecterOps.Passkeys.Injector;

public interface IKeepassXCSigningDialogService
{
    string? SignCredential(
        string challenge,
        string rpId,
        string? userVerification = null,
        PublicKeyCredentialDescriptor[]? allowCredentials = null);
}
