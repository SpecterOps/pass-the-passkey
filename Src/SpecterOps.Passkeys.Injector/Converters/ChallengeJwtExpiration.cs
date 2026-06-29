using System.Buffers.Text;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Extracts an expiration timestamp from a WebAuthn challenge when the challenge carries a JWT.
/// </summary>
internal static class ChallengeJwtExpiration
{
    /// <summary>
    /// Attempts to interpret <paramref name="challenge"/> as a JWT and return its <c>exp</c> claim as a local time.
    /// The challenge bytes may be the UTF-8 representation of a JWT string, optionally prefixed with extra
    /// dot-separated metadata (e.g. Microsoft Entra ID prepends "O.").
    /// </summary>
    public static DateTime? TryGet(byte[]? challenge)
    {
        if (challenge is not { Length: > 0 })
        {
            return null;
        }

        return TryGet(Encoding.UTF8.GetString(challenge));
    }

    /// <summary>
    /// Attempts to interpret <paramref name="challenge"/> as a JWT and return its <c>exp</c> claim as a local time.
    /// The challenge may be a JWT "header.payload.signature" string directly, or it may be base64url-encoded
    /// bytes whose UTF-8 representation is such a string, optionally prefixed with extra dot-separated
    /// metadata (e.g. Microsoft Entra ID prepends "O.").
    /// </summary>
    public static DateTime? TryGet(string challenge)
    {
        if (string.IsNullOrEmpty(challenge))
        {
            return null;
        }

        DateTime? direct = TryParse(challenge);
        if (direct.HasValue)
        {
            return direct;
        }

        try
        {
            byte[] decoded = Base64Url.DecodeFromChars(challenge);
            return TryParse(Encoding.UTF8.GetString(decoded));
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? TryParse(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        // Microsoft Entra ID may prepend "O." before the JWT.
        if (token.StartsWith("O.", StringComparison.Ordinal))
        {
            token = token[2..];
        }

        try
        {
            var jwt = new JsonWebToken(token);
            // JsonWebToken.ValidTo is DateTime.MinValue (UTC) when the token has no exp claim.
            return jwt.ValidTo == DateTime.MinValue ? null : jwt.ValidTo.ToLocalTime();
        }
        catch
        {
            return null;
        }
    }
}
