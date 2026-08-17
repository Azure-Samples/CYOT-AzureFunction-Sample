using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Cyot.Otp;

// Validates the Entra JWT when REQUIRE_AUTH=true (aud=EXPECTED_AUDIENCE, issuer tenant=ISSUER_TENANT_ID,
// RS256 via JWKS). No-op pass-through when REQUIRE_AUTH is not "true".
public sealed class TokenValidator
{
    private readonly JwtSecurityTokenHandler _handler = new();
    private ConfigurationManager<OpenIdConnectConfiguration>? _configManager;

    public sealed record Result(bool Ok, string? Reason = null, string? CallerObjectId = null);

    public async Task<Result> ValidateAsync(string? authorizationHeader)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("REQUIRE_AUTH"), "true", StringComparison.OrdinalIgnoreCase))
            return new Result(true);

        var audience = Environment.GetEnvironmentVariable("EXPECTED_AUDIENCE");
        var tenantId = Environment.GetEnvironmentVariable("ISSUER_TENANT_ID");
        if (string.IsNullOrEmpty(audience) || string.IsNullOrEmpty(tenantId))
            return new Result(false, "auth misconfigured");

        if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return new Result(false, "missing bearer token");

        var token = authorizationHeader["Bearer ".Length..].Trim();
        var authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
        _configManager ??= new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());

        try
        {
            var config = await _configManager.GetConfigurationAsync();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = new[] { $"https://login.microsoftonline.com/{tenantId}/v2.0", $"https://sts.windows.net/{tenantId}/" },
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateIssuerSigningKey = true,
            };
            var principal = _handler.ValidateToken(token, parameters, out _);
            var oid = principal.FindFirst("oid")?.Value ?? principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
            return new Result(true, CallerObjectId: oid);
        }
        catch
        {
            return new Result(false, "token validation failed");
        }
    }
}
