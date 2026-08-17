using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cyot.Otp;

// Decrypted JWE plaintext (CyotDeliveryContext). Contains the PII: phone + the rendered message,
// which includes the passcode. Never logged.
public sealed class CyotDeliveryContext
{
    [JsonPropertyName("nonce")] public string? Nonce { get; set; }
    [JsonPropertyName("phoneNumber")] public string? PhoneNumber { get; set; }
    [JsonPropertyName("extension")] public string? Extension { get; set; }
    [JsonPropertyName("locale")] public string? Locale { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("riskContext")] public JsonElement? RiskContext { get; set; }
}

// Supplies the RSA private key for the JWE `kid`. Injectable so tests use a local key, not Key Vault.
public interface IJweKeyProvider
{
    RSA GetPrivateKey(string? kid);
}

// Decrypts the RSA-OAEP-256 + A256GCM JWE compact serialization to a CyotDeliveryContext.
public sealed class JweDecryptor
{
    private readonly IJweKeyProvider _keys;

    public JweDecryptor(IJweKeyProvider keys) => _keys = keys;

    // Reject oversized or structurally invalid JWEs before base64-decoding or allocating buffers.
    private const int MaxJweLength = 16384;

    public CyotDeliveryContext Decrypt(string compactJwe)
    {
        AssertWellFormed(compactJwe);
        var kid = ReadKid(compactJwe);
        var rsa = _keys.GetPrivateKey(kid);
        // Pin alg/enc so a tampered header can't downgrade the crypto (contract: RSA-OAEP-256 + A256GCM).
        var plaintext = Jose.JWT.Decrypt(compactJwe, rsa, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A256GCM);
        return JsonSerializer.Deserialize<CyotDeliveryContext>(plaintext) ?? new CyotDeliveryContext();
    }

    // Contract: exactly five non-empty compact segments; alg/enc/IV/tag are enforced by the JWE decrypt.
    private static void AssertWellFormed(string compactJwe)
    {
        if (string.IsNullOrEmpty(compactJwe))
            throw new InvalidOperationException("malformed JWE");
        if (compactJwe.Length > MaxJweLength)
            throw new InvalidOperationException("delivery context exceeds size limit");
        var segments = compactJwe.Split('.');
        if (segments.Length != 5 || Array.Exists(segments, string.IsNullOrEmpty))
            throw new InvalidOperationException("malformed JWE: expected five non-empty segments");
    }

    public static string? ReadKid(string compactJwe)
    {
        var headers = Jose.JWT.Headers(compactJwe);
        return headers.TryGetValue("kid", out var kid) ? kid?.ToString() : null;
    }
}

// Default key source: an inline PEM (CYOT_JWE_PRIVATE_KEY_PEM, local/dev) or a Key Vault secret
// (name = JWE_PRIVATE_KEY_SECRET, else the `kid`).
public sealed class KeyVaultJweKeyProvider : IJweKeyProvider
{
    private readonly ISecretResolver _secrets;
    private readonly IEnv _env;

    public KeyVaultJweKeyProvider(ISecretResolver secrets, IEnv env)
    {
        _secrets = secrets;
        _env = env;
    }

    public RSA GetPrivateKey(string? kid)
    {
        var pem = _env.Get("CYOT_JWE_PRIVATE_KEY_PEM");
        if (string.IsNullOrEmpty(pem))
        {
            var secretName = _env.Get("JWE_PRIVATE_KEY_SECRET") ?? kid;
            pem = string.IsNullOrEmpty(secretName) ? null : _secrets.ResolveAsync(secretName).GetAwaiter().GetResult();
        }
        if (string.IsNullOrEmpty(pem))
            throw new InvalidOperationException("private key unavailable");

        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }
}
