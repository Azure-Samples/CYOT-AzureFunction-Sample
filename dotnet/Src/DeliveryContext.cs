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

// Result of a successful decrypt: the protected header (for kid/alg logging) plus the plaintext context.
public sealed record JweResult(string? Kid, string? Alg, string? Enc, CyotDeliveryContext Context);

// Supplies the RSA private key for the JWE `kid`. Injectable so tests use a local key.
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

    public JweResult Decrypt(string compactJwe)
    {
        AssertWellFormed(compactJwe);
        var headers = Jose.JWT.Headers(compactJwe);
        var kid = headers.TryGetValue("kid", out var kidValue) ? kidValue?.ToString() : null;
        var alg = headers.TryGetValue("alg", out var algValue) ? algValue?.ToString() : null;
        var enc = headers.TryGetValue("enc", out var encValue) ? encValue?.ToString() : null;
        var rsa = _keys.GetPrivateKey(kid);
        // Pin alg/enc so a tampered header can't downgrade the crypto (contract: RSA-OAEP-256 + A256GCM).
        var plaintext = Jose.JWT.Decrypt(compactJwe, rsa, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A256GCM);
        var context = JsonSerializer.Deserialize<CyotDeliveryContext>(plaintext) ?? new CyotDeliveryContext();
        return new JweResult(kid, alg, enc, context);
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
}

// Key source: the EPP_DECRYPTION_KEY_PEM app setting, which is a Key Vault reference — the runtime only
// ever sees the resolved PEM. Imported once, because doing it per delivery would add an RSA import
// inside the response budget and turn a bad key into a failure on every call.
public sealed class EnvJweKeyProvider : IJweKeyProvider
{
    private readonly IEnv _env;
    private RSA? _cached;
    private string? _cachedPem;

    public EnvJweKeyProvider(IEnv env) => _env = env;

    public RSA GetPrivateKey(string? kid)
    {
        var pem = _env.Get("EPP_DECRYPTION_KEY_PEM");
        if (string.IsNullOrEmpty(pem))
            throw new InvalidOperationException("private key unavailable (EPP_DECRYPTION_KEY_PEM is not set)");

        if (_cached is not null && _cachedPem == pem) return _cached;

        var rsa = RSA.Create();
        rsa.ImportFromPem(NormalizePem(pem));
        _cached = rsa;
        _cachedPem = pem;
        return rsa;
    }

    // The setup script stores the key as base64 over the PEM so its newlines survive being carried as a
    // secret and then as an app setting, so accept either form.
    private static string NormalizePem(string value) =>
        value.Contains("-----BEGIN", StringComparison.Ordinal)
            ? value
            : System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(value.Trim()));
}
