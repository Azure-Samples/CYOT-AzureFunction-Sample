using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Cyot.Otp;

// Core engine: resolve provider -> credential (Key Vault) -> endpoint -> adapter builds request ->
// send with a timeout -> map status to outcome + HTTP status. Fail-closed.
public sealed class DispatchEngine
{
    private const int DefaultTimeoutMs = 1500;
    private readonly ProviderRegistry _registry;
    private readonly ISecretResolver _secrets;
    private readonly IHttpClientFactory _httpFactory;
    private readonly IEnv _env;

    public DispatchEngine(ProviderRegistry registry, ISecretResolver secrets, IHttpClientFactory httpFactory, IEnv? env = null)
    {
        _registry = registry;
        _secrets = secrets;
        _httpFactory = httpFactory;
        _env = env ?? new ProcessEnv();
    }

    public async Task<DispatchResult> DispatchAsync(DispatchRequest dispatch, string? requestProvider, bool shutter, string requestId, ILogger log)
    {
        var adapter = _registry.Resolve(requestProvider);
        if (adapter is null)
        {
            log.LogWarning("[DISPATCH_ERROR] requestId={RequestId} unknown provider={Provider}", requestId, requestProvider ?? "n/a");
            return new DispatchResult(400, new { status = "error", reason = "unknown provider", requestId });
        }

        var manifest = adapter.Manifest;
        var providerId = manifest.Id;
        var channel = (dispatch.Channel ?? "sms").ToLowerInvariant();

        if (!OutcomeMapper.DefaultChannels.Contains(channel))
            return new DispatchResult(400, new { status = "error", provider = providerId, reason = $"channel '{channel}' not supported", requestId });

        // Credential (fail closed 502 if missing) — this is our credential, not the caller's token.
        ProviderCredential? credential = null;
        try { credential = await ResolveCredentialAsync(manifest.Auth); }
        catch (Exception ex) { log.LogError("[DISPATCH_ERROR] requestId={RequestId} provider={Provider} credential error={Error}", requestId, providerId, ex.Message); }

        var identityRequired = credential is { Mode: "apiKey" } && !string.IsNullOrEmpty(manifest.Auth.IdentityKeyVaultSecretName);
        var credentialUnavailable = credential is null
            || (credential.Mode == "oauth2" && string.IsNullOrEmpty(credential.Token))
            || (credential.Mode == "apiKey" && string.IsNullOrEmpty(credential.Secret))
            || (identityRequired && string.IsNullOrEmpty(credential.Identity));
        if (credentialUnavailable)
            return new DispatchResult(502, FailBody(providerId, channel, "provider credential unavailable", dispatch, requestId));

        var endpoint = ResolveEndpoint(manifest, _env);
        if (string.IsNullOrEmpty(endpoint))
            return new DispatchResult(502, FailBody(providerId, channel, "provider endpoint not configured", dispatch, requestId));

        var req = adapter.BuildRequest(channel, endpoint, dispatch, credential!, _env);
        log.LogInformation("[DISPATCH] requestId={RequestId} provider={Provider} channel={Channel} shutter={Shutter}", requestId, providerId, channel, shutter);

        if (shutter)
            return new DispatchResult(200, new { status = "accepted", shutterProcessed = true, provider = providerId, channel, correlationId = dispatch.CorrelationId, messageId = dispatch.MessageId, requestId });

        var timeoutMs = int.TryParse(_env.Get("EPP_PROVIDER_TIMEOUT_MS"), out var parsedTimeout) ? parsedTimeout : DefaultTimeoutMs;
        HttpResponseMessage resp;
        string body;
        try
        {
            (resp, body) = await SendAsync(req, timeoutMs);
        }
        catch (OperationCanceledException)
        {
            log.LogWarning("[DISPATCH_TIMEOUT] requestId={RequestId} provider={Provider}", requestId, providerId);
            return new DispatchResult(504, FailBody(providerId, channel, $"endpoint timeout after {timeoutMs}ms", dispatch, requestId));
        }
        catch (Exception ex)
        {
            log.LogError("[DISPATCH_ERROR] requestId={RequestId} provider={Provider} reason={Reason}", requestId, providerId, ex.Message);
            return new DispatchResult(502, FailBody(providerId, channel, ex.Message, dispatch, requestId));
        }

        JsonElement json;
        try { using var responseDocument = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body); json = responseDocument.RootElement.Clone(); }
        catch { using var emptyDocument = JsonDocument.Parse("{}"); json = emptyDocument.RootElement.Clone(); }

        var parsed = adapter.ParseResponse((int)resp.StatusCode, resp.IsSuccessStatusCode, json);
        var outcome = OutcomeMapper.ResolveOutcome(manifest, parsed);
        var httpStatus = OutcomeMapper.ToHttpStatus(outcome, parsed.ProviderHttpStatus);

        log.LogInformation("[DISPATCH_RESULT] requestId={RequestId} provider={Provider} channel={Channel} outcome={Outcome} providerStatus={Status} httpStatus={Http}",
            requestId, providerId, channel, outcome, parsed.ProviderStatusName ?? parsed.ProviderStatusCode ?? "n/a", httpStatus);

        return new DispatchResult(httpStatus, new
        {
            status = outcome == Outcome.Continue ? "accepted" : "failed",
            outcome = outcome.ToString(),
            provider = providerId,
            channel,
            messageId = dispatch.MessageId,
            correlationId = dispatch.CorrelationId,
            providerMessageId = parsed.ProviderMessageId,
            providerStatus = parsed.ProviderStatusName ?? parsed.ProviderStatusCode,
            providerStatusDescription = parsed.ProviderStatusDescription,
            requestId,
        });
    }

    private async Task<ProviderCredential> ResolveCredentialAsync(AuthConfig auth)
    {
        if (auth.Mode == "oauth2") return new ProviderCredential("oauth2", Token: null); // not wired -> fails closed
        var secret = await _secrets.ResolveAsync(auth.KeyVaultSecretName);
        var identity = string.IsNullOrEmpty(auth.IdentityKeyVaultSecretName) ? string.Empty : await _secrets.ResolveAsync(auth.IdentityKeyVaultSecretName);
        return new ProviderCredential("apiKey", Secret: secret, Identity: identity);
    }

    // Base URL from app settings: one provider is active per deployment, so the endpoint is a single
    // EPP_PROVIDER_ENDPOINT rather than a per-provider key.
    private static string? ResolveEndpoint(ProviderManifest manifest, IEnv env) => env.Get("EPP_PROVIDER_ENDPOINT");

    private async Task<(HttpResponseMessage, string)> SendAsync(ProviderHttpRequest req, int timeoutMs)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var client = _httpFactory.CreateClient();
        using var message = new HttpRequestMessage(new HttpMethod(req.Method), req.Url)
        {
            Content = new StringContent(req.Body, Encoding.UTF8, req.Headers.TryGetValue("Content-Type", out var ct) ? ct : "application/json"),
        };
        foreach (var (k, v) in req.Headers)
        {
            if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
            if (!message.Headers.TryAddWithoutValidation(k, v)) message.Content.Headers.TryAddWithoutValidation(k, v);
        }
        var resp = await client.SendAsync(message, cts.Token);
        var body = await resp.Content.ReadAsStringAsync(cts.Token);
        return (resp, body);
    }

    private static object FailBody(string provider, string channel, string reason, DispatchRequest d, string requestId) =>
        new { status = "failed", outcome = "Fail", provider, channel, reason, correlationId = d.CorrelationId, messageId = d.MessageId, requestId };
}
