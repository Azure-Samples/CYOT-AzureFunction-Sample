using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Cyot.Otp;

// HTTP trigger: POST /api/SendOtp — the SAS → CYOT delivery endpoint. Validates the Entra token, parses
// the cleartext routing envelope, decrypts the JWE delivery context (PII lives there), dispatches to the
// provider, and echoes the nonce to prove decryption. Privacy: phone and OTP code are never logged or
// returned; the response body is the minimal CyotEndpointResponse.
public sealed class SendOtp
{
    private readonly DispatchEngine _engine;
    private readonly TokenValidator _tokens;
    private readonly JweDecryptor _decryptor;
    private readonly ILogger<SendOtp> _log;

    public SendOtp(DispatchEngine engine, TokenValidator tokens, JweDecryptor decryptor, ILogger<SendOtp> log)
    {
        _engine = engine;
        _tokens = tokens;
        _decryptor = decryptor;
        _log = log;
    }

    [Function("SendOtp")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "SendOtp")] HttpRequest req)
    {
        var requestId = Guid.NewGuid().ToString("n");
        var clientRequestId = req.Headers["x-ms-client-request-id"].FirstOrDefault() ?? requestId;
        var headerCorrelationId = req.Headers["x-ms-correlation-id"].FirstOrDefault();

        var auth = await _tokens.ValidateAsync(req.Headers.Authorization.FirstOrDefault());
        if (!auth.Ok)
        {
            _log.LogWarning("[AUTH_ERROR] requestId={RequestId} reason={Reason}", requestId, auth.Reason);
            return new ObjectResult(new { error = "unauthorized", reason = auth.Reason, requestId }) { StatusCode = 401 };
        }

        JsonElement payload;
        try
        {
            using var doc = await JsonDocument.ParseAsync(req.Body);
            payload = doc.RootElement.Clone();
        }
        catch
        {
            _log.LogWarning("[ERROR] requestId={RequestId} invalid JSON body", requestId);
            return new BadRequestObjectResult(new { error = "bad_request", reason = "invalid JSON body", requestId });
        }

        var (envelope, envelopeError) = EnvelopeParser.Parse(payload);
        if (envelopeError is not null)
        {
            _log.LogWarning("[VALIDATION_ERROR] requestId={RequestId} {Reason}", requestId, envelopeError);
            return new BadRequestObjectResult(new { error = "bad_request", reason = envelopeError, requestId });
        }

        var correlationId = envelope!.CorrelationId ?? headerCorrelationId ?? requestId;

        CyotDeliveryContext context;
        try
        {
            context = _decryptor.Decrypt(envelope.EncryptedDeliveryContext);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[DECRYPT_ERROR] requestId={RequestId} correlationId={CorrelationId} reason={Reason}", requestId, correlationId, ex.Message);
            return new ObjectResult(new { error = "decryption_failed", correlationId, requestId }) { StatusCode = 400 };
        }

        if (string.IsNullOrEmpty(context.Nonce) || string.IsNullOrEmpty(context.PhoneNumber) || string.IsNullOrEmpty(context.Message))
        {
            _log.LogWarning("[VALIDATION_ERROR] requestId={RequestId} correlationId={CorrelationId} incomplete delivery context", requestId, correlationId);
            return new ObjectResult(new { error = "bad_request", reason = "incomplete delivery context", correlationId, requestId }) { StatusCode = 400 };
        }

        var evaluation = envelope.Mode == EnvelopeParser.ModeEvaluation;
        var channel = EnvelopeParser.ChannelName(envelope.Channel)!;

        // Respect ttlSeconds: don't start a live delivery for an already-expired passcode (contract §7).
        if (!evaluation && envelope.TtlSeconds is <= 0)
        {
            _log.LogWarning("[EXPIRED] requestId={RequestId} correlationId={CorrelationId} ttl={Ttl}", requestId, correlationId, envelope.TtlSeconds);
            return new ObjectResult(new { error = "request_expired", correlationId, requestId }) { StatusCode = 400 };
        }

        _log.LogInformation(
            "[SENDOTP] requestId={RequestId} caller={Caller} type={Type} tenant={Tenant} correlationId={CorrelationId} channel={Channel} mode={Mode} ttl={Ttl} phone=present message=present risk={Risk}",
            requestId, auth.CallerObjectId ?? "n/a", envelope.Type ?? "n/a", envelope.TenantId ?? "n/a", correlationId,
            envelope.Channel, envelope.Mode, envelope.TtlSeconds?.ToString() ?? "n/a", context.RiskContext.HasValue ? "present" : "absent");

        var dispatch = new DispatchRequest(
            Destination: context.PhoneNumber!,
            Message: context.Message,
            Channel: channel,
            MessageId: clientRequestId,
            CorrelationId: correlationId,
            Locale: context.Locale);

        try
        {
            var result = await _engine.DispatchAsync(dispatch, null, evaluation, requestId, _log);
            // Contract: acceptance is 202 Accepted (async delivery); the engine signals acceptance as 200.
            var accepted = result.HttpStatus == 200;
            return new ObjectResult(new { nonce = context.Nonce, correlationId, providerStatus = accepted ? "accepted" : "failed" })
                { StatusCode = accepted ? 202 : result.HttpStatus };
        }
        catch (Exception ex)
        {
            _log.LogError("[EXCEPTION] requestId={RequestId} error={Error}", requestId, ex.Message);
            return new ObjectResult(new { nonce = context.Nonce, correlationId, providerStatus = "failed" }) { StatusCode = 500 };
        }
    }
}
