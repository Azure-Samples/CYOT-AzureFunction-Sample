using System.Text.Json;

namespace Cyot.Otp;

// The cleartext SAS → CYOT routing envelope (SendCyotOtpRequest). PII lives in the encrypted JWE.
public sealed record CyotEnvelope(
    string? Type,
    string? TenantId,
    string? CorrelationId,
    int Channel,
    int Mode,
    int? TtlSeconds,
    string EncryptedDeliveryContext);

// Parses + validates the cleartext envelope (see docs/CONTRACT.md §1).
public static class EnvelopeParser
{
    public const int ModeLive = 1;
    public const int ModeEvaluation = 2;

    private static readonly Dictionary<int, string> ChannelByCode = new() { [1] = "sms", [2] = "voice" };
    private static readonly Dictionary<string, int> ChannelByName = new(StringComparer.OrdinalIgnoreCase) { ["sms"] = 1, ["voice"] = 2 };
    private static readonly Dictionary<string, int> ModeByName = new(StringComparer.OrdinalIgnoreCase) { ["live"] = ModeLive, ["evaluation"] = ModeEvaluation };

    public static string? ChannelName(int code) => ChannelByCode.TryGetValue(code, out var name) ? name : null;

    public static (CyotEnvelope? Envelope, string? Error) Parse(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
            return (null, "invalid envelope");

        string? String(string name) =>
            payload.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        int? Int(string name) =>
            payload.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;

        // channel/mode accept the int enum (1/2) or the string form ("sms"/"voice", "live"/"evaluation").
        int? Channel()
        {
            var code = Int("channel");
            if (code is not null) return ChannelByCode.ContainsKey(code.Value) ? code : null;
            var name = String("channel");
            return name is not null && ChannelByName.TryGetValue(name, out var mapped) ? mapped : null;
        }
        int? Mode()
        {
            var code = Int("mode");
            if (code is not null) return code is ModeLive or ModeEvaluation ? code : null;
            var name = String("mode");
            return name is not null && ModeByName.TryGetValue(name, out var mapped) ? mapped : null;
        }

        var encrypted = String("encryptedDeliveryContext");
        if (string.IsNullOrEmpty(encrypted))
            return (null, "encryptedDeliveryContext is required");

        var channel = Channel();
        if (channel is null)
            return (null, "unsupported channel");

        var mode = Mode();
        if (mode is null)
            return (null, "unsupported mode");

        return (new CyotEnvelope(String("type"), String("tenantId"), String("correlationId"),
            channel.Value, mode.Value, Int("ttlSeconds"), encrypted), null);
    }
}
