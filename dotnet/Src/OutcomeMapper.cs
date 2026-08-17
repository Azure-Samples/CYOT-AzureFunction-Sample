namespace Cyot.Otp;

// Maps a provider's parsed status to a normalized outcome, then to an HTTP status. Fail-closed:
// an unknown/unmapped status is treated as Fail.
public static class OutcomeMapper
{
    public static readonly string[] DefaultChannels = { "sms", "voice" };

    public static Outcome ResolveOutcome(ProviderManifest manifest, ParsedResponse parsed)
    {
        var key = parsed.ProviderStatusName ?? parsed.ProviderStatusCode;
        if (!string.IsNullOrEmpty(key))
        {
            if (manifest.ResponseMapping.TryGetValue(key, out var mapped)) return mapped;
            return manifest.ResponseMapping.TryGetValue("default", out var defaultOutcome) ? defaultOutcome : Outcome.Fail;
        }
        if (parsed.Success) return Outcome.Continue;
        return manifest.ResponseMapping.TryGetValue("default", out var fallbackOutcome) ? fallbackOutcome : Outcome.Fail;
    }

    // Continue 200, Block 403, StepUp 409; a Fail surfaces the provider's failure class.
    public static int ToHttpStatus(Outcome outcome, int providerHttpStatus) => outcome switch
    {
        Outcome.Continue => 200,
        Outcome.Block => 403,
        Outcome.StepUp => 409,
        Outcome.Fail when providerHttpStatus == 429 => 429,
        Outcome.Fail when providerHttpStatus is 401 or 403 => 401,
        Outcome.Fail when providerHttpStatus >= 400 && providerHttpStatus < 500 => 400,
        _ => 502,
    };
}
