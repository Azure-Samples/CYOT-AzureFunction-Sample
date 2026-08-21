using System.Text.Json;
using Cyot.Otp;
using Cyot.Otp.Providers;
using Xunit;

namespace Cyot.Otp.Tests;

// Conformance tests for the pure contract logic (see /docs/CONTRACT.md §6).
public class ContractTests
{
    private sealed class FakeEnv : Dictionary<string, string?>, IEnv
    {
        public string? Get(string key) => TryGetValue(key, out var v) ? v : null;
    }

    private static DispatchRequest Disp(string channel = "sms", string? message = null) =>
        new("+15551234567", message, channel, "m", "c", null);

    [Fact]
    public void OutcomeMappingAndHttpStatus()
    {
        var m = new InfobipProvider().Manifest;
        Assert.Equal(Outcome.Continue, OutcomeMapper.ResolveOutcome(m, new ParsedResponse(true, 200, ProviderStatusName: "DELIVERED")));
        // Unknown status fails closed even on HTTP 200.
        Assert.Equal(Outcome.Fail, OutcomeMapper.ResolveOutcome(m, new ParsedResponse(true, 200, ProviderStatusName: "WATWAT")));
        Assert.Equal(200, OutcomeMapper.ToHttpStatus(Outcome.Continue, 200));
        Assert.Equal(403, OutcomeMapper.ToHttpStatus(Outcome.Block, 200));
        Assert.Equal(409, OutcomeMapper.ToHttpStatus(Outcome.StepUp, 200));
        Assert.Equal(429, OutcomeMapper.ToHttpStatus(Outcome.Fail, 429));
        Assert.Equal(401, OutcomeMapper.ToHttpStatus(Outcome.Fail, 403));
        Assert.Equal(400, OutcomeMapper.ToHttpStatus(Outcome.Fail, 422));
        Assert.Equal(502, OutcomeMapper.ToHttpStatus(Outcome.Fail, 500));
    }

    [Fact]
    public void InfobipBuildsHttpsSmsRequestWithAppAuthAndCode()
    {
        var env = new FakeEnv { ["EPP_PROVIDER_ACCOUNT_NAME"] = "CYOT" };
        var req = new InfobipProvider().BuildRequest("sms", "https://api.infobip.com",
            Disp(message: "Use verification code 918273 for Microsoft authentication."),
            new ProviderCredential("apiKey", Secret: "ib"), env);

        Assert.StartsWith("https://", req.Url);
        Assert.EndsWith("/sms/3/messages", req.Url);
        Assert.StartsWith("App ", req.Headers["Authorization"]);
        Assert.Contains("918273", req.Body);
    }

    [Fact]
    public void TelesignUsesBasicAuthAndVoiceMapping()
    {
        var env = new FakeEnv();
        var req = new TelesignProvider().BuildRequest("sms", "https://rest-api.telesign.com",
            Disp(message: "code 918273"), new ProviderCredential("apiKey", Secret: "key", Identity: "cust"), env);
        Assert.StartsWith("Basic ", req.Headers["Authorization"]);
        Assert.EndsWith("/v1/messaging", req.Url);

        var m = new TelesignProvider().Manifest;
        Assert.Equal(Outcome.Continue, OutcomeMapper.ResolveOutcome(m, new ParsedResponse(true, 200, ProviderStatusCode: "100")));
    }

    [Fact]
    public void ProviderRegistryResolvesById()
    {
        var reg = new ProviderRegistry(new IProviderAdapter[]
        {
            new InfobipProvider(), new TelesignProvider(), new SopranoProvider(), new SinchProvider(),
        });
        Assert.Equal("telesign", reg.Get("TELESIGN")!.Manifest.Id);
        Assert.Null(reg.Get("nope"));
    }
}
