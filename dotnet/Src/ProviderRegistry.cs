namespace Epp.Otp;

// Registry of provider adapters (keyed by lowercased id), and resolution of the active provider:
// the request's Provider, else the deployment's EPP_PROVIDER_NAME. One provider active per deployment.
public sealed class ProviderRegistry
{
    private readonly IReadOnlyDictionary<string, IProviderAdapter> _byId;
    private readonly IEnv _env;

    public ProviderRegistry(IEnumerable<IProviderAdapter> adapters, IEnv? env = null)
    {
        _byId = adapters.ToDictionary(a => a.Manifest.Id.ToLowerInvariant(), a => a);
        _env = env ?? new ProcessEnv();
    }

    public IProviderAdapter? Get(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        return _byId.TryGetValue(id.ToLowerInvariant(), out var adapter) ? adapter : null;
    }

    public IProviderAdapter? Resolve(string? requestProvider)
    {
        var id = !string.IsNullOrWhiteSpace(requestProvider)
            ? requestProvider
            : _env.Get("EPP_PROVIDER_NAME");
        return Get(id);
    }
}
