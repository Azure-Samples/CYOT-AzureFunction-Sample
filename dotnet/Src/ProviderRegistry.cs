namespace Cyot.Otp;

// Registry of provider adapters (keyed by lowercased id), and resolution of the active provider:
// the request's Provider, else the deployment's DEFAULT_PROVIDER. One provider active per deployment.
public sealed class ProviderRegistry
{
    private readonly IReadOnlyDictionary<string, IProviderAdapter> _byId;

    public ProviderRegistry(IEnumerable<IProviderAdapter> adapters)
    {
        _byId = adapters.ToDictionary(a => a.Manifest.Id.ToLowerInvariant(), a => a);
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
            : Environment.GetEnvironmentVariable("DEFAULT_PROVIDER");
        return Get(id);
    }
}
