"""Registry of provider adapters + resolution of the active provider."""
import os


class ProviderRegistry:
    def __init__(self, adapters):
        self._by_id = {adapter.manifest["id"].lower(): adapter for adapter in adapters}

    def get(self, provider_id):
        if not provider_id:
            return None
        return self._by_id.get(provider_id.lower())

    def resolve(self, request_provider):
        provider_id = request_provider or os.environ.get("DEFAULT_PROVIDER")
        return self.get(provider_id)
