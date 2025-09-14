from cachetools import TTLCache


class MemoryCache:
    def __init__(self, maxsize: int = 1000, ttl: int = 3600):
        self.cache = TTLCache(maxsize=maxsize, ttl=ttl)

    def set_cache(self, key, value):
        """Set value in the cache with a key and reset its TTL."""
        self.cache[key] = value

    def get_cache(self, key):
        """Get value from the cache by key, returns None if key is expired or not found."""
        return self.cache.get(key, None)

    def update_cache(self, key, value):
        """Update the value for an existing key and reset its TTL."""
        self.set_cache(key, value)
