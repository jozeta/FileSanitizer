"""
Redis Caching Infrastructure for External Threat Intelligence and Network Lookups.
Provides high-performance TTL-based caching for VirusTotal, CrowdStrike, ThreatFox,
MalwareBazaar, AlienVault OTX, WHOIS/RDAP, and GeoIP queries to minimize external API usage.
"""

import json
import os
import threading
from typing import Any, Dict, Optional
import redis

from app.core.logging_config import logger


class RedisCacheManager:
    """
    Centralized caching layer using Redis with graceful offline fallback.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_client()
        return cls._instance

    def _init_client(self) -> None:
        self.redis_url = os.getenv("REDIS_URL", "redis://filesanitizer-redis:6379/0")
        self._client: Optional[redis.Redis] = None
        self._is_connected = False
        self._hits = 0
        self._misses = 0

        try:
            self._client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
                retry_on_timeout=True
            )
            self._client.ping()
            self._is_connected = True
            logger.info("Connected to Redis intelligence cache at %s", self.redis_url)
        except Exception as e:
            logger.warning("Redis intelligence cache unavailable (%s); operating with in-memory pass-through", e)
            self._is_connected = False

    def _check_connection(self) -> bool:
        if self._client is None:
            self._init_client()
            return self._is_connected
        try:
            self._client.ping()
            self._is_connected = True
            return True
        except Exception:
            self._is_connected = False
            return False

    def is_available(self) -> bool:
        """Return True if Redis is reachable."""
        return self._check_connection()

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """Retrieve and parse JSON object from Redis cache."""
        clean_key = f"fs_cache:{namespace}:{str(key).strip().lower()}"
        if not self._check_connection():
            return None

        try:
            val = self._client.get(clean_key)
            if val is not None:
                self._hits += 1
                return json.loads(val)
            self._misses += 1
            return None
        except Exception as e:
            logger.debug("Redis cache read error for %s: %s", clean_key, e)
            return None

    def set(self, namespace: str, key: str, value: Any, ttl_seconds: int = 86400) -> bool:
        """Store JSON-serializable value in Redis cache with TTL."""
        clean_key = f"fs_cache:{namespace}:{str(key).strip().lower()}"
        if not self._check_connection() or value is None:
            return False

        try:
            serialized = json.dumps(value)
            return bool(self._client.setex(clean_key, ttl_seconds, serialized))
        except Exception as e:
            logger.debug("Redis cache write error for %s: %s", clean_key, e)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Return cache health, memory usage, key counts, and hit/miss statistics."""
        stats = {
            "connected": False,
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": round((self._hits / (self._hits + self._misses)) * 100, 1) if (self._hits + self._misses) > 0 else 0.0,
            "total_cached_items": 0,
            "namespaces": {},
            "used_memory_human": "0B"
        }

        if not self._check_connection():
            return stats

        try:
            stats["connected"] = True
            info = self._client.info()
            stats["used_memory_human"] = info.get("used_memory_human", "0B")

            # Scan cache keys
            keys = self._client.keys("fs_cache:*")
            stats["total_cached_items"] = len(keys)

            ns_counts: Dict[str, int] = {}
            for k in keys:
                parts = k.split(":")
                if len(parts) >= 2:
                    ns = parts[1]
                    ns_counts[ns] = ns_counts.get(ns, 0) + 1
            stats["namespaces"] = ns_counts
        except Exception as e:
            logger.debug("Failed to retrieve Redis cache stats: %s", e)

        return stats

    def clear_cache(self, namespace: Optional[str] = None) -> int:
        """Purge all cached intelligence items or a specific namespace."""
        if not self._check_connection():
            return 0

        try:
            pattern = f"fs_cache:{namespace}:*" if namespace else "fs_cache:*"
            keys = self._client.keys(pattern)
            if keys:
                deleted = self._client.delete(*keys)
                return int(deleted)
            return 0
        except Exception as e:
            logger.error("Failed to flush Redis cache keys for %s: %s", namespace, e)
            return 0


# Global singleton instance
redis_cache = RedisCacheManager()
