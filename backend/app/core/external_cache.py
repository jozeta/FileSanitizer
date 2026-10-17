"""
Universal External API Cache Manager with Persistent SQLite & Redis Accelerator.
Provides durable, TTL-configurable caching across all third-party external intelligence APIs:
- Shodan (Host telemetry, Domain search, DNS records)
- VirusTotal (v3 Domain, IP, and File Hash reports)
- Abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
- AbuseIPDB & AlienVault OTX
- WHOIS / RDAP & BGP Routing
- Google Dork & Sensitive File Artifact Scans
- CISA KEV & NVD CVE Intelligence

Features:
- Policy-driven cache lifetime: user-configurable hours or days, or 'always fetch live'.
- Persistent SQLite database in the job config directory that survives all reboots.
- Automatic Redis second-level acceleration with graceful offline fallback.
- Granular cache status metadata (cached_at, age_seconds, age_human, service).
- Safe stale cache fallback on network/rate-limit failure.
"""

import datetime
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from app.config import get_effective_jobs_dir
from app.core.logging_config import logger
from app.core.redis_cache import redis_cache
from app.core.settings_store import settings_store


def format_age_human(age_seconds: float) -> str:
    """Formats age in seconds into a friendly human-readable label."""
    if age_seconds < 60:
        return "just now"
    minutes = int(age_seconds / 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = round(age_seconds / 3600.0, 1)
    if hours < 24:
        h_int = int(hours) if hours.is_integer() else hours
        return f"{h_int} hour{'s' if h_int != 1 else ''} ago"
    days = round(age_seconds / 86400.0, 1)
    d_int = int(days) if days.is_integer() else days
    return f"{d_int} day{'s' if d_int != 1 else ''} ago"


class ExternalApiCacheManager:
    """
    Thread-safe SQLite + Redis backed persistent cache manager for external APIs.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_db()
        return cls._instance

    def _get_db_path(self) -> Path:
        base = Path(get_effective_jobs_dir()) / "config"
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        return base / "external_api_cache.sqlite"

    def _init_db(self) -> None:
        self._db_path = self._get_db_path()
        self._hits = 0
        self._misses = 0
        try:
            with sqlite3.connect(str(self._db_path), timeout=10.0) as conn:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS external_api_cache (
                        service TEXT NOT NULL,
                        cache_key TEXT NOT NULL,
                        data TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        created_at_iso TEXT NOT NULL,
                        PRIMARY KEY (service, cache_key)
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_created ON external_api_cache (created_at);")
                conn.commit()
            logger.info("External API Cache initialized with SQLite backend at %s", self._db_path)
        except Exception as e:
            logger.error("Failed to initialize external API cache SQLite database: %s", e)

    def _get_cache_policy(self) -> Dict[str, Any]:
        """Reads user cache policy from settings_store."""
        try:
            all_settings = settings_store.get_all(mask_keys=False)
            cs = all_settings.get("cache_settings", {})
        except Exception:
            cs = {}

        mode = cs.get("mode", "use_cache")  # 'use_cache' or 'always_fetch'
        max_age_val = float(cs.get("max_age_value", 24))
        max_age_unit = cs.get("max_age_unit", "hours").lower()  # 'hours' or 'days'

        if max_age_unit == "days":
            max_age_seconds = max_age_val * 86400.0
        else:
            max_age_seconds = max_age_val * 3600.0

        return {
            "mode": mode,
            "max_age_value": max_age_val,
            "max_age_unit": max_age_unit,
            "max_age_seconds": max_age_seconds
        }

    def get(
        self,
        service: str,
        key: str,
        force_refresh: bool = False
    ) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        """
        Retrieves a cached API response if it exists, is fresh according to user policy,
        and force_refresh is not requested.

        Returns (data, cache_info) or (None, None).
        """
        clean_service = service.strip().lower()
        clean_key = str(key).strip().lower()
        policy = self._get_cache_policy()

        # If user selected 'always_fetch' or force_refresh is requested, bypass cache
        if force_refresh or policy["mode"] == "always_fetch":
            self._misses += 1
            return None, None

        now = time.time()
        record = None

        # 1. Check Redis accelerator
        try:
            redis_val = redis_cache.get(f"ext_{clean_service}", clean_key)
            if redis_val and isinstance(redis_val, dict) and "_cached_at_epoch" in redis_val:
                record = {
                    "data": redis_val.get("payload", redis_val),
                    "created_at": redis_val["_cached_at_epoch"],
                    "created_at_iso": redis_val.get("_cached_at_iso", datetime.datetime.now(datetime.timezone.utc).isoformat())
                }
        except Exception as e:
            logger.debug("Redis cache check error for %s:%s: %s", clean_service, clean_key, e)

        # 2. Check SQLite persistent database if not in Redis
        if not record:
            try:
                with sqlite3.connect(str(self._db_path), timeout=5.0) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT data, created_at, created_at_iso FROM external_api_cache WHERE service = ? AND cache_key = ?",
                        (clean_service, clean_key)
                    )
                    row = cursor.fetchone()
                    if row:
                        record = {
                            "data": json.loads(row[0]),
                            "created_at": float(row[1]),
                            "created_at_iso": row[2]
                        }
            except Exception as e:
                logger.debug("SQLite cache read error for %s:%s: %s", clean_service, clean_key, e)

        if not record:
            self._misses += 1
            return None, None

        age_seconds = max(0.0, now - record["created_at"])
        if age_seconds <= policy["max_age_seconds"]:
            # Valid cache hit!
            self._hits += 1
            cache_info = {
                "cached": True,
                "cached_at": record["created_at_iso"],
                "cached_at_epoch": record["created_at"],
                "age_seconds": round(age_seconds, 1),
                "age_hours": round(age_seconds / 3600.0, 2),
                "age_days": round(age_seconds / 86400.0, 2),
                "age_human": format_age_human(age_seconds),
                "service": clean_service,
                "max_age_limit_hours": round(policy["max_age_seconds"] / 3600.0, 1),
                "mode": policy["mode"]
            }

            payload = record["data"]
            if isinstance(payload, dict):
                payload["_cache_info"] = cache_info
                payload["cached"] = True

            return payload, cache_info
        else:
            # Stale according to user policy
            self._misses += 1
            logger.debug(
                "Cache entry %s:%s is stale (age=%.1fs, max=%.1fs)",
                clean_service, clean_key, age_seconds, policy["max_age_seconds"]
            )
            return None, None

    def set(self, service: str, key: str, data: Any) -> Dict[str, Any]:
        """
        Stores API response in persistent SQLite cache and Redis accelerator with UTC timestamp.
        """
        clean_service = service.strip().lower()
        clean_key = str(key).strip().lower()
        now = time.time()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        cache_info = {
            "cached": False,
            "cached_at": now_iso,
            "cached_at_epoch": now,
            "age_seconds": 0.0,
            "age_hours": 0.0,
            "age_days": 0.0,
            "age_human": "just now",
            "service": clean_service
        }

        if isinstance(data, dict):
            # Clean any old cache info before serialization
            data_to_store = dict(data)
            data_to_store.pop("_cache_info", None)
            data_to_store.pop("cached", None)
        else:
            data_to_store = data

        # 1. Write to SQLite
        try:
            data_str = json.dumps(data_to_store)
            with sqlite3.connect(str(self._db_path), timeout=5.0) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO external_api_cache (service, cache_key, data, created_at, created_at_iso)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (clean_service, clean_key, data_str, now, now_iso)
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to write external API cache to SQLite: %s", e)

        # 2. Write to Redis (30 days TTL so it functions as fast accelerator)
        try:
            redis_payload = {
                "payload": data_to_store,
                "_cached_at_epoch": now,
                "_cached_at_iso": now_iso
            }
            redis_cache.set(f"ext_{clean_service}", clean_key, redis_payload, ttl_seconds=2592000)
        except Exception as e:
            logger.debug("Failed to set Redis cache for %s:%s: %s", clean_service, clean_key, e)

        if isinstance(data, dict):
            data["_cache_info"] = cache_info
            data["cached"] = False

        return cache_info

    def get_stale_fallback(self, service: str, key: str) -> Optional[Tuple[Any, Dict[str, Any]]]:
        """
        Retrieves any available cached record regardless of age when the live API call fails.
        """
        clean_service = service.strip().lower()
        clean_key = str(key).strip().lower()
        now = time.time()
        record = None

        try:
            with sqlite3.connect(str(self._db_path), timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT data, created_at, created_at_iso FROM external_api_cache WHERE service = ? AND cache_key = ?",
                    (clean_service, clean_key)
                )
                row = cursor.fetchone()
                if row:
                    record = {
                        "data": json.loads(row[0]),
                        "created_at": float(row[1]),
                        "created_at_iso": row[2]
                    }
        except Exception as e:
            logger.debug("SQLite stale fallback read error for %s:%s: %s", clean_service, clean_key, e)

        if not record:
            return None

        age_seconds = max(0.0, now - record["created_at"])
        cache_info = {
            "cached": True,
            "stale_fallback": True,
            "cached_at": record["created_at_iso"],
            "cached_at_epoch": record["created_at"],
            "age_seconds": round(age_seconds, 1),
            "age_hours": round(age_seconds / 3600.0, 2),
            "age_days": round(age_seconds / 86400.0, 2),
            "age_human": format_age_human(age_seconds),
            "service": clean_service
        }

        payload = record["data"]
        if isinstance(payload, dict):
            payload["_cache_info"] = cache_info
            payload["cached"] = True

        return payload, cache_info

    def clear(self, service: Optional[str] = None) -> int:
        """
        Flushes cached records from SQLite and Redis.
        """
        deleted = 0
        try:
            with sqlite3.connect(str(self._db_path), timeout=5.0) as conn:
                if service:
                    cursor = conn.execute("DELETE FROM external_api_cache WHERE service = ?", (service.strip().lower(),))
                else:
                    cursor = conn.execute("DELETE FROM external_api_cache")
                deleted = cursor.rowcount
                conn.commit()
        except Exception as e:
            logger.error("Failed to clear SQLite cache: %s", e)

        try:
            redis_ns = f"ext_{service.strip().lower()}" if service else None
            redis_cache.clear_cache(namespace=redis_ns)
        except Exception as e:
            logger.debug("Failed to clear Redis keys: %s", e)

        return deleted

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics on cached queries, age distribution, and hit/miss counts."""
        stats: Dict[str, Any] = {
            "total_items": 0,
            "services": {},
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": round((self._hits / (self._hits + self._misses)) * 100, 1) if (self._hits + self._misses) > 0 else 0.0,
            "policy": self._get_cache_policy(),
            "db_size_bytes": 0
        }

        try:
            if self._db_path.exists():
                stats["db_size_bytes"] = self._db_path.stat().st_size
            with sqlite3.connect(str(self._db_path), timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT service, COUNT(*) FROM external_api_cache GROUP BY service")
                for s_name, count in cursor.fetchall():
                    stats["services"][s_name] = count
                    stats["total_items"] += count
        except Exception as e:
            logger.debug("Error computing cache stats: %s", e)

        return stats


external_api_cache = ExternalApiCacheManager()
