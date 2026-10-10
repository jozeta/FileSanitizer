import base64
import urllib.parse
from typing import Dict, Any, Optional
import httpx

from app.core.settings_store import settings_store
from app.core.logging_config import logger
from app.core.redis_cache import redis_cache

VT_BASE_URL = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    @staticmethod
    def get_api_key() -> str:
        return settings_store.get_api_key("virustotal_api_key")

    @staticmethod
    def is_configured() -> bool:
        return bool(VirusTotalClient.get_api_key())

    @staticmethod
    def get_hash_web_link(sha256: str) -> str:
        return f"https://www.virustotal.com/gui/file/{sha256}"

    @staticmethod
    def get_url_web_link(url: str) -> str:
        encoded = urllib.parse.quote(url, safe="")
        return f"https://www.virustotal.com/gui/search/{encoded}"

    @classmethod
    def lookup_file_hash(cls, sha256: str) -> Dict[str, Any]:
        """
        Check file hash on VirusTotal with Redis cache support.
        If API key is configured, queries VT API v3.
        If not configured, returns direct web link for manual inspection.
        """
        api_key = cls.get_api_key()
        web_link = cls.get_hash_web_link(sha256)

        # Check Redis Cache first
        cached = redis_cache.get("vt_file", sha256)
        if cached and isinstance(cached, dict):
            cached["cached"] = True
            return cached

        if not api_key:
            return {
                "configured": False,
                "queried": False,
                "web_link": web_link,
                "sha256": sha256,
                "message": "VirusTotal API key not configured. Click the direct link to inspect."
            }

        try:
            headers = {
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "FileSanitizer-Platform/1.0"
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.get(f"{VT_BASE_URL}/files/{sha256}", headers=headers)

                if res.status_code == 200:
                    data = res.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    results = attr.get("last_analysis_results", {})

                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    total_count = sum(stats.values()) if stats else 0

                    flagged_engines = []
                    for engine, eng_res in results.items():
                        if eng_res.get("category") in ["malicious", "suspicious"]:
                            flagged_engines.append({
                                "engine": engine,
                                "category": eng_res.get("category"),
                                "result": eng_res.get("result")
                            })

                    popular_threat = attr.get("popular_threat_classification", {})
                    suggested_threat_label = popular_threat.get("suggested_threat_label", "")
                    threat_category = popular_threat.get("popular_threat_category", [{}])[0].get("value") if popular_threat.get("popular_threat_category") else None

                    result_data = {
                        "configured": True,
                        "queried": True,
                        "found": True,
                        "web_link": web_link,
                        "sha256": sha256,
                        "positives": malicious_count + suspicious_count,
                        "total_engines": total_count,
                        "malicious_count": malicious_count,
                        "suspicious_count": suspicious_count,
                        "reputation": attr.get("reputation", 0),
                        "meaningful_name": attr.get("meaningful_name", ""),
                        "type_description": attr.get("type_description", ""),
                        "suggested_threat_label": suggested_threat_label,
                        "threat_category": threat_category,
                        "tags": attr.get("tags", [])[:8],
                        "times_submitted": attr.get("times_submitted", 1),
                        "first_submission_date": attr.get("first_submission_date"),
                        "last_analysis_date": attr.get("last_analysis_date"),
                        "flagged_engines": flagged_engines[:15]
                    }
                    redis_cache.set("vt_file", sha256, result_data, ttl_seconds=86400)
                    return result_data

                elif res.status_code == 404:
                    not_found_data = {
                        "configured": True,
                        "queried": True,
                        "found": False,
                        "web_link": web_link,
                        "sha256": sha256,
                        "message": "File hash not found in VirusTotal database (unseen sample)."
                    }
                    redis_cache.set("vt_file", sha256, not_found_data, ttl_seconds=21600)
                    return not_found_data
                else:
                    return {
                        "configured": True,
                        "queried": True,
                        "found": False,
                        "web_link": web_link,
                        "sha256": sha256,
                        "error": f"VirusTotal API returned HTTP {res.status_code}"
                    }

        except Exception as e:
            logger.warning(f"VirusTotal hash query failed for {sha256}: {e}")
            return {
                "configured": True,
                "queried": False,
                "web_link": web_link,
                "sha256": sha256,
                "error": str(e)
            }

    @classmethod
    def lookup_url(cls, url: str) -> Dict[str, Any]:
        """
        Check URL on VirusTotal v3 with Redis cache.
        """
        api_key = cls.get_api_key()
        web_link = cls.get_url_web_link(url)

        # Check Redis Cache
        cached = redis_cache.get("vt_url", url)
        if cached and isinstance(cached, dict):
            cached["cached"] = True
            return cached

        if not api_key:
            return {
                "configured": False,
                "queried": False,
                "web_link": web_link,
                "url": url
            }

        try:
            # URL identifier is base64 without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "FileSanitizer-Platform/1.0"
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    res_obj = {
                        "configured": True,
                        "queried": True,
                        "found": True,
                        "web_link": web_link,
                        "url": url,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "total": sum(stats.values()) if stats else 0,
                        "reputation": attr.get("reputation", 0)
                    }
                    redis_cache.set("vt_url", url, res_obj, ttl_seconds=86400)
                    return res_obj
                elif res.status_code == 404:
                    nf_obj = {
                        "configured": True,
                        "queried": True,
                        "found": False,
                        "web_link": web_link,
                        "url": url,
                        "message": "URL not found in VirusTotal database."
                    }
                    redis_cache.set("vt_url", url, nf_obj, ttl_seconds=21600)
                    return nf_obj
                else:
                    return {
                        "configured": True,
                        "queried": True,
                        "web_link": web_link,
                        "url": url,
                        "error": f"HTTP {res.status_code}"
                    }
        except Exception as e:
            return {
                "configured": True,
                "queried": False,
                "web_link": web_link,
                "url": url,
                "error": str(e)
            }
