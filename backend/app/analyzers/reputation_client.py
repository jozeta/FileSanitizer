import re
import time
from typing import Dict, Any, Optional, Tuple
import httpx

from app.config import settings
from app.core.settings_store import settings_store
from app.core.logging_config import logger
from app.core.redis_cache import redis_cache

# Hybrid in-memory and Redis intelligence cache for IP, domain, hash and reputation lookups
class ReputationCacheDict(dict):
    """Transparent Redis-backed cache dictionary with in-memory fast tier."""
    def __contains__(self, key):
        if super().__contains__(key):
            ts, _ = super().__getitem__(key)
            if time.time() - ts < CACHE_TTL_SECONDS:
                return True
        val = redis_cache.get("reputation", str(key))
        if val is not None and isinstance(val, dict):
            super().__setitem__(key, (time.time(), val))
            return True
        return False

    def __getitem__(self, key):
        if super().__contains__(key):
            ts, val = super().__getitem__(key)
            if time.time() - ts < CACHE_TTL_SECONDS:
                return ts, val
        val = redis_cache.get("reputation", str(key))
        if val is not None and isinstance(val, dict):
            res = (time.time(), val)
            super().__setitem__(key, res)
            return res
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], dict):
            redis_cache.set("reputation", str(key), value[1], ttl_seconds=86400)

_REPUTATION_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = ReputationCacheDict()
CACHE_TTL_SECONDS = 300

class AbuseIPDBClient:
    """Query AbuseIPDB API v2 for IP reputation, blacklist reports, and abuse confidence."""

    @classmethod
    def check_ip(cls, ip: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("abuseipdb_api_key") or settings.ABUSEIPDB_API_KEY
        if not api_key:
            return {"configured": False, "status": "NOT_CONFIGURED"}

        cache_key = f"abuseipdb:{ip}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": "true"
            }
            with httpx.Client(timeout=4.5) as client:
                resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    country = data.get("countryCode", "Unknown")
                    usage = data.get("usageType", "Unknown")
                    domain = data.get("domain", "")
                    isp = data.get("isp", "")

                    if score >= 25:
                        verdict = "MALICIOUS"
                    elif score >= 10 or reports > 0:
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"

                    result = {
                        "configured": True,
                        "status": verdict,
                        "score": score,
                        "total_reports": reports,
                        "country": country,
                        "usage_type": usage,
                        "domain": domain,
                        "isp": isp,
                        "is_whitelisted": data.get("isWhitelisted", False)
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in (401, 403):
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid AbuseIPDB API Key"}
                elif resp.status_code == 429:
                    return {"configured": True, "status": "RATE_LIMITED", "error": "AbuseIPDB Rate Limit Exceeded"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"AbuseIPDB request error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        """Verify an AbuseIPDB API key against a public DNS IP."""
        if not api_key:
            return False, "AbuseIPDB API key is empty."
        try:
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": "1.1.1.1", "maxAgeInDays": 30}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return True, f"AbuseIPDB key is valid! (Queried 1.1.1.1 successfully, ISP: {data.get('isp', 'Cloudflare')})"
                elif resp.status_code in (401, 403):
                    return False, "Authentication failed. The AbuseIPDB API key is invalid or rejected."
                else:
                    return False, f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:100]}"
        except Exception as e:
            return False, f"Connection to AbuseIPDB failed: {e}"


class AlienVaultOTXClient:
    """Query AlienVault Open Threat Exchange (OTX) v1 for IP, Domain, and File Hash pulses."""

    @classmethod
    def check_indicator(cls, indicator_type: str, indicator: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        """
        indicator_type: 'IPv4', 'domain', 'hostname', 'url', 'FileHash-SHA256'
        """
        api_key = custom_key or settings_store.get_api_key("alienvault_otx_api_key") or settings.ALIENVAULT_OTX_API_KEY
        if not api_key:
            return {"configured": False, "status": "NOT_CONFIGURED"}

        cache_key = f"otx:{indicator_type}:{indicator}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {
                "X-OTX-API-KEY": api_key,
                "Accept": "application/json"
            }
            url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
            with httpx.Client(timeout=4.5) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    count = pulse_info.get("count", 0)
                    pulses = pulse_info.get("pulses", [])[:5]
                    pulse_names = [p.get("name") for p in pulses if p.get("name")]
                    tags = list(set(tag for p in pulses for tag in p.get("tags", [])))[:8]

                    verdict = "MALICIOUS" if count > 0 else "CLEAN"
                    result = {
                        "configured": True,
                        "status": verdict,
                        "pulse_count": count,
                        "pulse_names": pulse_names,
                        "pulse_dates": [p.get("created") for p in pulses if p.get("created")],
                        "tags": tags
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code == 404:
                    result = {"configured": True, "status": "CLEAN", "pulse_count": 0, "pulse_names": [], "tags": []}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in (401, 403):
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid AlienVault OTX Key"}
                elif resp.status_code == 429:
                    return {"configured": True, "status": "RATE_LIMITED", "error": "AlienVault Rate Limit Exceeded"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"AlienVault OTX error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        """Verify an AlienVault OTX API key."""
        if not api_key:
            return False, "AlienVault OTX API key is empty."
        try:
            headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
            url = "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    return True, "AlienVault OTX key is valid! (Connected and queried OTX indicator API)"
                elif resp.status_code in (401, 403):
                    return False, "Authentication failed. The AlienVault OTX key is invalid or rejected."
                else:
                    return False, f"AlienVault OTX returned HTTP {resp.status_code}: {resp.text[:100]}"
        except Exception as e:
            return False, f"Connection to AlienVault OTX failed: {e}"


class ThreatFoxClient:
    """Query Abuse.ch ThreatFox IOC API for indicators (hashes, domains, URLs)."""

    @classmethod
    def check_hash(cls, file_hash: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("threatfox_api_key") or settings_store.get_api_key("urlhaus_api_key")
        cache_key = f"threatfox:hash:{file_hash}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {"Accept": "application/json"}
            if api_key:
                headers["Auth-Key"] = api_key
            payload = {"query": "search_hash", "hash": file_hash}
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        items = data.get("data", [])
                        malware = items[0].get("malware_printable", "Malware") if items else "Malware"
                        threat_type = items[0].get("threat_type", "Threat") if items else "Threat"
                        confidence = items[0].get("confidence_level", 100) if items else 100
                        result = {
                            "configured": True,
                            "status": "MALICIOUS",
                            "malware": malware,
                            "threat_type": threat_type,
                            "confidence": confidence,
                            "matches_count": len(items)
                        }
                    else:
                        result = {"configured": True, "status": "CLEAN", "matches_count": 0}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid ThreatFox API Key"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"ThreatFox hash query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def check_ioc(cls, indicator: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("threatfox_api_key") or settings_store.get_api_key("urlhaus_api_key")
        if not api_key:
            return {"configured": False, "status": "NOT_CONFIGURED"}

        cache_key = f"threatfox:ioc:{indicator}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {"Accept": "application/json", "Auth-Key": api_key}
            payload = {"query": "search_ioc", "search_term": indicator}
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        items = data.get("data", [])
                        malware = items[0].get("malware_printable") or items[0].get("malware") or "Malware"
                        threat_type = items[0].get("threat_type_desc") or items[0].get("threat_type") or "Malicious IOC"
                        confidence = items[0].get("confidence_level", 100) if items else 100
                        result = {
                            "configured": True,
                            "status": "MALICIOUS",
                            "malware": malware,
                            "threat_type": threat_type,
                            "confidence": confidence,
                            "matches_count": len(items)
                        }
                    else:
                        result = {"configured": True, "status": "CLEAN", "matches_count": 0}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid ThreatFox API Key"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"ThreatFox IOC query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        if not api_key:
            return False, "ThreatFox API key is empty."
        try:
            headers = {"Auth-Key": api_key.strip(), "Accept": "application/json"}
            payload = {"query": "search_ioc", "search_term": "google.com"}
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=headers)
                if resp.status_code == 200:
                    return True, "ThreatFox API key verified successfully! Connected and ready."
                elif resp.status_code in (401, 403):
                    return False, "Authentication failed. The ThreatFox key is invalid."
                else:
                    return False, f"ThreatFox returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to ThreatFox failed: {e}"


class MalwareBazaarClient:
    """
    Query Abuse.ch MalwareBazaar API for file hash intelligence, malware family,
    signature tags, and sample metadata. (Free & public API).
    """

    @classmethod
    def check_hash(cls, file_hash: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("malwarebazaar_api_key") or settings_store.get_api_key("threatfox_api_key")
        cache_key = f"malwarebazaar:hash:{file_hash}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {"Accept": "application/json"}
            if api_key:
                headers["Auth-Key"] = api_key
            payload = {"query": "get_info", "hash": file_hash}
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.post("https://mb-api.abuse.ch/api/v1/", data=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        items = data.get("data", [])
                        item = items[0] if items else {}
                        signature = item.get("signature") or "Unknown Malware"
                        file_type = item.get("file_type") or ""
                        reporter = item.get("reporter") or "abuse.ch"
                        first_seen = item.get("first_seen") or ""
                        tags = item.get("tags") or []
                        delivery_method = item.get("delivery_method") or ""
                        result = {
                            "configured": True,
                            "status": "MALICIOUS",
                            "signature": signature,
                            "file_type": file_type,
                            "reporter": reporter,
                            "first_seen": first_seen,
                            "tags": tags,
                            "delivery_method": delivery_method,
                            "search_url": f"https://bazaar.abuse.ch/sample/{file_hash}/"
                        }
                    else:
                        result = {
                            "configured": True,
                            "status": "CLEAN",
                            "search_url": f"https://bazaar.abuse.ch/sample/{file_hash}/"
                        }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid MalwareBazaar API Key", "search_url": f"https://bazaar.abuse.ch/sample/{file_hash}/"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}", "search_url": f"https://bazaar.abuse.ch/sample/{file_hash}/"}
        except Exception as e:
            logger.debug(f"MalwareBazaar hash query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e), "search_url": f"https://bazaar.abuse.ch/sample/{file_hash}/"}

    @classmethod
    def verify_service(cls) -> Tuple[bool, str]:
        """Verify public availability of MalwareBazaar API."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"})
                if resp.status_code == 200:
                    return True, "Abuse.ch MalwareBazaar service is reachable and operational."
                return False, f"MalwareBazaar returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to MalwareBazaar failed: {e}"


class UrlScanClient:
    """Query urlscan.io for URL and domain security reports."""

    @classmethod
    def check_url(cls, url: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("urlscan_api_key")
        cache_key = f"urlscan:{url}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            import urllib.parse
            headers = {"Accept": "application/json"}
            if api_key:
                headers["API-Key"] = api_key
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or url
            query = f'page.domain:"{domain}"'
            with httpx.Client(timeout=4.5) as client:
                resp = client.get(f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query)}&size=3", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if results:
                        top = results[0]
                        page = top.get("page", {})
                        verdicts = top.get("verdicts", {}).get("overall", {})
                        malicious = verdicts.get("malicious", False)
                        score = verdicts.get("score", 0)
                        categories = verdicts.get("categories", [])
                        screenshot = top.get("screenshot")
                        status = "MALICIOUS" if (malicious or score >= 50) else ("SUSPICIOUS" if score > 0 else "CLEAN")
                        result = {
                            "configured": True,
                            "status": status,
                            "malicious": malicious,
                            "score": score,
                            "categories": categories,
                            "country": page.get("country", ""),
                            "asn_name": page.get("asnname", ""),
                            "screenshot": screenshot,
                            "report_url": top.get("result", "")
                        }
                    else:
                        result = {"configured": True, "status": "CLEAN", "score": 0, "categories": []}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in (401, 403):
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid urlscan.io API Key"}
                elif resp.status_code == 429:
                    return {"configured": True, "status": "RATE_LIMITED", "error": "urlscan.io Rate Limit Exceeded"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"urlscan query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        if not api_key:
            return False, "urlscan.io API key is empty."
        try:
            headers = {"API-Key": api_key, "Accept": "application/json"}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://urlscan.io/api/v1/search/?q=domain:google.com&size=1", headers=headers)
                if resp.status_code == 200:
                    return True, "urlscan.io API key verified successfully! Connected and ready."
                elif resp.status_code in (401, 403):
                    return False, "Authentication failed. The urlscan.io key is invalid."
                else:
                    return False, f"urlscan.io returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to urlscan.io failed: {e}"


class CirclHashlookupClient:
    """
    Query CIRCL Hashlookup API (Computer Incident Response Center Luxembourg).
    Cross-checks SHA-256 against the National Software Reference Library (NSRL)
    to identify known benign or malicious software files.
    """

    @classmethod
    def check_hash(cls, file_hash: str) -> Dict[str, Any]:
        cache_key = f"circl:hash:{file_hash}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {"Accept": "application/json"}
            url = f"https://hashlookup.circl.lu/api/v1/info/{file_hash}"
            with httpx.Client(timeout=4.5) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    known_name = data.get("FileName") or data.get("ProductCode") or data.get("description", "Known Software")
                    vendor = data.get("OpSystemCode") or data.get("MfgCode", "Known Vendor")
                    result = {
                        "configured": True,
                        "status": "BENIGN_KNOWN",
                        "is_nsrl": True,
                        "file_name": known_name,
                        "vendor": vendor,
                        "details": data
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code == 404:
                    result = {"configured": True, "status": "UNKNOWN", "is_nsrl": False}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"CIRCL Hashlookup error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_service(cls) -> Tuple[bool, str]:
        """Test public availability of CIRCL Hashlookup."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://hashlookup.circl.lu/api/v1/info/da39a3ee5e6b4b0d3255bfef95601890afd80709")
                if resp.status_code in [200, 404]:
                    return True, "CIRCL Hashlookup service is reachable and operational."
                return False, f"CIRCL returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to CIRCL Hashlookup failed: {e}"


class HybridAnalysisClient:
    """
    Query CrowdStrike Falcon Sandbox / Hybrid Analysis API v2 for automated detonation telemetry,
    verdicts, threat scores, malware families, and MITRE ATT&CK tactics.
    """

    @classmethod
    def check_hash(cls, file_hash: str, custom_key: Optional[str] = None) -> Dict[str, Any]:
        api_key = custom_key or settings_store.get_api_key("hybrid_analysis_api_key")
        if not api_key:
            return {"configured": False, "status": "NOT_CONFIGURED"}

        cache_key = f"hybrid:{file_hash}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {
                "api-key": api_key,
                "User-Agent": "Falcon Sandbox / FileSanitizer",
                "Accept": "application/json"
            }
            # Hybrid Analysis API v2.35+ modern sample overview endpoint
            url = f"https://hybrid-analysis.com/api/v2/overview/{file_hash}"
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    top = resp.json()
                    verdict = (top.get("verdict") or "unknown").lower()
                    score = top.get("threat_score")
                    family = top.get("vx_family") or ""
                    env = top.get("environment_description") or ""
                    av_detect = top.get("multiscan_result")
                    if av_detect is None:
                        av_detect = 0
                    _ATTCK_ID_REGEX = re.compile(r'^T\d{4}(?:\.\d{3})?$', re.IGNORECASE)
                    raw_mitre = top.get("mitre_attcks") or []
                    mitre_tags = []
                    for m in raw_mitre:
                        val = (m.get("attck_id") or m.get("id") or "") if isinstance(m, dict) else str(m)
                        val_clean = val.strip().upper()
                        if _ATTCK_ID_REGEX.match(val_clean) and val_clean not in mitre_tags:
                            mitre_tags.append(val_clean)

                    raw_tags = top.get("tags") or []
                    tags_list = []
                    for t in raw_tags:
                        t_str = str(t).strip()
                        if t_str and t_str not in tags_list:
                            tags_list.append(t_str)

                    status = "MALICIOUS" if verdict in ["malicious", "threat"] or (score is not None and score >= 70) else (
                        "SUSPICIOUS" if verdict in ["suspicious"] or (score is not None and score >= 40) else "CLEAN"
                    )
                    result = {
                        "configured": True,
                        "status": status,
                        "verdict": verdict,
                        "threat_score": score if score is not None else 0,
                        "malware_family": family,
                        "environment": env,
                        "av_detect_rate": av_detect,
                        "mitre_attck": mitre_tags[:8],
                        "tags": tags_list[:12],
                        "start_time": top.get("analysis_start_time") or top.get("start_time") or top.get("created_at"),
                        "report_url": f"https://hybrid-analysis.com/sample/{file_hash}"
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code == 404:
                    result = {
                        "configured": True,
                        "status": "UNKNOWN",
                        "verdict": "not_found",
                        "threat_score": 0,
                        "report_url": f"https://hybrid-analysis.com/sample/{file_hash}"
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {
                        "configured": True,
                        "status": "AUTH_ERROR",
                        "error": "Invalid Hybrid Analysis API Key",
                        "report_url": f"https://hybrid-analysis.com/sample/{file_hash}"
                    }
                else:
                    return {
                        "configured": True,
                        "status": "ERROR",
                        "error": f"HTTP {resp.status_code}",
                        "report_url": f"https://hybrid-analysis.com/sample/{file_hash}"
                    }
        except Exception as e:
            logger.debug(f"Hybrid Analysis query error: {e}")
            return {
                "configured": True,
                "status": "ERROR",
                "error": str(e),
                "report_url": f"https://hybrid-analysis.com/sample/{file_hash}"
            }

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        """Verify Hybrid Analysis API key."""
        clean_key = (api_key or "").strip()
        if not clean_key:
            return False, "Hybrid Analysis API key is empty."
        try:
            headers = {
                "api-key": clean_key,
                "User-Agent": "Falcon Sandbox / FileSanitizer",
                "Accept": "application/json"
            }
            # Hybrid Analysis API v2 system version check
            version_url = "https://hybrid-analysis.com/api/v2/system/version"
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                resp = client.get(version_url, headers=headers)
                if resp.status_code == 200:
                    v_str = ""
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and "version" in data:
                            v_str = f" (API v{data.get('version')})"
                    except Exception:
                        pass
                    return True, f"Hybrid Analysis (Falcon Sandbox) API key verified successfully!{v_str} Connected and ready."
                elif resp.status_code in [401, 403]:
                    err_msg = "Authentication failed. The Hybrid Analysis API key is invalid or rejected."
                    try:
                        err_json = resp.json()
                        if isinstance(err_json, dict) and "message" in err_json:
                            err_msg = f"Authentication failed: {err_json['message']}"
                    except Exception:
                        pass
                    return False, err_msg

                # Fallback to search hash if /system/version behaves unexpectedly
                search_url = "https://hybrid-analysis.com/api/v2/search/hash"
                search_resp = client.post(search_url, data={"hash": "ed01ebf83040402b036656f7318daecb13b058a32e318a47144e50e938470f77"}, headers=headers)
                if search_resp.status_code == 200:
                    return True, "Hybrid Analysis (Falcon Sandbox) API key verified successfully! Connected and ready."
                elif search_resp.status_code in [401, 403]:
                    err_msg = "Authentication failed. The Hybrid Analysis API key is invalid or rejected."
                    try:
                        err_json = search_resp.json()
                        if isinstance(err_json, dict) and "message" in err_json:
                            err_msg = f"Authentication failed: {err_json['message']}"
                    except Exception:
                        pass
                    return False, err_msg
                else:
                    return False, f"Hybrid Analysis returned HTTP {resp.status_code}: {resp.text[:120]}"
        except Exception as e:
            return False, f"Connection to Hybrid Analysis failed: {e}"


class MXToolboxClient:
    """
    Query MXToolbox API v1 for MX records, SPF validation, DKIM selector health,
    DMARC enforcement policies, and 100+ multi-RBL DNS blacklists.
    """

    @classmethod
    def check_domain(cls, domain: str, command: str = "mx", custom_key: Optional[str] = None) -> Dict[str, Any]:
        """
        command options: 'mx', 'spf', 'dmarc', 'blacklist'
        """
        api_key = custom_key or settings_store.get_api_key("mxtoolbox_api_key")
        if not api_key:
            return {"configured": False, "status": "NOT_CONFIGURED"}

        cache_key = f"mxtoolbox:{command}:{domain}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            headers = {
                "Authorization": api_key,
                "Accept": "application/json"
            }
            url = f"https://api.mxtoolbox.com/api/v1/lookup/{command}/{domain}"
            with httpx.Client(timeout=6.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    errors = [f.get("Name") for f in data.get("Failed", []) if isinstance(f, dict)]
                    warnings = [w.get("Name") for w in data.get("Warnings", []) if isinstance(w, dict)]
                    has_errors = len(errors) > 0
                    is_blacklisted = False
                    if command == "blacklist":
                        is_blacklisted = any(b.get("Status") == 1 for b in data.get("Information", []) if isinstance(b, dict))

                    status = "MALICIOUS" if is_blacklisted else ("SUSPICIOUS" if has_errors else "CLEAN")
                    result = {
                        "configured": True,
                        "status": status,
                        "command": command,
                        "domain": domain,
                        "errors": errors,
                        "warnings": warnings,
                        "is_blacklisted": is_blacklisted,
                        "reporting_records": len(data.get("Information", []))
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid MXToolbox API Key"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"MXToolbox query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, api_key: str) -> Tuple[bool, str]:
        """Verify an MXToolbox API key."""
        if not api_key:
            return False, "MXToolbox API key is empty."
        try:
            headers = {"Authorization": api_key, "Accept": "application/json"}
            url = "https://api.mxtoolbox.com/api/v1/lookup/mx/google.com"
            with httpx.Client(timeout=6.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    return True, "MXToolbox API key verified successfully! Connected and ready."
                elif resp.status_code in [401, 403]:
                    return False, "Authentication failed. The MXToolbox API key is invalid or rejected."
                else:
                    return False, f"MXToolbox returned HTTP {resp.status_code}: {resp.text[:120]}"
        except Exception as e:
            return False, f"Connection to MXToolbox failed: {e}"


class RdapClient:
    """
    Query official Registration Data Access Protocol (RDAP) endpoints (RFC 7482 / RFC 9083)
    via IANA/ARIN/RIPE for authoritative domain registration age, registrar, and IP allocations.
    Requires NO API keys (100% open public REST standard).
    """

    @classmethod
    def check_domain(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.lower().strip().rstrip('.')
        cache_key = f"rdap:domain:{clean_domain}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            url = f"https://rdap.org/domain/{clean_domain}"
            with httpx.Client(timeout=5.5, follow_redirects=True) as client:
                resp = client.get(url, headers={"Accept": "application/rdap+json, application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    created_date = ""
                    for ev in events:
                        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                            created_date = ev.get("eventDate", "")
                            break

                    age_days = None
                    is_new = False
                    if created_date:
                        try:
                            # e.g. 2024-05-10T12:00:00Z
                            import datetime
                            dt_str = created_date[:10]
                            c_dt = datetime.datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
                            diff = datetime.datetime.now(datetime.timezone.utc) - c_dt
                            age_days = max(0, diff.days)
                            if age_days < 30:
                                is_new = True
                        except Exception:
                            pass

                    # Extract registrar
                    registrar = "Unknown Registrar"
                    for entity in data.get("entities", []):
                        if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                for item in vcard[1]:
                                    if isinstance(item, list) and item and item[0] == "fn":
                                        registrar = item[3]
                                        break
                            if registrar == "Unknown Registrar":
                                registrar = entity.get("handle") or "Unknown Registrar"

                    result = {
                        "configured": True,
                        "status": "SUSPICIOUS" if is_new else "CLEAN",
                        "domain": clean_domain,
                        "created_date": created_date,
                        "age_days": age_days,
                        "is_newly_registered": is_new,
                        "registrar": registrar,
                        "raw_status": data.get("status", [])[:4]
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code == 404:
                    result = {"configured": True, "status": "UNKNOWN", "domain": clean_domain, "error": "Domain not found in RDAP registry"}
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"RDAP domain lookup error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_service(cls) -> Tuple[bool, str]:
        """Verify public RDAP endpoint availability."""
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.get("https://rdap.org/domain/google.com", headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    return True, "Public RDAP / WHOIS directory (IANA/ARIN/RIPE bootstrap) is reachable and operational."
                return False, f"RDAP service returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to RDAP service failed: {e}"


class IPinfoClient:
    """
    Query IPinfo.io for rich Autonomous System (ASN), organization name, carrier/ISP,
    geolocation, and privacy detection (VPN, Tor, Proxy, Hosting botnet).
    """

    @classmethod
    def check_ip(cls, ip: str, custom_token: Optional[str] = None) -> Dict[str, Any]:
        token = custom_token or settings_store.get_api_key("ipinfo_api_key")
        cache_key = f"ipinfo:{ip}"
        now = time.time()
        if cache_key in _REPUTATION_CACHE:
            ts, val = _REPUTATION_CACHE[cache_key]
            if now - ts < CACHE_TTL_SECONDS:
                return val

        try:
            url = f"https://ipinfo.io/{ip}/json"
            params = {}
            if token:
                params["token"] = token
            with httpx.Client(timeout=4.5) as client:
                resp = client.get(url, params=params, headers={"Accept": "application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    org = data.get("org", "Unknown ISP")
                    asn = org.split(" ")[0] if org.startswith("AS") else ""
                    city = data.get("city", "")
                    region = data.get("region", "")
                    country = data.get("country", "")
                    loc = data.get("loc", "")
                    hostname = data.get("hostname", "")
                    anycast = data.get("anycast", False)
                    privacy = data.get("privacy", {})
                    is_vpn = privacy.get("vpn", False)
                    is_proxy = privacy.get("proxy", False)
                    is_tor = privacy.get("tor", False)
                    is_hosting = privacy.get("hosting", False)

                    result = {
                        "configured": True,
                        "status": "SUSPICIOUS" if (is_tor or is_vpn or is_proxy) else "CLEAN",
                        "ip": ip,
                        "asn": asn,
                        "org": org,
                        "city": city,
                        "region": region,
                        "country": country,
                        "loc": loc,
                        "hostname": hostname,
                        "anycast": anycast,
                        "privacy": {
                            "is_vpn": is_vpn,
                            "is_proxy": is_proxy,
                            "is_tor": is_tor,
                            "is_hosting": is_hosting
                        }
                    }
                    _REPUTATION_CACHE[cache_key] = (now, result)
                    return result
                elif resp.status_code in [401, 403]:
                    return {"configured": True, "status": "AUTH_ERROR", "error": "Invalid IPinfo.io token"}
                elif resp.status_code == 429:
                    return {"configured": True, "status": "RATE_LIMITED", "error": "IPinfo.io rate limit reached"}
                else:
                    return {"configured": True, "status": "ERROR", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.debug(f"IPinfo query error: {e}")
            return {"configured": True, "status": "ERROR", "error": str(e)}

    @classmethod
    def verify_key(cls, token: str) -> Tuple[bool, str]:
        """Verify an IPinfo.io token."""
        try:
            params = {"token": token} if token else {}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://ipinfo.io/8.8.8.8/json", params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    return True, f"IPinfo.io connection verified successfully! (Queried 8.8.8.8: {data.get('org', 'Google LLC')})"
                elif resp.status_code in [401, 403]:
                    return False, "Authentication failed. The IPinfo.io token is invalid or rejected."
                else:
                    return False, f"IPinfo.io returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection to IPinfo.io failed: {e}"


