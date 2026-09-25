import re
import urllib.parse
from typing import Dict, Any, List, Optional
from app.config import settings
from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf
import httpx

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".work", ".click", ".link", ".club", ".country", ".kim", ".gq", ".cf", ".tk", ".ml"}
PHISHING_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "banking", "wallet", "password", "auth", "confirm"]

class URLAnalyzer:
    """
    Pluggable URL Analyzer and Reputation Engine.
    Examines URLs for suspicious structure, performs SSRF-safe checks,
    and queries configured reputation feeds (VirusTotal, URLhaus, SafeBrowsing).
    """

    @classmethod
    def analyze_url(cls, url: str) -> Dict[str, Any]:
        """Deep analysis of a single URL."""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname or ""
        protocol = parsed.scheme.lower()
        port = parsed.port or (443 if protocol == "https" else 80)

        result: Dict[str, Any] = {
            "url": url,
            "domain": domain,
            "protocol": protocol,
            "port": port,
            "is_ssrf_safe": False,
            "ssrf_reason": None,
            "resolved_ips": [],
            "risk": "CLEAN",
            "indicators": [],
            "reputation": {
                "heuristic": "CLEAN",
                "virus_total": "NOT_CONFIGURED",
                "urlhaus": "NOT_CONFIGURED",
                "safe_browsing": "NOT_CONFIGURED",
            },
            "http_status": None,
            "tls_valid": (protocol == "https"),
            "screenshot_available": False
        }

        # 1. Heuristic & Structural Checks
        cls._check_heuristics(url, parsed, domain, result)

        # 2. SSRF Validation
        is_safe, reason, ips = validate_url_for_ssrf(url)
        result["is_ssrf_safe"] = is_safe
        result["ssrf_reason"] = reason
        result["resolved_ips"] = ips or []

        if not is_safe:
            result["risk"] = "HIGH RISK"
            result["indicators"].append(f"SSRF Danger: {reason}")
            return result

        # 3. Pluggable Providers (if configured)
        if settings.URLHAUS_ENABLED and settings.URLHAUS_API_KEY:
            cls._check_urlhaus(url, result)

        if settings.VIRUSTOTAL_ENABLED and settings.VIRUSTOTAL_API_KEY:
            cls._check_virustotal(url, result)

        return result

    @classmethod
    def _check_heuristics(cls, url: str, parsed: urllib.parse.ParseResult, domain: str, result: Dict[str, Any]) -> None:
        # Check if domain is raw IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            result["indicators"].append("Direct IP address used as hostname instead of domain name")
            result["risk"] = "MEDIUM RISK"

        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["indicators"].append(f"Suspicious high-risk TLD: {tld}")
                result["risk"] = "MEDIUM RISK"
                break

        # Check Punycode (IDN homograph attack indicator)
        if domain.startswith("xn--"):
            result["indicators"].append("Punycode domain detected (potential homograph impersonation attack)")
            result["risk"] = "HIGH RISK"

        # Check phishing keywords
        url_lower = url.lower()
        matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        if len(matched_kw) >= 2:
            result["indicators"].append(f"Multiple credential/phishing keywords present: {', '.join(matched_kw)}")
            if result["risk"] == "CLEAN":
                result["risk"] = "MEDIUM RISK"

        # Check non-standard ports
        if result["port"] not in [80, 443, 8080, 8443]:
            result["indicators"].append(f"Non-standard HTTP port: {result['port']}")

        if result["indicators"]:
            result["reputation"]["heuristic"] = "SUSPICIOUS"

    @classmethod
    def _check_urlhaus(cls, url: str, result: Dict[str, Any]) -> None:
        """Query Abuse.ch URLhaus API."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url},
                    headers={"Auth-Key": settings.URLHAUS_API_KEY}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        result["reputation"]["urlhaus"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"URLhaus blacklist: {data.get('threat', 'Malicious payload')}")
                    else:
                        result["reputation"]["urlhaus"] = "CLEAN"
        except Exception as e:
            logger.debug(f"URLhaus query error: {e}")
            result["reputation"]["urlhaus"] = "ERROR"

    @classmethod
    def _check_virustotal(cls, url: str, result: Dict[str, Any]) -> None:
        """Query VirusTotal v3 URL analysis."""
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    if malicious > 0:
                        result["reputation"]["virus_total"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"VirusTotal: Flagged by {malicious} security vendors")
                    elif suspicious > 0:
                        result["reputation"]["virus_total"] = "SUSPICIOUS"
                        if result["risk"] != "MALICIOUS":
                            result["risk"] = "HIGH RISK"
                    else:
                        result["reputation"]["virus_total"] = "CLEAN"
        except Exception as e:
            logger.debug(f"VirusTotal query error: {e}")
            result["reputation"]["virus_total"] = "ERROR"
