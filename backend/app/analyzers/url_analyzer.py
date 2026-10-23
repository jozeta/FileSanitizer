import re
import ssl
import socket
import datetime
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from app.config import settings
from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf, is_ip_blocked
import httpx

# High-risk malware & exploit path extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".apk",
    ".dll", ".jar", ".msi", ".hta", ".cpl", ".pif", ".elf"
}

# High-confidence malware / exploit keywords in path or query
HIGH_RISK_KEYWORDS = [
    "c2-infrastructure", "exfiltrate", "dropper", "reverse_shell",
    "keylogger", "payload.exe", "beacon.xyz", "malicious-domain",
    "credential-harvest", "fake-login", "stealer"
]

# Suspicious backdoor / C2 communication ports
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 8888, 9999, 5555}

# Known public URL shortening services
URL_SHORTENER_DOMAINS = {
    "shorturl.at", "tinyurl.com", "bit.ly", "t.co", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rebrand.ly", "rb.gy", "goo.gl", "rotf.lol"
}

def inspect_tls_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Examines the live TLS certificate of an HTTPS endpoint.
    Extracts issuer, subject, expiration date, days remaining, cipher, and protocol version.
    """
    if not hostname:
        return {"valid": False, "error": "No hostname provided"}

    # Avoid connecting to local/private addresses
    try:
        ip = socket.gethostbyname(hostname)
        import ipaddress
        if is_ip_blocked(ipaddress.ip_address(ip)):
            return {"valid": False, "error": "Internal or private destination blocked"}
    except Exception:
        return {"valid": False, "error": "DNS resolution failed"}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=2.5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                expires_at = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                now = datetime.datetime.utcnow()
                days_left = (expires_at - now).days if expires_at else None
                is_expired = (days_left < 0) if days_left is not None else False

                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"
                subject_name = subject_dict.get("commonName") or hostname

                return {
                    "valid": True,
                    "tls_version": tls_version,
                    "cipher": cipher[0] if cipher else None,
                    "issuer": issuer_name,
                    "subject": subject_name,
                    "valid_from": not_before,
                    "valid_to": not_after,
                    "days_remaining": days_left,
                    "is_expired": is_expired,
                    "serial_number": cert.get("serialNumber")
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "valid": False,
            "error": f"Untrusted / Invalid Certificate: {e.verify_message}",
            "is_expired": "expired" in str(e).lower()
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }

from app.core.settings_store import settings_store

class URLAnalyzer:
    """
    Refined Pluggable URL Analyzer and Reputation Engine.
    Only classifies URLs as HIGH RISK or MALICIOUS if genuine danger is identified:
    malware payloads, true SSRF attempts, credential harvesting, phishing keywords, or threat feed hits.
    Standard web links (e.g. google.com, sunet.se, github.com) are classified as CLEAN.
    Supports URL shortener detection and deep destination analysis.
    """

    @classmethod
    def analyze_url(cls, url: str, _depth: int = 0, include_deep_domain: bool = False) -> Dict[str, Any]:
        """Deep analysis of a single URL."""
        raw_url = url.strip()
        normalized_url = raw_url
        if "://" not in raw_url:
            normalized_url = f"http://{raw_url}"

        try:
            parsed = urllib.parse.urlparse(normalized_url)
        except ValueError:
            parsed = urllib.parse.urlparse("http://invalid.invalid")
        try:
            domain = parsed.hostname or ""
        except ValueError:
            domain = parsed.netloc.rsplit("@", 1)[-1].split(":")[0]
        protocol = (parsed.scheme or "http").lower()
        # Binaries often embed printf-style templates (e.g. http://%s:%d/x) whose
        # "port" is not numeric; fall back to the protocol default instead of raising.
        try:
            port = parsed.port or (443 if protocol == "https" else 80)
        except ValueError:
            port = 443 if protocol == "https" else 80
        is_template_url = bool(re.search(r'%[0-9]*[sdixXu]|\{[^}]*\}|\$\{?\w+', domain or parsed.netloc))
        is_shortener = (domain.lower() in URL_SHORTENER_DOMAINS)

        vt_key = settings_store.get_api_key("virustotal_api_key")
        uh_key = settings_store.get_api_key("urlhaus_api_key")
        sb_key = settings_store.get_api_key("safe_browsing_api_key")
        abuse_key = settings_store.get_api_key("abuseipdb_api_key") or settings.ABUSEIPDB_API_KEY
        otx_key = settings_store.get_api_key("alienvault_otx_api_key") or settings.ALIENVAULT_OTX_API_KEY
        urlscan_key = settings_store.get_api_key("urlscan_api_key")

        result: Dict[str, Any] = {
            "url": url,
            "domain": domain,
            "protocol": protocol,
            "port": port,
            "is_ssrf_safe": True,
            "ssrf_reason": None,
            "resolved_ips": [],
            "risk": "CLEAN",
            "indicators": [],
            "reputation": {
                "heuristic": "CLEAN",
                "virus_total": "PENDING" if vt_key else "NOT_CONFIGURED",
                "urlhaus": "PENDING" if uh_key else "NOT_CONFIGURED",
                "safe_browsing": "PENDING" if sb_key else "NOT_CONFIGURED",
                "abuseipdb": "PENDING" if abuse_key else "NOT_CONFIGURED",
                "alienvault_otx": "PENDING" if otx_key else "NOT_CONFIGURED",
                "urlscan": "PENDING" if urlscan_key else "NOT_CONFIGURED",
            },
            "http_status": None,
            "redirect_url": None,
            "is_shortener": is_shortener,
            "target_analysis": None,
            "tls_valid": (protocol == "https"),
            "certificate": None,
            "screenshot_available": False,
            "subdomains": [],
            "subfinder_dnsx": None
        }

        # 1. Structural & Malware Heuristic Checks
        cls._check_heuristics(url, parsed, domain, result)

        # Template / placeholder URLs (e.g. http://%s:%d/Mozi.m) cannot be resolved or looked up
        if is_template_url:
            result["is_ssrf_safe"] = False
            result["ssrf_reason"] = "URL contains format-string placeholders (template found in binary); not resolvable"
            result["indicators"].append("Templated URL (format placeholders) - likely dynamically-built C2/dropper download command")
            result["reputation"] = {k: ("SKIPPED" if v in ("PENDING",) else v) for k, v in result["reputation"].items()}
            return result

        # 2. SSRF Validation
        is_safe, reason, ips = validate_url_for_ssrf(url)
        result["resolved_ips"] = ips or []

        if not is_safe:
            # Distinguish genuine private network SSRF attack vs offline/unresolved test domain
            if reason and ("private/internal network" in reason or "Forbidden local destination" in reason):
                result["is_ssrf_safe"] = False
                result["ssrf_reason"] = reason
                result["risk"] = "HIGH RISK"
                result["indicators"].append(f"SSRF Threat: {reason}")
                if vt_key:
                    result["reputation"]["virus_total"] = "INTERNAL_TARGET"
                if uh_key:
                    result["reputation"]["urlhaus"] = "INTERNAL_TARGET"
                if sb_key:
                    result["reputation"]["safe_browsing"] = "INTERNAL_TARGET"
                if abuse_key:
                    result["reputation"]["abuseipdb"] = "INTERNAL_TARGET"
                if otx_key:
                    result["reputation"]["alienvault_otx"] = "INTERNAL_TARGET"
                return result
            else:
                # Domain simply failed DNS (e.g. offline environment or dummy test domain)
                result["is_ssrf_safe"] = False
                result["ssrf_reason"] = reason
                if result["risk"] == "CLEAN":
                    result["risk"] = "LOW RISK"
                result["indicators"].append("Unresolved Domain (Offline environment or unassigned host)")

        # 3. HTTPS Certificate Inspection (if HTTPS and external TLS inspection allowed)
        if protocol == "https" and domain and result["is_ssrf_safe"]:
            if settings_store.is_external_allowed("allow_tls_inspection"):
                cert_data = inspect_tls_certificate(domain, port)
                result["certificate"] = cert_data
                if cert_data.get("valid"):
                    result["tls_valid"] = True
                    if cert_data.get("is_expired"):
                        result["indicators"].append("TLS Certificate Expired")
                        if result["risk"] == "CLEAN":
                            result["risk"] = "MEDIUM RISK"
                elif cert_data.get("error") and "Untrusted" in cert_data.get("error", ""):
                    result["tls_valid"] = False
                    result["indicators"].append(f"TLS Warning: {cert_data['error']}")
                    if result["risk"] == "CLEAN":
                        result["risk"] = "MEDIUM RISK"

        # 3b. High-Speed Domain Threat & Homograph Analysis (Punycode & Obfuscations)
        if domain:
            try:
                from app.analyzers.domain_analyzer import DomainAnalyzer
                puny = DomainAnalyzer.analyze_punycode(domain)
                obf = DomainAnalyzer.detect_obfuscation(url)

                result["domain_intelligence"] = {
                    "punycode_analysis": puny,
                    "obfuscation_analysis": obf,
                }

                # Check for Punycode homograph attack
                if puny.get("is_homograph") or puny.get("is_punycode"):
                    unicode_disp = puny.get("unicode_rendered") or puny.get("visual_appearance") or domain
                    simulated = puny.get("simulated_latin") or unicode_disp
                    result["risk"] = "MALICIOUS"
                    result["indicators"].append(
                        f"Punycode homograph impersonation attack: '{domain}' visually renders as '{unicode_disp}' (masquerading as '{simulated}')"
                    )

                # Check for obfuscated address representations
                if obf.get("is_obfuscated"):
                    for tech in obf.get("techniques", []):
                        if result["risk"] != "MALICIOUS":
                            result["risk"] = "HIGH RISK"
                        result["indicators"].append(f"Obfuscated Address: {tech.get('name')}")

                if include_deep_domain:
                    domain_intel = DomainAnalyzer.analyze(domain)
                    result["domain_intelligence"] = domain_intel
                    whois_age = domain_intel.get("whois", {}).get("domain_age_days")
                    if whois_age is not None and whois_age < 30:
                        if result["risk"] in ["CLEAN", "LOW RISK"]:
                            result["risk"] = "MEDIUM RISK"
                        result["indicators"].append(f"Newly registered domain ({whois_age} days old)")
            except Exception as e:
                logger.debug(f"Fast domain threat check skipped for {domain}: {e}")

        # 3c. Subfinder & dnsx Subdomain Enumeration
        if domain and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) and ":" not in domain:
            try:
                from app.network.subfinder_dnsx import SubfinderDnsxScanner
                subfinder_data = SubfinderDnsxScanner.discover_subdomains(domain)
                result["subfinder_dnsx"] = subfinder_data
                result["subdomains"] = [s["subdomain"] for s in subfinder_data.get("subdomains", [])]
                if subfinder_data.get("total_discovered", 0) > 0:
                    result["indicators"].append(
                        f"Subdomain Discovery: {subfinder_data['total_discovered']} active subdomain(s) resolved via Subfinder & dnsx"
                    )
                    if not result.get("resolved_ips"):
                        all_ips = set()
                        for s_item in subfinder_data.get("subdomains", []):
                            all_ips.update(s_item.get("ips", []))
                        if all_ips:
                            result["resolved_ips"] = sorted(list(all_ips))
            except Exception as e:
                logger.debug(f"Subfinder/dnsx discovery skipped for URL domain {domain}: {e}")

        # 4. HTTP Status Verification & Deep Redirect Analysis (if allowed)
        if result["is_ssrf_safe"] and protocol in ["http", "https"]:
            if settings_store.is_external_allowed("allow_http_status_and_redirects"):
                try:
                    with httpx.Client(timeout=2.5, follow_redirects=True) as client:
                        resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 FileSanitizer-URL-Inspector/1.0"})
                        result["http_status"] = resp.status_code
                        final_url = str(resp.url)
                        if final_url != url:
                            result["redirect_url"] = final_url
                            # Deeply analyze destination if top-level URL
                            if _depth == 0:
                                target_res = cls.analyze_url(final_url, _depth=1)
                                result["target_analysis"] = target_res
                                if target_res.get("risk") in ["HIGH RISK", "MALICIOUS"]:
                                    result["risk"] = target_res["risk"]
                                    result["indicators"].append(f"Redirect Destination Threat: {final_url} flagged as {target_res['risk']}")
                                elif is_shortener:
                                    result["indicators"].append(f"Redirect destination unmasked: {final_url}")
                except Exception:
                    pass

        # 5. External Threat Intelligence Feeds (if allowed and keys configured)
        if settings_store.is_external_allowed("allow_threat_intel_lookups"):
            vt_key = settings_store.get_api_key("virustotal_api_key")
            urlhaus_key = settings_store.get_api_key("urlhaus_api_key")
            sb_key = settings_store.get_api_key("safe_browsing_api_key")
            abuse_key = settings_store.get_api_key("abuseipdb_api_key") or settings.ABUSEIPDB_API_KEY
            otx_key = settings_store.get_api_key("alienvault_otx_api_key") or settings.ALIENVAULT_OTX_API_KEY

            if (settings.URLHAUS_ENABLED or urlhaus_key) and urlhaus_key:
                cls._check_urlhaus(url, result, api_key=urlhaus_key)

            if (settings.VIRUSTOTAL_ENABLED or vt_key) and vt_key:
                cls._check_virustotal(url, result, api_key=vt_key)

            if (settings.SAFE_BROWSING_ENABLED or sb_key) and sb_key:
                cls._check_safe_browsing(url, result, api_key=sb_key)

            if (settings.ABUSEIPDB_ENABLED or abuse_key) and abuse_key:
                cls._check_abuseipdb(result, api_key=abuse_key)

            if (settings.ALIENVAULT_OTX_ENABLED or otx_key) and otx_key:
                cls._check_alienvault_otx(url, domain, result, api_key=otx_key)

            # ThreatFox & urlscan.io Checks
            try:
                from app.analyzers.reputation_client import ThreatFoxClient, UrlScanClient
                tf_res = ThreatFoxClient.check_ioc(domain or url)
                if tf_res.get("status") == "MALICIOUS":
                    result["reputation"]["threatfox"] = "MALICIOUS"
                    result["risk"] = "MALICIOUS"
                    result["indicators"].append(f"ThreatFox Blacklist: {tf_res.get('malware')} ({tf_res.get('threat_type')})")
                elif tf_res.get("configured"):
                    result["reputation"]["threatfox"] = "CLEAN"

                urlscan_key = settings_store.get_api_key("urlscan_api_key")
                if urlscan_key:
                    us_res = UrlScanClient.check_url(url, custom_key=urlscan_key)
                    if us_res.get("status") == "MALICIOUS":
                        result["reputation"]["urlscan"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"urlscan.io: Malicious threat verdict (Score: {us_res.get('score')})")
                    elif us_res.get("status") == "SUSPICIOUS":
                        result["reputation"]["urlscan"] = "SUSPICIOUS"
                        if result["risk"] == "CLEAN":
                            result["risk"] = "SUSPICIOUS"
                        result["indicators"].append(f"urlscan.io: Suspicious threat score ({us_res.get('score')})")
                    elif us_res.get("status") in ("AUTH_ERROR", "RATE_LIMITED", "ERROR"):
                        result["reputation"]["urlscan"] = us_res.get("status")
                    elif us_res.get("configured"):
                        result["reputation"]["urlscan"] = us_res.get("status", "CLEAN")
                else:
                    result["reputation"]["urlscan"] = "NOT_CONFIGURED"
            except Exception as ex:
                logger.debug(f"ThreatFox/urlscan check note: {ex}")

        return result


    @classmethod
    def _check_heuristics(cls, url: str, parsed: urllib.parse.ParseResult, domain: str, result: Dict[str, Any]) -> None:
        url_lower = url.lower()
        path_lower = parsed.path.lower()

        # Check for dangerous executable file download in URL path
        dangerous_exts = set(settings_store.get_dangerous_extensions())
        for ext in dangerous_exts:
            if path_lower.endswith(ext) or f"{ext}?" in url_lower:
                result["indicators"].append(f"Dangerous executable payload extension detected in URL path: {ext}")
                result["risk"] = "HIGH RISK"
                result["reputation"]["heuristic"] = "MALICIOUS"
                break

        # Check for high-confidence malware keywords in URL
        for kw in HIGH_RISK_KEYWORDS:
            if kw in url_lower:
                result["indicators"].append(f"Malware / C2 indicator keyword detected: '{kw}'")
                result["risk"] = "HIGH RISK"
                result["reputation"]["heuristic"] = "SUSPICIOUS"
                break

        # Check for embedded credentials in userinfo (e.g. http://victim:pass@phishing.com)
        if parsed.username or parsed.password:
            result["indicators"].append("Embedded user credentials in URL (potential credential harvesting / phishing)")
            result["risk"] = "HIGH RISK"
            result["reputation"]["heuristic"] = "SUSPICIOUS"

        # Check Punycode (IDN homograph attack indicator)
        if "xn--" in domain.lower():
            try:
                unicode_name = domain.encode("ascii").decode("idna")
            except Exception:
                unicode_name = domain
            result["indicators"].append(f"Punycode homograph impersonation attack: '{domain}' visually renders as '{unicode_name}'")
            result["risk"] = "HIGH RISK"
            result["reputation"]["heuristic"] = "SUSPICIOUS"

        # Check suspicious backdoor ports
        if result["port"] in SUSPICIOUS_PORTS:
            result["indicators"].append(f"Suspicious backdoor / C2 port in URL: {result['port']}")
            result["risk"] = "HIGH RISK"
            result["reputation"]["heuristic"] = "SUSPICIOUS"

        # Check if hostname is a raw public IP address without domain name
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            result["indicators"].append("Direct IP address used as hostname instead of domain name")
            if result["risk"] == "CLEAN":
                result["risk"] = "MEDIUM RISK"

        # Check for URL shortening service
        if domain.lower() in URL_SHORTENER_DOMAINS:
            result["indicators"].append(f"URL Shortening Service Detected ({domain}): Target destination is masked")
            if result["risk"] == "CLEAN":
                result["risk"] = "LOW RISK"

    @classmethod
    def _check_urlhaus(cls, url: str, result: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Query Abuse.ch URLhaus API."""
        key = api_key or settings_store.get_api_key("urlhaus_api_key") or settings.URLHAUS_API_KEY
        if not key:
            result["reputation"]["urlhaus"] = "NOT_CONFIGURED"
            return
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url},
                    headers={"Auth-Key": key}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        result["reputation"]["urlhaus"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"URLhaus Blacklist: {data.get('threat', 'Malicious payload')}")
                    elif status == "no_results":
                        result["reputation"]["urlhaus"] = "CLEAN"
                    else:
                        result["reputation"]["urlhaus"] = "CLEAN"
                elif resp.status_code in [401, 403]:
                    result["reputation"]["urlhaus"] = "AUTH_ERROR"
                elif resp.status_code == 429:
                    result["reputation"]["urlhaus"] = "RATE_LIMITED"
                else:
                    result["reputation"]["urlhaus"] = "ERROR"
        except Exception as e:
            logger.debug(f"URLhaus query error: {e}")
            result["reputation"]["urlhaus"] = "ERROR"

    @classmethod
    def _check_virustotal(cls, url: str, result: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Query VirusTotal v3 URL analysis."""
        key = api_key or settings_store.get_api_key("virustotal_api_key") or settings.VIRUSTOTAL_API_KEY
        if not key:
            result["reputation"]["virus_total"] = "NOT_CONFIGURED"
            return
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": key, "Accept": "application/json"}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total = sum(stats.values()) if stats else 0

                    details = {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "total": total,
                        "reputation": attr.get("reputation", 0),
                        "categories": list(attr.get("categories", {}).values())[:5],
                        "tags": attr.get("tags", [])[:5]
                    }
                    result["reputation"]["virus_total_details"] = details

                    if malicious > 0:
                        result["reputation"]["virus_total"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"VirusTotal: Flagged by {malicious}/{total} security engines")
                    elif suspicious > 0:
                        result["reputation"]["virus_total"] = "SUSPICIOUS"
                        if result["risk"] != "MALICIOUS":
                            result["risk"] = "HIGH RISK"
                        result["indicators"].append(f"VirusTotal: Flagged suspicious by {suspicious}/{total} engines")
                    else:
                        result["reputation"]["virus_total"] = "CLEAN"
                elif resp.status_code == 404:
                    result["reputation"]["virus_total"] = "NOT_FOUND"
                elif resp.status_code == 429:
                    result["reputation"]["virus_total"] = "RATE_LIMITED"
                elif resp.status_code in [401, 403]:
                    result["reputation"]["virus_total"] = "AUTH_ERROR"
                else:
                    logger.debug(f"VirusTotal returned status {resp.status_code}")
                    result["reputation"]["virus_total"] = "ERROR"
        except Exception as e:
            logger.debug(f"VirusTotal query error: {e}")
            result["reputation"]["virus_total"] = "ERROR"

    @classmethod
    def _check_safe_browsing(cls, url: str, result: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Query Google Safe Browsing API v4."""
        key = api_key or settings_store.get_api_key("safe_browsing_api_key") or settings.SAFE_BROWSING_API_KEY
        if not key:
            result["reputation"]["safe_browsing"] = "NOT_CONFIGURED"
            return
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
        payload = {
            "client": {
                "clientId": "FileSanitizer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_type = matches[0].get("threatType", "MALICIOUS")
                        result["reputation"]["safe_browsing"] = "MALICIOUS"
                        result["risk"] = "MALICIOUS"
                        result["indicators"].append(f"Google Safe Browsing: Flagged as {threat_type}")
                    else:
                        result["reputation"]["safe_browsing"] = "CLEAN"
                elif resp.status_code in [400, 401, 403]:
                    result["reputation"]["safe_browsing"] = "AUTH_ERROR"
                elif resp.status_code == 429:
                    result["reputation"]["safe_browsing"] = "RATE_LIMITED"
                else:
                    logger.debug(f"Google Safe Browsing returned status {resp.status_code}")
                    result["reputation"]["safe_browsing"] = "ERROR"
        except Exception as e:
            logger.debug(f"Google Safe Browsing query error: {e}")
            result["reputation"]["safe_browsing"] = "ERROR"

    @classmethod
    def _check_abuseipdb(cls, result: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Query AbuseIPDB API for resolved IP address reputation."""
        from app.analyzers.reputation_client import AbuseIPDBClient
        ips = result.get("resolved_ips", [])
        if not ips:
            domain = result.get("domain", "")
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                ips = [domain]

        if not ips:
            result["reputation"]["abuseipdb"] = "NO_IP"
            return

        ip_to_check = ips[0]
        rep = AbuseIPDBClient.check_ip(ip_to_check, custom_key=api_key)
        status = rep.get("status", "ERROR")
        result["reputation"]["abuseipdb"] = status
        result["reputation"]["abuseipdb_details"] = rep

        if status == "MALICIOUS":
            result["risk"] = "MALICIOUS"
            result["indicators"].append(
                f"AbuseIPDB: IP {ip_to_check} has {rep.get('score', 0)}% abuse confidence ({rep.get('total_reports', 0)} reports)"
            )
        elif status == "SUSPICIOUS":
            if result["risk"] != "MALICIOUS":
                result["risk"] = "HIGH RISK"
            result["indicators"].append(
                f"AbuseIPDB: IP {ip_to_check} flagged suspicious ({rep.get('total_reports', 0)} reports)"
            )

    @classmethod
    def _check_alienvault_otx(cls, url: str, domain: str, result: Dict[str, Any], api_key: Optional[str] = None) -> None:
        """Query AlienVault OTX for indicator pulses."""
        from app.analyzers.reputation_client import AlienVaultOTXClient
        indicator_type = "IPv4" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else "domain"
        otx_res = AlienVaultOTXClient.check_indicator(indicator_type, domain, custom_key=api_key)
        status = otx_res.get("status", "CLEAN")
        result["reputation"]["alienvault_otx"] = status
        result["reputation"]["alienvault_otx_details"] = otx_res

        if status == "MALICIOUS" and otx_res.get("pulse_count", 0) > 0:
            result["risk"] = "MALICIOUS"
            result["indicators"].append(
                f"AlienVault OTX: {indicator_type} '{domain}' flagged in {otx_res.get('pulse_count')} threat pulse(s)"
            )

