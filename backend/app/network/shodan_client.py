"""
Shodan Threat Intelligence & Infrastructure Profiling Client.
Integrates with the official Shodan API to perform automated reconnaissance on IPs and domains:
- Open port discovery & active service banners
- Correlated vulnerabilities (CVEs)
- Operating system, ISP, ASN, and organization details
- Shodan threat tags (e.g. vpn, cloud, honeypot, c2)
- Subdomain enumeration & DNS history
"""

from typing import Dict, Any, List, Optional, Tuple
import urllib.parse
import httpx

from app.core.settings_store import settings_store
from app.core.logging_config import logger
from app.core.redis_cache import redis_cache

SHODAN_BASE_URL = "https://api.shodan.io"


class ShodanClient:
    """
    Client for Shodan REST API v1.
    """

    @staticmethod
    def get_api_key() -> str:
        return settings_store.get_api_key("shodan_api_key").strip()

    @classmethod
    def is_configured(cls) -> bool:
        return bool(cls.get_api_key())

    @classmethod
    def verify_key(cls, key: str) -> Tuple[bool, str]:
        """
        Verifies the Shodan API key via the official /api-info endpoint.
        """
        clean_key = (key or "").strip()
        if not clean_key:
            return False, "API key is empty."

        try:
            with httpx.Client(timeout=8.0) as client:
                res = client.get(f"{SHODAN_BASE_URL}/api-info?key={clean_key}")
                if res.status_code == 200:
                    data = res.json()
                    plan = (data.get("plan") or "community").upper()
                    credits_left = data.get("query_credits", 0)
                    return True, f"Shodan API key verified! Plan: {plan} ({credits_left} query credits remaining)."
                elif res.status_code in (401, 403):
                    return False, "Authentication failed: Invalid Shodan API key (HTTP 401/403)."
                elif res.status_code == 429:
                    return True, "Key is valid, but Shodan query credit limit reached (HTTP 429)."
                else:
                    return False, f"Shodan returned unexpected HTTP status {res.status_code}."
        except Exception as e:
            return False, f"Failed to connect to Shodan API: {e}"

    @classmethod
    def lookup_ip(cls, ip: str) -> Dict[str, Any]:
        """
        Query Shodan Host API for an IP address.
        """
        clean_ip = (ip or "").strip()
        web_link = f"https://www.shodan.io/host/{clean_ip}"

        cached = redis_cache.get("shodan_ip", clean_ip)
        if cached and isinstance(cached, dict):
            cached["cached"] = True
            return cached

        key = cls.get_api_key()
        if not key:
            return {
                "configured": False,
                "queried": False,
                "target": clean_ip,
                "is_ip": True,
                "web_link": web_link,
                "ports": [],
                "vulns": [],
                "services": [],
                "tags": [],
                "message": "Shodan API key not configured. Add your key in Administrator Settings for automated open port enumeration, banners, and CVE correlation."
            }

        try:
            with httpx.Client(timeout=9.0) as client:
                url = f"{SHODAN_BASE_URL}/shodan/host/{clean_ip}?key={key}&minify=false"
                res = client.get(url)

                if res.status_code == 200:
                    data = res.json()
                    ports = data.get("ports", [])
                    hostnames = data.get("hostnames", [])
                    vulns = list(data.get("vulns", [])) if isinstance(data.get("vulns"), (list, dict)) else []
                    tags = data.get("tags", [])
                    os_name = data.get("os")
                    isp = data.get("isp")
                    org = data.get("org")
                    asn = data.get("asn")
                    last_update = data.get("last_update")

                    services: List[Dict[str, Any]] = []
                    for item in data.get("data", []):
                        p = item.get("port")
                        transport = item.get("transport", "tcp")
                        product = item.get("product")
                        version = item.get("version")
                        cpe = item.get("cpe", [])
                        raw_data = item.get("data", "")
                        banner = raw_data[:240].strip() if raw_data else None
                        ssl_info = item.get("ssl")

                        services.append({
                            "port": p,
                            "transport": transport,
                            "product": product,
                            "version": version,
                            "cpe": cpe if isinstance(cpe, list) else [cpe],
                            "banner_snippet": banner,
                            "ssl_enabled": bool(ssl_info)
                        })

                    result = {
                        "configured": True,
                        "queried": True,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": sorted(ports),
                        "hostnames": hostnames,
                        "os": os_name,
                        "isp": isp,
                        "org": org,
                        "asn": asn,
                        "vulns": vulns,
                        "tags": tags,
                        "services": services,
                        "total_services": len(services),
                        "last_update": last_update,
                        "message": f"Successfully retrieved Shodan host telemetry ({len(ports)} open ports, {len(vulns)} CVEs)."
                    }
                    redis_cache.set("shodan_ip", clean_ip, result, ttl_seconds=3600)
                    return result

                elif res.status_code == 404:
                    result = {
                        "configured": True,
                        "queried": True,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": [],
                        "vulns": [],
                        "services": [],
                        "tags": [],
                        "message": "No open ports or services indexed by Shodan for this IP."
                    }
                    redis_cache.set("shodan_ip", clean_ip, result, ttl_seconds=1800)
                    return result

                elif res.status_code in (401, 403):
                    return {
                        "configured": False,
                        "queried": False,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": [],
                        "vulns": [],
                        "services": [],
                        "message": "Shodan authentication failed (invalid API key)."
                    }
                else:
                    return {
                        "configured": True,
                        "queried": False,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": [],
                        "vulns": [],
                        "services": [],
                        "message": f"Shodan API returned HTTP status {res.status_code}."
                    }

        except Exception as e:
            logger.debug(f"Shodan lookup_ip error for {clean_ip}: {e}")
            return {
                "configured": True,
                "queried": False,
                "target": clean_ip,
                "is_ip": True,
                "web_link": web_link,
                "ports": [],
                "vulns": [],
                "services": [],
                "message": f"Connection error querying Shodan: {e}"
            }

    @classmethod
    def lookup_domain(cls, domain: str) -> Dict[str, Any]:
        """
        Query Shodan DNS Domain API and Host Search for a domain.
        """
        clean_domain = (domain or "").strip().lower()
        web_link = f"https://www.shodan.io/search?query=hostname:{clean_domain}"

        cached = redis_cache.get("shodan_domain", clean_domain)
        if cached and isinstance(cached, dict):
            cached["cached"] = True
            return cached

        key = cls.get_api_key()
        if not key:
            return {
                "configured": False,
                "queried": False,
                "target": clean_domain,
                "is_ip": False,
                "web_link": web_link,
                "subdomains": [],
                "ports": [],
                "vulns": [],
                "total_hosts": 0,
                "message": "Shodan API key not configured. Add your key in Administrator Settings for automated Shodan intelligence."
            }

        try:
            subdomains: List[str] = []
            dns_records: List[Dict[str, Any]] = []
            open_ports: List[int] = []
            vulns: List[str] = []
            total_hosts = 0

            with httpx.Client(timeout=9.0) as client:
                # 1. Shodan DNS Domain Endpoint
                try:
                    dns_url = f"{SHODAN_BASE_URL}/dns/domain/{clean_domain}?key={key}"
                    dns_res = client.get(dns_url)
                    if dns_res.status_code == 200:
                        dns_data = dns_res.json()
                        subdomains = [f"{s}.{clean_domain}" for s in dns_data.get("subdomains", [])]
                        for rec in dns_data.get("data", []):
                            dns_records.append({
                                "subdomain": rec.get("subdomain"),
                                "type": rec.get("type"),
                                "value": rec.get("value")
                            })
                except Exception as e:
                    logger.debug(f"Shodan DNS domain query failed: {e}")

                # 2. Shodan Host Search (aggregated exposure)
                try:
                    search_url = f"{SHODAN_BASE_URL}/shodan/host/search?key={key}&query=hostname:{clean_domain}&facets=port:10"
                    search_res = client.get(search_url)
                    if search_res.status_code == 200:
                        sdata = search_res.json()
                        total_hosts = sdata.get("total", 0)
                        for match in sdata.get("matches", []):
                            if match.get("port") and match["port"] not in open_ports:
                                open_ports.append(match["port"])
                            for v in match.get("vulns", {}).keys() if isinstance(match.get("vulns"), dict) else match.get("vulns", []):
                                if v not in vulns:
                                    vulns.append(v)
                except Exception as e:
                    logger.debug(f"Shodan host search query failed: {e}")

            result = {
                "configured": True,
                "queried": True,
                "target": clean_domain,
                "is_ip": False,
                "web_link": web_link,
                "subdomains": sorted(subdomains)[:30],
                "dns_records": dns_records[:30],
                "ports": sorted(open_ports),
                "vulns": sorted(vulns),
                "total_hosts": total_hosts,
                "message": f"Shodan indexed {total_hosts} exposed hosts, {len(subdomains)} subdomains, and {len(open_ports)} distinct ports."
            }
            redis_cache.set("shodan_domain", clean_domain, result, ttl_seconds=3600)
            return result

        except Exception as e:
            logger.debug(f"Shodan lookup_domain error for {clean_domain}: {e}")
            return {
                "configured": True,
                "queried": False,
                "target": clean_domain,
                "is_ip": False,
                "web_link": web_link,
                "subdomains": [],
                "ports": [],
                "vulns": [],
                "message": f"Connection error querying Shodan: {e}"
            }

    @classmethod
    def lookup(cls, target: str, is_ip: bool = False, primary_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Unified Shodan intelligence lookup for IP or Domain.
        """
        clean_target = (target or "").strip().lower()
        if is_ip:
            return cls.lookup_ip(clean_target)

        # For domains: perform domain lookup and if primary IP exists, enrich with IP host telemetry
        domain_res = cls.lookup_domain(clean_target)
        if primary_ip:
            ip_res = cls.lookup_ip(primary_ip)
            domain_res["primary_ip_telemetry"] = ip_res
            # Merge open ports and vulns from primary IP if available
            if ip_res.get("ports"):
                merged_ports = sorted(list(set(domain_res.get("ports", []) + ip_res.get("ports", []))))
                domain_res["ports"] = merged_ports
            if ip_res.get("vulns"):
                merged_vulns = sorted(list(set(domain_res.get("vulns", []) + ip_res.get("vulns", []))))
                domain_res["vulns"] = merged_vulns
            if ip_res.get("services"):
                domain_res["services"] = ip_res.get("services", [])
            if ip_res.get("os"):
                domain_res["os"] = ip_res.get("os")
            if ip_res.get("isp"):
                domain_res["isp"] = ip_res.get("isp")
            if ip_res.get("tags"):
                domain_res["tags"] = ip_res.get("tags")

        return domain_res
