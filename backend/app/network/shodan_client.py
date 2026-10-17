"""
Shodan Threat Intelligence & Infrastructure Profiling Client.
Integrates with the official Shodan API to perform automated reconnaissance on IPs and domains:
- Open port discovery & active service banners
- Correlated vulnerabilities (CVEs)
- Operating system, ISP, ASN, and organization details
- Cloud provider detection (Azure, AWS, GCP, Cloudflare, etc.)
- Shodan threat tags (e.g. vpn, cloud, honeypot, c2)
- Subdomain enumeration & DNS history
- Unified caching via ExternalApiCache with user-configurable lifetime & age tracking
"""

from typing import Dict, Any, List, Optional, Tuple, Set
import urllib.parse
import httpx

from app.core.settings_store import settings_store
from app.core.logging_config import logger
from app.core.external_cache import external_api_cache

SHODAN_BASE_URL = "https://api.shodan.io"


class ShodanClient:
    """
    Client for Shodan REST API v1 with rich multi-host parsing and persistent caching.
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
    def lookup_ip(cls, ip: str, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Query Shodan Host API for an IP address.
        """
        clean_ip = (ip or "").strip()
        web_link = f"https://www.shodan.io/host/{clean_ip}"

        cached, cache_info = external_api_cache.get("shodan_ip", clean_ip, force_refresh=force_refresh)
        if cached and isinstance(cached, dict):
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
                "hosts": [],
                "cloud_providers": [],
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
                    city = data.get("city")
                    country_name = data.get("country_name")
                    country_code = data.get("country_code")
                    last_update = data.get("last_update")

                    cloud_providers_set: Set[str] = set()
                    services: List[Dict[str, Any]] = []

                    for item in data.get("data", []):
                        p = item.get("port")
                        transport = item.get("transport", "tcp")
                        product = item.get("product")
                        version = item.get("version")
                        cpe = item.get("cpe", [])
                        raw_data = item.get("data", "")
                        banner = raw_data[:500].strip() if raw_data else None
                        ssl_info = item.get("ssl")
                        cloud_info = item.get("cloud")

                        if cloud_info:
                            prov = cloud_info.get("provider") or cloud_info.get("service") or "Cloud"
                            reg = cloud_info.get("region")
                            cloud_label = f"{prov} ({reg})" if reg else prov
                            cloud_providers_set.add(cloud_label)

                        http_info = item.get("http")
                        parsed_http = None
                        if http_info:
                            parsed_http = {
                                "title": http_info.get("title"),
                                "server": http_info.get("server"),
                                "dom_hash": http_info.get("dom_hash"),
                                "favicon_hash": (http_info.get("favicon") or {}).get("murmur_hash") or (http_info.get("favicon") or {}).get("dom_hash"),
                                "cookies": list((http_info.get("cookies") or {}).keys()) if isinstance(http_info.get("cookies"), dict) else None,
                                "security_headers": list((http_info.get("security_headers") or {}).keys()) if isinstance(http_info.get("security_headers"), dict) else None,
                            }

                        parsed_ssl = None
                        if ssl_info:
                            parsed_ssl = {
                                "enabled": True,
                                "cert_subject": (ssl_info.get("cert") or {}).get("subject", {}).get("CN"),
                                "cert_issuer": (ssl_info.get("cert") or {}).get("issuer", {}).get("CN"),
                                "cipher": (ssl_info.get("cipher") or {}).get("name"),
                            }

                        services.append({
                            "port": p,
                            "transport": transport,
                            "product": product,
                            "version": version,
                            "cpe": cpe if isinstance(cpe, list) else [cpe],
                            "banner_snippet": banner,
                            "raw_banner": raw_data[:2000].strip() if raw_data else None,
                            "ssl_enabled": bool(ssl_info),
                            "ssl": parsed_ssl,
                            "cloud": cloud_info,
                            "http": parsed_http,
                            "vulns": list(item.get("vulns", {}).keys()) if isinstance(item.get("vulns"), dict) else list(item.get("vulns", []))
                        })

                    # Build unified host record
                    single_host: Dict[str, Any] = {
                        "ip": clean_ip,
                        "ports": sorted(ports),
                        "hostnames": hostnames,
                        "domains": data.get("domains", []),
                        "os": os_name,
                        "isp": isp,
                        "org": org,
                        "asn": asn,
                        "city": city,
                        "country_name": country_name,
                        "country_code": country_code,
                        "vulns": vulns,
                        "cloud_providers": sorted(list(cloud_providers_set)),
                        "services": services
                    }

                    result = {
                        "configured": True,
                        "queried": True,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": sorted(ports),
                        "hostnames": hostnames,
                        "domains": data.get("domains", []),
                        "os": os_name,
                        "isp": isp,
                        "org": org,
                        "asn": asn,
                        "city": city,
                        "country_name": country_name,
                        "country_code": country_code,
                        "vulns": vulns,
                        "tags": tags,
                        "services": services,
                        "hosts": [single_host],
                        "cloud_providers": sorted(list(cloud_providers_set)),
                        "total_services": len(services),
                        "total_hosts": 1,
                        "last_update": last_update,
                        "message": f"Successfully retrieved Shodan host telemetry ({len(ports)} open ports, {len(vulns)} CVEs)."
                    }
                    external_api_cache.set("shodan_ip", clean_ip, result)
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
                        "hosts": [],
                        "cloud_providers": [],
                        "tags": [],
                        "message": "No open ports or services indexed by Shodan for this IP."
                    }
                    external_api_cache.set("shodan_ip", clean_ip, result)
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
                        "hosts": [],
                        "cloud_providers": [],
                        "message": "Shodan authentication failed (invalid API key)."
                    }
                else:
                    fallback, _ = external_api_cache.get_stale_fallback("shodan_ip", clean_ip)
                    if fallback:
                        return fallback
                    return {
                        "configured": True,
                        "queried": False,
                        "target": clean_ip,
                        "is_ip": True,
                        "web_link": web_link,
                        "ports": [],
                        "vulns": [],
                        "services": [],
                        "hosts": [],
                        "cloud_providers": [],
                        "message": f"Shodan API returned HTTP status {res.status_code}."
                    }

        except Exception as e:
            logger.debug(f"Shodan lookup_ip error for {clean_ip}: {e}")
            fallback, _ = external_api_cache.get_stale_fallback("shodan_ip", clean_ip)
            if fallback:
                return fallback
            return {
                "configured": True,
                "queried": False,
                "target": clean_ip,
                "is_ip": True,
                "web_link": web_link,
                "ports": [],
                "vulns": [],
                "services": [],
                "hosts": [],
                "cloud_providers": [],
                "message": f"Connection error querying Shodan: {e}"
            }

    @classmethod
    def lookup_domain(cls, domain: str, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Query Shodan DNS Domain API and Host Search for a domain.
        Aggregates all matching hosts, ports, cloud services, and banners.
        """
        clean_domain = (domain or "").strip().lower()
        web_link = f"https://www.shodan.io/search?query=hostname:{clean_domain}"

        cached, cache_info = external_api_cache.get("shodan_domain", clean_domain, force_refresh=force_refresh)
        if cached and isinstance(cached, dict):
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
                "dns_records": [],
                "ports": [],
                "vulns": [],
                "hosts": [],
                "services": [],
                "cloud_providers": [],
                "total_hosts": 0,
                "message": "Shodan API key not configured. Add your key in Administrator Settings for automated Shodan intelligence."
            }

        try:
            subdomains: List[str] = []
            dns_records: List[Dict[str, Any]] = []
            open_ports: List[int] = []
            all_vulns: List[str] = []
            cloud_providers_set: Set[str] = set()
            hosts_list: List[Dict[str, Any]] = []
            seen_host_endpoints: Set[str] = set()
            total_hosts = 0

            with httpx.Client(timeout=10.0) as client:
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
                                "value": rec.get("value"),
                                "last_seen": rec.get("last_seen")
                            })
                except Exception as e:
                    logger.debug(f"Shodan DNS domain query failed: {e}")

                # 2. Shodan Host Search by hostname query
                raw_matches: List[Dict[str, Any]] = []
                try:
                    search_url = f"{SHODAN_BASE_URL}/shodan/host/search?key={key}&query=hostname:{clean_domain}"
                    search_res = client.get(search_url)
                    if search_res.status_code == 200:
                        sdata = search_res.json()
                        total_hosts = max(total_hosts, sdata.get("total", 0))
                        raw_matches.extend(sdata.get("matches", []))
                except Exception as e:
                    logger.debug(f"Shodan host search query failed: {e}")

                # 3. Supplemental SSL search if hostname search returned few results
                if len(raw_matches) < 3:
                    try:
                        ssl_url = f"{SHODAN_BASE_URL}/shodan/host/search?key={key}&query=ssl:{clean_domain}"
                        ssl_res = client.get(ssl_url)
                        if ssl_res.status_code == 200:
                            sdata = ssl_res.json()
                            total_hosts = max(total_hosts, sdata.get("total", 0))
                            for m in sdata.get("matches", []):
                                if m not in raw_matches:
                                    raw_matches.append(m)
                    except Exception as e:
                        logger.debug(f"Shodan SSL search query failed: {e}")

                # 4. Parse all discovered matches into structured ShodanHost objects
                for match in raw_matches:
                    ip_str = match.get("ip_str")
                    p = match.get("port")
                    if not ip_str:
                        continue

                    endpoint_key = f"{ip_str}:{p}"
                    if endpoint_key in seen_host_endpoints:
                        continue
                    seen_host_endpoints.add(endpoint_key)

                    if p and p not in open_ports:
                        open_ports.append(p)

                    # Extract CVEs
                    m_vulns = list(match.get("vulns", {}).keys()) if isinstance(match.get("vulns"), dict) else list(match.get("vulns", []))
                    for v in m_vulns:
                        if v not in all_vulns:
                            all_vulns.append(v)

                    # Extract Cloud Provider
                    cloud_info = match.get("cloud")
                    if cloud_info:
                        prov = cloud_info.get("provider") or cloud_info.get("service") or "Cloud"
                        reg = cloud_info.get("region")
                        cloud_label = f"{prov} ({reg})" if reg else prov
                        cloud_providers_set.add(cloud_label)

                    loc = match.get("location") or {}
                    raw_data = match.get("data") or ""
                    banner = raw_data[:500].strip() if raw_data else None

                    http_info = match.get("http")
                    parsed_http = None
                    if http_info:
                        parsed_http = {
                            "title": http_info.get("title"),
                            "server": http_info.get("server"),
                            "dom_hash": http_info.get("dom_hash"),
                            "favicon_hash": (http_info.get("favicon") or {}).get("murmur_hash") or (http_info.get("favicon") or {}).get("dom_hash"),
                            "cookies": list((http_info.get("cookies") or {}).keys()) if isinstance(http_info.get("cookies"), dict) else None,
                            "security_headers": list((http_info.get("security_headers") or {}).keys()) if isinstance(http_info.get("security_headers"), dict) else None,
                        }

                    ssl_info = match.get("ssl")
                    parsed_ssl = None
                    if ssl_info:
                        parsed_ssl = {
                            "enabled": True,
                            "cert_subject": (ssl_info.get("cert") or {}).get("subject", {}).get("CN"),
                            "cert_issuer": (ssl_info.get("cert") or {}).get("issuer", {}).get("CN"),
                            "cipher": (ssl_info.get("cipher") or {}).get("name"),
                        }

                    host_obj = {
                        "ip": ip_str,
                        "port": p,
                        "transport": match.get("transport", "tcp"),
                        "hostnames": match.get("hostnames", []),
                        "domains": match.get("domains", []),
                        "asn": match.get("asn"),
                        "org": match.get("org"),
                        "isp": match.get("isp"),
                        "city": loc.get("city"),
                        "country_name": loc.get("country_name"),
                        "country_code": loc.get("country_code"),
                        "product": match.get("product"),
                        "version": match.get("version"),
                        "banner_snippet": banner,
                        "raw_banner": raw_data[:2000].strip() if raw_data else None,
                        "cloud": cloud_info,
                        "http": parsed_http,
                        "ssl": parsed_ssl,
                        "vulns": m_vulns,
                        "ports": [p] if p else []
                    }
                    hosts_list.append(host_obj)

            total_hosts = max(total_hosts, len(hosts_list))
            result = {
                "configured": True,
                "queried": True,
                "target": clean_domain,
                "is_ip": False,
                "web_link": web_link,
                "subdomains": sorted(subdomains),
                "dns_records": dns_records,
                "ports": sorted(open_ports),
                "vulns": sorted(all_vulns),
                "hosts": hosts_list,
                "services": [h for h in hosts_list if h.get("port")],
                "cloud_providers": sorted(list(cloud_providers_set)),
                "total_hosts": total_hosts,
                "message": f"Shodan indexed {total_hosts} exposed hosts/endpoints, {len(subdomains)} subdomains, and {len(open_ports)} distinct ports."
            }
            external_api_cache.set("shodan_domain", clean_domain, result)
            return result

        except Exception as e:
            logger.debug(f"Shodan lookup_domain error for {clean_domain}: {e}")
            fallback, _ = external_api_cache.get_stale_fallback("shodan_domain", clean_domain)
            if fallback:
                return fallback
            return {
                "configured": True,
                "queried": False,
                "target": clean_domain,
                "is_ip": False,
                "web_link": web_link,
                "subdomains": [],
                "dns_records": [],
                "ports": [],
                "vulns": [],
                "hosts": [],
                "cloud_providers": [],
                "total_hosts": 0,
                "message": f"Connection error querying Shodan: {e}"
            }

    @classmethod
    def lookup(
        cls,
        target: str,
        is_ip: bool = False,
        primary_ip: Optional[str] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Unified Shodan intelligence lookup for IP or Domain.
        Automatically enriches domain targets with primary IP host telemetry and cloud tags.
        """
        clean_target = (target or "").strip().lower()
        if is_ip:
            return cls.lookup_ip(clean_target, force_refresh=force_refresh)

        # For domains: perform domain search + subdomains
        domain_res = cls.lookup_domain(clean_target, force_refresh=force_refresh)

        # Enrich with primary IP telemetry if available
        if primary_ip:
            ip_res = cls.lookup_ip(primary_ip, force_refresh=force_refresh)
            domain_res["primary_ip_telemetry"] = ip_res

            # Merge ports
            if ip_res.get("ports"):
                domain_res["ports"] = sorted(list(set(domain_res.get("ports", []) + ip_res.get("ports", []))))

            # Merge vulns
            if ip_res.get("vulns"):
                domain_res["vulns"] = sorted(list(set(domain_res.get("vulns", []) + ip_res.get("vulns", []))))

            # Merge cloud providers
            if ip_res.get("cloud_providers"):
                merged_cloud = set(domain_res.get("cloud_providers", []))
                merged_cloud.update(ip_res["cloud_providers"])
                domain_res["cloud_providers"] = sorted(list(merged_cloud))

            # Merge hosts
            existing_ips = {h.get("ip") for h in domain_res.get("hosts", [])}
            for ip_host in ip_res.get("hosts", []):
                if ip_host.get("ip") not in existing_ips:
                    domain_res.setdefault("hosts", []).append(ip_host)

            if not domain_res.get("os") and ip_res.get("os"):
                domain_res["os"] = ip_res.get("os")
            if not domain_res.get("isp") and ip_res.get("isp"):
                domain_res["isp"] = ip_res.get("isp")
            if not domain_res.get("org") and ip_res.get("org"):
                domain_res["org"] = ip_res.get("org")
            if not domain_res.get("asn") and ip_res.get("asn"):
                domain_res["asn"] = ip_res.get("asn")

        return domain_res
