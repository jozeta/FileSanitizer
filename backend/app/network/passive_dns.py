"""
Passive DNS (pDNS) Co-Location & Sibling Infrastructure Pivots.
Queries AlienVault OTX and HackerTarget to discover historical DNS resolutions,
sibling hosts, co-located infrastructure, and resolution change timelines.
"""

from typing import Dict, Any, List, Optional
import httpx
from app.core.logging_config import logger


class PassiveDnsClient:
    """
    Client for querying passive DNS databases to uncover historical resolutions and related assets.
    """

    OTX_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    HACKERTARGET_HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/"

    @classmethod
    def query_pdns(cls, target: str, is_ip: bool = False, timeout: float = 4.0) -> Dict[str, Any]:
        clean_target = (target or "").strip().lower().rstrip(".")
        result: Dict[str, Any] = {
            "target": clean_target,
            "is_ip": is_ip,
            "total_records": 0,
            "records": [],
            "discovered_domains": [],
            "discovered_ips": [],
            "sources": []
        }

        if not clean_target:
            return result

        # 1. Query AlienVault OTX
        try:
            url = cls.OTX_IP_URL.format(ip=clean_target) if is_ip else cls.OTX_DOMAIN_URL.format(domain=clean_target)
            with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "FileSanitizer-CTI/1.0"}) as client:
                resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                pdns_list = data.get("passive_dns") or []
                if pdns_list:
                    result["sources"].append("AlienVault OTX")
                    for item in pdns_list[:100]:
                        hostname = item.get("hostname", "")
                        address = item.get("address", "")
                        record_type = item.get("record_type", "")
                        first = item.get("first", "")
                        last = item.get("last", "")

                        result["records"].append({
                            "hostname": hostname,
                            "address": address,
                            "record_type": record_type,
                            "first_seen": first,
                            "last_seen": last,
                            "source": "AlienVault OTX"
                        })
                        if hostname and hostname not in result["discovered_domains"]:
                            result["discovered_domains"].append(hostname)
                        if address and address not in result["discovered_ips"]:
                            result["discovered_ips"].append(address)
        except Exception as e:
            logger.debug(f"OTX pDNS query note for {clean_target}: {e}")

        # 2. Query HackerTarget Hostsearch (if domain)
        if not is_ip:
            try:
                with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "FileSanitizer-CTI/1.0"}) as client:
                    resp = client.get(cls.HACKERTARGET_HOSTSEARCH_URL, params={"q": clean_target})
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if text and not text.lower().startswith("error") and "api count exceeded" not in text.lower():
                        result["sources"].append("HackerTarget")
                        for line in text.splitlines():
                            parts = line.split(",")
                            if len(parts) >= 2:
                                host, ip_addr = parts[0].strip(), parts[1].strip()
                                result["records"].append({
                                    "hostname": host,
                                    "address": ip_addr,
                                    "record_type": "A",
                                    "first_seen": None,
                                    "last_seen": None,
                                    "source": "HackerTarget"
                                })
                                if host and host not in result["discovered_domains"]:
                                    result["discovered_domains"].append(host)
                                if ip_addr and ip_addr not in result["discovered_ips"]:
                                    result["discovered_ips"].append(ip_addr)
            except Exception as e:
                logger.debug(f"HackerTarget hostsearch query note for {clean_target}: {e}")

        result["total_records"] = len(result["records"])
        return result
