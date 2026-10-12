"""
Reverse Nameserver (Reverse-NS) & Reverse Mail Server (Reverse-MX) Attribution Pivots.
Identifies sibling domains sharing authoritative nameservers or dedicated mail exchangers.
Differentiates private/dedicated infrastructure (high attribution confidence) from
shared multi-tenant cloud providers (e.g. Cloudflare, AWS Route53, Google Workspace, M365,
Ports Group, Telia, Baffin Bay Networks).
"""

from typing import Dict, Any, List, Set, Optional
import httpx
from app.core.logging_config import logger


# Broad multi-tenant nameserver providers and registrars that should NOT be treated as private dedicated infrastructure
GENERIC_NS_HOSTS = [
    "cloudflare.com", "awsdns", "googledomains.com", "google.com", "azure-dns",
    "domaincontrol.com", "registrar-servers.com", "dnspod", "alidns",
    "name-services.com", "dnsimple.com", "dynect.net", "ultradns.net",
    "ports.se", "ports.net", "dipcon.com", "telia.com", "tele2.com", "loopia",
    "binero", "one.com", "bahnhof", "markmonitor", "cscdns", "cscglobal",
    "cscdbs", "safebrands", "inwx", "infomaniak", "baffinbay", "mastercard",
    "nsone", "porkbun", "hover", "godaddy", "namecheap", "he.net", "afraid.org",
    "easydns", "zoneedit", "eurodns", "ovh.net", "hetzner", "hostinger",
    "rackspace", "bluehost", "hostgator", "dreamhost", "siteground", "wixdns"
]

# Broad multi-tenant mail providers that should NOT be treated as private dedicated infrastructure
GENERIC_MX_HOSTS = [
    "google.com", "googlemail.com", "outlook.com", "pphosted.com", "mimecast.com",
    "barracudanetworks.com", "mailgun.org", "sendgrid.net", "zoho.com",
    "secureserver.net", "protection.outlook.com", "messagelabs.com",
    "proofpoint.com", "forcepoint.net", "trendmicro.com", "sophos.com",
    "ports.se", "telia.com", "tele2.com", "one.com", "binero.se", "loopia.se"
]


class ReverseInfrastructurePivoter:
    """
    Pivots on authoritative nameservers and mail exchangers to uncover actor infrastructure.
    Filters out public registrars, multi-tenant DNS clouds, and DDoS protection providers.
    """

    @classmethod
    def pivot(
        cls,
        target_domain: str,
        nameservers: Optional[List[str]] = None,
        mx_hosts: Optional[List[str]] = None,
        timeout_s: float = 3.5
    ) -> Dict[str, Any]:
        """
        Executes Reverse-NS and Reverse-MX lookups for custom infrastructure.
        """
        clean_target = target_domain.strip().lower()
        def _to_str(val: Any) -> Optional[str]:
            if isinstance(val, dict):
                v = val.get("host") or val.get("exchange") or val.get("server") or ""
                return str(v).strip().lower().rstrip(".") if v else None
            if isinstance(val, str):
                s = val.strip().lower().rstrip(".")
                return s if s else None
            return None

        ns_list = [s for s in (_to_str(ns) for ns in (nameservers or [])) if s]
        mx_list = [s for s in (_to_str(mx) for mx in (mx_hosts or [])) if s]

        ns_results: List[Dict[str, Any]] = []
        mx_results: List[Dict[str, Any]] = []
        discovered_siblings: Set[str] = set()

        with httpx.Client(timeout=timeout_s, headers={"User-Agent": "FileSanitizer-HostAudit/1.0"}) as client:
            # 1. Reverse NS Lookups (check top 2 nameservers)
            for ns in ns_list[:2]:
                is_shared = any(g in ns for g in GENERIC_NS_HOSTS)
                entry: Dict[str, Any] = {
                    "nameserver": ns,
                    "is_shared_provider": is_shared,
                    "associated_domains": [],
                    "count": 0,
                    "attribution_confidence": "LOW (Multi-Tenant Provider)" if is_shared else "HIGH (Dedicated DNS Infrastructure)"
                }

                if not is_shared:
                    try:
                        url = f"https://api.hackertarget.com/findshareddns/?q={ns}"
                        resp = client.get(url)
                        if resp.status_code == 200 and resp.text and not resp.text.startswith("error"):
                            domains = []
                            for line in resp.text.splitlines():
                                d = line.strip().lower()
                                if d and "." in d and d != clean_target and len(d) < 80:
                                    domains.append(d)

                            # If a nameserver hosts more than 10 domains, it is dynamically confirmed
                            # to be a shared multi-tenant / registrar nameserver rather than a private cluster
                            if len(domains) > 10:
                                entry["is_shared_provider"] = True
                                entry["attribution_confidence"] = "LOW (Multi-Tenant Provider)"
                            else:
                                for d in domains:
                                    discovered_siblings.add(d)

                            entry["associated_domains"] = domains[:25]
                            entry["count"] = len(domains)
                    except Exception as e:
                        logger.debug(f"Reverse NS lookup failed for {ns}: {e}")

                ns_results.append(entry)

            # 2. Reverse MX Lookups (check top 2 MX hosts)
            for mx in mx_list[:2]:
                is_shared = any(g in mx for g in GENERIC_MX_HOSTS)
                entry = {
                    "mx_host": mx,
                    "is_shared_provider": is_shared,
                    "associated_domains": [],
                    "count": 0,
                    "attribution_confidence": "LOW (Public Cloud Mail)" if is_shared else "HIGH (Dedicated Mail Exchanger)"
                }

                if not is_shared:
                    try:
                        url = f"https://api.hackertarget.com/findsharedmx/?q={mx}"
                        resp = client.get(url)
                        if resp.status_code == 200 and resp.text and not resp.text.startswith("error"):
                            domains = []
                            for line in resp.text.splitlines():
                                d = line.strip().lower()
                                if d and "." in d and d != clean_target and len(d) < 80:
                                    domains.append(d)

                            if len(domains) > 10:
                                entry["is_shared_provider"] = True
                                entry["attribution_confidence"] = "LOW (Public Cloud Mail)"
                            else:
                                for d in domains:
                                    discovered_siblings.add(d)

                            entry["associated_domains"] = domains[:25]
                            entry["count"] = len(domains)
                    except Exception as e:
                        logger.debug(f"Reverse MX lookup failed for {mx}: {e}")

                mx_results.append(entry)

        return {
            "tested": True,
            "target": clean_target,
            "reverse_ns": ns_results,
            "reverse_mx": mx_results,
            "discovered_siblings": sorted(list(discovered_siblings)),
            "total_siblings_discovered": len(discovered_siblings)
        }
