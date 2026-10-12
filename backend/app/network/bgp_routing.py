"""
BGP Routing, RPKI Validation & Route Hijack Detection.
Queries BGP route announcements, RPKI validation status (valid/invalid/not-found),
and detects Anycast infrastructure and route anomalies via RIPE Stat APIs.
"""

from typing import Dict, Any, List, Optional
import httpx
from app.core.logging_config import logger


ANYCAST_ASNS = {
    "AS13335": "Cloudflare Anycast CDN",
    "AS209242": "Cloudflare Anycast",
    "AS15169": "Google Global Anycast",
    "AS16509": "Amazon AWS Global Anycast",
    "AS54113": "Fastly Anycast CDN",
    "AS20940": "Akamai Anycast CDN",
    "AS8075": "Microsoft Azure Global Anycast",
    "AS2635": "Automattic Anycast",
    "AS62785": "BunnyCDN Anycast",
}


class BgpRoutingInspector:
    """
    Analyzes BGP routing status, RPKI route origin authorization, and Anycast signals.
    """

    RIPE_RPKI_URL = "https://stat.ripe.net/data/rpki-validation/data.json"
    RIPE_ROUTING_STATUS_URL = "https://stat.ripe.net/data/routing-status/data.json"
    RIPE_PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"

    @classmethod
    def inspect(cls, ip: str, asn: Optional[str] = None, timeout: float = 3.5) -> Dict[str, Any]:
        clean_ip = (ip or "").strip()
        result: Dict[str, Any] = {
            "ip": clean_ip,
            "asn": asn,
            "prefix": None,
            "rpki_status": "unknown",  # valid, invalid, not_found, unknown
            "is_rpki_valid": None,
            "is_anycast": False,
            "anycast_provider": None,
            "bgp_visibility": {
                "first_seen": None,
                "last_seen": None,
                "visibility_ratio": None,
                "peers_seeing": 0,
            },
            "risk_flags": [],
        }

        if not clean_ip:
            return result

        clean_asn_num = ""
        if asn:
            clean_asn_num = str(asn).upper().replace("AS", "").strip()

        try:
            # 1. Check known Anycast ASNs
            if asn:
                norm_asn = f"AS{clean_asn_num}"
                if norm_asn in ANYCAST_ASNS:
                    result["is_anycast"] = True
                    result["anycast_provider"] = ANYCAST_ASNS[norm_asn]

            with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "FileSanitizer-CTI/1.0"}) as client:
                # 2. Get Prefix and ASN if missing
                prefix = None
                resp_pre = client.get(cls.RIPE_PREFIX_OVERVIEW_URL, params={"resource": clean_ip})
                if resp_pre.status_code == 200:
                    pdata = resp_pre.json().get("data", {})
                    prefix = pdata.get("resource")
                    result["prefix"] = prefix
                    asns = pdata.get("asns") or []
                    if asns and not clean_asn_num:
                        clean_asn_num = str(asns[0].get("asn", "")).strip()
                        result["asn"] = f"AS{clean_asn_num}"

                # 3. Check RPKI Validation
                if prefix and clean_asn_num:
                    rpki_resp = client.get(cls.RIPE_RPKI_URL, params={"resource": clean_asn_num, "prefix": prefix})
                    if rpki_resp.status_code == 200:
                        rdata = rpki_resp.json().get("data", {})
                        status = rdata.get("status", "").lower()
                        result["rpki_status"] = status
                        result["is_rpki_valid"] = (status == "valid")

                        if status == "invalid":
                            result["risk_flags"].append({
                                "id": "RPKI_INVALID_ROUTE",
                                "severity": "HIGH",
                                "title": "BGP Route Origin Invalid (RPKI Invalid)",
                                "description": f"Prefix {prefix} announced by AS{clean_asn_num} contradicts ROA (Route Origin Authorization). Potential BGP hijack or misconfigured routing announcement."
                            })
                        elif status == "not_found":
                            result["risk_flags"].append({
                                "id": "RPKI_ROA_NOT_FOUND",
                                "severity": "LOW",
                                "title": "No RPKI ROA Published",
                                "description": f"Prefix {prefix} has no published RPKI Route Origin Authorization, leaving it vulnerable to unauthorized BGP route injection or hijacks."
                            })

                # 4. Check BGP Routing Status
                target_resource = prefix or clean_ip
                route_resp = client.get(cls.RIPE_ROUTING_STATUS_URL, params={"resource": target_resource})
                if route_resp.status_code == 200:
                    rstat = route_resp.json().get("data", {})
                    vis = rstat.get("visibility", {})
                    result["bgp_visibility"]["first_seen"] = rstat.get("first_seen", {}).get("time")
                    result["bgp_visibility"]["last_seen"] = rstat.get("last_seen", {}).get("time")
                    if vis:
                        result["bgp_visibility"]["visibility_ratio"] = vis.get("v4", {}).get("ratio")
                        result["bgp_visibility"]["peers_seeing"] = vis.get("v4", {}).get("total_ris_peers_seeing", 0)

        except Exception as e:
            logger.debug(f"BGP routing lookup error for {clean_ip}: {e}")

        return result
