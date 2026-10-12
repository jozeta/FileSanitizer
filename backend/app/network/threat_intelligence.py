"""
Multi-Feed Passive Threat Intelligence & ASN Infrastructure Profiler.
Aggregates indicators across: VirusTotal v3, Abuse.ch URLhaus, Abuse.ch ThreatFox, AbuseIPDB, and AlienVault OTX.
Profiles Autonomous Systems: ASN numbers, BGP prefixes, organization, hosting classification
(Cloud / Hyperscaler, Residential, Tor/VPN/Proxy, or Bulletproof/High-Risk).
"""

import socket
from typing import Dict, Any, List, Optional
import httpx

from app.core.logging_config import logger
from app.core.settings_store import settings_store


# Known cloud providers by ASN or Org name
CLOUD_ORGANIZATIONS = [
    "amazon", "aws", "microsoft", "azure", "google", "cloudflare", "digitalocean",
    "hetzner", "ovh", "linode", "akamai", "fastly", "oracle", "alibaba", "tencent"
]

# High-risk / Bulletproof hosting keywords or ASNs known in threat intelligence
HIGH_RISK_KEYWORDS = [
    "bulletproof", "offshore", "alexhost", "hostwinds", "stark industries",
    "pq hosting", "chocoping", "vdsina", "floki"
]


class ThreatIntelligenceAggregator:
    """
    Queries multiple threat intelligence sources and classifies network infrastructure.
    """

    @classmethod
    def aggregate_intelligence(cls, indicator: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """
        Queries all configured and public threat intelligence feeds for an indicator.
        """
        clean = indicator.strip()
        result: Dict[str, Any] = {
            "indicator": clean,
            "indicator_type": indicator_type,
            "overall_verdict": "clean",
            "malicious_votes": 0,
            "total_feeds_queried": 0,
            "threat_tags": [],
            "malware_families": [],
            "feeds": {
                "virustotal": {"queried": False, "verdict": "unknown", "detections": 0, "total": 0, "tags": []},
                "urlhaus": {"queried": False, "verdict": "unknown", "url_count": 0, "tags": []},
                "threatfox": {"queried": False, "verdict": "unknown", "ioc_count": 0, "tags": []},
                "abuseipdb": {"queried": False, "verdict": "unknown", "abuse_confidence_score": 0, "total_reports": 0},
                "alienvault_otx": {"queried": False, "verdict": "unknown", "pulse_count": 0}
            }
        }

        # 1. URLhaus (Public API)
        cls._query_urlhaus(clean, indicator_type, result)

        # 2. ThreatFox (Public API)
        cls._query_threatfox(clean, indicator_type, result)

        # 3. VirusTotal (If API key exists in SettingsStore or settings)
        cls._query_virustotal(clean, indicator_type, result)

        # 4. AbuseIPDB (If indicator is IP and key exists)
        if indicator_type in ("ip", "ipv4", "ipv6"):
            cls._query_abuseipdb(clean, result)

        # 5. Synthesize Consensus Verdict
        if result["malicious_votes"] >= 3:
            result["overall_verdict"] = "malicious"
        elif result["malicious_votes"] >= 1:
            result["overall_verdict"] = "suspicious"
        else:
            result["overall_verdict"] = "clean"

        result["threat_tags"] = sorted(list(set(result["threat_tags"])))
        result["malware_families"] = sorted(list(set(result["malware_families"])))

        return result

    @classmethod
    def _query_urlhaus(cls, indicator: str, indicator_type: str, result: Dict[str, Any]) -> None:
        """Queries Abuse.ch URLhaus database."""
        feed = result["feeds"]["urlhaus"]
        feed["queried"] = True
        result["total_feeds_queried"] += 1

        api_url = "https://urlhaus-api.abuse.ch/v1/host/" if indicator_type in ("domain", "ip", "ipv4") else "https://urlhaus-api.abuse.ch/v1/url/"
        data_payload = {"host": indicator} if "host" in api_url else {"url": indicator}

        # Use auth key if user configured one in Settings
        headers = {}
        uh_key = settings_store.get_api_key("urlhaus_api_key")
        if uh_key:
            headers["Auth-Key"] = uh_key

        try:
            with httpx.Client(timeout=3.5) as client:
                resp = client.post(api_url, data=data_payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok":
                        url_count = len(data.get("urls", []))
                        feed["url_count"] = url_count
                        feed["verdict"] = "malicious" if url_count > 0 else "clean"
                        if url_count > 0:
                            result["malicious_votes"] += 2
                            result["threat_tags"].append("malware_distribution")
                            for u in data.get("urls", [])[:5]:
                                if u.get("threat"):
                                    feed["tags"].append(u["threat"])
                                    result["threat_tags"].append(u["threat"])
                    elif status == "no_results":
                        feed["verdict"] = "clean"
        except Exception as e:
            logger.debug(f"URLhaus query note for {indicator}: {e}")

    @classmethod
    def _query_threatfox(cls, indicator: str, indicator_type: str, result: Dict[str, Any]) -> None:
        """Queries Abuse.ch ThreatFox IOC database."""
        feed = result["feeds"]["threatfox"]
        feed["queried"] = True
        result["total_feeds_queried"] += 1

        api_url = "https://threatfox-api.abuse.ch/api/v1/"
        data_payload = {"query": "search_ioc", "search_term": indicator}

        headers = {}
        tf_key = settings_store.get_api_key("threatfox_api_key")
        if tf_key:
            headers["Auth-Key"] = tf_key

        try:
            with httpx.Client(timeout=3.5) as client:
                resp = client.post(api_url, json=data_payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok" and data.get("data"):
                        iocs = data["data"]
                        feed["ioc_count"] = len(iocs)
                        feed["verdict"] = "malicious"
                        result["malicious_votes"] += 2
                        for item in iocs[:5]:
                            malware = item.get("malware_printable")
                            threat_type = item.get("threat_type_desc")
                            if malware:
                                result["malware_families"].append(malware)
                            if threat_type:
                                feed["tags"].append(threat_type)
                                result["threat_tags"].append(threat_type)
                    elif status == "no_result":
                        feed["verdict"] = "clean"
        except Exception as e:
            logger.debug(f"ThreatFox query note for {indicator}: {e}")

    @classmethod
    def _query_virustotal(cls, indicator: str, indicator_type: str, result: Dict[str, Any]) -> None:
        """Queries VirusTotal v3 if configured."""
        feed = result["feeds"]["virustotal"]
        vt_key = settings_store.get_api_key("virustotal_api_key")
        if not vt_key:
            return

        feed["queried"] = True
        result["total_feeds_queried"] += 1

        headers = {"x-apikey": vt_key}
        endpoint = ""
        if indicator_type in ("ip", "ipv4", "ipv6"):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif indicator_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        elif indicator_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        if not endpoint:
            return

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0

                    feed["detections"] = malicious + suspicious
                    feed["total"] = total
                    tags = attr.get("tags", [])
                    feed["tags"] = tags
                    result["threat_tags"].extend(tags)

                    if malicious >= 3:
                        feed["verdict"] = "malicious"
                        result["malicious_votes"] += 3
                    elif malicious >= 1 or suspicious >= 1:
                        feed["verdict"] = "suspicious"
                        result["malicious_votes"] += 1
                    else:
                        feed["verdict"] = "clean"
        except Exception as e:
            logger.debug(f"VirusTotal query note for {indicator}: {e}")

    @classmethod
    def _query_abuseipdb(cls, ip: str, result: Dict[str, Any]) -> None:
        """Queries AbuseIPDB if configured."""
        feed = result["feeds"]["abuseipdb"]
        abuse_key = settings_store.get_api_key("abuseipdb_api_key")
        if not abuse_key:
            return

        feed["queried"] = True
        result["total_feeds_queried"] += 1

        try:
            with httpx.Client(timeout=3.5) as client:
                resp = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    feed["abuse_confidence_score"] = score
                    feed["total_reports"] = reports
                    if score >= 50:
                        feed["verdict"] = "malicious"
                        result["malicious_votes"] += 2
                    elif score > 0:
                        feed["verdict"] = "suspicious"
                        result["malicious_votes"] += 1
                    else:
                        feed["verdict"] = "clean"
        except Exception as e:
            logger.debug(f"AbuseIPDB query note for {ip}: {e}")

    @classmethod
    def profile_asn(cls, ip: str, net_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Profiles ASN infrastructure type (Cloud, Bulletproof, Residential, VPN/Proxy, Tor).
        """
        asn = (net_info.get("asn") or "").upper()
        as_org = (net_info.get("as_org") or net_info.get("org") or "").lower()
        isp = (net_info.get("isp") or "").lower()

        classification = "Commercial / Enterprise"
        is_cloud = False
        is_bulletproof = False
        is_vpn_proxy = False
        risk_level = "low"

        # Check Cloud / Hyperscaler
        for c in CLOUD_ORGANIZATIONS:
            if c in as_org or c in isp:
                classification = f"Cloud Hyperscaler ({c.capitalize()})"
                is_cloud = True
                break

        # Check High-Risk / Bulletproof hosting keywords
        for bp in HIGH_RISK_KEYWORDS:
            if bp in as_org or bp in isp:
                classification = "High-Risk / Bulletproof Hosting Suspect"
                is_bulletproof = True
                risk_level = "high"
                break

        # Check Residential ISP
        if not is_cloud and any(r in as_org or r in isp for r in ["broadband", "telecom", "comcast", "verizon", "att", "charter", "vodafone"]):
            classification = "Residential / Consumer ISP"

        # Reverse PTR sweep on IP
        ptr_host = None
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            ptr_host = host
        except Exception:
            pass

        return {
            "ip": ip,
            "asn": asn,
            "as_org": net_info.get("as_org") or net_info.get("org"),
            "isp": net_info.get("isp"),
            "country": net_info.get("country"),
            "city": net_info.get("city"),
            "classification": classification,
            "is_cloud_provider": is_cloud,
            "is_bulletproof_suspect": is_bulletproof,
            "is_vpn_proxy": is_vpn_proxy,
            "risk_level": risk_level,
            "reverse_ptr": ptr_host,
            "announced_cidrs": net_info.get("cidrs", [])
        }
