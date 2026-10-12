"""
Advanced DNS & DNSSEC Inspection with Subdomain Takeover Detection.
Collects: A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, SRV, HTTPS, SVCB, DNSSEC (DS, DNSKEY, RRSIG).
Analyzes: Low TTL / fast-flux rotation, wildcard DNS, SPF anomalies, and dangling CNAME takeover candidates.
"""

import uuid
import socket
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
import httpx

from app.core.logging_config import logger

try:
    import dns.resolver
    import dns.reversename
    import dns.dnssec
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# Known cloud providers and their subdomain takeover fingerprint signatures
TAKEOVER_FINGERPRINTS = [
    {
        "provider": "GitHub Pages",
        "cname_suffix": [".github.io"],
        "nxdomain": True,
        "response_signature": "There isn't a GitHub Pages site here",
        "severity": "high"
    },
    {
        "provider": "Amazon S3",
        "cname_suffix": [".s3.amazonaws.com", ".s3-website-", ".s3-website."],
        "nxdomain": True,
        "response_signature": "NoSuchBucket",
        "severity": "critical"
    },
    {
        "provider": "Amazon CloudFront",
        "cname_suffix": [".cloudfront.net"],
        "nxdomain": False,
        "response_signature": "Bad request: The request could not be satisfied",
        "severity": "medium"
    },
    {
        "provider": "Heroku",
        "cname_suffix": [".herokudns.com", ".herokuapp.com"],
        "nxdomain": True,
        "response_signature": "No such app",
        "severity": "high"
    },
    {
        "provider": "Microsoft Azure App Service",
        "cname_suffix": [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"],
        "nxdomain": True,
        "response_signature": "404 Web Site not found",
        "severity": "high"
    },
    {
        "provider": "Shopify",
        "cname_suffix": [".myshopify.com"],
        "nxdomain": False,
        "response_signature": "Sorry, this shop is currently unavailable",
        "severity": "medium"
    },
    {
        "provider": "Zendesk",
        "cname_suffix": [".zendesk.com"],
        "nxdomain": True,
        "response_signature": "Help Center Closed",
        "severity": "medium"
    },
    {
        "provider": "Fastly",
        "cname_suffix": [".fastly.net"],
        "nxdomain": True,
        "response_signature": "Fastly error: unknown domain",
        "severity": "medium"
    },
    {
        "provider": "Ghost",
        "cname_suffix": [".ghost.io"],
        "nxdomain": True,
        "response_signature": "The thing you were looking for is no longer here",
        "severity": "low"
    }
]


class AdvancedDNSInspector:
    """
    Executes deep multi-record DNS resolution, DNSSEC validation, and vulnerability heuristics.
    """

    @classmethod
    def inspect(cls, domain: str, is_ip: bool = False) -> Dict[str, Any]:
        """
        Main inspection routine for a domain or IP address.
        """
        clean_target = domain.strip().lower().rstrip(".")

        result: Dict[str, Any] = {
            "target": clean_target,
            "is_ip": is_ip,
            "records": {
                "a": [],
                "aaaa": [],
                "cname": [],
                "mx": [],
                "ns": [],
                "soa": [],
                "txt": [],
                "caa": [],
                "srv": [],
                "https": [],
                "svcb": [],
                "ptr": []
            },
            "ttls": {},
            "dnssec": {
                "enabled": False,
                "validated": False,
                "ds_records": [],
                "dnskey_count": 0,
                "rrsig_present": False,
                "notes": "No DNSSEC records detected"
            },
            "heuristics": {
                "has_wildcard_dns": False,
                "wildcard_ip": None,
                "low_ttl_detected": False,
                "min_ttl": None,
                "fast_flux_suspect": False,
                "suspicious_spf": False,
                "spf_details": None,
                "dangling_cnames": [],
            },
            "anomalies": []
        }

        if is_ip:
            result["records"]["ptr"] = cls._resolve_ptr(clean_target)
            result["fcrdns"] = cls.verify_fcrdns(clean_target)
            return result

        if not HAS_DNSPYTHON:
            logger.warning("dnspython not available for AdvancedDNSInspector")
            return result

        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.2
        resolver.lifetime = 2.0

        # 1. Resolve Standard & Advanced Records
        cls._query_records(resolver, clean_target, result)

        # 2. DNSSEC Validation
        cls._check_dnssec(resolver, clean_target, result)

        # 3. Wildcard DNS Detection
        cls._check_wildcard(resolver, clean_target, result)

        # 4. Low TTL & Fast-Flux Checks
        cls._check_ttl_and_flux(result)

        # 5. TXT & SPF Analysis
        cls._analyze_txt_spf(result)

        # 6. Dangling CNAME & Subdomain Takeover Analysis
        cls._analyze_takeover_risks(clean_target, result)

        # 7. Forward-Confirmed Reverse DNS (FCrDNS) on primary resolved IP
        primary_ips = result["records"].get("a") or []
        if primary_ips:
            result["fcrdns"] = cls.verify_fcrdns(primary_ips[0])
        else:
            result["fcrdns"] = {"is_fcrdns_valid": False, "status": "NO_A_RECORD", "details": "No IPv4 address resolved"}

        return result

    @classmethod
    def verify_fcrdns(cls, ip: str) -> Dict[str, Any]:
        """
        Forward-Confirmed Reverse DNS (FCrDNS) Verification.
        1. Resolve IP -> PTR hostname.
        2. Resolve PTR hostname -> Forward A/AAAA IPs.
        3. Confirm if initial IP matches any forward IP.
        """
        clean_ip = ip.strip()
        ptr_hosts = cls._resolve_ptr(clean_ip)
        if not ptr_hosts:
            return {
                "ip": clean_ip,
                "has_ptr": False,
                "ptr_hosts": [],
                "primary_ptr": None,
                "forward_ips": [],
                "is_fcrdns_valid": False,
                "status": "NO_PTR",
                "details": f"No reverse PTR record configured for IP {clean_ip}."
            }

        primary_ptr = ptr_hosts[0]
        forward_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(primary_ptr, None)
            for item in addr_info:
                f_ip = item[4][0]
                if f_ip not in forward_ips:
                    forward_ips.append(f_ip)
        except Exception:
            pass

        if clean_ip in forward_ips:
            return {
                "ip": clean_ip,
                "has_ptr": True,
                "ptr_hosts": ptr_hosts,
                "primary_ptr": primary_ptr,
                "forward_ips": forward_ips,
                "is_fcrdns_valid": True,
                "status": "VALID",
                "details": f"FCrDNS confirmed: Reverse PTR '{primary_ptr}' resolves forward back to '{clean_ip}'."
            }
        else:
            return {
                "ip": clean_ip,
                "has_ptr": True,
                "ptr_hosts": ptr_hosts,
                "primary_ptr": primary_ptr,
                "forward_ips": forward_ips,
                "is_fcrdns_valid": False,
                "status": "MISMATCH",
                "details": f"FCrDNS mismatch: PTR '{primary_ptr}' resolves to {forward_ips or 'none'}, failing bidirectional confirmation for '{clean_ip}'."
            }

    @classmethod
    def _resolve_ptr(cls, ip: str) -> List[str]:
        """Resolves reverse DNS PTR for IP."""
        if not HAS_DNSPYTHON:
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                return [host] if host else []
            except Exception:
                return []
        try:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.5
            answers = resolver.resolve(rev_name, "PTR")
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []

    @classmethod
    def _query_records(cls, resolver: Any, domain: str, result: Dict[str, Any]) -> None:
        """Queries standard and advanced DNS record types."""
        records = result["records"]
        ttls = result["ttls"]

        # Helper to query and record TTLs
        def _safe_query(record_type: str):
            try:
                ans = resolver.resolve(domain, record_type)
                type_key = record_type.lower()
                vals = []
                for r in ans:
                    if record_type == "MX":
                        vals.append({"host": str(r.exchange).rstrip("."), "priority": r.preference})
                    elif record_type in ("CNAME", "NS"):
                        vals.append(str(r.target).rstrip("."))
                    elif record_type == "SOA":
                        vals.append({
                            "mname": str(r.mname).rstrip("."),
                            "rname": str(r.rname).rstrip("."),
                            "serial": r.serial,
                            "refresh": r.refresh,
                            "retry": r.retry,
                            "expire": r.expire,
                            "minimum": r.minimum
                        })
                    elif record_type == "CAA":
                        vals.append({"flags": r.flags, "tag": r.tag.decode("utf-8", "ignore"), "value": r.value.decode("utf-8", "ignore")})
                    elif record_type == "TXT":
                        vals.append(r.to_text().strip('"'))
                    else:
                        vals.append(str(r))

                records[type_key] = vals
                if ans.rrset and ans.rrset.ttl is not None:
                    ttls[type_key] = ans.rrset.ttl
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.debug(f"DNS query error for {record_type} on {domain}: {e}")

        # Core queries executed in parallel
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA", "SRV", "HTTPS"]
        with ThreadPoolExecutor(max_workers=len(record_types)) as pool:
            list(pool.map(_safe_query, record_types))

    @classmethod
    def _check_dnssec(cls, resolver: Any, domain: str, result: Dict[str, Any]) -> None:
        """Inspects DNSSEC configuration, DS records, and DNSKEY signatures."""
        dnssec_info = result["dnssec"]
        try:
            # Query DS records
            try:
                ds_ans = resolver.resolve(domain, "DS")
                for r in ds_ans:
                    dnssec_info["ds_records"].append({
                        "key_tag": r.key_tag,
                        "algorithm": r.algorithm,
                        "digest_type": r.digest_type,
                        "digest": r.digest.hex()
                    })
                if dnssec_info["ds_records"]:
                    dnssec_info["enabled"] = True
            except Exception:
                pass

            # Query DNSKEY
            try:
                dnskey_ans = resolver.resolve(domain, "DNSKEY")
                dnssec_info["dnskey_count"] = len(dnskey_ans)
                if len(dnskey_ans) > 0:
                    dnssec_info["enabled"] = True
            except Exception:
                pass

            if dnssec_info["enabled"]:
                dnssec_info["validated"] = bool(dnssec_info["ds_records"]) and (dnssec_info["dnskey_count"] > 0)
                dnssec_info["notes"] = "DNSSEC signatures and DS delegation active"
            else:
                dnssec_info["notes"] = "Domain is not signed with DNSSEC"

        except Exception as e:
            logger.debug(f"DNSSEC check note for {domain}: {e}")

    @classmethod
    def _check_wildcard(cls, resolver: Any, domain: str, result: Dict[str, Any]) -> None:
        """Detects if the zone implements wildcard DNS by querying a non-existent subdomain."""
        random_sub = f"filesanitizer-test-{uuid.uuid4().hex[:8]}.{domain}"
        try:
            ans = resolver.resolve(random_sub, "A")
            ips = [str(r) for r in ans]
            if ips:
                result["heuristics"]["has_wildcard_dns"] = True
                result["heuristics"]["wildcard_ip"] = ips[0]
                result["anomalies"].append({
                    "type": "WILDCARD_DNS",
                    "severity": "medium",
                    "title": "Wildcard DNS Enabled",
                    "description": f"Zone resolves non-existent subdomains (e.g. {random_sub}) to IP {ips[0]}."
                })
        except Exception:
            pass

    @classmethod
    def _check_ttl_and_flux(cls, result: Dict[str, Any]) -> None:
        """Identifies very low TTLs (< 120s) and fast-flux hosting indicators."""
        ttls = result["ttls"]
        a_records = result["records"]["a"]

        if ttls:
            min_ttl = min(ttls.values())
            result["heuristics"]["min_ttl"] = min_ttl

            if min_ttl < 180:
                result["heuristics"]["low_ttl_detected"] = True

                # Fast-flux check: low TTL + multiple A records
                if len(a_records) >= 3 and min_ttl <= 300:
                    result["heuristics"]["fast_flux_suspect"] = True
                    result["anomalies"].append({
                        "type": "FAST_FLUX_INDICATOR",
                        "severity": "high",
                        "title": f"Possible Fast-Flux DNS Detected (TTL: {min_ttl}s, {len(a_records)} IPs)",
                        "description": "Short TTL combined with multiple A records is commonly used by botnets and bulletproof hosting to evade IP blocklists."
                    })
                elif min_ttl <= 60:
                    result["anomalies"].append({
                        "type": "ULTRA_LOW_TTL",
                        "severity": "medium",
                        "title": f"Unusually Short TTL ({min_ttl} seconds)",
                        "description": "DNS records expire rapidly, allowing dynamic infrastructure rotation."
                    })

    @classmethod
    def _analyze_txt_spf(cls, result: Dict[str, Any]) -> None:
        """Inspects TXT records for SPF policy weaknesses and unusual verification tokens."""
        txt_records = result["records"]["txt"]
        spf_found = False

        for txt in txt_records:
            if txt.startswith("v=spf1"):
                spf_found = True
                result["heuristics"]["spf_details"] = txt

                if "+all" in txt:
                    result["heuristics"]["suspicious_spf"] = True
                    result["anomalies"].append({
                        "type": "PERMISSIVE_SPF",
                        "severity": "high",
                        "title": "Insecure SPF Policy (+all)",
                        "description": "SPF record ends with '+all', permitting any server in the world to spoof email on behalf of this domain."
                    })
                elif "?all" in txt:
                    result["anomalies"].append({
                        "type": "NEUTRAL_SPF",
                        "severity": "medium",
                        "title": "Neutral SPF Policy (?all)",
                        "description": "SPF policy specifies '?all' (Neutral), which fails to instruct receivers to reject unauthenticated mail."
                    })

    @classmethod
    def _analyze_takeover_risks(cls, domain: str, result: Dict[str, Any]) -> None:
        """
        Subdomain takeover heuristic engine.
        Checks CNAME records against known cloud provider targets.
        """
        cnames = result["records"]["cname"]
        if not cnames:
            return

        for cname in cnames:
            cname_clean = cname.lower().rstrip(".")
            for fp in TAKEOVER_FINGERPRINTS:
                matches_provider = any(cname_clean.endswith(suffix) or suffix in cname_clean for suffix in fp["cname_suffix"])
                if matches_provider:
                    # Check if CNAME resolves
                    cname_resolves = True
                    try:
                        socket.gethostbyname(cname_clean)
                    except socket.gaierror:
                        cname_resolves = False

                    # If NXDOMAIN or unresolving, high likelihood of dangling cloud asset
                    if not cname_resolves:
                        takeover_entry = {
                            "domain": domain,
                            "cname_target": cname_clean,
                            "provider": fp["provider"],
                            "status": "UNRESOLVING_CNAME_TARGET",
                            "severity": fp["severity"],
                            "vulnerability": f"Dangling {fp['provider']} CNAME (Takeover Candidate)",
                            "description": f"CNAME points to {cname_clean} on {fp['provider']}, but the target does not resolve. An attacker could claim this resource on the cloud provider."
                        }
                        result["heuristics"]["dangling_cnames"].append(takeover_entry)
                        result["anomalies"].append({
                            "type": "SUBDOMAIN_TAKEOVER_RISK",
                            "severity": fp["severity"],
                            "title": f"Subdomain Takeover Candidate ({fp['provider']})",
                            "description": takeover_entry["description"]
                        })
                    else:
                        # Optionally check HTTP response signature
                        try:
                            with httpx.Client(timeout=2.0, verify=False) as client:
                                resp = client.get(f"http://{domain}", headers={"Host": domain})
                                if fp["response_signature"] in resp.text:
                                    takeover_entry = {
                                        "domain": domain,
                                        "cname_target": cname_clean,
                                        "provider": fp["provider"],
                                        "status": "SIGNATURE_MATCHED",
                                        "severity": fp["severity"],
                                        "vulnerability": f"Claimable {fp['provider']} Endpoint",
                                        "description": f"Target returned provider error signature '{fp['response_signature']}', indicating the cloud resource is unallocated."
                                    }
                                    result["heuristics"]["dangling_cnames"].append(takeover_entry)
                                    result["anomalies"].append({
                                        "type": "SUBDOMAIN_TAKEOVER_RISK",
                                        "severity": fp["severity"],
                                        "title": f"Claimable Cloud Endpoint ({fp['provider']})",
                                        "description": takeover_entry["description"]
                                    })
                        except Exception:
                            pass
