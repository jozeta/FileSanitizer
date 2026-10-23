"""
Passive Subdomain Enumeration & Attack Surface Mapper.
Aggregates discovered subdomains from Certificate Transparency (crt.sh), TLS SANs, DNS CNAMEs, and sibling lookups.
Performs non-intrusive DNS resolution checks to classify subdomains (resolving, unresolving, cloud-hosted)
and attributes exact discovery provenance and dormant/unresolved rationale to each asset.
"""

import socket
import concurrent.futures
from typing import Dict, Any, List, Set, Optional

from app.core.logging_config import logger


class SubdomainMapper:
    """
    Consolidates subdomains from multiple passive intelligence sources into an attack surface map,
    annotating discovery source provenance and explaining unresolving / dormant states.
    """

    @classmethod
    def map_surface(
        cls,
        root_domain: str,
        ct_subdomains: List[str],
        tls_sans: List[str],
        dns_cnames: List[str],
        sibling_domains: List[str],
        additional_sources: Optional[Dict[str, List[str]]] = None,
        subfinder_results: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Deduplicates subdomains and performs passive resolution to identify active vs dormant endpoints,
        recording provenance source and technical resolution rationale.
        """
        clean_root = root_domain.strip().lower().rstrip(".")
        candidate_sources: Dict[str, Set[str]] = {}
        known_resolved_ips: Dict[str, List[str]] = {}

        # Helper to sanitize and add with discovery source
        def _add_candidate(name: str, src: str):
            clean = name.strip().lower().lstrip("*.").rstrip(".")
            if not clean:
                return
            # Must belong to root domain or be a subdomain
            if clean == clean_root or clean.endswith(f".{clean_root}"):
                if clean not in candidate_sources:
                    candidate_sources[clean] = set()
                candidate_sources[clean].add(src)

        # 1. Queried root domain
        _add_candidate(clean_root, "Queried Target")

        # 2. Subfinder & dnsx active reconnaissance
        if subfinder_results:
            for item in subfinder_results:
                s_name = item.get("subdomain") or item.get("domain") or ""
                s_clean = s_name.strip().lower().lstrip("*.").rstrip(".")
                if s_clean:
                    _add_candidate(s_clean, "Subfinder + dnsx")
                    if item.get("ips"):
                        known_resolved_ips[s_clean] = item["ips"]

        # 3. Live TLS Certificate SANs
        for s in tls_sans:
            _add_candidate(s, "Live TLS SAN")

        # 4. Certificate Transparency (crt.sh)
        for s in ct_subdomains:
            _add_candidate(s, "Certificate Transparency (crt.sh)")

        # 5. DNS CNAME chains
        for s in dns_cnames:
            _add_candidate(s, "DNS CNAME Chain")

        # 6. Passive DNS / Sibling lookup
        for s in sibling_domains:
            _add_candidate(s, "Passive DNS / Sibling")

        # 7. Additional external sources if provided
        if additional_sources:
            for src_label, subs in additional_sources.items():
                for s in subs:
                    _add_candidate(s, src_label)

        # 8. Standard common prefixes if discovery is sparse (< 8)
        if len(candidate_sources) < 8:
            common_prefixes = ["www", "mail", "api", "vpn", "admin", "remote", "autodiscover", "dev", "staging", "portal"]
            for pref in common_prefixes:
                _add_candidate(f"{pref}.{clean_root}", "DNS Wordlist Probe")

        sorted_candidates = sorted(list(candidate_sources.keys()))[:80]  # Cap at 80 for optimal latency

        resolved_items: List[Dict[str, Any]] = []

        def _resolve_sub(sub: str) -> Dict[str, Any]:
            status = "unresolving"
            ips: List[str] = []
            unresolving_reason: Optional[str] = None
            srcs = sorted(list(candidate_sources.get(sub, set())))

            # Derive primary provenance label for display
            if "Subfinder + dnsx" in srcs:
                primary_source = "Subfinder + dnsx"
            elif "Queried Target" in srcs:
                primary_source = "Queried Target"
            elif "Live TLS SAN" in srcs:
                primary_source = "Live TLS SAN"
            elif "Certificate Transparency (crt.sh)" in srcs:
                primary_source = "Certificate Transparency"
            elif "DNS CNAME Chain" in srcs:
                primary_source = "DNS CNAME"
            elif "Passive DNS / Sibling" in srcs:
                primary_source = "Passive DNS"
            elif "DNS Wordlist Probe" in srcs:
                primary_source = "DNS Wordlist"
            elif srcs:
                primary_source = srcs[0]
            else:
                primary_source = "Passive Discovery"

            # Check if already resolved by dnsx
            if sub in known_resolved_ips and known_resolved_ips[sub]:
                status = "active"
                ips = known_resolved_ips[sub][:4]
            else:
                try:
                    # Fast standard socket lookup
                    addrs = socket.gethostbyname_ex(sub)[2]
                    if addrs:
                        status = "active"
                        ips = addrs[:4]
                except Exception:
                    status = "unresolving"
                    if "Certificate Transparency (crt.sh)" in srcs:
                        unresolving_reason = "Historical CT certificate log entry; DNS record decommissioned or internal-only split-horizon"
                    elif "Live TLS SAN" in srcs:
                        unresolving_reason = "Listed on certificate SANs but has no active public A/AAAA DNS mapping"
                    elif "DNS Wordlist Probe" in srcs:
                        unresolving_reason = "Wordlist candidate does not exist on public authoritative DNS (NXDOMAIN)"
                    elif "DNS CNAME Chain" in srcs:
                        unresolving_reason = "Dangling CNAME alias points to non-existent or unallocated host"
                    else:
                        unresolving_reason = "No public DNS A/AAAA records returned by resolver (NXDOMAIN)"

            return {
                "subdomain": sub,
                "status": status,
                "status_label": "Active (Resolving)" if status == "active" else "Unresolved (Dormant)",
                "unresolving_reason": unresolving_reason,
                "ips": ips,
                "is_root": (sub == clean_root),
                "discovered_from": primary_source,
                "sources": srcs
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_resolve_sub, sub) for sub in sorted_candidates]
            for f in concurrent.futures.as_completed(futures):
                try:
                    res = f.result()
                    resolved_items.append(res)
                except Exception:
                    pass

        # Sort: root domain first, active subdomains next, then alphabetical
        resolved_items.sort(key=lambda x: (not x["is_root"], x["status"] != "active", x["subdomain"]))

        active_count = sum(1 for item in resolved_items if item["status"] == "active")
        dormant_count = len(resolved_items) - active_count

        return {
            "root_domain": clean_root,
            "total_discovered": len(resolved_items),
            "active_count": active_count,
            "dormant_count": dormant_count,
            "explanation": "Active subdomains resolve to live IPv4/IPv6 addresses. Unresolved subdomains were discovered from historical Certificate Transparency (crt.sh) logs or certificate SANs where the DNS record has been decommissioned, used only on private corporate intranets (split-horizon DNS), or unallocated.",
            "subdomains": resolved_items
        }
