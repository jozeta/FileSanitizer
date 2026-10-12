"""
Reverse Tracking & Analytics Identifier Pivots.
Extracts Google Analytics (GA4/UA), Google Tag Manager (GTM), and AdSense (pub-) IDs
from target web responses and discovers co-managed or sibling websites sharing identical tracking infrastructure.
"""

import re
from typing import Dict, Any, List, Set, Optional
import httpx
from app.core.logging_config import logger


TRACKING_PATTERNS = [
    (r"\b(G-[A-Z0-9]{6,12})\b", "Google Analytics 4 (GA4)"),
    (r"\b(UA-[0-9]{4,10}-[0-9]{1,4})\b", "Universal Analytics (Legacy)"),
    (r"\b(GTM-[A-Z0-9]{5,10})\b", "Google Tag Manager Container"),
    (r"\b(pub-[0-9]{14,18})\b", "Google AdSense Publisher ID"),
    (r"\b(ca-pub-[0-9]{14,18})\b", "Google AdSense Client ID"),
    (r"\b(MC-[A-Z0-9]{6,10})\b", "Microsoft Clarity Project"),
]


class TrackingIdentifierPivoter:
    """
    Extracts web tracking codes and performs reverse-analytics relationship discovery.
    """

    @classmethod
    def extract_and_pivot(
        cls,
        target_domain: str,
        html_content: Optional[str] = None,
        existing_identifiers: Optional[List[str]] = None,
        timeout_s: float = 3.5
    ) -> Dict[str, Any]:
        """
        Extracts tracking IDs from HTML content and queries reverse-analytics relationships.
        """
        clean_target = target_domain.strip().lower()
        discovered_ids: Dict[str, str] = {}  # id -> type

        # 1. Existing identifiers passed in
        for ident in (existing_identifiers or []):
            ident = ident.strip()
            if ident:
                for pat, label in TRACKING_PATTERNS:
                    if re.match(pat, ident, re.IGNORECASE):
                        discovered_ids[ident] = label
                        break
                if ident not in discovered_ids:
                    discovered_ids[ident] = "Web Tracking Identifier"

        # 2. Extract from raw HTML if available
        if html_content:
            for pat, label in TRACKING_PATTERNS:
                matches = re.findall(pat, html_content)
                for m in matches:
                    if m not in discovered_ids:
                        discovered_ids[m] = label

        id_entries: List[Dict[str, Any]] = []
        all_related_domains: Set[str] = set()

        with httpx.Client(timeout=timeout_s, headers={"User-Agent": "FileSanitizer-HostAudit/1.0"}) as client:
            for ident, id_type in list(discovered_ids.items())[:4]:
                entry: Dict[str, Any] = {
                    "identifier": ident,
                    "type": id_type,
                    "associated_domains": [],
                    "count": 0,
                    "attribution_confidence": "MEDIUM (Shared author, web development agency, or template)",
                    "query_url": f"https://dnslytics.com/search?q={ident}"
                }

                # Attempt reverse lookup if provider available
                try:
                    # Query public analytics reverse search
                    resp = client.get(f"https://api.hackertarget.com/analyticslookup/?q={ident}")
                    if resp.status_code == 200 and resp.text and not resp.text.startswith("error"):
                        for line in resp.text.splitlines():
                            dom = line.strip().lower()
                            if dom and "." in dom and dom != clean_target and len(dom) < 80:
                                entry["associated_domains"].append(dom)
                                all_related_domains.add(dom)
                        entry["count"] = len(entry["associated_domains"])
                except Exception as e:
                    logger.debug(f"Reverse analytics lookup failed for {ident}: {e}")

                id_entries.append(entry)

        return {
            "tested": True,
            "target": clean_target,
            "total_identifiers": len(id_entries),
            "tracking_identifiers": id_entries,
            "related_domains_from_analytics": sorted(list(all_related_domains)),
            "has_shared_tracking": len(all_related_domains) > 0
        }
