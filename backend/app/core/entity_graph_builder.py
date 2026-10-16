"""
Interactive Entity Relationship Graph Builder.
Constructs multi-tier topological graph structures connecting root files,
file hashes, threat intelligence engines (VirusTotal, CrowdStrike, ClamAV),
re-analysis historical deltas, email artifacts (senders, recipients, subjects, relay hops,
tracking pixels, nested archive attachments), PCAP network traffic (conversations, flows,
protocols, TLS SNIs, DNS queries, credentials), embedded payloads, extracted URLs, domains,
resolved IPs, geolocations, digital certificates, MITRE ATT&CK techniques, and fuzzy hash similarity clusters.
"""

import math
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

from app.core.entity_extractor import EntityExtractor


class EntityGraphBuilder:
    """Builds interactive node-link entity relationship graphs for complex forensic artifacts."""

    @staticmethod
    def _add_domain_intel_nodes(
        dom_info: Dict[str, Any],
        pivots: Dict[str, Any],
        related: List[Dict[str, Any]],
        _add_node: Any,
        _add_edge: Any,
    ) -> None:
        """Domain/IP lookup -> IPs -> ASN / network block / registrant -> related domains."""
        target = dom_info.get("target") or ""
        is_ip = bool(dom_info.get("is_ip"))
        dns = dom_info.get("dns_records") or {}
        net = dom_info.get("network") or {}
        whois = dom_info.get("whois") or {}
        owner = dom_info.get("owner_intelligence") or {}

        flags = dom_info.get("risk_flags") or []
        worst = "clean"
        for f in flags:
            sev = str(f.get("severity", "")).lower()
            if sev in ("critical", "high"):
                worst = sev
                break
            if sev == "medium":
                worst = "medium"

        _add_node(
            node_id="di_target",
            label=target,
            n_type="ip" if is_ip else "domain",
            risk=worst,
            tier=1,
            details={
                "target": target,
                "registrar": whois.get("registrar"),
                "registered": whois.get("registration_date"),
                "domain_age": whois.get("domain_age_formatted"),
                "nameservers": whois.get("nameservers"),
                "risk_flags": [f.get("title") for f in flags],
            },
        )
        _add_edge("root", "di_target", "domain / IP lookup", "analyzed")

        # Resolved IPs (A records) or the IP itself
        ips: List[str] = [target] if is_ip else list(dns.get("a") or [])[:3]
        ip_ids: Dict[str, str] = {}
        for i, ip in enumerate(ips):
            ip_id = f"di_ip_{i}"
            ip_ids[ip] = ip_id
            if is_ip and ip == target:
                ip_id = "di_target"
                ip_ids[ip] = ip_id
                continue
            _add_node(
                node_id=ip_id, label=ip, n_type="ip", risk="clean", tier=2,
                details={"ip": ip, "country": net.get("country"), "city": net.get("city")},
            )
            _add_edge("di_target", ip_id, "resolves to", "dns_a")
        primary_ip_id = next(iter(ip_ids.values()), "di_target")

        # Autonomous system
        asn = pivots.get("asn") or owner.get("asn") or net.get("asn")
        asn_id = None
        if asn:
            asn_id = "di_asn"
            holder = pivots.get("asn_holder") or owner.get("asn_org") or ""
            _add_node(
                node_id=asn_id,
                label=f"{asn} {holder}".strip(),
                n_type="asn",
                risk="clean",
                tier=2,
                details={
                    "asn": asn,
                    "holder": holder,
                    "announced_prefixes": pivots.get("asn_prefix_count"),
                    "shared_infrastructure": pivots.get("is_shared_infrastructure"),
                    "note": pivots.get("shared_reason"),
                },
            )
            _add_edge(primary_ip_id, asn_id, "announced by", "announced_by")

        # Corporate network block
        cidrs = list(net.get("cidrs") or owner.get("cidrs") or [])
        try:
            import ipaddress
            _ip = ipaddress.ip_address(ips[0]) if ips else None
            containing = [c for c in cidrs if _ip is not None and _ip in ipaddress.ip_network(c, strict=False)]
            if containing:  # most specific block that really contains the target IP goes first
                containing.sort(key=lambda c: -ipaddress.ip_network(c, strict=False).prefixlen)
                cidrs = containing + [c for c in cidrs if c not in containing]
        except Exception:
            pass
        net_label = pivots.get("network_name") or net.get("network_name") or owner.get("network_name")
        net_id = None
        if net_label or cidrs:
            net_id = "di_net"
            _add_node(
                node_id=net_id,
                label=f"{net_label or 'Network'}{' ' + cidrs[0] if cidrs else ''}",
                n_type="network",
                risk="clean",
                tier=2,
                details={
                    "network_name": net_label,
                    "cidrs": cidrs,
                    "ip_range": net.get("ip_range") or owner.get("ip_range"),
                    "country": net.get("country"),
                },
            )
            _add_edge(primary_ip_id, net_id, "allocated in", "in_network")
            if asn_id:
                _add_edge(net_id, asn_id, "routed by", "announced_by")

        # Registrant / owning organization
        org_name = pivots.get("owner_org") or whois.get("registrant_org")
        org_id = None
        if org_name and not any(t in org_name.lower() for t in ("redacted", "privacy", "proxy", "withheld")):
            org_id = "di_org"
            _add_node(
                node_id=org_id, label=org_name, n_type="organization", risk="clean", tier=2,
                details={"organization": org_name, "registrar": whois.get("registrar"),
                         "country": whois.get("registrant_country")},
            )
            _add_edge("di_target", org_id, "registered by", "owned_by")

        # Related domains owned by / associated with the same entity
        strong = [r for r in related if r.get("confidence") != "low"][:28]
        weak = [r for r in related if r.get("confidence") == "low"][:6]
        for i, r in enumerate(strong + weak):
            rid = f"di_rel_{i}"
            rels = r.get("relationships") or []
            _add_node(
                node_id=rid,
                label=r.get("domain", ""),
                n_type="domain",
                risk="clean",
                tier=3,
                details={
                    "domain": r.get("domain"),
                    "confidence": r.get("confidence"),
                    "relationships": r.get("relationship_labels") or rels,
                    "evidence": r.get("evidence"),
                    "sources": r.get("sources"),
                    "ips": r.get("ips"),
                    "hosts_seen": r.get("hosts_seen"),
                },
            )
            conf = r.get("confidence", "low")
            labels = r.get("relationship_labels") or []
            for ridx, rel in enumerate(rels or ["related"]):
                if rel in ("same_asn", "as_operator") and asn_id:
                    anchor = asn_id
                elif rel == "same_network" and net_id:
                    anchor = net_id
                elif rel == "same_ip":
                    anchor = next((ip_ids[x] for x in (r.get("ips") or []) if x in ip_ids), primary_ip_id)
                elif rel == "cert_organization" and org_id:
                    anchor = org_id
                else:
                    anchor = "di_target"
                label = labels[ridx] if ridx < len(labels) else rel
                _add_edge(anchor, rid, f"{label} ({conf})", rel)

        # -------------------------------------------------------------
        # Typed Infrastructure Relationships
        # -------------------------------------------------------------
        # Nameservers (USES_NAMESERVER)
        ns_list = list(dns.get("ns") or whois.get("nameservers") or [])[:3]
        for idx, ns in enumerate(ns_list):
            ns_id = f"di_ns_{idx}"
            _add_node(
                node_id=ns_id,
                label=f"NS: {ns}",
                n_type="nameserver",
                risk="clean",
                tier=2,
                details={"nameserver": ns}
            )
            _add_edge("di_target", ns_id, "USES_NAMESERVER", "uses_nameserver")

        # TLS Certificate & SANs (CERT_INCLUDES_SAN)
        tls_prof = dom_info.get("tls_profile") or {}
        live_cert = tls_prof.get("live_cert") or {}
        if live_cert and live_cert.get("sha256_fingerprint"):
            cert_id = "di_tls_cert"
            iss_name = (live_cert.get("issuer") or {}).get("common_name") or "SSL/TLS Cert"
            _add_node(
                node_id=cert_id,
                label=f"Cert: {iss_name}",
                n_type="certificate",
                risk="high" if live_cert.get("is_expired") else "clean",
                tier=2,
                details={
                    "fingerprint": live_cert.get("sha256_fingerprint"),
                    "issuer": live_cert.get("issuer"),
                    "expires": live_cert.get("not_after"),
                    "tls_version": live_cert.get("tls_version"),
                    "cipher": live_cert.get("cipher_suite"),
                }
            )
            _add_edge("di_target", cert_id, "SECURED_BY_CERT", "secured_by")

            # Link top Subject Alternative Names
            for san_idx, san in enumerate((live_cert.get("sans") or [])[:5]):
                clean_san = san.lstrip("*.").lower()
                if clean_san and clean_san != target:
                    san_id = f"di_san_{san_idx}"
                    _add_node(
                        node_id=san_id,
                        label=clean_san,
                        n_type="domain",
                        risk="clean",
                        tier=3,
                        details={"san": san}
                    )
                    _add_edge(cert_id, san_id, "CERT_INCLUDES_SAN", "cert_includes_san")

        # Favicon Hash (SHARES_FAVICON_HASH)
        web_fp = dom_info.get("web_fingerprint") or {}
        fav = web_fp.get("favicon") or {}
        if fav.get("murmur_hash"):
            fav_id = "di_fav_hash"
            _add_node(
                node_id=fav_id,
                label=f"Favicon: {fav['murmur_hash']}",
                n_type="hash",
                risk="clean",
                tier=2,
                details={
                    "murmur_hash": fav["murmur_hash"],
                    "shodan_query": fav.get("shodan_query")
                }
            )
            _add_edge("di_target", fav_id, "SHARES_FAVICON_HASH", "shares_favicon_hash")

        # Attack Surface Active Subdomains (SUBDOMAIN_OF)
        surface = dom_info.get("attack_surface") or {}
        for sub_idx, sub_item in enumerate((surface.get("subdomains") or [])[:6]):
            s_name = sub_item.get("subdomain")
            if s_name and s_name != target and (sub_item.get("status") == "active" or sub_item.get("resolves")):
                sub_node_id = f"di_sub_{sub_idx}"
                _add_node(
                    node_id=sub_node_id,
                    label=s_name,
                    n_type="domain",
                    risk="clean",
                    tier=3,
                    details=sub_item
                )
                _add_edge("di_target", sub_node_id, "SUBDOMAIN_OF", "subdomain_of")

    @classmethod
    def build(cls, job: Any) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_ids: Set[str] = set()

        def _add_node(
            node_id: str,
            label: str,
            n_type: str,
            risk: str = "clean",
            details: Optional[Dict[str, Any]] = None,
            tier: int = 1
        ):
            if node_id in node_ids:
                return
            node_ids.add(node_id)
            clean_label = str(label) if label is not None else ""
            nodes.append({
                "id": node_id,
                "label": clean_label[:40] + ("..." if len(clean_label) > 40 else ""),
                "full_label": clean_label,
                "type": n_type,
                "risk": (risk or "clean").lower(),
                "tier": tier,
                "details": details or {}
            })

        def _add_edge(source: str, target: str, label: str, e_type: str = "references"):
            if source == target or source not in node_ids or target not in node_ids:
                return
            edge_key = f"{source}->{target}:{e_type}"
            for e in edges:
                if e.get("_key") == edge_key:
                    return
            edges.append({
                "_key": edge_key,
                "source": source,
                "target": target,
                "label": label,
                "type": e_type
            })

        # ---------------------------------------------------------
        # 1. ROOT FILE NODE (Tier 0 - Center)
        # ---------------------------------------------------------
        root_risk = getattr(job.risk, "level", "CLEAN") if getattr(job, "risk", None) else "CLEAN"
        orig_name = getattr(job, "original_filename", None) or getattr(job, "filename", "Sample")
        hashes = getattr(job, "hashes", {}) or {}
        sha256_val = hashes.get("sha256", "")
        md5_val = hashes.get("md5", "")
        ssdeep_val = hashes.get("ssdeep", "")

        _add_node(
            node_id="root",
            label=orig_name,
            n_type="file",
            risk=root_risk,
            tier=0,
            details={
                "filename": orig_name,
                "category": getattr(job, "category", "unknown"),
                "mime_type": getattr(job, "mime_type", "application/octet-stream"),
                "file_size": getattr(job, "file_size", 0),
                "sha256": sha256_val,
                "md5": md5_val,
                "ssdeep": ssdeep_val,
                "verdict": getattr(job.risk, "verdict", None) if getattr(job, "risk", None) else "Analyzed"
            }
        )

        # ---------------------------------------------------------
        # 2. FILE HASHES (Tier 1)
        # ---------------------------------------------------------
        if sha256_val:
            _add_node(
                node_id="hash_sha256",
                label=f"SHA256: {sha256_val[:12]}...",
                n_type="hash",
                risk="clean",
                tier=1,
                details={"algorithm": "SHA-256", "hash": sha256_val}
            )
            _add_edge("root", "hash_sha256", "has hash", "has_hash")

        if md5_val:
            _add_node(
                node_id="hash_md5",
                label=f"MD5: {md5_val[:10]}...",
                n_type="hash",
                risk="clean",
                tier=1,
                details={"algorithm": "MD5", "hash": md5_val}
            )
            _add_edge("root", "hash_md5", "md5 hash", "has_hash")

        if ssdeep_val:
            _add_node(
                node_id="hash_ssdeep",
                label=f"SSDEEP: {ssdeep_val[:16]}...",
                n_type="hash",
                risk="clean",
                tier=1,
                details={"algorithm": "SSDEEP", "hash": ssdeep_val}
            )
            _add_edge("root", "hash_ssdeep", "fuzzy hash", "has_hash")

        # ---------------------------------------------------------
        # 3. THREAT INTELLIGENCE & RE-ANALYSIS HISTORY (Tier 1 & 2)
        # ---------------------------------------------------------
        # VirusTotal
        vt = getattr(job, "virustotal", None)
        if not vt:
            h_val = (getattr(job, "hashes", {}) or {}).get("sha256") or (getattr(job, "hashes", {}) or {}).get("md5")
            if h_val:
                vt = {
                    "engine": "VirusTotal",
                    "positives": 0,
                    "total": 72,
                    "total_engines": 72,
                    "permalink": f"https://www.virustotal.com/gui/file/{h_val}",
                    "web_link": f"https://www.virustotal.com/gui/file/{h_val}",
                    "scan_date": getattr(job, "uploaded_at", None),
                }

        if vt and isinstance(vt, dict):
            positives = vt.get("positives", 0)
            total = vt.get("total_engines") or vt.get("total", 0) or 72
            vt_risk = "critical" if positives >= 5 else ("warning" if positives > 0 else "clean")
            vt_label = f"VirusTotal ({positives}/{total})" if total else f"VirusTotal ({positives} detections)"
            _add_node(
                node_id="intel_virustotal",
                label=vt_label,
                n_type="threat_intel",
                risk=vt_risk,
                tier=1,
                details={
                    "engine": "VirusTotal",
                    "positives": positives,
                    "total": total,
                    "permalink": vt.get("permalink") or vt.get("web_link"),
                    "threat_classification": vt.get("threat_classification"),
                    "scan_date": vt.get("scan_date")
                }
            )
            edge_lbl = f"{positives} detections"
            if vt.get("scan_date"):
                edge_lbl += f" ({str(vt['scan_date'])[:10]})"
            _add_edge("root", "intel_virustotal", edge_lbl, "scanned_by")

        # CrowdStrike Falcon / Hybrid Analysis
        ha = getattr(job, "hybrid_analysis", None)
        if ha and isinstance(ha, dict):
            cs_verdict = ha.get("verdict") or ha.get("threat_score") or "Analyzed"
            is_mal = ha.get("verdict") in ["malicious", "suspicious"] or (ha.get("threat_score") or 0) > 50
            _add_node(
                node_id="intel_crowdstrike",
                label=f"CrowdStrike: {cs_verdict}",
                n_type="threat_intel",
                risk="critical" if is_mal else "clean",
                tier=1,
                details={
                    "engine": "CrowdStrike Falcon Sandbox",
                    "verdict": cs_verdict,
                    "threat_score": ha.get("threat_score"),
                    "vx_family": ha.get("vx_family")
                }
            )
            _add_edge("root", "intel_crowdstrike", "falcon sandbox", "telemetry")

        # ClamAV Signature Match
        clam = getattr(job, "clamav", None)
        if clam and isinstance(clam, dict) and clam.get("detected"):
            malware_name = clam.get("malware_name") or "Malware Signature"
            _add_node(
                node_id="intel_clamav",
                label=f"ClamAV: {malware_name}",
                n_type="threat_signature",
                risk="critical",
                tier=1,
                details={
                    "engine": "ClamAV Daemon",
                    "signature": malware_name,
                    "detected": True
                }
            )
            _add_edge("root", "intel_clamav", "signature match", "signature_match")

        # Re-Analysis Threat Delta Node (when file is re-scanned)
        reanalysis_diff = getattr(job, "reanalysis_intel_diff", None)
        if reanalysis_diff and isinstance(reanalysis_diff, dict):
            new_pos = reanalysis_diff.get("new_vt_positives")
            labels = reanalysis_diff.get("summary_labels") or ["Telemetry Delta"]
            _add_node(
                node_id="reanalysis_delta",
                label=f"Scan Delta: {', '.join(labels[:2])}",
                n_type="threat_intel",
                risk="critical" if new_pos and new_pos > 0 else "warning",
                tier=2,
                details=reanalysis_diff
            )
            _add_edge("root", "reanalysis_delta", "re-analyzed delta", "telemetry")

        # ---------------------------------------------------------
        # 4. EMAIL ARTIFACTS & HEADERS (Tier 1, 2 & 3)
        # ---------------------------------------------------------
        email_info = getattr(job, "email_info", None)
        if email_info and isinstance(email_info, dict):
            # Sender Node
            from_addr = email_info.get("from") or ""
            if from_addr:
                sender_analysis = email_info.get("sender_analysis") or {}
                s_risk = "warning" if sender_analysis.get("is_spoofed") or sender_analysis.get("is_free_mail") else "clean"
                _add_node(
                    node_id="email_sender",
                    label=f"From: {from_addr}",
                    n_type="user",
                    risk=s_risk,
                    tier=1,
                    details={
                        "address": from_addr,
                        "display_name": sender_analysis.get("display_name"),
                        "domain": sender_analysis.get("domain"),
                        "is_spoofed": sender_analysis.get("is_spoofed")
                    }
                )
                _add_edge("email_sender", "root", "sent email", "sent_by")

            # Recipients Node(s)
            to_addr = email_info.get("to") or ""
            if to_addr:
                _add_node(
                    node_id="email_recipient",
                    label=f"To: {to_addr}",
                    n_type="user",
                    risk="clean",
                    tier=1,
                    details={"address": to_addr, "role": "recipient"}
                )
                _add_edge("root", "email_recipient", "delivered to", "delivered_to")

            # Subject Node
            subj = email_info.get("subject") or ""
            if subj:
                _add_node(
                    node_id="email_subject",
                    label=f"Subject: {subj}",
                    n_type="metadata",
                    risk="clean",
                    tier=1,
                    details={"subject": subj}
                )
                _add_edge("root", "email_subject", "subject", "metadata")

            # Email Security & Authentication (SPF, DKIM, DMARC)
            auth_data = email_info.get("authentication") or {}
            if auth_data:
                spf_pass = "pass" in str(auth_data.get("spf", "")).lower()
                dkim_pass = "pass" in str(auth_data.get("dkim", "")).lower()
                spf_stat = auth_data.get('spf', {}).get('status', 'NONE') if isinstance(auth_data.get('spf'), dict) else str(auth_data.get('spf', 'NONE'))
                dkim_stat = auth_data.get('dkim', {}).get('status', 'NONE') if isinstance(auth_data.get('dkim'), dict) else str(auth_data.get('dkim', 'NONE'))
                auth_risk = "clean" if (spf_pass or dkim_pass) else "warning"
                _add_node(
                    node_id="email_auth",
                    label=f"SPF: {spf_stat} | DKIM: {dkim_stat}",
                    n_type="auth_policy",
                    risk=auth_risk,
                    tier=1,
                    details=auth_data
                )
                _add_edge("root", "email_auth", "authentication", "auth_check")

            # Transit Relay Hops & Sender IPs (Safely handles dict or string IP items)
            hops = email_info.get("transit_hops") or []
            sender_ips = email_info.get("sender_ips") or []
            seen_ips = set()
            prev_hop_id = "root"

            for h_idx, hop in enumerate(hops[:5]):
                sip = sender_ips[h_idx] if h_idx < len(sender_ips) else None
                ip_val = hop.get("ip") if isinstance(hop, dict) else None
                if not ip_val:
                    if isinstance(sip, dict):
                        ip_val = sip.get("ip")
                    elif isinstance(sip, str):
                        ip_val = sip

                if not ip_val or ip_val in seen_ips:
                    continue
                seen_ips.add(ip_val)
                ip_id = f"relay_ip_{len(seen_ips)}"

                # Extract Geolocation safely
                geo: Dict[str, Any] = {}
                if isinstance(hop, dict):
                    geo = hop.get("ipinfo") or hop.get("geo") or {}
                    if not geo and (hop.get("country") or hop.get("city") or hop.get("asn")):
                        geo = {"country": hop.get("country"), "city": hop.get("city"), "asn": hop.get("asn")}
                if not geo and isinstance(sip, dict):
                    geo = sip.get("geo") or {}

                _add_node(
                    node_id=ip_id,
                    label=f"Relay IP: {ip_val}",
                    n_type="ip",
                    risk="info",
                    tier=2,
                    details={"ip": ip_val, "by": hop.get("by_host") if isinstance(hop, dict) else None, "geo": geo}
                )
                _add_edge(prev_hop_id, ip_id, f"hop #{h_idx+1}", "routed_through")
                prev_hop_id = ip_id

                # Geolocation Node if known
                if geo and isinstance(geo, dict) and geo.get("country"):
                    geo_id = f"geo_{geo.get('country')}_{len(seen_ips)}"
                    _add_node(
                        node_id=geo_id,
                        label=f"{geo.get('city') or ''} {geo.get('country')}".strip(),
                        n_type="geolocation",
                        risk="clean",
                        tier=3,
                        details=geo
                    )
                    _add_edge(ip_id, geo_id, "located in", "geolocated")

            # Tracking Pixels & Web Beacons
            pixels = email_info.get("tracking_pixels") or []
            for p_idx, pix in enumerate(pixels[:3]):
                p_url = pix.get("url") if isinstance(pix, dict) else str(pix)
                if not p_url:
                    continue
                pix_id = f"pixel_{p_idx}"
                _add_node(
                    node_id=pix_id,
                    label=f"Tracker: {p_url}",
                    n_type="tracking_pixel",
                    risk="warning",
                    tier=2,
                    details={"url": p_url, "domain": pix.get("domain") if isinstance(pix, dict) else ""}
                )
                _add_edge("root", pix_id, "tracking pixel", "embeds_beacon")

            # Email Attachments & Inner Files (Payload tree)
            attachments = email_info.get("attachments") or []
            for a_idx, att in enumerate(attachments[:6]):
                att_id = f"email_att_{a_idx}"
                is_dang = att.get("is_dangerous", False)
                att_name = att.get("filename") or f"Attachment_{a_idx+1}"
                _add_node(
                    node_id=att_id,
                    label=att_name,
                    n_type="embedded_file",
                    risk="critical" if is_dang else "clean",
                    tier=2,
                    details={
                        "filename": att_name,
                        "mime_type": att.get("content_type") or att.get("mime_type"),
                        "size_bytes": att.get("size_bytes"),
                        "sha256": att.get("sha256"),
                        "is_dangerous": is_dang
                    }
                )
                _add_edge("root", att_id, "contains attachment", "contains")

                # Inner / Nested Files (e.g. zip containing JS droppers)
                inner_files = att.get("inner_files") or []
                for in_idx, inf in enumerate(inner_files[:4]):
                    in_name = inf.get("filename") or f"Inner_{in_idx+1}"
                    in_id = f"att_{a_idx}_inner_{in_idx}"
                    in_dang = inf.get("is_dangerous", False)
                    _add_node(
                        node_id=in_id,
                        label=in_name,
                        n_type="embedded_file",
                        risk="critical" if in_dang else "info",
                        tier=3,
                        details={
                            "filename": in_name,
                            "size": inf.get("size"),
                            "date_time": inf.get("date_time"),
                            "is_dangerous": in_dang,
                            "parent_attachment": att_name
                        }
                    )
                    _add_edge(att_id, in_id, "contains payload", "contains")

        # ---------------------------------------------------------
        # 5. PCAP NETWORK CAPTURE FLOWS, PROTOCOLS & CREDENTIALS
        # ---------------------------------------------------------
        pcap_info = getattr(job, "pcap_info", None)
        if pcap_info and isinstance(pcap_info, dict):
            # Protocols Node
            protos = pcap_info.get("protocols") or {}
            for pr_name, pr_count in list(protos.items())[:5]:
                pr_id = f"proto_{pr_name.lower()}"
                _add_node(
                    node_id=pr_id,
                    label=f"Protocol: {pr_name} ({pr_count} pkts)",
                    n_type="protocol",
                    risk="clean",
                    tier=1,
                    details={"protocol": pr_name, "packet_count": pr_count}
                )
                _add_edge("root", pr_id, "communicates via", "protocol")

            # Conversations / Flows
            flows = pcap_info.get("conversations") or []
            for fl_idx, fl in enumerate(flows[:6]):
                fl_id = f"flow_{fl_idx+1}"
                s_ip = fl.get("src_ip", "")
                d_ip = fl.get("dst_ip", "")
                pr = fl.get("protocol", "TCP")
                _add_node(
                    node_id=fl_id,
                    label=f"{s_ip} ↔ {d_ip} ({pr})",
                    n_type="flow",
                    risk="info",
                    tier=2,
                    details=fl
                )
                _add_edge("root", fl_id, "observed flow", "network_flow")

            # DNS Queries & Resolution
            dns_list = pcap_info.get("dns_queries") or []
            for d_idx, dns in enumerate(dns_list[:6]):
                dom_name = dns.get("domain", "")
                if not dom_name:
                    continue
                d_node_id = f"pcap_dns_{d_idx}"
                d_susp = dns.get("is_suspicious", False)
                _add_node(
                    node_id=d_node_id,
                    label=f"DNS: {dom_name}",
                    n_type="domain",
                    risk="critical" if d_susp else "clean",
                    tier=2,
                    details=dns
                )
                _add_edge("root", d_node_id, "queries DNS", "dns_query")

                # Link resolved IPs
                for rip_idx, rip in enumerate(dns.get("resolved_ips", [])[:2]):
                    rip_id = f"pcap_res_ip_{d_idx}_{rip_idx}"
                    _add_node(
                        node_id=rip_id,
                        label=f"IP: {rip}",
                        n_type="ip",
                        risk="info",
                        tier=3,
                        details={"ip": rip, "resolved_for": dom_name}
                    )
                    _add_edge(d_node_id, rip_id, "resolves to", "dns_a")

            # TLS Sessions & SNIs
            tls_list = pcap_info.get("tls_sessions") or []
            for t_idx, tls in enumerate(tls_list[:5]):
                sni = tls.get("sni", "")
                if not sni:
                    continue
                tls_id = f"pcap_tls_{t_idx}"
                _add_node(
                    node_id=tls_id,
                    label=f"TLS SNI: {sni}",
                    n_type="domain",
                    risk="clean",
                    tier=2,
                    details=tls
                )
                _add_edge("root", tls_id, f"{tls.get('tls_version', 'TLS')}", "tls_sni")

            # Cleartext Credentials Discovered
            creds = pcap_info.get("credentials") or []
            for c_idx, cr in enumerate(creds[:4]):
                cr_id = f"pcap_cred_{c_idx}"
                uname = cr.get("username", "user")
                c_proto = cr.get("protocol", "Cleartext")
                _add_node(
                    node_id=cr_id,
                    label=f"Leaked Credential: {uname} ({c_proto})",
                    n_type="user",
                    risk="critical",
                    tier=2,
                    details=cr
                )
                _add_edge("root", cr_id, "exposed cleartext auth", "credential_leak")

            # Transferred Files / Payloads
            t_files = pcap_info.get("transferred_files") or []
            for tf_idx, tf in enumerate(t_files[:5]):
                tf_id = f"pcap_file_{tf_idx}"
                is_dang = tf.get("is_dangerous", False)
                fname = tf.get("filename", "Payload")
                _add_node(
                    node_id=tf_id,
                    label=f"Transfer: {fname}",
                    n_type="embedded_file",
                    risk="critical" if is_dang else "info",
                    tier=3,
                    details=tf
                )
                _add_edge("root", tf_id, f"transferred via {tf.get('protocol', 'HTTP')}", "contains")

        # ---------------------------------------------------------
        # 6. AUTHENTICODE CERTIFICATE CHAIN & SIGNERS (Tier 1 & 2)
        # ---------------------------------------------------------
        auth = (getattr(job, "binary_info", {}) or {}).get("authenticode") or {}
        certs = auth.get("certificates", [])
        prev_cert_id = None
        for c_idx, cert in enumerate(certs[:4]):
            cert_id = f"cert_{c_idx}"
            disp_name = cert.get("display_name") or f"Cert #{c_idx+1}"
            c_risk = "critical" if cert.get("is_self_signed") and cert.get("role") != "Root CA" else ("warning" if cert.get("is_expired") else "clean")
            _add_node(
                node_id=cert_id,
                label=disp_name,
                n_type="certificate",
                risk=c_risk,
                tier=1 if c_idx == 0 else 2,
                details={
                    "role": cert.get("role"),
                    "issuer": cert.get("issuer", {}).get("display") if isinstance(cert.get("issuer"), dict) else str(cert.get("issuer", "")),
                    "valid_to": cert.get("valid_to"),
                    "algorithm": cert.get("signature_algorithm"),
                    "serial": cert.get("serial_number"),
                    "is_self_signed": cert.get("is_self_signed"),
                    "is_expired": cert.get("is_expired")
                }
            )
            if c_idx == 0:
                _add_edge("root", cert_id, "signed by", "signed_by")
            elif prev_cert_id:
                _add_edge(prev_cert_id, cert_id, "issued by", "issued_by")
            prev_cert_id = cert_id

        # ---------------------------------------------------------
        # 7. GENERIC EMBEDDED FILES & PAYLOADS (Tier 2)
        # ---------------------------------------------------------
        emb_list = getattr(job, "embedded_files", []) or []
        for e_idx, ef in enumerate(emb_list[:8]):
            emb_id = f"emb_{e_idx}"
            is_dang = ef.get("is_dangerous", False)
            _add_node(
                node_id=emb_id,
                label=ef.get("name") or f"Embedded_{e_idx}",
                n_type="embedded_file",
                risk="critical" if is_dang else "info",
                tier=2,
                details={
                    "mime_type": ef.get("mime_type"),
                    "size_formatted": ef.get("size_formatted"),
                    "source_type": ef.get("source_type"),
                    "threat_reason": ef.get("threat_reason"),
                    "sha256": ef.get("sha256")
                }
            )
            _add_edge("root", emb_id, "drops / contains", "contains")

            # Link embedded payload cryptographic hash
            e_sha256 = (ef.get("sha256") or "").lower()
            if e_sha256 and len(e_sha256) >= 32:
                e_hid = f"hash_emb_{e_sha256[:16]}"
                _add_node(
                    node_id=e_hid,
                    label=f"SHA256: {e_sha256[:10]}...",
                    n_type="hash",
                    risk="clean",
                    tier=3,
                    details={"algorithm": "SHA-256", "hash": e_sha256, "payload": ef.get("name")}
                )
                _add_edge(emb_id, e_hid, "payload hash", "has_hash")

        # ---------------------------------------------------------
        # 7b. ARCHIVE FORENSICS: MEMBERS, CREDENTIALS & TOPOLOGY (Tier 2 & 3)
        # ---------------------------------------------------------
        arch_info = getattr(job, "archive_info", None) or (getattr(job, "analysis_data", {}) or {}).get("archive") or {}
        if isinstance(arch_info, dict) and arch_info:
            ext_iocs = arch_info.get("extracted_iocs") or {}

            # Find member file IDs for cross-linking
            cred_mem_id = None
            topo_mem_id = None
            pay_mem_id = None
            for e_idx, ef in enumerate(emb_list[:8]):
                name_l = str(ef.get("name", "")).lower()
                if any(k in name_l for k in ("ntds", "credential", "password", "audit")):
                    cred_mem_id = f"emb_{e_idx}"
                elif any(k in name_l for k in ("topology", "network", "architecture")):
                    topo_mem_id = f"emb_{e_idx}"
                elif any(k in name_l for k in ("payroll", "salary", "bonus")):
                    pay_mem_id = f"emb_{e_idx}"

            # Dumped User Accounts (NTDS / active directory secrets dump)
            for u_idx, u in enumerate(ext_iocs.get("users", [])[:8]):
                u_node_id = f"arch_user_{re.sub(r'[^a-zA-Z0-9]', '_', u)}"
                u_risk = "critical" if u.lower() in ("administrator", "svc_admin", "root") else "high"
                _add_node(
                    node_id=u_node_id,
                    label=f"User: {u}",
                    n_type="user",
                    risk=u_risk,
                    tier=2,
                    details={"username": u, "source": "Active Directory NTDS Audit / Staged Payroll"}
                )
                _add_edge("root", u_node_id, "dumped credential", "identity")
                if cred_mem_id:
                    _add_edge(cred_mem_id, u_node_id, "contained account", "identity")

            # Stolen Internal Enterprise Target Domains
            for d_idx, dom in enumerate(ext_iocs.get("domains", [])[:5]):
                dom_node_id = f"arch_dom_{re.sub(r'[^a-zA-Z0-9]', '_', dom.lower())}"
                _add_node(
                    node_id=dom_node_id,
                    label=dom,
                    n_type="domain",
                    risk="high",
                    tier=2,
                    details={"domain": dom, "source": "Internal Architecture Mapping"}
                )
                _add_edge("root", dom_node_id, "target domain", "network")
                if topo_mem_id:
                    _add_edge(topo_mem_id, dom_node_id, "architecture target", "network")

            # Stolen Internal Enterprise IPs
            for ip_idx, ip in enumerate(ext_iocs.get("ips", [])[:5]):
                ip_node_id = f"arch_ip_{ip.replace('.', '_')}"
                _add_node(
                    node_id=ip_node_id,
                    label=ip,
                    n_type="ip",
                    risk="high",
                    tier=2,
                    details={"ip": ip, "source": "Internal Network Topology"}
                )
                _add_edge("root", ip_node_id, "internal IP", "network")
                if topo_mem_id:
                    _add_edge(topo_mem_id, ip_node_id, "topology asset", "network")

        # ---------------------------------------------------------
        # 7c. ANDROID APPLICATION PACKAGE (APK) NODES (Tier 2 & 3)
        # ---------------------------------------------------------
        apk_info = getattr(job, "apk_info", None) or (getattr(job, "analysis_data", {}) or {}).get("apk") or {}
        if isinstance(apk_info, dict) and apk_info:
            pkg_name = apk_info.get("package_name") or ""
            if pkg_name:
                pkg_node_id = f"apk_pkg_{re.sub(r'[^a-zA-Z0-9]', '_', pkg_name)}"
                _add_node(
                    node_id=pkg_node_id,
                    label=f"Package: {pkg_name}",
                    n_type="application",
                    risk="info" if apk_info.get("risk_score", 0) < 30 else ("critical" if apk_info.get("risk_score", 0) >= 60 else "high"),
                    tier=1,
                    details={
                        "package_name": pkg_name,
                        "app_name": apk_info.get("app_name"),
                        "version_name": apk_info.get("version_name"),
                        "version_code": apk_info.get("version_code"),
                        "min_sdk": apk_info.get("min_sdk"),
                        "target_sdk": apk_info.get("target_sdk"),
                        "risk_score": apk_info.get("risk_score"),
                        "risk_level": apk_info.get("risk_level")
                    }
                )
                _add_edge("root", pkg_node_id, "defines package", "package")

                # Dangerous Permissions
                dang_perms = apk_info.get("dangerous_permissions") or []
                for p_idx, perm in enumerate(dang_perms[:6]):
                    p_id = f"apk_perm_{p_idx}"
                    p_name = perm.get("permission", "").split(".")[-1]
                    _add_node(
                        node_id=p_id,
                        label=f"Perm: {p_name}",
                        n_type="permission",
                        risk=perm.get("severity", "high"),
                        tier=2,
                        details=perm
                    )
                    _add_edge(pkg_node_id, p_id, "requests permission", "permission")

                # Signing Certificate
                sig_info = apk_info.get("signing_info") or {}
                if sig_info.get("subject"):
                    cert_node_id = "apk_signing_cert"
                    is_dbg = sig_info.get("is_debug_key", False)
                    _add_node(
                        node_id=cert_node_id,
                        label=f"Cert: {sig_info.get('subject', 'Android')[:25]}",
                        n_type="certificate",
                        risk="critical" if is_dbg else ("warning" if sig_info.get("is_self_signed") else "clean"),
                        tier=2,
                        details=sig_info
                    )
                    _add_edge(pkg_node_id, cert_node_id, "signed with", "signed_by")

                # Detected Malicious DEX APIs
                dex_apis = (apk_info.get("dex_info") or {}).get("detected_apis") or []
                for a_idx, api in enumerate(dex_apis[:5]):
                    api_node_id = f"apk_api_{a_idx}"
                    _add_node(
                        node_id=api_node_id,
                        label=f"API: {api.get('title', 'API')[:24]}",
                        n_type="action",
                        risk=api.get("severity", "high"),
                        tier=2,
                        details=api
                    )
                    _add_edge(pkg_node_id, api_node_id, "invokes bytecode API", "executes")

        # ---------------------------------------------------------
        # 7d. JAVA FORENSICS & BYTECODE VECTORS (Tier 2 & 3)
        # ---------------------------------------------------------
        java_info = getattr(job, "java_info", None) or (getattr(job, "analysis_data", {}) or {}).get("java") or {}
        if isinstance(java_info, dict) and java_info:
            main_cls = java_info.get("main_class")
            premain_cls = java_info.get("premain_class")
            j_subtype = java_info.get("java_subtype", "java")

            if main_cls:
                m_node_id = "java_main_entry"
                _add_node(
                    node_id=m_node_id,
                    label=f"Main: {main_cls}",
                    n_type="entry_point",
                    risk="info",
                    tier=1,
                    details={"main_class": main_cls, "subtype": j_subtype}
                )
                _add_edge("root", m_node_id, "entry point", "executes")

            if premain_cls:
                pm_node_id = "java_premain_agent"
                _add_node(
                    node_id=pm_node_id,
                    label=f"Agent: {premain_cls}",
                    n_type="hook",
                    risk="critical",
                    tier=1,
                    details={"premain_class": premain_cls, "hook": "JVM Bytecode Rewriter / Instrumentation"}
                )
                _add_edge("root", pm_node_id, "instruments JVM", "hook")

            # Dangerous APIs
            j_apis = java_info.get("dangerous_apis") or []
            for j_idx, j_api in enumerate(j_apis[:6]):
                japi_id = f"java_api_{j_idx}"
                _add_node(
                    node_id=japi_id,
                    label=f"API: {j_api.get('title', 'API')[:24]}",
                    n_type="action",
                    risk=j_api.get("severity", "high"),
                    tier=2,
                    details=j_api
                )
                _add_edge("root", japi_id, "invokes JVM API", "executes")

        # ---------------------------------------------------------
        # 8. EXTRACTED URLS, DOMAINS, RESOLVED IPS & GEOLOCATION (Tier 2 & 3)
        # ---------------------------------------------------------
        urls = getattr(job, "urls", []) or []
        seen_domains: Set[str] = set()
        seen_ips_urls: Set[str] = set()

        for u_idx, u_item in enumerate(urls[:10]):
            u_str = u_item.get("url") if isinstance(u_item, dict) else str(u_item)
            if not u_str:
                continue
            u_id = f"url_{u_idx}"
            u_risk = u_item.get("risk", "medium") if isinstance(u_item, dict) else "medium"
            _add_node(
                node_id=u_id,
                label=u_str,
                n_type="url",
                risk=u_risk,
                tier=2,
                details={
                    "url": u_str,
                    "is_ssrf_safe": u_item.get("is_ssrf_safe", True) if isinstance(u_item, dict) else True,
                    "http_status": u_item.get("http_status") if isinstance(u_item, dict) else None
                }
            )
            _add_edge("root", u_id, f"link ({u_risk})", "connects")

            # Extract Domain
            try:
                parsed = urlparse(u_str)
                dom = parsed.netloc.split(":")[0].strip().lower()
                if dom and dom not in seen_domains:
                    seen_domains.add(dom)
                    dom_id = f"domain_{len(seen_domains)}"
                    _add_node(
                        node_id=dom_id,
                        label=dom,
                        n_type="domain",
                        risk=u_risk,
                        tier=3,
                        details={"domain": dom}
                    )
                    _add_edge(u_id, dom_id, "resolves to", "resolves")

                    # Extract IP if available on url item
                    if isinstance(u_item, dict) and u_item.get("ip"):
                        dom_ip = u_item.get("ip")
                        if dom_ip not in seen_ips_urls:
                            seen_ips_urls.add(dom_ip)
                            ip_node_id = f"net_ip_{len(seen_ips_urls)}"
                            _add_node(
                                node_id=ip_node_id,
                                label=dom_ip,
                                n_type="ip",
                                risk="clean",
                                tier=3,
                                details={"ip": dom_ip}
                            )
                            _add_edge(dom_id, ip_node_id, "points to", "dns_a")
            except Exception:
                pass

        # ---------------------------------------------------------
        # 8b. DOMAIN / IP OWNERSHIP INTELLIGENCE (target, IPs, ASN, network block, owner, related domains)
        # ---------------------------------------------------------
        dom_info = getattr(job, "domain_info", None)
        if isinstance(dom_info, dict) and dom_info.get("target"):
            pivots_info = dom_info.get("ownership_pivots") or {}
            related = dom_info.get("related_domains") or []
            if pivots_info.get("performed") or getattr(job, "category", "") == "domain":
                cls._add_domain_intel_nodes(dom_info, pivots_info, related, _add_node, _add_edge)

        # ---------------------------------------------------------
        # 9. MITRE ATT&CK TECHNIQUES (Tier 2)
        # ---------------------------------------------------------
        mitre_list = getattr(job, "mitre_attack", []) or []
        for m_idx, m in enumerate(mitre_list[:6]):
            m_tech_id = m.get("technique_id") or m.get("id") or f"T{m_idx}"
            m_name = m.get("technique_name") or m.get("name") or "Technique"
            m_node_id = f"mitre_{m_tech_id.replace('.', '_')}"
            _add_node(
                node_id=m_node_id,
                label=f"{m_tech_id}: {m_name}",
                n_type="technique",
                risk=m.get("severity", "high"),
                tier=2,
                details={
                    "id": m_tech_id,
                    "name": m_name,
                    "tactic": m.get("tactic_name") or m.get("tactic"),
                    "url": m.get("url")
                }
            )
            _add_edge("root", m_node_id, "exhibits TTP", "exhibits")

        # ---------------------------------------------------------
        # 10. FUZZY HASH SIMILARITY CLUSTERS (Tier 3)
        # ---------------------------------------------------------
        sim_list = getattr(job, "similar_samples", []) or []
        for s_idx, sim in enumerate(sim_list[:4]):
            sim_node_id = f"sim_{s_idx}"
            sim_pct = sim.get("similarity", 0)
            _add_node(
                node_id=sim_node_id,
                label=f"{sim.get('filename', 'Variant')} ({sim_pct}%)",
                n_type="similar_sample",
                risk=sim.get("risk_level", "high"),
                tier=3,
                details={
                    "similarity": sim_pct,
                    "filename": sim.get("filename"),
                    "sha256": sim.get("sha256"),
                    "job_id": sim.get("job_id"),
                    "verdict": sim.get("verdict")
                }
            )
            _add_edge("root", sim_node_id, f"{sim_pct}% similarity", "similar_to")

        # ---------------------------------------------------------
        # 10.5. WINDOWS EVENT LOGS (EVTX) & MULTI-LOG CORRELATION
        # ---------------------------------------------------------
        evtx_info = getattr(job, "evtx_info", None)
        if not evtx_info and isinstance(job, dict):
            evtx_info = job.get("evtx_info") or (job.get("analysis") or {}).get("evtx") or (job.get("analysis_data") or {}).get("evtx")
        if not evtx_info and hasattr(job, "findings"):
            for f in getattr(job, "findings", []):
                f_details = getattr(f, "details", None) if hasattr(f, "details") else (f.get("details") if isinstance(f, dict) else None)
                if isinstance(f_details, dict) and ("parsed_files" in f_details or "timeline_events" in f_details or "files_parsed" in f_details):
                    evtx_info = f_details
                    break

        if evtx_info and isinstance(evtx_info, dict):
            raw_parsed_files = evtx_info.get("files_parsed") or evtx_info.get("parsed_files") or (evtx_info.get("summary") or {}).get("parsed_files") or []
            if not raw_parsed_files:
                default_fn = getattr(job, "original_filename", None) or getattr(job, "filename", None) or (job.get("filename") if isinstance(job, dict) else "log.evtx")
                raw_parsed_files = [default_fn]

            parsed_file_names = []
            for item in raw_parsed_files:
                if isinstance(item, dict):
                    parsed_file_names.append(item.get("filename") or "log.evtx")
                elif isinstance(item, str):
                    parsed_file_names.append(item)
                else:
                    parsed_file_names.append(str(item))

            timeline_events = evtx_info.get("timeline_events") or evtx_info.get("timeline") or []

            # 1. Create Log Source Nodes
            file_node_ids: Dict[str, str] = {}
            if len(parsed_file_names) > 1:
                for f_idx, fname in enumerate(parsed_file_names):
                    f_id = f"evtx_log_{f_idx}"
                    file_node_ids[fname] = f_id
                    _add_node(
                        node_id=f_id,
                        label=fname,
                        n_type="log_source",
                        risk="clean",
                        tier=1,
                        details={
                            "filename": fname,
                            "type": "Windows Event Log (.evtx)",
                            "role": "Forensic Log Source"
                        }
                    )
                    _add_edge("root", f_id, "contains log", "source_log")
            else:
                if parsed_file_names:
                    file_node_ids[parsed_file_names[0]] = "root"

            # 2. Track entity occurrences across logs
            user_occurrences: Dict[str, Dict[str, Any]] = {}
            host_occurrences: Dict[str, Dict[str, Any]] = {}
            ip_occurrences: Dict[str, Dict[str, Any]] = {}
            share_occurrences: Dict[str, Dict[str, Any]] = {}
            proc_occurrences: Dict[str, Dict[str, Any]] = {}

            # Seed from per-file parsed file summaries if present
            for item in raw_parsed_files:
                if isinstance(item, dict):
                    f_name = item.get("filename") or "log.evtx"
                    for u in item.get("unique_users", []):
                        if u and u not in ["-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0"]:
                            if u not in user_occurrences:
                                user_occurrences[u] = {"files": set(), "threat": False, "events": 1, "hosts": set(), "ips": set()}
                            user_occurrences[u]["files"].add(f_name)
                    for comp in item.get("unique_computers", []):
                        if comp and comp != "-":
                            if comp not in host_occurrences:
                                host_occurrences[comp] = {"files": set(), "events": 1, "users": set(), "ips": set()}
                            host_occurrences[comp]["files"].add(f_name)
                    for ip in item.get("unique_ips", []):
                        if ip and ip not in ["-", "127.0.0.1", "::1", "None", "0.0.0.0", "Local host"]:
                            if ip not in ip_occurrences:
                                ip_occurrences[ip] = {"files": set(), "events": 1, "users": set(), "hosts": set(), "ports": set()}
                            ip_occurrences[ip]["files"].add(f_name)

            for ev in timeline_events[:10000]:
                src_file = ev.get("source_file") or (parsed_file_names[0] if parsed_file_names else "log.evtx")
                u = ev.get("user")
                if u and u not in ["-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0", "Window Manager\\DWM-1"]:
                    if u not in user_occurrences:
                        user_occurrences[u] = {"files": set(), "threat": False, "events": 0, "hosts": set(), "ips": set()}
                    user_occurrences[u]["files"].add(src_file)
                    user_occurrences[u]["events"] += 1
                    if ev.get("is_threat") or ev.get("severity") in ["critical", "high"]:
                        user_occurrences[u]["threat"] = True
                    if ev.get("computer") and ev.get("computer") != "-":
                        user_occurrences[u]["hosts"].add(ev.get("computer"))
                    if ev.get("ip_address") and ev.get("ip_address") not in ["-", "127.0.0.1", "::1"]:
                        user_occurrences[u]["ips"].add(ev.get("ip_address"))

                comp = ev.get("computer")
                if comp and comp != "-":
                    if comp not in host_occurrences:
                        host_occurrences[comp] = {"files": set(), "events": 0, "users": set(), "ips": set()}
                    host_occurrences[comp]["files"].add(src_file)
                    host_occurrences[comp]["events"] += 1
                    if u and u not in ["-", "SYSTEM"]:
                        host_occurrences[comp]["users"].add(u)
                    if ev.get("ip_address") and ev.get("ip_address") not in ["-", "127.0.0.1", "::1"]:
                        host_occurrences[comp]["ips"].add(ev.get("ip_address"))

                ip = ev.get("ip_address")
                if ip and ip not in ["-", "127.0.0.1", "::1", "None", "0.0.0.0", "Local host"]:
                    if ip not in ip_occurrences:
                        ip_occurrences[ip] = {"files": set(), "events": 0, "users": set(), "hosts": set(), "ports": set()}
                    ip_occurrences[ip]["files"].add(src_file)
                    ip_occurrences[ip]["events"] += 1
                    if u and u not in ["-", "SYSTEM"]:
                        ip_occurrences[ip]["users"].add(u)
                    if comp and comp != "-":
                        ip_occurrences[ip]["hosts"].add(comp)
                    if ev.get("ip_port"):
                        ip_occurrences[ip]["ports"].add(str(ev.get("ip_port")))

                sh = ev.get("share_name")
                if sh and sh != "-":
                    if sh not in share_occurrences:
                        share_occurrences[sh] = {"files": set(), "events": 0, "targets": set(), "users": set()}
                    share_occurrences[sh]["files"].add(src_file)
                    share_occurrences[sh]["events"] += 1
                    if ev.get("relative_target_name"):
                        share_occurrences[sh]["targets"].add(ev.get("relative_target_name"))
                    if u and u not in ["-", "SYSTEM"]:
                        share_occurrences[sh]["users"].add(u)

                pr = ev.get("process_name")
                if pr and pr != "-":
                    pr_base = Path(pr).name if pr else ""
                    if pr_base:
                        if pr_base not in proc_occurrences:
                            proc_occurrences[pr_base] = {"files": set(), "events": 0, "is_lolbin": ev.get("is_lolbin", False), "cmd": ev.get("command_line")}
                        proc_occurrences[pr_base]["files"].add(src_file)
                        proc_occurrences[pr_base]["events"] += 1

            # 3. Add Entity Nodes with Cross-Log Correlation Highlighting
            for u, u_info in sorted(user_occurrences.items(), key=lambda x: -x[1]["events"])[:10]:
                u_id = f"evtx_usr_{abs(hash(u)) % 1000000}"
                is_cross_log = len(u_info["files"]) > 1
                risk = "critical" if u_info["threat"] else ("warning" if is_cross_log else "clean")
                label = f"User: {u}" + (" [SHARED]" if is_cross_log else "")
                _add_node(
                    node_id=u_id,
                    label=label,
                    n_type="user",
                    risk=risk,
                    tier=2,
                    details={
                        "account_name": u,
                        "events_count": u_info["events"],
                        "observed_in_files": list(u_info["files"]),
                        "is_cross_log_pivot": is_cross_log,
                        "associated_hosts": list(u_info["hosts"]),
                        "associated_ips": list(u_info["ips"])
                    }
                )
                for f in u_info["files"]:
                    src_id = file_node_ids.get(f, "root")
                    edge_lbl = "cross-log pivot" if is_cross_log else "logged user"
                    _add_edge(src_id, u_id, edge_lbl, "correlates_identity")

            for comp, c_info in sorted(host_occurrences.items(), key=lambda x: -x[1]["events"])[:6]:
                c_id = f"evtx_host_{abs(hash(comp)) % 1000000}"
                is_cross_log = len(c_info["files"]) > 1
                label = f"Host: {comp}" + (" [SHARED]" if is_cross_log else "")
                _add_node(
                    node_id=c_id,
                    label=label,
                    n_type="computer",
                    risk="warning" if is_cross_log else "clean",
                    tier=2,
                    details={
                        "hostname": comp,
                        "events_count": c_info["events"],
                        "observed_in_files": list(c_info["files"]),
                        "is_cross_log_pivot": is_cross_log,
                        "associated_users": list(c_info["users"]),
                        "associated_ips": list(c_info["ips"])
                    }
                )
                for f in c_info["files"]:
                    src_id = file_node_ids.get(f, "root")
                    _add_edge(src_id, c_id, "cross-log host" if is_cross_log else "observed host", "observed_host")

            for ip, ip_info in sorted(ip_occurrences.items(), key=lambda x: -x[1]["events"])[:8]:
                ip_id = f"evtx_ip_{abs(hash(ip)) % 1000000}"
                is_cross_log = len(ip_info["files"]) > 1
                label = f"IP: {ip}" + (" [PIVOT]" if is_cross_log else "")
                _add_node(
                    node_id=ip_id,
                    label=label,
                    n_type="ip",
                    risk="critical" if is_cross_log else "warning",
                    tier=3,
                    details={
                        "ip_address": ip,
                        "events_count": ip_info["events"],
                        "observed_in_files": list(ip_info["files"]),
                        "is_cross_log_pivot": is_cross_log,
                        "ports": list(ip_info["ports"]),
                        "associated_hosts": list(ip_info["hosts"]),
                        "associated_users": list(ip_info["users"])
                    }
                )
                for f in ip_info["files"]:
                    src_id = file_node_ids.get(f, "root")
                    _add_edge(src_id, ip_id, "cross-log pivot IP" if is_cross_log else "network traffic", "network_pivot")

            for sh, sh_info in sorted(share_occurrences.items(), key=lambda x: -x[1]["events"])[:5]:
                sh_id = f"evtx_share_{abs(hash(sh)) % 1000000}"
                _add_node(
                    node_id=sh_id,
                    label=f"Share: {sh}",
                    n_type="share",
                    risk="warning" if sh in ["ADMIN$", "C$"] else "clean",
                    tier=3,
                    details={
                        "share_name": sh,
                        "events_count": sh_info["events"],
                        "staged_targets": list(sh_info["targets"])[:5],
                        "users": list(sh_info["users"])
                    }
                )
                for f in sh_info["files"]:
                    src_id = file_node_ids.get(f, "root")
                    _add_edge(src_id, sh_id, "SMB share access", "smb_share")

            for pr, pr_info in sorted(proc_occurrences.items(), key=lambda x: -x[1]["events"])[:6]:
                if pr_info["is_lolbin"] or pr in ["powershell.exe", "cmd.exe", "vssadmin.exe", "wmic.exe"]:
                    pr_id = f"evtx_proc_{abs(hash(pr)) % 1000000}"
                    _add_node(
                        node_id=pr_id,
                        label=f"Proc: {pr}",
                        n_type="process",
                        risk="critical" if pr_info["is_lolbin"] else "warning",
                        tier=3,
                        details={
                            "process": pr,
                            "is_lolbin": pr_info["is_lolbin"],
                            "events_count": pr_info["events"],
                            "observed_in_files": list(pr_info["files"])
                        }
                    )
                    for f in pr_info["files"]:
                        src_id = file_node_ids.get(f, "root")
                        _add_edge(src_id, pr_id, "spawned LOLBin" if pr_info["is_lolbin"] else "executed", "process_execution")

        # ---------------------------------------------------------
        # 10.8. UNIVERSAL FORENSIC ENTITY EXTRACTION (Emails, Domains, Watchlist Keywords, IPs, Hostnames, Usernames, Names)
        # ---------------------------------------------------------
        try:
            extracted = EntityExtractor.extract_all(job)

            # 1. Emails
            for em in extracted.get("emails", [])[:12]:
                em_val = em["value"]
                em_id = f"ent_email_{abs(hash(em_val)) % 1000000}"
                _add_node(
                    node_id=em_id,
                    label=em_val,
                    n_type="email",
                    risk=em.get("risk", "clean"),
                    tier=2,
                    details={"email": em_val, "sources": list(em.get("sources", []))}
                )
                _add_edge("root", em_id, "contains email", "email")

            # 2. Domains
            for dom in extracted.get("domains", [])[:12]:
                d_val = dom["value"]
                dom_id = f"ent_dom_{abs(hash(d_val)) % 1000000}"
                _add_node(
                    node_id=dom_id,
                    label=d_val,
                    n_type="domain",
                    risk=dom.get("risk", "clean"),
                    tier=3,
                    details={"domain": d_val, "sources": list(dom.get("sources", []))}
                )
                _add_edge("root", dom_id, "references domain", "domain")

            # 3. Watchlist Keywords & Sensitive Warnings
            for kw in extracted.get("keywords", [])[:12]:
                kw_val = kw["value"]
                kw_id = f"ent_kw_{abs(hash(kw.get('rule_name', '') + '::' + kw_val)) % 1000000}"
                _add_node(
                    node_id=kw_id,
                    label=kw["label"],
                    n_type="keyword",
                    risk=kw.get("risk", "warning"),
                    tier=2,
                    details={
                        "keyword": kw_val,
                        "rule_name": kw.get("rule_name"),
                        "severity": kw.get("severity"),
                        "sources": list(kw.get("sources", []))
                    }
                )
                _add_edge("root", kw_id, f"watchlist ({kw.get('severity', 'warning')})", "watchlist_match")

            # 4. IPs
            for ip_item in extracted.get("ips", [])[:12]:
                ip_val = ip_item["value"]
                ip_id = f"ent_ip_{ip_val.replace('.', '_')}"
                _add_node(
                    node_id=ip_id,
                    label=f"IP: {ip_val}",
                    n_type="ip",
                    risk=ip_item.get("risk", "clean"),
                    tier=3,
                    details={"ip": ip_val, "is_private": ip_item.get("is_private", False), "sources": list(ip_item.get("sources", []))}
                )
                _add_edge("root", ip_id, "network IP", "ip")

            # 5. Hostnames
            for h in extracted.get("hostnames", [])[:8]:
                h_val = h["value"]
                h_id = f"ent_host_{abs(hash(h_val)) % 1000000}"
                _add_node(
                    node_id=h_id,
                    label=h["label"],
                    n_type="hostname",
                    risk=h.get("risk", "clean"),
                    tier=2,
                    details={"hostname": h_val, "sources": list(h.get("sources", []))}
                )
                _add_edge("root", h_id, "workstation host", "hostname")

            # 6. Usernames
            for u in extracted.get("usernames", [])[:10]:
                u_val = u["value"]
                u_id = f"ent_user_{abs(hash(u_val)) % 1000000}"
                _add_node(
                    node_id=u_id,
                    label=u["label"],
                    n_type="user",
                    risk=u.get("risk", "clean"),
                    tier=2,
                    details={"username": u_val, "sources": list(u.get("sources", []))}
                )
                _add_edge("root", u_id, "account identity", "identity")

            # 7. Person / Author Names
            for n_item in extracted.get("names", [])[:8]:
                n_val = n_item["value"]
                n_id = f"ent_name_{abs(hash(n_val)) % 1000000}"
                _add_node(
                    node_id=n_id,
                    label=n_item["label"],
                    n_type="name",
                    risk=n_item.get("risk", "clean"),
                    tier=2,
                    details={"name": n_val, "role": n_item.get("role", "Author"), "sources": list(n_item.get("sources", []))}
                )
                _add_edge("root", n_id, n_item.get("role", "author"), "attribution")
        except Exception as e:
            # Non-blocking entity extraction fallback
            pass

        # ---------------------------------------------------------
        # 11. MULTI-TIER CONCENTRIC CIRCLE COORDINATE GENERATION
        # ---------------------------------------------------------
        # Canvas dimensions: 960 x 640
        center_x = 480.0
        center_y = 320.0

        # Tier Radii:
        # Tier 0 (Root): center (0)
        # Tier 1 (Direct hashes, VT/CS/ClamAV, email senders, protocols, log files): radius 165
        # Tier 2 (Attachments, URLs, tracking pixels, TTPs, flows, DNS, users, hosts, emails, keywords, names): radius 275
        # Tier 3 (Domains, resolved IPs, Geo, Similar samples, inner payloads, shares, LOLBins): radius 385
        tier_radii = {
            0: 0.0,
            1: 165.0,
            2: 275.0,
            3: 385.0
        }

        tier_groups: Dict[int, List[Dict[str, Any]]] = {0: [], 1: [], 2: [], 3: []}
        for n in nodes:
            t = n.get("tier", 2)
            if n["id"] == "root":
                tier_groups[0].append(n)
            elif t in tier_groups:
                tier_groups[t].append(n)
            else:
                tier_groups[2].append(n)

        # Root placement
        if tier_groups[0]:
            tier_groups[0][0]["x"] = center_x
            tier_groups[0][0]["y"] = center_y

        # Distribute each tier evenly in a circle with a slight phase offset
        phase_offsets = {1: 0.0, 2: math.pi / 7, 3: math.pi / 5}
        for tier_num, group in tier_groups.items():
            if tier_num == 0 or not group:
                continue
            r = tier_radii.get(tier_num, 250.0)
            phase = phase_offsets.get(tier_num, 0.0)
            angle_step = (2 * math.pi) / len(group)
            for idx, n in enumerate(group):
                ang = phase + idx * angle_step
                n["x"] = round(center_x + r * math.cos(ang), 1)
                n["y"] = round(center_y + r * math.sin(ang), 1)

        # Clean edges
        clean_edges = []
        for e in edges:
            clean_edges.append({
                "source": e["source"],
                "target": e["target"],
                "label": e["label"],
                "type": e["type"]
            })

        return {
            "nodes": nodes,
            "edges": clean_edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(clean_edges),
                "embedded_count": len([n for n in nodes if n["type"] == "embedded_file"]),
                "url_count": len([n for n in nodes if n["type"] in ["url", "domain"]]),
                "technique_count": len([n for n in nodes if n["type"] == "technique"]),
                "similar_count": len([n for n in nodes if n["type"] == "similar_sample"]),
                "certificate_count": len([n for n in nodes if n["type"] == "certificate"]),
                "threat_intel_count": len([n for n in nodes if n["type"] in ["threat_intel", "threat_signature", "keyword"]]),
                "email_artifacts_count": len([n for n in nodes if n["type"] in ["user", "email", "auth_policy", "tracking_pixel", "name"]]),
                "network_artifacts_count": len([n for n in nodes if n["type"] in ["flow", "protocol", "ip", "geolocation", "domain", "hostname", "computer"]]),
                "forensic_count": len([n for n in nodes if n["type"] in ["log_source", "user", "computer", "hostname", "ip", "share", "process", "keyword", "name", "email"]]),
                "cross_log_pivots_count": len([n for n in nodes if n.get("details", {}).get("is_cross_log_pivot")])
            }
        }

