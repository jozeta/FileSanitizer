"""
Investigation Snapshot Comparison & Time-Series Delta Tracking.
Compares the current host/domain investigation against a previous baseline job in the workspace.
Generates an audit trail of infrastructure changes: IP migrations, nameserver modifications,
certificate renewals, newly observed subdomains, and risk posture changes.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime


class InvestigationSnapshotDiffer:
    """
    Diff engine comparing current domain intelligence state against earlier workspace snapshots.
    """

    @classmethod
    def compare(
        cls,
        current_data: Dict[str, Any],
        previous_data: Optional[Dict[str, Any]] = None,
        previous_job_id: Optional[str] = None,
        previous_timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculates deltas across DNS, TLS, Web, and Subdomain attack surfaces.
        """
        if not previous_data:
            return {
                "has_historical_baseline": False,
                "baseline_job_id": None,
                "baseline_timestamp": None,
                "message": "Baseline established. Subsequent investigations will track infrastructure deltas.",
                "timeline_events": [],
                "delta_summary": {
                  "ip_changed": False,
                  "cert_changed": False,
                  "ns_changed": False,
                  "new_subdomains_count": 0
                }
            }

        timeline: List[Dict[str, Any]] = []

        # 1. IP Address Delta
        curr_ips = set(current_data.get("resolved_ips") or (current_data.get("dns_records") or {}).get("a") or [])
        prev_ips = set(previous_data.get("resolved_ips") or (previous_data.get("dns_records") or {}).get("a") or [])

        added_ips = list(curr_ips - prev_ips)
        removed_ips = list(prev_ips - curr_ips)

        if added_ips or removed_ips:
            timeline.append({
                "type": "IP_MIGRATION",
                "severity": "medium",
                "title": "A-Record IP Infrastructure Shift",
                "description": f"IP addresses changed. Added: {', '.join(added_ips) if added_ips else 'None'} | Removed: {', '.join(removed_ips) if removed_ips else 'None'}"
            })

        # 2. Nameserver Delta
        curr_ns_list = current_data.get("dns_records", {}).get("nameservers") or current_data.get("dns_records", {}).get("ns") or (current_data.get("advanced_dns", {}).get("records", {}).get("ns")) or []
        prev_ns_list = previous_data.get("dns_records", {}).get("nameservers") or previous_data.get("dns_records", {}).get("ns") or (previous_data.get("advanced_dns", {}).get("records", {}).get("ns")) or []
        curr_ns = set(curr_ns_list)
        prev_ns = set(prev_ns_list)

        added_ns = list(curr_ns - prev_ns)
        removed_ns = list(prev_ns - curr_ns)

        if added_ns or removed_ns:
            timeline.append({
                "type": "NAMESERVER_CHANGE",
                "severity": "high",
                "title": "Authoritative Nameserver Delegation Modified",
                "description": f"Nameservers altered. Added: {', '.join(added_ns) if added_ns else 'None'} | Removed: {', '.join(removed_ns) if removed_ns else 'None'}"
            })

        # 3. TLS Certificate Delta
        curr_cert = (current_data.get("tls_profile") or {}).get("live_cert") or {}
        prev_cert = (previous_data.get("tls_profile") or {}).get("live_cert") or {}

        curr_serial = curr_cert.get("serial_number") or curr_cert.get("fingerprint_sha256") or curr_cert.get("sha256_fingerprint")
        prev_serial = prev_cert.get("serial_number") or prev_cert.get("fingerprint_sha256") or prev_cert.get("sha256_fingerprint")

        cert_changed = False
        if curr_serial and prev_serial and curr_serial != prev_serial:
            cert_changed = True
            timeline.append({
                "type": "CERTIFICATE_RENEWAL",
                "severity": "info",
                "title": "TLS Certificate Replaced / Renewed",
                "description": f"New certificate observed. Serial: {curr_serial[:18]}... (Previous: {prev_serial[:18]}...)"
            })

        # 4. Subdomain Growth Delta
        curr_subs = {s.get("subdomain") for s in (current_data.get("attack_surface", {}).get("subdomains") or []) if s.get("subdomain")}
        prev_subs = {s.get("subdomain") for s in (previous_data.get("attack_surface", {}).get("subdomains") or []) if s.get("subdomain")}

        new_subs = list(curr_subs - prev_subs)
        if new_subs:
            timeline.append({
                "type": "NEW_SUBDOMAINS_DISCOVERED",
                "severity": "info",
                "title": f"Attack Surface Expanded (+{len(new_subs)} Hostnames)",
                "description": f"Newly observed subdomains: {', '.join(new_subs[:4])}{'...' if len(new_subs) > 4 else ''}"
            })

        # 5. Risk Score Evolution
        curr_mal = (current_data.get("risk_scores", {}).get("maliciousness") or {}).get("score", 0)
        prev_mal = (previous_data.get("risk_scores", {}).get("maliciousness") or {}).get("score", 0)

        if curr_mal != prev_mal:
            score_diff = curr_mal - prev_mal
            direction = "increased" if score_diff > 0 else "decreased"
            timeline.append({
                "type": "RISK_POSTURE_CHANGE",
                "severity": "high" if score_diff > 0 else "info",
                "title": f"Threat Maliciousness Score {direction.capitalize()} ({direction[0] if direction=='increased' else ''}{score_diff:+d})",
                "description": f"Score changed from {prev_mal}/100 to {curr_mal}/100 based on recent threat intelligence."
            })

        return {
            "has_historical_baseline": True,
            "baseline_job_id": previous_job_id,
            "baseline_timestamp": previous_timestamp,
            "total_changes_detected": len(timeline),
            "timeline_events": timeline,
            "delta_summary": {
                "ip_changed": bool(added_ips or removed_ips),
                "added_ips": added_ips,
                "removed_ips": removed_ips,
                "ns_changed": bool(added_ns or removed_ns),
                "added_ns": added_ns,
                "removed_ns": removed_ns,
                "cert_changed": cert_changed,
                "new_subdomains_count": len(new_subs),
                "new_subdomains": new_subs[:10]
            }
        }
