"""
OASIS STIX 2.1 Incident Response & Threat Intelligence Bundle Generator.
Exports file observables, IOC indicators, malware identifications,
and MITRE ATT&CK tactics into standardized STIX 2.1 JSON.
"""

import uuid
import datetime
from typing import Dict, Any, List, Optional


class Stix21Exporter:
    """Generates standard OASIS STIX 2.1 JSON bundles from FileSanitizer jobs."""

    @classmethod
    def generate_bundle(cls, job: Any) -> Dict[str, Any]:
        """Convert a FileSanitizer JobModel into a STIX 2.1 bundle."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

        objects: List[Dict[str, Any]] = []

        # 1. Identity Object (FileSanitizer)
        identity_id = "identity--a83b271d-55e1-4cfa-9311-fc20163364f2"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "FileSanitizer Forensics & CDR Engine",
            "identity_class": "system",
            "sectors": ["technology", "defense"]
        })

        # 2. File SCO (Cyber Observable Object)
        file_sco_id = f"file--{uuid.uuid4()}"
        file_hashes = {}
        if getattr(job, "hashes", None):
            if job.hashes.get("sha256"):
                file_hashes["SHA-256"] = job.hashes["sha256"]
            if job.hashes.get("md5"):
                file_hashes["MD5"] = job.hashes["md5"]
            if job.hashes.get("sha1"):
                file_hashes["SHA-1"] = job.hashes["sha1"]

        file_obj = {
            "type": "file",
            "spec_version": "2.1",
            "id": file_sco_id,
            "name": getattr(job, "original_filename", None) or getattr(job, "filename", "sample.bin"),
            "size": getattr(job, "file_size", 0),
            "mime_type": getattr(job, "mime_type", "application/octet-stream"),
            "hashes": file_hashes
        }
        objects.append(file_obj)

        # 3. File Hash Indicator
        sha256 = file_hashes.get("SHA-256")
        risk_score = 0
        risk_val = getattr(job, "risk", None)
        if risk_val:
            if isinstance(risk_val, dict):
                risk_score = risk_val.get("risk_score", 0)
            else:
                risk_score = getattr(risk_val, "risk_score", 0)
        is_malicious = risk_score >= 40

        if sha256:
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": identity_id,
                "name": f"File Hash Indicator: {sha256[:16]}...",
                "description": f"File hash observed in {file_obj['name']}",
                "indicator_types": ["malicious-activity" if is_malicious else "unknown"],
                "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": min(100, int(risk_score or 50))
            })

            # Relationship: indicator -> indicates -> file
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": file_sco_id
            })

        # 4. URLs as Indicators
        urls = getattr(job, "urls", [])
        for u in urls[:10]:
            target_url = u.get("url") if isinstance(u, dict) else str(u)
            if not target_url:
                continue
            is_bad = isinstance(u, dict) and u.get("risk") in ["HIGH RISK", "MALICIOUS"]
            url_ind_id = f"indicator--{uuid.uuid4()}"
            safe_url_pattern = target_url.replace("'", "\\'")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": url_ind_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": identity_id,
                "name": f"Embedded URL: {target_url[:60]}",
                "description": f"URL extracted from document content or metadata",
                "indicator_types": ["malicious-activity" if is_bad else "anomalous-activity"],
                "pattern": f"[url:value = '{safe_url_pattern}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": 85 if is_bad else 40
            })

        # 5. MITRE ATT&CK Attack Patterns
        mitre_entries = getattr(job, "mitre_attack", [])
        for m in mitre_entries:
            tech_id = m.get("technique_id", "T0000")
            tech_name = m.get("technique_name", "Unknown Technique")
            attack_pat_id = f"attack-pattern--{uuid.uuid4()}"
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pat_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": identity_id,
                "name": f"{tech_id}: {tech_name}",
                "description": m.get("matched_indicator", f"MITRE ATT&CK Technique {tech_id}"),
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": m.get("tactic", "execution").lower().replace(" ", "-")
                }],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                }]
            })

            # Relationship: file uses attack-pattern
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "uses",
                "source_ref": file_sco_id,
                "target_ref": attack_pat_id
            })

        # 6. Malware Object (if identified by ClamAV or Threat Intelligence)
        malware_name = None
        clam_data = getattr(job, "clamav", {}) or {}
        mb_data = getattr(job, "malwarebazaar", {}) or {}
        tf_data = getattr(job, "threatfox", {}) or {}

        if clam_data.get("virus_name"):
            malware_name = clam_data["virus_name"]
        elif mb_data.get("signature") and mb_data["signature"] != "Unknown Malware":
            malware_name = mb_data["signature"]
        elif tf_data.get("malware") and tf_data["malware"] != "Malware":
            malware_name = tf_data["malware"]

        if malware_name:
            malware_id = f"malware--{uuid.uuid4()}"
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": now_iso,
                "modified": now_iso,
                "created_by_ref": identity_id,
                "name": malware_name,
                "is_family": False,
                "malware_types": ["trojan", "malicious-code"],
                "description": f"Identified signature: {malware_name}"
            })

            # Relationship: file delivers malware
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "delivers",
                "source_ref": file_sco_id,
                "target_ref": malware_id
            })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
