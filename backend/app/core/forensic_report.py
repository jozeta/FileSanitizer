import html
import json
from datetime import datetime
from typing import Dict, Any, Optional

class ForensicReportGenerator:
    """Generates structured incident JSON and printable, styled HTML forensic triage reports."""

    @classmethod
    def build_report_data(cls, job: Any) -> Dict[str, Any]:
        """Assemble comprehensive, normalized forensic dataset from a JobModel."""
        risk = getattr(job, "risk", None)
        risk_level = risk.level if risk else "UNKNOWN"
        risk_score = risk.score if risk else 0
        risk_reasons = risk.reasons if risk else []
        risk_recommendation = risk.recommendation if risk else "N/A"

        clamav = getattr(job, "clamav", {}) or {}
        yara = getattr(job, "yara", {}) or {}
        findings = getattr(job, "findings", []) or []
        urls = getattr(job, "urls", []) or []
        metadata = getattr(job, "metadata", None)
        sanitization_result = getattr(job, "sanitization_result", None)

        # Convert findings to clean dicts
        findings_list = []
        for f in findings:
            if hasattr(f, "model_dump"):
                findings_list.append(f.model_dump())
            elif hasattr(f, "dict"):
                findings_list.append(f.dict())
            elif isinstance(f, dict):
                findings_list.append(f)

        # Convert metadata fields
        meta_dict = {}
        if metadata:
            if hasattr(metadata, "model_dump"):
                meta_dict = metadata.model_dump()
            elif hasattr(metadata, "dict"):
                meta_dict = metadata.dict()
            elif isinstance(metadata, dict):
                meta_dict = metadata

        # Sanitization audit
        sanitization_data = None
        if sanitization_result:
            if hasattr(sanitization_result, "model_dump"):
                sanitization_data = sanitization_result.model_dump()
            elif hasattr(sanitization_result, "dict"):
                sanitization_data = sanitization_result.dict()
            elif isinstance(sanitization_result, dict):
                sanitization_data = sanitization_result

        return {
            "report_version": "1.0",
            "report_type": "FileSanitizer Security & CDR Audit Report / Forensic Triage Dossier",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "case_id": getattr(job, "job_id", ""),
            "file_profile": {
                "original_filename": getattr(job, "original_filename", ""),
                "stored_filename": getattr(job, "filename", ""),
                "file_size_bytes": getattr(job, "file_size", 0),
                "mime_type": getattr(job, "mime_type", "application/octet-stream"),
                "category": getattr(job, "category", "unknown"),
                "signature_description": getattr(job, "signature_description", ""),
                "cryptographic_hashes": getattr(job, "hashes", {}),
                "is_password_protected": getattr(job, "is_password_protected", False),
                "is_unlocked": getattr(job, "is_unlocked", False),
                "unlock_password": getattr(job, "unlock_password", None)
            },
            "threat_assessment": {
                "verdict": risk_level,
                "score": risk_score,
                "reasons": risk_reasons,
                "recommendation": risk_recommendation
            },
            "antivirus_clamav": {
                "scanner": clamav.get("scanner", "ClamAV Native Daemon"),
                "status": clamav.get("status", "UNAVAILABLE"),
                "engine_version": clamav.get("engine_version", "N/A"),
                "signature_db": clamav.get("signature_db", "N/A"),
                "threat_name": clamav.get("threat_name")
            },
            "yara_heuristic_engine": {
                "matches_count": yara.get("matches_count", 0),
                "matches": yara.get("matches", [])
            },
            "threat_intelligence": {
                "virustotal": getattr(job, "virustotal", None),
                "hybrid_analysis": getattr(job, "hybrid_analysis", None),
                "threatfox": getattr(job, "threatfox", None),
                "malwarebazaar": getattr(job, "malwarebazaar", None),
                "circl_hashlookup": getattr(job, "circl", None)
            },
            "mitre_attack": getattr(job, "mitre_attack", []),
            "script_triage": getattr(job, "script_triage", None),
            "findings": findings_list,
            "network_and_urls": {
                "total_urls_discovered": len(urls),
                "items": urls
            },
            "metadata_breakdown": meta_dict,
            "cdr_sanitization_log": sanitization_data
        }

    @classmethod
    def generate_html_report(cls, data: Dict[str, Any]) -> str:
        """Render a standalone, printable, cybersecurity-grade HTML report."""
        fp = data.get("file_profile", {})
        threat = data.get("threat_assessment", {})
        hashes = fp.get("cryptographic_hashes", {})
        clamav = data.get("antivirus_clamav", {})
        yara = data.get("yara_heuristic_engine", {})
        findings = data.get("findings", [])
        urls = data.get("network_and_urls", {}).get("items", [])
        cdr = data.get("cdr_sanitization_log")

        verdict = threat.get("verdict", "UNKNOWN")
        score = threat.get("score", 0)

        # Color mapping for verdict
        badge_color = "#10b981"
        badge_bg = "#ecfdf5"
        if verdict in ["MALICIOUS", "CRITICAL"]:
            badge_color = "#e11d48"
            badge_bg = "#fff1f2"
        elif verdict in ["HIGH RISK", "HIGH"]:
            badge_color = "#f97316"
            badge_bg = "#fff7ed"
        elif verdict in ["MEDIUM RISK", "MEDIUM"]:
            badge_color = "#eab308"
            badge_bg = "#fefce8"

        # Build findings table rows
        findings_rows = ""
        for f in findings:
            sev = f.get("severity", "info").upper()
            sev_color = "#64748b"
            if sev in ["CRITICAL", "MALICIOUS"]:
                sev_color = "#e11d48"
            elif sev == "HIGH":
                sev_color = "#ea580c"
            elif sev == "MEDIUM":
                sev_color = "#ca8a04"
            elif sev in ["LOW", "INFO"]:
                sev_color = "#0284c7"

            title = html.escape(str(f.get("title", "")))
            desc = html.escape(str(f.get("description", "")))
            findings_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px 12px; font-weight: bold; color: {sev_color}; white-space: nowrap;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; background: #f8fafc; border: 1px solid {sev_color}40;">
                        {sev}
                    </span>
                </td>
                <td style="padding: 10px 12px; font-weight: 600; color: #0f172a;">{title}</td>
                <td style="padding: 10px 12px; color: #475569; font-size: 13px;">{desc}</td>
            </tr>
            """

        # Build URLs rows
        url_rows = ""
        for u in urls[:25]:
            url_str = html.escape(u.get("url", ""))
            domain_str = html.escape(u.get("domain", ""))
            rep = u.get("reputation", {})
            vt = rep.get("virus_total", "NOT_CONFIGURED")
            uh = rep.get("urlhaus", "NOT_CONFIGURED")
            abuse = rep.get("abuseipdb", "NOT_CONFIGURED")
            sb = rep.get("safe_browsing", "NOT_CONFIGURED")

            url_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0; font-size: 12px;">
                <td style="padding: 8px 10px; font-family: monospace; word-break: break-all; color: #2563eb;">{url_str}</td>
                <td style="padding: 8px 10px; font-weight: 500; color: #334155;">{domain_str}</td>
                <td style="padding: 8px 10px;">
                    <span style="font-weight: 600; font-size: 11px; color: {'#e11d48' if vt == 'MALICIOUS' else '#10b981' if vt == 'CLEAN' else '#64748b'};">VT: {vt}</span> | 
                    <span style="font-weight: 600; font-size: 11px; color: {'#e11d48' if uh == 'MALICIOUS' else '#10b981' if uh == 'CLEAN' else '#64748b'};">URLhaus: {uh}</span> | 
                    <span style="font-weight: 600; font-size: 11px; color: {'#e11d48' if abuse == 'MALICIOUS' else '#10b981' if abuse == 'CLEAN' else '#64748b'};">AbuseIPDB: {abuse}</span>
                </td>
            </tr>
            """

        # Password protection badge
        pwd_badge = ""
        if fp.get("is_password_protected"):
            if fp.get("is_unlocked"):
                pwd_badge = f"""<span style="display:inline-block; padding: 4px 10px; background:#ecfdf5; border:1px solid #10b981; color:#065f46; font-size:12px; font-weight:600; border-radius:8px; margin-left:8px;">🔓 Unlocked (pwd: '{fp.get('unlock_password')}')</span>"""
            else:
                pwd_badge = """<span style="display:inline-block; padding: 4px 10px; background:#fff1f2; border:1px solid #e11d48; color:#9f1239; font-size:12px; font-weight:600; border-radius:8px; margin-left:8px;">🔒 Locked Encrypted Container</span>"""

        # CDR audit rows
        cdr_section = ""
        if cdr:
            artifacts = cdr.get("artifacts_removed", [])
            art_items = "".join(f"<li style='margin-bottom: 4px;'>{html.escape(str(a))}</li>" for a in artifacts) or "<li>Clean reconstruction without detected artifacts</li>"
            cdr_section = f"""
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 24px;">
                <h3 style="margin-top: 0; color: #0f172a; font-size: 16px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                    🛡️ Content Disarm & Reconstruction (CDR) Audit Trail
                </h3>
                <div style="display: flex; gap: 20px; margin-bottom: 14px; font-size: 13px;">
                    <div><strong>Original Size:</strong> {cdr.get('original_size', 0):,} bytes</div>
                    <div><strong>Sanitized Size:</strong> {cdr.get('sanitized_size', 0):,} bytes</div>
                    <div><strong>Status:</strong> <span style="color: #10b981; font-weight: bold;">Verified Clean</span></div>
                </div>
                <div style="font-size: 13px; color: #475569;">
                    <strong>Sanitized Artifacts Removed:</strong>
                    <ul style="margin-top: 8px; padding-left: 20px; color: #334155;">
                        {art_items}
                    </ul>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Triage Report - {html.escape(fp.get("original_filename", "File"))}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #0f172a;
            margin: 0;
            padding: 30px;
            font-size: 14px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        @media print {{
            body {{
                background-color: #ffffff;
                padding: 0;
            }}
            .no-print {{
                display: none !important;
            }}
            .card {{
                box-shadow: none !important;
                border: 1px solid #cbd5e1 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Action Bar -->
        <div class="no-print" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div style="font-weight: 600; color: #64748b;">FileSanitizer Enterprise Incident Response</div>
            <button onclick="window.print()" style="background: #4f46e5; color: #ffffff; border: none; padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 13px; cursor: pointer;">
                🖨️ Print / Save as PDF
            </button>
        </div>

        <!-- Header Card -->
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
                <div>
                    <div style="font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; color: #6366f1;">
                        Cybersecurity Forensic Dossier
                    </div>
                    <h1 style="margin: 6px 0 2px 0; font-size: 22px; color: #0f172a;">
                        {html.escape(fp.get("original_filename", "Uploaded File"))}
                    </h1>
                    <div style="font-size: 12px; color: #64748b; font-family: monospace;">
                        Case ID: {data.get("case_id")} | Generated: {data.get("generated_at")}
                    </div>
                </div>

                <div style="text-align: right;">
                    <div style="display: inline-block; padding: 6px 16px; border-radius: 9999px; font-weight: 800; font-size: 15px; background: {badge_bg}; color: {badge_color}; border: 1px solid {badge_color};">
                        {verdict} (Score: {score}/100)
                    </div>
                    {pwd_badge}
                </div>
            </div>

            <!-- Recommendation Alert -->
            <div style="margin-top: 18px; padding: 14px 18px; background: #f8fafc; border-left: 4px solid #6366f1; border-radius: 4px; font-size: 13px;">
                <strong>Executive Action Guidance:</strong> {html.escape(threat.get("recommendation", "Review technical findings."))}
            </div>
        </div>

        <!-- File Profile & Hash Verification -->
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 24px;">
            <h3 style="margin-top: 0; color: #0f172a; font-size: 15px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                📁 Cryptographic Fingerprints & Provenance
            </h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; font-size: 13px;">
                <div><strong>Detected MIME:</strong> <code style="background:#f1f5f9; padding:2px 6px; border-radius:4px;">{fp.get("mime_type")}</code></div>
                <div><strong>Category:</strong> <span style="text-transform: capitalize;">{fp.get("category")}</span></div>
                <div><strong>File Size:</strong> {fp.get("file_size_bytes", 0):,} bytes</div>
                <div><strong>Format Spec:</strong> {html.escape(fp.get("signature_description", ""))}</div>
            </div>

            <div style="margin-top: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px;">
                <div><strong>SHA-256:</strong> {hashes.get("sha256", "N/A")}</div>
                <div><strong>SHA-1:</strong> {hashes.get("sha1", "N/A")}</div>
                <div><strong>MD5:</strong> {hashes.get("md5", "N/A")}</div>
            </div>
        </div>

        <!-- Antivirus & Threat Engines Status -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px;">
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px;">
                <h3 style="margin-top: 0; font-size: 15px; color: #0f172a; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px;">
                    🦠 ClamAV Engine Status
                </h3>
                <div style="font-size: 13px;">
                    <div><strong>Verdict:</strong> <span style="font-weight:bold; color: {'#e11d48' if clamav.get('status') == 'MALICIOUS' else '#10b981'};">{clamav.get('status')}</span></div>
                    {f"<div><strong>Threat Signature:</strong> <span style='color:#e11d48; font-weight:bold;'>{clamav.get('threat_name')}</span></div>" if clamav.get('threat_name') else ""}
                    <div><strong>Engine:</strong> {clamav.get('engine_version', 'ClamAV Native')}</div>
                    <div><strong>Definition Version:</strong> {clamav.get('signature_db', 'N/A')}</div>
                </div>
            </div>

            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px;">
                <h3 style="margin-top: 0; font-size: 15px; color: #0f172a; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px;">
                    🔍 YARA Heuristic Rules
                </h3>
                <div style="font-size: 13px;">
                    <div><strong>Total Rules Triggered:</strong> <span style="font-weight:bold;">{yara.get('matches_count', 0)}</span></div>
                    <ul style="margin: 8px 0 0 0; padding-left: 20px; font-size: 12px; color: #475569;">
                        {"".join(f"<li><strong>{html.escape(m.get('rule_name', ''))}</strong> ({m.get('severity')})</li>" for m in yara.get('matches', [])[:5]) or "<li>No suspicious YARA signatures triggered</li>"}
                    </ul>
                </div>
            </div>
        </div>

        <!-- Security Findings Table -->
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 24px;">
            <h3 style="margin-top: 0; color: #0f172a; font-size: 15px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                ⚠️ Catalog of Security Findings ({len(findings)})
            </h3>
            <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                    <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0; font-size: 12px; text-transform: uppercase; color: #64748b;">
                        <th style="padding: 8px 12px; width: 100px;">Severity</th>
                        <th style="padding: 8px 12px; width: 260px;">Vulnerability / Detection</th>
                        <th style="padding: 8px 12px;">Detailed Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows or "<tr><td colspan='3' style='padding:12px; text-align:center; color:#64748b;'>No security vulnerabilities or indicators flagged.</td></tr>"}
                </tbody>
            </table>
        </div>

        <!-- Discovered URLs & Multi-Engine Threat Intel -->
        {f'''
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 24px;">
            <h3 style="margin-top: 0; color: #0f172a; font-size: 15px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">
                🌐 Discovered External URLs & Threat Intelligence ({len(urls)})
            </h3>
            <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                    <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0; font-size: 12px; text-transform: uppercase; color: #64748b;">
                        <th style="padding: 8px 10px; width: 50%;">URL</th>
                        <th style="padding: 8px 10px; width: 20%;">Domain</th>
                        <th style="padding: 8px 10px; width: 30%;">Multi-Engine Feeds</th>
                    </tr>
                </thead>
                <tbody>
                    {url_rows}
                </tbody>
            </table>
        </div>
        ''' if urls else ""}

        <!-- CDR Sanitization Section -->
        {cdr_section}

        <!-- Footer -->
        <div style="text-align: center; color: #94a3b8; font-size: 12px; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 16px;">
            Generated by FileSanitizer CDR & Threat Triage Engine • Confidential Forensic Incident Record
        </div>
    </div>
</body>
</html>"""
