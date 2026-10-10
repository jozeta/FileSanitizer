import re
import email
from email import policy
import email.utils
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
from bs4 import BeautifulSoup
import hashlib
import datetime
import urllib.parse

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.analyzers.virustotal_client import VirusTotalClient
from app.analyzers.reputation_client import (
    CirclHashlookupClient,
    ThreatFoxClient,
    AbuseIPDBClient,
    HybridAnalysisClient,
    MXToolboxClient,
    RdapClient,
    IPinfoClient,
)
from app.core.settings_store import settings_store
from app.network.geo_resolver import GeoResolver
from app.core.logging_config import logger
from app.analyzers.domain_analyzer import DomainAnalyzer

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".pif", ".jar", ".msi",
    ".dll", ".com", ".gadget", ".iso", ".img", ".vhd", ".lnk"
}

OFFICE_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "t-online.de", "web.de"
}

BRAND_KEYWORDS = [
    "microsoft", "office 365", "google", "apple", "paypal", "amazon",
    "bank", "chase", "wells fargo", "citibank", "dhl", "fedex", "ups",
    "security team", "it support", "helpdesk", "administrator", "payroll",
    "accounting", "human resources", "compliance"
]

PHISHING_URGENCY_REGEX = re.compile(
    r'(?i)\b(urgent\s+action|account\s+suspended|verify\s+your\s+(?:account|identity)|'
    r'unauthorized\s+activity|security\s+alert|password\s+expir\w+|immediate\s+response|'
    r'wire\s+transfer|gift\s+cards?|cryptocurrency\s+payment|overdue\s+invoice|'
    r'final\s+notice|click\s+here\s+to\s+verify|reactivate\s+your\s+account|'
    r'billing\s+failure|unusual\s+sign-in)\b'
)


class EmailAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "EmailAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str, workspace_dir: Optional[Path] = None) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to read email file: {e}",
                findings=[],
                data={}
            )

        # Detect if Outlook OLE Compound File (.msg)
        filename_str = str(filename) if isinstance(filename, (str, Path)) else file_path.name
        is_ole_msg = raw_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") or filename_str.lower().endswith(".msg")
        msg = None

        if is_ole_msg:
            try:
                import olefile
                msg = self._parse_ole_msg(file_path, raw_bytes)
            except Exception as oe:
                logger.debug(f"OLE MSG parsing attempt note: {oe}")

        if msg is None:
            try:
                msg = email.message_from_bytes(raw_bytes, policy=policy.default)
            except Exception as e:
                return AnalyzerResult(
                    analyzer_name=self.name,
                    success=False,
                    error_message=f"Failed to parse email message: {e}",
                    findings=[Finding(
                        category="structure",
                        severity="high",
                        title="Malformed Email Message",
                        description=f"Email parser encountered an error: {e}"
                    )],
                    data={}
                )

        # 1. Extract Headers
        headers: Dict[str, Any] = {}
        header_keys = [
            "from", "to", "cc", "bcc", "subject", "date",
            "message-id", "reply-to", "return-path", "delivered-to",
            "authentication-results", "received-spf", "dkim-signature",
            "arc-authentication-results", "x-mailer", "user-agent"
        ]
        for k in header_keys:
            val = msg.get(k)
            if val:
                headers[k] = str(val)

        from_header = headers.get("from", "")
        reply_to_header = headers.get("reply-to", "")
        return_path_header = headers.get("return-path", "")
        subject_header = headers.get("subject", "(No Subject)")

        # Extract all headers in original order as list of dicts
        all_headers: List[Dict[str, str]] = []
        try:
            for k, v in msg.items():
                all_headers.append({"name": str(k), "value": str(v)})
        except Exception:
            pass

        # Extract raw header block
        raw_headers = ""
        try:
            if is_ole_msg:
                raw_headers = getattr(msg, "_ole_raw_headers", "")
            else:
                for delim in [b"\r\n\r\n", b"\n\n"]:
                    if delim in raw_bytes:
                        raw_headers = raw_bytes.split(delim, 1)[0].decode("utf-8", errors="replace")
                        break
            if not raw_headers and all_headers:
                raw_headers = "\n".join(f"{h['name']}: {h['value']}" for h in all_headers)
        except Exception:
            raw_headers = "\n".join(f"{h['name']}: {h['value']}" for h in all_headers) if all_headers else ""

        # Extract full raw email text (RFC 822 / MIME source)
        raw_email = ""
        if not is_ole_msg:
            try:
                raw_email = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    raw_email = raw_bytes.decode("latin-1")
                except Exception:
                    raw_email = raw_bytes.decode("utf-8", errors="replace")
        else:
            ole_body = getattr(msg, "_ole_body_text", "")
            if raw_headers and ole_body:
                raw_email = f"{raw_headers}\r\n\r\n{ole_body}"
            else:
                try:
                    raw_email = msg.as_string()
                except Exception:
                    raw_email = ""

        # 2. Extract Body (Plain & HTML)
        body_plain = ""
        body_html = ""

        try:
            body_part = msg.get_body(preferencelist=('plain',))
            if body_part:
                body_plain = body_part.get_content()
        except Exception:
            pass

        try:
            html_part = msg.get_body(preferencelist=('html',))
            if html_part:
                body_html = html_part.get_content()
        except Exception:
            pass

        # If get_body didn't catch parts (e.g. multipart alternative or walk fallback)
        if not body_plain and not body_html:
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_content()
                    except Exception:
                        pass
                elif ctype == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:
                        pass

        # 3. Clean HTML Body for Safe Preview
        clean_html = ""
        deceptive_links: List[Dict[str, Any]] = []
        tracking_pixels: List[Dict[str, Any]] = []

        if body_html:
            clean_html, deceptive_links, tracking_pixels = self._clean_and_inspect_html(body_html, urls, findings)
            # If no plain text extracted, derive from HTML
            if not body_plain:
                try:
                    soup = BeautifulSoup(body_html, 'html.parser')
                    body_plain = soup.get_text(separator="\n").strip()
                except Exception:
                    pass
        elif body_plain:
            # Wrap plain text into formatted preview HTML
            clean_html = f"<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; white-space: pre-wrap; font-size: 14px; line-height: 1.6; color: #333;\">{self._escape_html(body_plain)}</div>"

        # Also extract URLs from plain body
        if body_plain:
            urls.update(extract_clean_urls(body_plain))

        # Tracking pixel / web beacon finding
        if tracking_pixels:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title=f"{len(tracking_pixels)} Tracking Pixel(s) / Web Beacon(s) Detected",
                description=(
                    f"Found {len(tracking_pixels)} invisible or 1x1 image beacons designed to notify "
                    "external telemetry servers when this email is opened."
                ),
                details={"tracking_pixels": tracking_pixels}
            ))

        # 4. Phishing Keywords & Urgency Detection
        phishing_matches = PHISHING_URGENCY_REGEX.findall(f"{subject_header} {body_plain}")
        phishing_keywords = list(set(m.lower() for m in phishing_matches))
        if phishing_keywords:
            findings.append(Finding(
                category="active_content",
                severity="medium",
                title=f"Coercive Phishing Keywords Detected ({len(phishing_keywords)} matches)",
                description=(
                    f"Message contains language designed to induce panic or urgency: "
                    f"'{', '.join(phishing_keywords[:5])}'. Attackers use psychological urgency to bypass scrutiny."
                ),
                details={"keywords": phishing_keywords}
            ))

        # 4.1 Thread Hijacking / In-Reply-To Verification
        subj_clean = subject_header.lower().strip()
        in_reply_to = headers.get("in-reply-to")
        references = headers.get("references")
        thread_hijacking = {
            "is_reply_subject": subj_clean.startswith(("re:", "fwd:")),
            "has_in_reply_to": bool(in_reply_to),
            "has_references": bool(references),
            "suspected_hijacking": False
        }
        if thread_hijacking["is_reply_subject"] and not in_reply_to and not references:
            thread_hijacking["suspected_hijacking"] = True
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Thread Hijacking Indicator: 'Re:' Subject without In-Reply-To Header",
                description=(
                    "Email subject simulates an ongoing conversation thread ('Re:'), but lacks authentic RFC In-Reply-To or References message headers. "
                    "This is a common tactic in reply-chain hijacking attacks (e.g. QakBot, Emotet) to fabricate familiarity and evade skepticism."
                ),
                details={"subject": subject_header}
            ))

        # 5. Sender Spoofing & Phishing Heuristics
        sender_analysis = self._inspect_sender(headers, body_html, body_plain, findings)

        # 6. Server Transit Data & Chronological MTA Hop Analysis
        transit_hops, sender_ips = self._inspect_transit_hops(msg)

        # Enrich originating transit hop IPs with AbuseIPDB and IPinfo
        if settings_store.is_external_allowed("allow_threat_intel_lookups"):
            for hop in transit_hops:
                hip = hop.get("ip", "")
                if hip and not hip.startswith(("127.", "0.", "10.", "192.168.", "172.16.")):
                    # AbuseIPDB check
                    if settings_store.is_global_enabled("abuseipdb_enabled"):
                        try:
                            abuse_res = AbuseIPDBClient.check_ip(hip)
                            hop["abuseipdb"] = abuse_res
                            if abuse_res.get("status") in ["MALICIOUS", "SUSPICIOUS"]:
                                findings.append(Finding(
                                    category="reputation",
                                    severity="critical" if abuse_res["status"] == "MALICIOUS" else "high",
                                    title=f"AbuseIPDB Flagged Hop IP {hip} (Score: {abuse_res.get('score')}%)",
                                    description=f"Originating mail server IP {hip} has {abuse_res.get('total_reports', 0)} abuse reports on AbuseIPDB (ISP: {abuse_res.get('isp', 'Unknown')}).",
                                    details=abuse_res
                                ))
                        except Exception as ae:
                            logger.debug(f"AbuseIPDB hop check error: {ae}")

                    # IPinfo check
                    if settings_store.is_global_enabled("ipinfo_enabled"):
                        try:
                            ipinfo_res = IPinfoClient.check_ip(hip)
                            hop["ipinfo"] = ipinfo_res
                            privacy = ipinfo_res.get("privacy", {})
                            if privacy.get("is_tor") or privacy.get("is_vpn") or privacy.get("is_proxy"):
                                privacy_badges = [k.replace("is_", "").upper() for k, v in privacy.items() if v]
                                findings.append(Finding(
                                    category="reputation",
                                    severity="medium",
                                    title=f"Mail Hop IP {hip} Routed via Anonymizer ({'/'.join(privacy_badges)})",
                                    description=f"IPinfo detected that hop IP {hip} is an anonymizing proxy/VPN/Tor node (Org: {ipinfo_res.get('org', '')}).",
                                    details=ipinfo_res
                                ))
                        except Exception as ie:
                            logger.debug(f"IPinfo hop check error: {ie}")

        # 7. Structured Authentication (SPF, DKIM, DMARC, ARC)
        authentication_data = self._inspect_authentication(headers, findings)

        # 8. Attachments Extraction, Indexing, and External Reputation
        attachments_info = self._process_attachments(msg, workspace_dir, findings)
        for att in attachments_info:
            for q in att.get("qr_codes", []):
                if q.get("url"):
                    urls.add(q["url"])

        # 9. Attachment Relationship Graph
        attachment_nodes = []
        for att in attachments_info:
            attachment_nodes.append({
                "id": att.get("sha256", "")[:12],
                "filename": att.get("filename"),
                "mime_type": att.get("mime_type"),
                "size_bytes": att.get("size"),
                "is_dangerous": att.get("is_dangerous", False),
                "threat_reason": att.get("threat_reason", ""),
                "is_container": att.get("filename", "").lower().endswith((".zip", ".tar", ".gz", ".7z", ".iso")),
                "is_executable": att.get("filename", "").lower().endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs")),
            })
        attachment_graph = {
            "root_email": {"subject": subject_header, "from": from_header},
            "attachments": attachment_nodes,
            "has_container": any(n["is_container"] for n in attachment_nodes),
            "has_executable": any(n["is_executable"] for n in attachment_nodes)
        }

        # Check for CVE-2023-23397 (Outlook Elevation of Privilege / NetNTLM Leak)
        cve_unc = getattr(msg, "_cve_2023_23397_unc", None)
        if not cve_unc:
            unc_m = re.search(r'(?i)\\\\([a-zA-Z0-9_\.\-]+(?:\\[a-zA-Z0-9_\.\-]+)+)', raw_email)
            if unc_m and any(k in raw_email for k in ["PidLidReminder", "851F", "ReminderFileParameter"]):
                cve_unc = unc_m.group(0)

        if cve_unc:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Microsoft Outlook NetNTLM Hash Leak via Reminder (CVE-2023-23397)",
                description=(
                    f"Message defines PidLidReminderFileParameter pointing to remote UNC path '{cve_unc}'. "
                    "When processed by Microsoft Outlook, this automatically forces SMB negotiation to the attacker server "
                    "without user interaction, leaking NetNTLM credentials."
                ),
                details={"unc_path": cve_unc, "cve": "CVE-2023-23397", "mitre_technique": "T1187"}
            ))

        # Check for CVE-2024-21378 (Outlook Synced Forms RCE)
        custom_form = getattr(msg, "_cve_2024_21378_custom_form", None)
        if custom_form:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title=f"Microsoft Outlook Synced Form RCE Indicator (CVE-2024-21378 / {custom_form})",
                description=(
                    f"Message specifies non-standard custom form class '{custom_form}'. "
                    "Exploited via Microsoft Outlook sync features (CVE-2024-21378) to install malicious form code and achieve remote execution."
                ),
                details={"message_class": custom_form, "cve": "CVE-2024-21378", "mitre_technique": "T1204"}
            ))

        # Check for CVE-2024-38021 / CVE-2024-21413 (Moniker Link in Email Body / Preview)
        moniker_in_body = re.findall(r'(?i)(?:file://|\\\\)[^\s"\'><]+![a-zA-Z0-9_\-\./]*', raw_email)
        if moniker_in_body:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Outlook Moniker Link Remote Code Execution (CVE-2024-38021 / CVE-2024-21413)",
                description=(
                    f"Email contains MonikerLink exclamation mark bypass targets ({', '.join(moniker_in_body[:2])}). "
                    "Bypasses Outlook Protected View / security restrictions and triggers remote code execution upon preview or click."
                ),
                details={"targets": moniker_in_body[:5], "cve": "CVE-2024-38021", "mitre_technique": "T1204.002"}
            ))

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data={
                "headers": headers,
                "all_headers": all_headers,
                "raw_headers": raw_headers,
                "raw_email": raw_email,
                "subject": subject_header,
                "from": from_header,
                "to": headers.get("to", ""),
                "cc": headers.get("cc", ""),
                "date": headers.get("date", ""),
                "message_id": headers.get("message-id", ""),
                "reply_to": reply_to_header,
                "return_path": return_path_header,
                "sender_ips": sender_ips,
                "sender_analysis": sender_analysis,
                "authentication": authentication_data,
                "transit_hops": transit_hops,
                "thread_hijacking": thread_hijacking,
                "body_plain": body_plain,
                "body_plain_snippet": body_plain[:500] if body_plain else "",
                "body_html_sanitized": clean_html,
                "has_html": bool(body_html),
                "tracking_pixels": tracking_pixels,
                "tracking_pixel_count": len(tracking_pixels),
                "deceptive_links": deceptive_links,
                "phishing_keywords": phishing_keywords,
                "attachments": attachments_info,
                "attachment_count": len(attachments_info),
                "attachment_graph": attachment_graph,
                "recipients_details": getattr(msg, "_ole_recipients", []),
                "ole_msg_metadata": getattr(msg, "_ole_metadata", {}),
                "urls": list(urls)
            }
        )

    # -------------------------------------------------------------------------
    # HTML Cleaning & Link Inspection
    # -------------------------------------------------------------------------
    def _clean_and_inspect_html(
        self,
        raw_html: str,
        urls: Set[str],
        findings: List[Finding]
    ) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Produce a safe, sanitized HTML preview while analyzing deceptive anchor text
        and tracking pixels.
        """
        soup = BeautifulSoup(raw_html, 'html.parser')
        deceptive_links: List[Dict[str, Any]] = []
        tracking_pixels: List[Dict[str, Any]] = []

        # Remove dangerous and active elements
        for tag in soup.find_all(['script', 'object', 'embed', 'iframe', 'form', 'meta', 'applet', 'base']):
            tag.decompose()

        # HTML Smuggling Detection
        html_smuggling_found = []
        if re.search(r'(?i)data:(text/html|application/octet-stream);base64,', raw_html):
            html_smuggling_found.append("Embedded Base64 Data URI Payload")
        if re.search(r'(?i)(window\.URL\.createObjectURL|msSaveOrOpenBlob|new\s+Blob\s*\()', raw_html):
            html_smuggling_found.append("JavaScript Blob Object Construction")
        if re.search(r'(?i)<svg[^>]*>\s*<animate[^>]*onload=', raw_html):
            html_smuggling_found.append("SVG Active Animate OnLoad Script Trigger")
        if re.search(r'(?i)(display:\s*none|font-size:\s*0px|color:\s*transparent|opacity:\s*0)', raw_html):
            html_smuggling_found.append("CSS-Hidden Text/Form Obfuscation")

        if html_smuggling_found:
            findings.append(Finding(
                category="active_content",
                severity="critical" if any("Blob" in s or "Base64" in s for s in html_smuggling_found) else "high",
                title=f"HTML Smuggling / Obfuscation Detected in Body ({len(html_smuggling_found)} techniques)",
                description=f"Identified HTML smuggling and hidden payload constructs: {', '.join(html_smuggling_found)}.",
                details={"techniques": html_smuggling_found}
            ))

        # Check for active HTML code finding
        if raw_html.lower().find("<script") != -1 or raw_html.lower().find("<iframe") != -1:
            findings.append(Finding(
                category="active_content",
                severity="high",
                title="Active Executable Elements Stripped from Email HTML",
                description="Email contained active script or iframe elements which have been stripped for safe viewing."
            ))

        # Check all tags for dangerous attributes
        for tag in soup.find_all(True):
            attrs = dict(tag.attrs)
            for attr in attrs:
                if attr.lower().startswith('on'):  # inline event handlers
                    del tag.attrs[attr]
                elif attr.lower() in ['href', 'src', 'action']:
                    val = str(tag.attrs[attr]).strip()
                    if val.lower().startswith(('javascript:', 'data:text/html', 'vbscript:')):
                        tag.attrs[attr] = '#'

        # Inspect and sanitize tracking pixels
        for img in soup.find_all('img'):
            src = str(img.get('src', '')).strip()
            width = str(img.get('width', '')).strip().lower()
            height = str(img.get('height', '')).strip().lower()
            style = str(img.get('style', '')).strip().lower()

            is_tracking = False
            reason = ""

            if width in ['0', '1', '0px', '1px'] and height in ['0', '1', '0px', '1px']:
                is_tracking = True
                reason = "1x1 hidden image dimensions"
            elif 'display:none' in style or 'visibility:hidden' in style:
                is_tracking = True
                reason = "CSS hidden image style"
            elif any(pat in src.lower() for pat in ['pixel.gif', 'beacon', 'track', 'open.php', 'wf.gif', 'trk']):
                is_tracking = True
                reason = "Known web beacon URL signature"

            if is_tracking and src:
                tracking_pixels.append({
                    "url": src,
                    "reason": reason,
                    "width": width,
                    "height": height
                })
                urls.update(extract_clean_urls(src))

        # Inspect links for deceptive anchors (<a href="evil.com">paypal.com</a>)
        # and neutralize them so they render visually as is, but point safely to '#'
        for a_tag in soup.find_all('a'):
            href = str(a_tag.get('href', '')).strip()

            if href and href != '#':
                if href.startswith(('http://', 'https://')):
                    urls.update(extract_clean_urls(href))
                    anchor_text = a_tag.get_text().strip()

                    # Check if anchor text resembles a URL or domain
                    text_has_domain = re.search(r'\b(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', anchor_text)
                    if text_has_domain:
                        claimed_domain = text_has_domain.group(1).lower()
                        try:
                            dest_domain = (urllib.parse.urlparse(href).hostname or "").lower()
                        except Exception:
                            dest_domain = ""

                        # If anchor displays one legitimate domain but links to an entirely different host
                        if dest_domain and claimed_domain and dest_domain != claimed_domain:
                            # Avoid flagging subdomains of same root
                            claimed_root = ".".join(claimed_domain.split(".")[-2:])
                            dest_root = ".".join(dest_domain.split(".")[-2:])
                            if claimed_root != dest_root:
                                deceptive_item = {
                                    "displayed_text": anchor_text,
                                    "claimed_destination": claimed_domain,
                                    "actual_destination": href,
                                    "destination_host": dest_domain
                                }
                                deceptive_links.append(deceptive_item)
                                findings.append(Finding(
                                    category="url",
                                    severity="critical",
                                    title=f"Deceptive Phishing Link: Visual text shows '{claimed_domain}' but opens '{dest_domain}'",
                                    description=(
                                        f"The link displayed to the recipient reads '{anchor_text}', deceiving the user into "
                                        f"expecting a trusted website, but navigates to an entirely different target ({href})."
                                    ),
                                    details=deceptive_item
                                ))

                # Keep original destination in data attributes & tooltip for safe inspection
                a_tag['data-original-href'] = href
                if not a_tag.get('title'):
                    a_tag['title'] = f"Original Link: {href} (Neutered to '#' for safety)"

            # Crucial: links render as-is visually, but strictly point to '#'
            a_tag['href'] = '#'
            if 'target' in a_tag.attrs:
                del a_tag.attrs['target']
            if 'rel' in a_tag.attrs:
                del a_tag.attrs['rel']

        # Also neutralize any image-map <area> links
        for area_tag in soup.find_all('area'):
            a_href = str(area_tag.get('href', '')).strip()
            if a_href and a_href != '#':
                urls.update(extract_clean_urls(a_href))
                area_tag['data-original-href'] = a_href
                if not area_tag.get('title'):
                    area_tag['title'] = f"Original Link: {a_href} (Neutered to '#' for safety)"
            area_tag['href'] = '#'
            if 'target' in area_tag.attrs:
                del area_tag.attrs['target']

        # Safe container styling wrapper
        safe_html = (
            "<div class=\"fs-email-preview-body\" style=\""
            "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;"
            "font-size: 14px; line-height: 1.6; color: #1e293b; background-color: #ffffff; padding: 16px; "
            "border-radius: 8px; max-width: 100%; overflow-x: auto; word-break: break-word;\">"
            f"{str(soup)}"
            "</div>"
        )

        return safe_html, deceptive_links, tracking_pixels

    # -------------------------------------------------------------------------
    # Sender Analysis & Phishing / Spoofing Heuristics
    # -------------------------------------------------------------------------
    def _inspect_sender(
        self,
        headers: Dict[str, Any],
        body_html: str,
        body_plain: str,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        from_hdr = headers.get("from", "")
        reply_to_hdr = headers.get("reply-to", "")
        return_path_hdr = headers.get("return-path", "")

        display_name, actual_from_addr = email.utils.parseaddr(from_hdr)
        _, actual_reply_addr = email.utils.parseaddr(reply_to_hdr)
        _, actual_return_path = email.utils.parseaddr(return_path_hdr)

        from_domain = actual_from_addr.split("@")[-1].lower() if "@" in actual_from_addr else ""
        reply_domain = actual_reply_addr.split("@")[-1].lower() if "@" in actual_reply_addr else ""
        return_path_domain = actual_return_path.split("@")[-1].lower() if "@" in actual_return_path else ""

        is_mismatched_reply = bool(from_domain and reply_domain and from_domain != reply_domain)
        is_mismatched_return = bool(from_domain and return_path_domain and from_domain != return_path_domain)

        # 1. From vs Reply-To mismatch
        if is_mismatched_reply:
            findings.append(Finding(
                category="structure",
                severity="medium",
                title=f"Mismatched From / Reply-To Email Domains ({from_domain} vs {reply_domain})",
                description=(
                    f"The sender domain ({from_domain}) differs from the reply routing domain ({reply_domain}). "
                    "This technique is used in business email compromise (BEC) and credential phishing to redirect victim responses."
                ),
                details={"from": from_hdr, "reply_to": reply_to_hdr, "from_domain": from_domain, "reply_domain": reply_domain}
            ))

        # 2. Display Name Spoofing: Display name contains email or brand
        display_spoofing = False
        display_spoof_detail = ""
        clean_display = display_name.strip(' "\'')

        if "@" in clean_display and clean_display.lower() != actual_from_addr.lower():
            display_spoofing = True
            display_spoof_detail = f"Display name contains fake email address '{clean_display}' masking envelope address '{actual_from_addr}'"
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Display Name Spoofing Detected in Sender Header",
                description=display_spoof_detail,
                details={"display_name": clean_display, "actual_address": actual_from_addr}
            ))

        # 3. Brand impersonation from generic freemail provider
        is_freemail = from_domain in FREE_WEBMAIL_DOMAINS
        impersonated_brand = None
        for brand in BRAND_KEYWORDS:
            if brand in clean_display.lower():
                impersonated_brand = brand
                break

        if is_freemail and impersonated_brand:
            findings.append(Finding(
                category="structure",
                severity="high",
                title=f"Brand Impersonation via Public Webmail: '{clean_display}' from @{from_domain}",
                description=(
                    f"The sender claims to represent '{impersonated_brand.title()}' in the display name, "
                    f"but the email was transmitted from a free personal webmail account (@{from_domain})."
                ),
                details={"brand": impersonated_brand, "display_name": clean_display, "from": from_hdr}
            ))

        # 4. Lookalike / Punycode / Homograph domain
        CYRILLIC_LOOKALIKES = {'а', 'с', 'е', 'о', 'р', 'х', 'у', 'і', 'ј', 'ѕ', 'ԁ', 'ԛ', 'ԝ'}
        cyrillic_matches = [c for c in from_domain if c in CYRILLIC_LOOKALIKES]
        is_punycode = "xn--" in from_domain or "xn--" in reply_domain or bool(cyrillic_matches)
        if is_punycode:
            findings.append(Finding(
                category="structure",
                severity="critical",
                title=f"Homoglyph / Punycode Lookalike Domain Spoofing (@{from_domain})",
                description=(
                    f"Sender domain uses deceptive lookalike Unicode/Punycode characters "
                    f"({'Cyrillic lookalikes: ' + ', '.join(set(cyrillic_matches)) if cyrillic_matches else 'IDN Punycode'}) "
                    "to visually impersonate an authentic domain."
                ),
                details={"domain": from_domain, "lookalikes": list(set(cyrillic_matches))}
            ))

        # 4.1 VIP Executive Impersonation
        VIP_TITLES = ["ceo", "cfo", "chief executive", "president", "director", "wire transfer", "payroll", "finance team", "urgent payment", "helpdesk admin"]
        is_vip = any(t in clean_display.lower() for t in VIP_TITLES)
        if is_vip and (is_freemail or is_mismatched_reply):
            findings.append(Finding(
                category="structure",
                severity="high",
                title=f"Executive / VIP Impersonation Detected: '{clean_display}'",
                description=(
                    f"Sender claims executive authority ('{clean_display}') but email is routed through unauthenticated "
                    f"or mismatching infrastructure (@{from_domain}). Typical BEC / Wire fraud indicator."
                ),
                details={"display_name": clean_display, "from_domain": from_domain}
            ))

        # 5. RDAP / WHOIS Domain Registration Age
        rdap_data: Dict[str, Any] = {}
        if from_domain and settings_store.is_global_enabled("rdap_enabled") and settings_store.is_external_allowed("allow_threat_intel_lookups"):
            try:
                rdap_data = RdapClient.check_domain(from_domain)
                if rdap_data.get("is_newly_registered"):
                    findings.append(Finding(
                        category="reputation",
                        severity="high",
                        title=f"Newly Registered Sender Domain (@{from_domain}) - Age: {rdap_data.get('age_days', 0)} days",
                        description=(
                            f"The sender domain @{from_domain} was registered {rdap_data.get('age_days', 0)} days ago "
                            f"({rdap_data.get('created_date', 'Unknown')}, Registrar: {rdap_data.get('registrar')}). "
                            "Newly registered domains (< 30 days old) represent high phishing and spear-phishing risk."
                        ),
                        details=rdap_data
                    ))
            except Exception as re_err:
                logger.debug(f"RDAP domain lookup error: {re_err}")

        # 6. MXToolbox DMARC / DNS Diagnostics
        mxtoolbox_data: Dict[str, Any] = {}
        if from_domain and settings_store.is_global_enabled("mxtoolbox_enabled") and settings_store.is_external_allowed("allow_threat_intel_lookups"):
            try:
                mxtoolbox_data = MXToolboxClient.check_domain(from_domain, command="dmarc")
                if mxtoolbox_data.get("status") == "MALICIOUS" or mxtoolbox_data.get("is_blacklisted"):
                    findings.append(Finding(
                        category="reputation",
                        severity="critical",
                        title=f"MXToolbox Blacklist Hit for @{from_domain}",
                        description=f"Domain @{from_domain} is flagged on MXToolbox email reputation blacklists.",
                        details=mxtoolbox_data
                    ))
                elif mxtoolbox_data.get("status") == "SUSPICIOUS" and mxtoolbox_data.get("errors"):
                    findings.append(Finding(
                        category="reputation",
                        severity="medium",
                        title=f"MXToolbox DMARC/DNS Warnings for @{from_domain}",
                        description=f"MXToolbox identified DNS configuration issues: {', '.join(mxtoolbox_data.get('errors', [])[:3])}",
                        details=mxtoolbox_data
                    ))
            except Exception as mx_err:
                logger.debug(f"MXToolbox lookup error: {mx_err}")

        return {
            "display_name": clean_display,
            "from_address": actual_from_addr,
            "from_domain": from_domain,
            "reply_to_address": actual_reply_addr,
            "reply_to_domain": reply_domain,
            "return_path_address": actual_return_path,
            "return_path_domain": return_path_domain,
            "is_mismatched_reply_to": is_mismatched_reply,
            "is_mismatched_return_path": is_mismatched_return,
            "is_freemail": is_freemail,
            "is_punycode": is_punycode,
            "has_homoglyphs": bool(cyrillic_matches),
            "homoglyphs_details": [f"Cyrillic character '{c}' in domain {from_domain}" for c in cyrillic_matches],
            "is_vip_impersonation": bool(is_vip),
            "vip_title": next((t for t in VIP_TITLES if t in clean_display.lower()), None) if is_vip else None,
            "display_name_spoofed": display_spoofing,
            "impersonated_brand": impersonated_brand,
            "rdap": rdap_data,
            "mxtoolbox": mxtoolbox_data,
            "sender_domain_intelligence": DomainAnalyzer.analyze(from_domain) if from_domain else {}
        }

    # -------------------------------------------------------------------------
    # Server Transit & Hop Analysis (Received headers)
    # -------------------------------------------------------------------------
    def _inspect_transit_hops(self, msg) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse all 'Received' MTA headers in chronological order (hop 1 to N),
        resolving sender IPs to Geolocation and ASN, and measuring hop delay.
        """
        raw_received = msg.get_all("received") or []
        hops: List[Dict[str, Any]] = []
        all_sender_ips: List[str] = []

        # Chronological order: check if timestamps are present to sort ascending
        parsed_entries = []
        for rec_val in raw_received:
            s = " ".join(str(rec_val).split())
            dt = None
            if ";" in s:
                try:
                    dt = email.utils.parsedate_to_datetime(s.split(";")[-1].strip())
                except Exception:
                    pass
            parsed_entries.append((dt, rec_val))

        has_all_dates = len(parsed_entries) > 0 and all(p[0] is not None for p in parsed_entries)
        if has_all_dates:
            chronological_received = [p[1] for p in sorted(parsed_entries, key=lambda p: p[0])]
        else:
            chronological_received = list(reversed(raw_received))

        prev_timestamp: Optional[datetime.datetime] = None

        for idx, rec_val in enumerate(chronological_received, start=1):
            s = " ".join(str(rec_val).split())

            # Extract from host
            from_match = re.search(r'from\s+([^\s\(\)]+)', s, re.IGNORECASE)
            from_host = from_match.group(1) if from_match else "Unknown"

            # Extract by host
            by_match = re.search(r'by\s+([^\s\(\)]+)', s, re.IGNORECASE)
            by_host = by_match.group(1) if by_match else "Unknown"

            # Extract protocol / with
            with_match = re.search(r'with\s+([A-Za-z0-9\-_]+)', s, re.IGNORECASE)
            protocol = with_match.group(1) if with_match else "SMTP"

            # Extract IP
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', s)
            if not ip_match:
                ip_match = re.search(r'\b(?<![\.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\.\d])\b', s)

            hop_ip = ip_match.group(1) if ip_match else ""
            if hop_ip and not hop_ip.startswith(("127.", "0.")):
                all_sender_ips.append(hop_ip)

            # Resolve Geo / ASN
            geo_info = GeoResolver.resolve_ip(hop_ip) if hop_ip else {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "is_private": True}

            # Parse date/time if present after ';'
            hop_time_str = ""
            hop_dt: Optional[datetime.datetime] = None
            delay_sec: Optional[int] = None

            if ";" in s:
                raw_time_part = s.split(";")[-1].strip()
                try:
                    hop_dt = email.utils.parsedate_to_datetime(raw_time_part)
                    hop_time_str = hop_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if prev_timestamp and hop_dt:
                        diff = int((hop_dt - prev_timestamp).total_seconds())
                        delay_sec = max(0, diff)
                    prev_timestamp = hop_dt
                except Exception:
                    hop_time_str = raw_time_part

            hops.append({
                "hop_number": idx,
                "from_host": from_host,
                "by_host": by_host,
                "ip": hop_ip,
                "protocol": protocol,
                "timestamp": hop_time_str,
                "delay_seconds": delay_sec,
                "country": geo_info.get("country", "Unknown"),
                "city": geo_info.get("city", "Unknown"),
                "asn": geo_info.get("asn", "Unknown"),
                "is_private": geo_info.get("is_private", False),
                "raw_header": s[:300]
            })

        return hops, list(dict.fromkeys(all_sender_ips))

    # -------------------------------------------------------------------------
    # Authentication (SPF, DKIM, DMARC, ARC)
    # -------------------------------------------------------------------------
    def _inspect_authentication(self, headers: Dict[str, Any], findings: List[Finding]) -> Dict[str, Any]:
        auth_results = headers.get("authentication-results", "").lower()
        received_spf = headers.get("received-spf", "").lower()
        dkim_sig = headers.get("dkim-signature", "")
        arc_results = headers.get("arc-authentication-results", "").lower()

        # 1. SPF
        spf_status = "NONE"
        if "spf=pass" in auth_results or received_spf.startswith("pass"):
            spf_status = "PASS"
        elif "spf=fail" in auth_results or received_spf.startswith("fail"):
            spf_status = "FAIL"
        elif "spf=softfail" in auth_results or received_spf.startswith("softfail"):
            spf_status = "SOFTFAIL"
        elif "spf=neutral" in auth_results or received_spf.startswith("neutral"):
            spf_status = "NEUTRAL"
        elif "spf=permerror" in auth_results or "spf=temperror" in auth_results:
            spf_status = "ERROR"

        # 2. DKIM
        dkim_status = "NONE"
        dkim_domain = ""
        if "dkim=pass" in auth_results:
            dkim_status = "PASS"
        elif "dkim=fail" in auth_results:
            dkim_status = "FAIL"
        elif "dkim=neutral" in auth_results:
            dkim_status = "NEUTRAL"
        elif dkim_sig:
            dkim_status = "SIGNED (Unverified local)"

        d_match = re.search(r'd=([a-zA-Z0-9.\-]+)', dkim_sig)
        if d_match:
            dkim_domain = d_match.group(1)

        # 3. DMARC
        dmarc_status = "NONE"
        dmarc_policy = ""
        if "dmarc=pass" in auth_results:
            dmarc_status = "PASS"
        elif "dmarc=fail" in auth_results:
            dmarc_status = "FAIL"

        p_match = re.search(r'p=([a-zA-Z]+)', auth_results)
        if p_match:
            dmarc_policy = p_match.group(1)

        # 4. DMARC Identifier Alignment (RFC 7489)
        from_hdr = headers.get("from", "")
        _, from_addr = email.utils.parseaddr(from_hdr)
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

        return_path_hdr = headers.get("return-path", "")
        _, return_path_addr = email.utils.parseaddr(return_path_hdr)
        return_path_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""

        def _get_org_domain(d: str) -> str:
            parts = d.strip().split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return d

        from_org = _get_org_domain(from_domain) if from_domain else ""
        spf_org = _get_org_domain(return_path_domain) if return_path_domain else ""
        dkim_org = _get_org_domain(dkim_domain) if dkim_domain else ""

        spf_aligned = bool(from_org and spf_org and from_org == spf_org)
        dkim_aligned = bool(from_org and dkim_org and from_org == dkim_org)
        dmarc_aligned = bool(spf_aligned or dkim_aligned)

        # 5. Generate Security Findings for Auth and Alignment Failures
        if spf_status in ["FAIL", "SOFTFAIL"]:
            findings.append(Finding(
                category="structure",
                severity="high",
                title=f"Email SPF Authentication {spf_status} (Forged Sender)",
                description=(
                    f"The sending mail server failed SPF policy verification ({spf_status}). "
                    "The IP address was not authorized to send mail on behalf of the domain."
                ),
                details={"spf_header": headers.get("received-spf"), "auth_results": headers.get("authentication-results")}
            ))

        if dkim_status == "FAIL":
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Email DKIM Cryptographic Signature Verification Failed",
                description="The cryptographic DKIM signature failed verification, indicating either header/body tampering or spoofed sender."
            ))

        if dmarc_status == "FAIL":
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Email DMARC Policy Validation Failed",
                description="The message failed domain DMARC validation, signaling unauthorized origin under domain owner policy."
            ))

        # Identifier Alignment Findings
        if dkim_domain and from_domain and not dkim_aligned:
            findings.append(Finding(
                category="structure",
                severity="high",
                title=f"DKIM Identifier Alignment Failed: d='{dkim_domain}' differs from From: @{from_domain}",
                description=(
                    f"The email was signed by DKIM domain '{dkim_domain}', but the recipient sees "
                    f"header From: @{from_domain}. Under RFC 7489, third-party DKIM signatures fail identifier alignment "
                    "and cannot authenticate the sender domain."
                ),
                details={"dkim_domain": dkim_domain, "from_domain": from_domain}
            ))

        if return_path_domain and from_domain and not spf_aligned:
            findings.append(Finding(
                category="structure",
                severity="medium",
                title=f"SPF Identifier Alignment Failed: Return-Path @{return_path_domain} vs From @{from_domain}",
                description=(
                    f"The envelope sender Return-Path (@{return_path_domain}) does not share the organizational domain "
                    f"with the header From address (@{from_domain}). Under RFC 7489, SPF identifier alignment fails."
                ),
                details={"return_path_domain": return_path_domain, "from_domain": from_domain}
            ))

        if from_domain and (dkim_domain or return_path_domain) and not dmarc_aligned:
            findings.append(Finding(
                category="structure",
                severity="critical",
                title=f"DMARC Identifier Alignment Broken: Neither SPF nor DKIM aligns with From @{from_domain}",
                description=(
                    f"Critical DMARC identifier alignment failure: Both SPF envelope source (@{return_path_domain or 'none'}) "
                    f"and DKIM signing domain ({dkim_domain or 'none'}) fail organizational alignment with the sender header (@{from_domain}). "
                    "This is a primary technical indicator of spearphishing and domain impersonation."
                ),
                details={
                    "from_domain": from_domain,
                    "return_path_domain": return_path_domain,
                    "dkim_domain": dkim_domain,
                    "spf_aligned": spf_aligned,
                    "dkim_aligned": dkim_aligned
                }
            ))

        return {
            "spf": {
                "status": spf_status,
                "raw": headers.get("received-spf", "")
            },
            "dkim": {
                "status": dkim_status,
                "domain": dkim_domain,
                "has_signature": bool(dkim_sig)
            },
            "dmarc": {
                "status": dmarc_status,
                "policy": dmarc_policy
            },
            "alignment": {
                "from_domain": from_domain,
                "return_path_domain": return_path_domain,
                "dkim_domain": dkim_domain,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
                "dmarc_aligned": dmarc_aligned
            },
            "arc": {
                "present": bool(arc_results),
                "status": "PASS" if "arc=pass" in arc_results else ("FAIL" if "arc=fail" in arc_results else "NONE")
            },
            "overall_trust": "TRUSTED" if (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS" and dmarc_aligned) else (
                "UNTRUSTED / SPOOFED" if (spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL" or not dmarc_aligned) else "NEUTRAL / UNVERIFIED"
            )
        }

    # -------------------------------------------------------------------------
    # Attachments Processing, Hash Reputation, and Disk Storage
    # -------------------------------------------------------------------------
    def _process_attachments(
        self,
        msg,
        workspace_dir: Optional[Path],
        findings: List[Finding]
    ) -> List[Dict[str, Any]]:
        attachments_info: List[Dict[str, Any]] = []
        attachments_dir = workspace_dir / "attachments" if workspace_dir else None
        if attachments_dir:
            attachments_dir.mkdir(parents=True, exist_ok=True)

        for idx, part in enumerate(msg.iter_attachments()):
            att_name = part.get_filename() or f"attachment_{idx}.bin"
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            att_size = len(payload)
            att_md5 = hashlib.md5(payload).hexdigest() if payload else ""
            att_sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
            att_ext = Path(att_name).suffix.lower()

            is_dangerous = att_ext in DANGEROUS_ATTACHMENT_EXTENSIONS
            has_macro_ext = att_ext in OFFICE_MACRO_EXTENSIONS

            # Check for Unicode Right-to-Left Override (RTLO) Extension Spoofing
            if "\u202e" in att_name or "\u202d" in att_name or "\u202b" in att_name:
                is_dangerous = True
                findings.append(Finding(
                    category="social_engineering",
                    severity="critical",
                    title=f"Unicode Right-to-Left Override (RTLO) Attachment Spoofing: '{att_name}'",
                    description=(
                        f"Attachment '{att_name}' contains invisible Unicode Right-to-Left Override characters (U+202E). "
                        "This reverses the visual display order in email clients to disguise malicious executable files as benign document types."
                    ),
                    details={"filename": att_name, "mitre_technique": "T1036.002"}
                ))

            # Query hash reputation across CIRCL, ThreatFox, VirusTotal
            reputation = self._query_attachment_reputation(att_sha256)

            safe_filename = f"att_{idx}_{re.sub(r'[^a-zA-Z0-9._-]', '_', att_name)}"
            saved_path_str = ""
            if attachments_dir and payload:
                safe_att_path = attachments_dir / safe_filename
                safe_att_path.write_bytes(payload)
                saved_path_str = str(safe_att_path)

            # If archive, inspect inner members for droppers/scripts
            inner_members = []
            if att_ext in [".zip", ".tar", ".gz", ".7z"] and payload:
                try:
                    import zipfile, io
                    if att_ext == ".zip":
                        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                            for zinfo in zf.infolist():
                                zname = zinfo.filename
                                zext = Path(zname).suffix.lower()
                                is_inner_dangerous = zext in DANGEROUS_ATTACHMENT_EXTENSIONS or zext in [".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".exe"]
                                inner_members.append({
                                    "filename": zname,
                                    "size": zinfo.file_size,
                                    "date_time": list(zinfo.date_time),
                                    "is_dangerous": is_inner_dangerous
                                })
                                if is_inner_dangerous:
                                    is_dangerous = True
                                    findings.append(Finding(
                                        category="structure",
                                        severity="critical",
                                        title=f"Malicious Script Dropper inside Attached Archive: '{zname}'",
                                        description=(
                                            f"Archive attachment '{att_name}' contains weaponized dropper script '{zname}' "
                                            f"({zinfo.file_size} bytes). This is a primary malware distribution vector."
                                        ),
                                        details={"archive": att_name, "member": zname, "size": zinfo.file_size}
                                    ))
                except Exception as z_err:
                    logger.debug(f"Attachment archive inspection note: {z_err}")

            # QR Code & Quishing Scanning for Image Attachments
            att_qr_codes = []
            if payload and (content_type.startswith("image/") or att_ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"]):
                try:
                    from app.analyzers.qr_scanner import QRScanner
                    att_qr_codes = QRScanner.scan_image_bytes(payload, f"Email Attachment '{att_name}'")
                    if att_qr_codes:
                        findings.extend(QRScanner.generate_findings(att_qr_codes, f"Email Attachment '{att_name}'"))
                except Exception as qr_err:
                    logger.debug(f"Email attachment QR scan note: {qr_err}")

            att_record = {
                "index": idx,
                "filename": att_name,
                "saved_filename": safe_filename,
                "saved_path": saved_path_str,
                "content_type": content_type,
                "size_bytes": att_size,
                "md5": att_md5,
                "sha256": att_sha256,
                "is_dangerous": is_dangerous or any(q.get("is_quishing_suspect") for q in att_qr_codes),
                "has_macros": has_macro_ext,
                "inner_files": inner_members,
                "reputation": reputation,
                "qr_codes": att_qr_codes
            }

            attachments_info.append(att_record)

            if is_dangerous and not inner_members:
                findings.append(Finding(
                    category="structure",
                    severity="critical",
                    title=f"Dangerous Executable Attachment in Email: '{att_name}' ({att_ext})",
                    description=f"Email contains dangerous executable payload file '{att_name}' with extension '{att_ext}'.",
                    details=att_record
                ))
            elif has_macro_ext:
                findings.append(Finding(
                    category="macro",
                    severity="high",
                    title=f"Macro-Enabled Office Attachment in Email: '{att_name}' ({att_ext})",
                    description=f"Email contains macro-enabled document container '{att_name}' ({att_ext}).",
                    details=att_record
                ))

            # External API alerts for attachment hash
            tf_rep = reputation.get("threatfox", {})
            if tf_rep.get("status") == "MALICIOUS":
                findings.append(Finding(
                    category="reputation",
                    severity="critical",
                    title=f"ThreatFox Malware IOC Hit on Attachment '{att_name}'",
                    description=(
                        f"Attachment hash is cataloged as malware in ThreatFox database: "
                        f"{tf_rep.get('malware')} ({tf_rep.get('threat_type')})."
                    ),
                    details=tf_rep
                ))

            vt_rep = reputation.get("virustotal", {})
            if vt_rep.get("positives", 0) > 0:
                findings.append(Finding(
                    category="reputation",
                    severity="critical" if vt_rep.get("positives", 0) >= 3 else "high",
                    title=f"VirusTotal Detections on Attachment '{att_name}' ({vt_rep.get('positives')}/{vt_rep.get('total_engines')})",
                    description=f"Attachment hash was flagged by {vt_rep.get('positives')} security vendors on VirusTotal.",
                    details=vt_rep
                ))

            ha_rep = reputation.get("hybrid_analysis", {})
            if ha_rep.get("status") in ["MALICIOUS", "SUSPICIOUS"]:
                findings.append(Finding(
                    category="reputation",
                    severity="critical" if ha_rep.get("status") == "MALICIOUS" else "high",
                    title=f"Hybrid Analysis Sandbox Hit on Attachment '{att_name}' ({ha_rep.get('verdict')})",
                    description=(
                        f"Falcon Sandbox community intelligence flagged attachment hash as {ha_rep.get('verdict')} "
                        f"(Threat Score: {ha_rep.get('threat_score', 0)}/100). Family: {ha_rep.get('malware_family', 'Generic')}."
                    ),
                    details=ha_rep
                ))

        return attachments_info

    def _query_attachment_reputation(self, sha256: str) -> Dict[str, Any]:
        """Query CIRCL Hashlookup, ThreatFox, VirusTotal, and Hybrid Analysis for an attachment hash."""
        reputation: Dict[str, Any] = {
            "circl": {"status": "UNKNOWN"},
            "threatfox": {"status": "NOT_CONFIGURED"},
            "virustotal": {"positives": 0, "total_engines": 0, "status": "NOT_CONFIGURED"},
            "hybrid_analysis": {"status": "NOT_CONFIGURED"}
        }

        if not sha256:
            return reputation

        # CIRCL Hashlookup (Free public API)
        try:
            circl_res = CirclHashlookupClient.check_hash(sha256)
            reputation["circl"] = circl_res
        except Exception as e:
            logger.debug(f"CIRCL check error for attachment: {e}")

        # ThreatFox IOC
        try:
            tf_res = ThreatFoxClient.check_hash(sha256)
            reputation["threatfox"] = tf_res
        except Exception as e:
            logger.debug(f"ThreatFox check error for attachment: {e}")

        # Hybrid Analysis (Falcon Sandbox)
        try:
            if settings_store.is_global_enabled("hybrid_analysis_enabled") and settings_store.is_external_allowed("allow_threat_intel_lookups"):
                ha_res = HybridAnalysisClient.check_hash(sha256)
                reputation["hybrid_analysis"] = ha_res
        except Exception as e:
            logger.debug(f"Hybrid Analysis check error for attachment: {e}")

        # VirusTotal
        try:
            if VirusTotalClient.is_configured():
                vt_res = VirusTotalClient.lookup_file_hash(sha256)
                reputation["virustotal"] = vt_res
            else:
                reputation["virustotal"] = {
                    "configured": False,
                    "positives": 0,
                    "total_engines": 0,
                    "web_link": VirusTotalClient.get_file_web_link(sha256),
                    "status": "NOT_CONFIGURED"
                }
        except Exception as e:
            logger.debug(f"VirusTotal check error for attachment: {e}")

        return reputation

    # -------------------------------------------------------------------------
    # MSG Parsing (.msg Outlook format)
    # -------------------------------------------------------------------------
    def _parse_ole_msg(self, file_path: Path, raw_bytes: bytes) -> Optional[Any]:
        """Parse Microsoft Outlook Compound File (.msg) and convert to an EmailMessage object with full metadata."""
        import olefile
        import email.message

        if not olefile.isOleFile(str(file_path)):
            return None

        try:
            with olefile.OleFileIO(str(file_path)) as ole:
                # 1. Body Text & HTML extraction
                body_text = ""
                for b_stream in ['__substg1.0_1000001F', '__substg1.0_1000001E']:
                    if ole.exists(b_stream):
                        raw = ole.openstream(b_stream).read()
                        body_text = raw.decode('utf-16le' if b_stream.endswith('1F') else 'latin-1', errors='ignore').strip('\x00')
                        break

                html_text = ""
                for h_stream in ['__substg1.0_10130102', '__substg1.0_1013001F']:
                    if ole.exists(h_stream):
                        raw = ole.openstream(h_stream).read()
                        html_text = raw.decode('utf-8', errors='ignore').strip('\x00')
                        break

                # 2. Initialize clean EmailMessage and set content FIRST
                msg = email.message.EmailMessage()
                if body_text:
                    msg.set_content(body_text)
                    if html_text:
                        msg.add_alternative(html_text, subtype='html')
                elif html_text:
                    msg.set_content(html_text, subtype='html')
                else:
                    msg.set_content("(No message body in MSG)")

                # 3. Extract attachments from storage directories (__attach_version1.0_#)
                attached_count = 0
                storages = ole.listdir(storages=True, streams=False)
                for st in storages:
                    st_name = st[0] if st else ""
                    if st_name.startswith("__attach_version1.0_"):
                        att_fname = "attachment.bin"
                        att_mime = "application/octet-stream"
                        att_data = b""
                        for sub_stream in ole.listdir(streams=True, storages=False):
                            if sub_stream and sub_stream[0] == st_name:
                                s_path = "/".join(sub_stream)
                                if "3707001F" in s_path:
                                    att_fname = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                                elif "3704001F" in s_path and att_fname == "attachment.bin":
                                    att_fname = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                                elif "370E001F" in s_path:
                                    att_mime = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                                elif "37010102" in s_path:
                                    # Never rstrip null bytes from binary attachment streams
                                    att_data = ole.openstream(sub_stream).read()

                        if att_data:
                            maintype, _, subtype = att_mime.partition('/')
                            if not maintype or not subtype:
                                maintype, subtype = 'application', 'octet-stream'
                            if att_fname.lower().endswith('.zip'):
                                maintype, subtype = 'application', 'zip'
                            msg.add_attachment(att_data, maintype=maintype, subtype=subtype, filename=att_fname)
                            attached_count += 1

                # 4. Extract and copy Transport Headers from __substg1.0_007D001F / 007D001E
                text_h = ""
                for h_stream in ['__substg1.0_007D001F', '__substg1.0_007D001E']:
                    if ole.exists(h_stream):
                        raw_h = ole.openstream(h_stream).read()
                        try:
                            if h_stream.endswith('1F'):
                                text_h = raw_h.decode('utf-16le', errors='ignore')
                            else:
                                text_h = raw_h.decode('latin-1', errors='ignore')
                            parsed_headers = email.message_from_string(text_h, policy=policy.default)
                            for k, v in parsed_headers.items():
                                k_lower = k.lower()
                                if k_lower in ['content-type', 'mime-version', 'content-transfer-encoding']:
                                    continue
                                if k_lower in ['received', 'authentication-results', 'x-forefront-antispam-report', 'received-spf']:
                                    msg[k] = v
                                elif not msg.get(k):
                                    msg[k] = v
                        except Exception as parse_h_err:
                            logger.debug(f"OLE transport header parse note: {parse_h_err}")
                        break

                # 5. Extract core MAPI properties (Subject, From, To, CC, Date, etc.)
                # Subject
                for s_stream in ['__substg1.0_0037001F', '__substg1.0_0037001E']:
                    if ole.exists(s_stream):
                        raw = ole.openstream(s_stream).read()
                        clean_subj = raw.decode('utf-16le' if s_stream.endswith('1F') else 'latin-1', errors='ignore').strip('\x00 \t\r\n')
                        if clean_subj:
                            if 'Subject' in msg:
                                del msg['Subject']
                            msg['Subject'] = clean_subj
                        break

                # From / Sender name and address
                sender_name = ""
                sender_email = ""
                for n_stream in ['__substg1.0_0C1A001F', '__substg1.0_0042001F', '__substg1.0_4030001F']:
                    if ole.exists(n_stream):
                        sender_name = ole.openstream(n_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                        if sender_name:
                            break
                for e_stream in ['__substg1.0_0C1F001F', '__substg1.0_0065001F', '__substg1.0_4023001F', '__substg1.0_5D01001F']:
                    if ole.exists(e_stream):
                        sender_email = ole.openstream(e_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                        if sender_email and "@" in sender_email:
                            break

                if sender_email:
                    from_full = f"{sender_name} <{sender_email}>" if sender_name else sender_email
                    if 'From' in msg:
                        del msg['From']
                    msg['From'] = from_full

                # To / Recipients
                to_display = ""
                for t_stream in ['__substg1.0_0E04001F', '__substg1.0_0E04001E']:
                    if ole.exists(t_stream):
                        to_display = ole.openstream(t_stream).read().decode('utf-16le' if t_stream.endswith('1F') else 'latin-1', errors='ignore').strip('\x00 \t\r\n')
                        if to_display:
                            if 'To' in msg:
                                del msg['To']
                            msg['To'] = to_display
                        break

                # Message-ID
                if not msg.get('Message-ID'):
                    for m_stream in ['__substg1.0_1035001F', '__substg1.0_1035001E']:
                        if ole.exists(m_stream):
                            mid = ole.openstream(m_stream).read().decode('utf-16le' if m_stream.endswith('1F') else 'latin-1', errors='ignore').strip('\x00 \t\r\n')
                            if mid:
                                msg['Message-ID'] = mid
                            break

                # User-Agent / X-Mailer
                x_mailer = ""
                for u_stream in ['__substg1.0_800F001F', '__substg1.0_800F001E']:
                    if ole.exists(u_stream):
                        x_mailer = ole.openstream(u_stream).read().decode('utf-16le' if u_stream.endswith('1F') else 'latin-1', errors='ignore').strip('\x00 \t\r\n')
                        if x_mailer:
                            if not msg.get('X-Mailer'):
                                msg['X-Mailer'] = x_mailer
                            break

                # Extract structured recipient entries (__recip_version1.0_#)
                recipients_list = []
                for st in storages:
                    st_name = st[0] if st else ""
                    if st_name.startswith("__recip_version1.0_"):
                        r_name = ""
                        r_email = ""
                        r_type = "To"
                        r_addrtype = "SMTP"
                        for sub_stream in ole.listdir(streams=True, storages=False):
                            if sub_stream and sub_stream[0] == st_name:
                                s_path = "/".join(sub_stream)
                                if "3001001F" in s_path:
                                    r_name = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                                elif "3003001F" in s_path:
                                    r_email = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                                elif "3002001F" in s_path:
                                    r_addrtype = ole.openstream(sub_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                        if r_email or r_name:
                            recipients_list.append({
                                "name": r_name,
                                "email": r_email,
                                "type": r_type,
                                "addrtype": r_addrtype
                            })

                # Additional recipient indicators from properties
                for extra_r_stream in ['__substg1.0_8014001F', '__substg1.0_0040001F']:
                    if ole.exists(extra_r_stream):
                        extra_val = ole.openstream(extra_r_stream).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                        if extra_val and not any(r.get("email") == extra_val or r.get("name") == extra_val for r in recipients_list):
                            recipients_list.append({
                                "name": extra_val if "@" not in extra_val else "",
                                "email": extra_val if "@" in extra_val else "",
                                "type": "Recipient",
                                "addrtype": "SMTP"
                            })

                # Check for CVE-2023-23397 (PidLidReminderFileParameter UNC Path)
                cve_2023_23397_unc = None
                for st in ole.listdir(streams=True, storages=False):
                    s_name = "/".join(st)
                    if "851F001F" in s_name or "851F001E" in s_name or "851F" in s_name:
                        try:
                            val = ole.openstream(st).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                            if val.startswith("\\\\") or "smb://" in val.lower():
                                cve_2023_23397_unc = val
                                break
                        except Exception:
                            pass

                if not cve_2023_23397_unc:
                    unc_m = re.search(rb'(?i)\\\\([a-zA-Z0-9_\.\-]+(?:\\[a-zA-Z0-9_\.\-]+)+)', raw_bytes)
                    if unc_m and (b"851F" in raw_bytes or b"PidLidReminder" in raw_bytes or b"ReminderFile" in raw_bytes):
                        cve_2023_23397_unc = unc_m.group(0).decode('latin-1', errors='ignore')

                if cve_2023_23397_unc:
                    setattr(msg, "_cve_2023_23397_unc", cve_2023_23397_unc)

                # Check for CVE-2024-21378 (Outlook Custom Synced Forms RCE)
                for st in ole.listdir(streams=True, storages=False):
                    s_name = "/".join(st)
                    if "001A001F" in s_name:  # Message Class
                        try:
                            msg_class = ole.openstream(st).read().decode('utf-16le', errors='ignore').strip('\x00 \t\r\n')
                            if msg_class.startswith("IPM.Note.") and len(msg_class) > 9:
                                setattr(msg, "_cve_2024_21378_custom_form", msg_class)
                                break
                        except Exception:
                            pass

                return msg
        except Exception as e:
            logger.debug(f"Failed to parse OLE MSG: {e}", exc_info=True)
            return None

    def _escape_html(self, text: str) -> str:
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#039;')
