"""
Unified Forensic Entity Extractor.

Extracts the 7 core analytical entity types across any analyzed artifact:
1. emails: RFC 5322 regex, sender/recipients, metadata contact/author, strings
2. domains: FQDNs, DNS queries, SNIs, URLs, email domains, strings
3. keywords / watchlist words: Administrator warning rules, sensitive keywords, YARA/threat findings
4. ips: IPv4 addresses, network flows, DNS resolutions, hops, strings
5. hostnames: Workstations, computer names, NetBIOS, LNK machines, strings
6. usernames: Accounts, logon IDs, PDB debug paths, credential dumps, metadata
7. names: Person / Author / Creator / Artist / Signer display names from metadata & certs
"""

import ipaddress
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.core.settings_store import settings_store
from app.core.logging_config import logger


# Non-domain file extensions that look like domains in text/regex
INVALID_DOMAIN_SUFFIXES: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".bmp", ".ico", ".webp", ".tiff",
    ".exe", ".dll", ".so", ".dylib", ".sys", ".drv", ".ocx", ".bin", ".dat",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".iso", ".dmg",
    ".py", ".pyc", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".css", ".scss",
    ".json", ".xml", ".yaml", ".yml", ".txt", ".md", ".log", ".csv", ".tsv",
    ".class", ".jar", ".war", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".bash",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rs", ".php", ".asp", ".aspx"
}

# Software/vendor names commonly found in document Creator/Producer metadata
NON_PERSON_SOFTWARE_NAMES: Set[str] = {
    "microsoft office", "microsoft word", "microsoft excel", "microsoft powerpoint",
    "adobe acrobat", "adobe pdf library", "adobe indesign", "adobe illustrator",
    "adobe photoshop", "canva", "google docs", "google sheets", "google slides",
    "libreoffice", "openoffice", "writer", "calc", "impress", "quartz pdfcontext",
    "macos", "windows", "skia/pdf", "reportlab", "wkhtmltopdf", "wkhtmltoimage",
    "ghostscript", "pdfium", "poppler", "fpdf", "tcpdf", "mpdf", "dompdf",
    "pdfkit", "itext", "pdfsharp", "aspose", "imagemagick", "exiftool",
    "system", "unknown", "administrator", "root", "default", "null", "none"
}

# System accounts to ignore for usernames
IGNORED_SYSTEM_USERS: Set[str] = {
    "-", "system", "local service", "network service", "anonymous logon",
    "dwm-1", "umfd-0", "window manager\\dwm-1", "window manager/dwm-1",
    "default", "public", "all users", "none", "null", "unknown", "n/a"
}


class EntityExtractor:
    """
    Extracts and standardizes the 7 core analytical entity types from an analyzed job.
    """

    @classmethod
    def extract_all(cls, job: Any) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extracts emails, domains, keywords, ips, hostnames, usernames, and names
        from job metadata, findings, code/text corpus, strings, and specialized analyzers.
        """
        emails: Dict[str, Dict[str, Any]] = {}
        domains: Dict[str, Dict[str, Any]] = {}
        keywords: Dict[str, Dict[str, Any]] = {}
        ips: Dict[str, Dict[str, Any]] = {}
        hostnames: Dict[str, Dict[str, Any]] = {}
        usernames: Dict[str, Dict[str, Any]] = {}
        names: Dict[str, Dict[str, Any]] = {}

        # -------------------------------------------------------------
        # 1. Build Searchable Text Corpus & String Sources
        # -------------------------------------------------------------
        corpus_pieces: List[str] = []

        orig_name = getattr(job, "original_filename", None) or getattr(job, "filename", None)
        if isinstance(orig_name, str) and orig_name:
            corpus_pieces.append(orig_name)
        fname = getattr(job, "filename", "") or ""
        if isinstance(fname, str) and fname:
            corpus_pieces.append(fname)

        for attr in ("extracted_code", "extracted_text", "text_content"):
            val = getattr(job, attr, None)
            if isinstance(val, str) and val:
                corpus_pieces.append(val)
            elif isinstance(val, (bytes, bytearray)):
                corpus_pieces.append(val.decode("utf-8", errors="ignore"))
            elif isinstance(val, dict):
                corpus_pieces.extend(str(v) for v in val.values() if v)
            elif isinstance(val, list):
                corpus_pieces.extend(str(v) for v in val if v)

        # File on disk reading for small text / log / script files
        fpath = getattr(job, "file_path", None)
        if fpath and os.path.exists(fpath):
            try:
                sz = os.path.getsize(fpath)
                if sz < 1000000:
                    cat = str(getattr(job, "category", "") or "").lower()
                    if cat in ("text", "script", "log", "email") or fpath.endswith((".txt", ".log", ".csv", ".json", ".xml", ".ps1", ".sh", ".py")):
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            corpus_pieces.append(f.read())
            except Exception:
                pass

        # Workspace original file reading
        jid = getattr(job, "job_id", None)
        if jid:
            try:
                from app.core.job_manager import job_manager
                ws = job_manager.get_workspace(jid)
                if ws:
                    orig_p = ws.original_file_path(getattr(job, "filename", ""))
                    if orig_p and orig_p.exists() and orig_p.stat().st_size < 1000000:
                        corpus_pieces.append(orig_p.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass

        # Analysis data text/corpus
        analysis_data = getattr(job, "analysis_data", {}) or {}
        if isinstance(analysis_data, dict):
            for k in ("extracted_text", "ocr_text", "body_text", "text_corpus", "script_content", "text"):
                val = analysis_data.get(k)
                if isinstance(val, str) and val:
                    corpus_pieces.append(val)

        # Findings descriptions and titles
        findings = getattr(job, "findings", []) or []
        for f in findings:
            if hasattr(f, "title"):
                corpus_pieces.append(getattr(f, "title", "") or "")
                corpus_pieces.append(getattr(f, "description", "") or "")
            elif isinstance(f, dict):
                corpus_pieces.append(f.get("title", "") or "")
                corpus_pieces.append(f.get("description", "") or "")

        full_corpus = "\n".join(corpus_pieces)

        # -------------------------------------------------------------
        # 2. Extract from Document / File Metadata
        # -------------------------------------------------------------
        meta_sources = []
        meta = getattr(job, "metadata", None)
        if meta:
            if hasattr(meta, "model_dump"):
                meta_sources.append(meta.model_dump())
            elif hasattr(meta, "dict"):
                meta_sources.append(meta.dict())
            elif isinstance(meta, dict):
                meta_sources.append(meta)

        doc_meta = getattr(job, "document_metadata", None) or analysis_data.get("document_metadata") or analysis_data.get("metadata")
        if isinstance(doc_meta, dict):
            meta_sources.append(doc_meta)

        def _handle_meta_field(f_name: str, f_val: Any):
            if f_val is None:
                return
            if isinstance(f_val, (list, tuple, set)):
                for item in f_val:
                    _handle_meta_field(f_name, item)
                return
            if isinstance(f_val, dict):
                for k, v in f_val.items():
                    _handle_meta_field(f"{f_name}.{k}", v)
                return

            f_str = str(f_val).strip()
            if not f_str:
                return

            corpus_pieces.append(f_str)
            fn_lower = f_name.lower()

            # Author / Creator / Artist / Signer
            if any(k in fn_lower for k in (
                "author", "creator", "artist", "last_modified_by", "lastmodifiedby",
                "modifier", "camera_owner", "cameraowner", "by_line", "dc:creator",
                "cp:lastmodifiedby", "manager", "xpauthor", "producer", "signer"
            )):
                cls._process_author_field(f_str, f_name, names, usernames, emails)

            # Check if field contains email
            for em in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', f_str):
                cls._add_email(emails, em, f"Metadata: {f_name}")

            # Check if field contains IP
            for ip_str in re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', f_str):
                cls._add_ip(ips, ip_str, f"Metadata: {f_name}")

            # Check if field contains Computer/Host name
            if any(k in fn_lower for k in ("computer", "hostname", "workstation", "machine")):
                cls._add_hostname(hostnames, f_str, f"Metadata: {f_name}")

        for m_src in meta_sources:
            for cat_or_key, val in m_src.items():
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict) and "name" in item and "value" in item:
                            _handle_meta_field(item.get("name", ""), item.get("value"))
                        else:
                            _handle_meta_field(cat_or_key, item)
                else:
                    _handle_meta_field(cat_or_key, val)

        # -------------------------------------------------------------
        # 3. Extract from Email Info (job.email_info)
        # -------------------------------------------------------------
        email_info = getattr(job, "email_info", None) or analysis_data.get("email")
        if isinstance(email_info, dict):
            # From
            from_addr = email_info.get("from") or ""
            if from_addr:
                cls._process_email_address_header(from_addr, "Email Sender", emails, names)

            # To / CC / BCC
            for header_k, role_name in [("to", "Email Recipient"), ("cc", "Email CC"), ("bcc", "Email BCC")]:
                vals = email_info.get(header_k) or []
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    cls._process_email_address_header(v, role_name, emails, names)

            # Sender Analysis Display Name
            s_analysis = email_info.get("sender_analysis") or {}
            disp_name = s_analysis.get("display_name")
            if disp_name and isinstance(disp_name, str) and disp_name.strip():
                cls._add_name(names, disp_name.strip(), "Email Sender Display Name")

            # Transit Hops & IPs
            hops = email_info.get("transit_hops") or email_info.get("received_hops") or []
            for h in hops:
                if isinstance(h, dict) and h.get("ip"):
                    cls._add_ip(ips, h["ip"], "Email Transit Relay Hop")

            sender_ips = email_info.get("sender_ips") or []
            for sip in sender_ips:
                ip_v = sip.get("ip") if isinstance(sip, dict) else sip
                if isinstance(ip_v, str) and ip_v:
                    cls._add_ip(ips, ip_v, "Email Originating Sender IP")

        # -------------------------------------------------------------
        # 4. Extract from PCAP Info (job.pcap_info)
        # -------------------------------------------------------------
        pcap = getattr(job, "pcap_info", None) or analysis_data.get("pcap")
        if isinstance(pcap, dict):
            # Conversations
            for conv in (pcap.get("conversations") or []):
                if conv.get("src_ip"): cls._add_ip(ips, conv["src_ip"], "PCAP Traffic Source")
                if conv.get("dst_ip"): cls._add_ip(ips, conv["dst_ip"], "PCAP Traffic Destination")

            # Top Endpoints
            for ep in (pcap.get("top_endpoints") or []):
                if ep.get("ip"): cls._add_ip(ips, ep["ip"], "PCAP Network Endpoint")

            # DNS Queries & Resolutions
            for dns in (pcap.get("dns_queries") or []):
                q = dns.get("domain") or dns.get("query")
                if q: cls._add_domain(domains, q, "PCAP DNS Query")
                for rip in (dns.get("resolved_ips") or ([dns.get("resolved_ip")] if dns.get("resolved_ip") else [])):
                    if rip and rip not in ("-", "0.0.0.0", "N/A"):
                        cls._add_ip(ips, rip, f"PCAP DNS Resolution ({q})")

            # TLS SNIs
            for tls in (pcap.get("tls_sessions") or []):
                sni = tls.get("sni")
                if sni: cls._add_domain(domains, sni, "PCAP TLS SNI")

            # HTTP Requests / Hosts
            for req in (pcap.get("http_requests") or pcap.get("http_transactions") or []):
                h = req.get("host")
                if h: cls._add_domain(domains, h, "PCAP HTTP Host")

            # Credentials (Usernames)
            for cred in (pcap.get("credentials") or []):
                uname = cred.get("username")
                if uname: cls._add_username(usernames, uname, f"PCAP Discovered Credential ({cred.get('protocol', 'Auth')})")

        # -------------------------------------------------------------
        # 5. Extract from Windows Event Logs (EVTX)
        # -------------------------------------------------------------
        evtx = getattr(job, "evtx_info", None) or analysis_data.get("evtx")
        if isinstance(evtx, dict):
            for u in (evtx.get("unique_users") or []):
                cls._add_username(usernames, u, "EVTX Unique User")
            for comp in (evtx.get("unique_computers") or []):
                cls._add_hostname(hostnames, comp, "EVTX Forensic Hostname")
            for ip_v in (evtx.get("unique_ips") or []):
                cls._add_ip(ips, ip_v, "EVTX Network Telemetry IP")

            events = evtx.get("timeline_events") or evtx.get("timeline") or evtx.get("records") or []
            for ev in events[:5000]:
                u = ev.get("user") or ev.get("target_user_name") or ev.get("account_name")
                if u: cls._add_username(usernames, u, f"EVTX Event {ev.get('event_id', '')} User")

                comp = ev.get("computer") or ev.get("workstation")
                if comp: cls._add_hostname(hostnames, comp, f"EVTX Event {ev.get('event_id', '')} Host")

                ip_val = ev.get("ip_address") or ev.get("ip")
                if ip_val: cls._add_ip(ips, ip_val, f"EVTX Event {ev.get('event_id', '')} IP")

        # -------------------------------------------------------------
        # 6. Extract from Binary Info (job.binary_info)
        # -------------------------------------------------------------
        bin_info = getattr(job, "binary_info", None) or analysis_data.get("binary")
        if isinstance(bin_info, dict):
            # PE Debug PDB Path Usernames
            pdb_path = bin_info.get("debug_path") or ""
            user_match = re.search(r'[Uu]sers[\\/]([^\\/]+)[\\/]', pdb_path)
            if user_match:
                cls._add_username(usernames, user_match.group(1), "PE Debug PDB User Path")

            # Authenticode Signer Names
            sig_obj = bin_info.get("signature") or {}
            signer = sig_obj.get("signer") if isinstance(sig_obj, dict) else None
            if signer and str(signer).strip() and str(signer).lower() not in ("none", "unknown", "null"):
                cls._add_name(names, str(signer).strip(), "PE Authenticode Signer")

            auth_chain = bin_info.get("authenticode") or {}
            for cert in (auth_chain.get("certificates") or []):
                d_name = cert.get("display_name")
                if d_name and "Root CA" not in d_name and "Intermediate" not in d_name:
                    cls._add_name(names, d_name, "Certificate Signer")

        # -------------------------------------------------------------
        # 7. Extract from Archive Info (job.archive_info)
        # -------------------------------------------------------------
        arch = getattr(job, "archive_info", None) or analysis_data.get("archive")
        if isinstance(arch, dict):
            ext_iocs = arch.get("extracted_iocs") or {}
            for u in ext_iocs.get("users", []):
                cls._add_username(usernames, u, "Archive Dumped Credential / User")
            for dom in ext_iocs.get("domains", []):
                cls._add_domain(domains, dom, "Archive Internal Target Domain")
            for ip_v in ext_iocs.get("ips", []):
                cls._add_ip(ips, ip_v, "Archive Network Topology IP")

        # -------------------------------------------------------------
        # 8. Extract from Domain Info (job.domain_info)
        # -------------------------------------------------------------
        dom_info = getattr(job, "domain_info", None) or analysis_data.get("domain")
        if isinstance(dom_info, dict):
            target = dom_info.get("target") or ""
            is_ip = bool(dom_info.get("is_ip"))
            if target:
                if is_ip:
                    cls._add_ip(ips, target, "Domain Intelligence Target IP")
                else:
                    cls._add_domain(domains, target, "Domain Intelligence Target")

            for sub in (dom_info.get("attack_surface", {}).get("subdomains") or []):
                s_name = sub.get("subdomain") if isinstance(sub, dict) else str(sub)
                if s_name: cls._add_domain(domains, s_name, "Attack Surface Subdomain")

            for rel in (dom_info.get("related_domains") or []):
                r_dom = rel.get("domain") if isinstance(rel, dict) else str(rel)
                if r_dom: cls._add_domain(domains, r_dom, "Affiliated Domain Infrastructure")

            whois = dom_info.get("whois") or {}
            reg_name = whois.get("registrant_name") or whois.get("admin_name")
            if reg_name and not any(k in reg_name.lower() for k in ("privacy", "redacted", "withheld", "proxy")):
                cls._add_name(names, reg_name, "WHOIS Domain Registrant")

        # -------------------------------------------------------------
        # 8b. Extract from Android APK Info (job.apk_info)
        # -------------------------------------------------------------
        apk = getattr(job, "apk_info", None) or analysis_data.get("apk")
        if isinstance(apk, dict):
            iocs = apk.get("iocs") or {}
            for u in iocs.get("urls", []):
                try:
                    parsed = urlparse(u)
                    host = parsed.hostname or (parsed.netloc.split(":")[0].strip())
                    if host:
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                            cls._add_ip(ips, host, "APK Hardcoded Network Endpoint")
                        else:
                            cls._add_domain(domains, host, "APK Hardcoded Endpoint Domain")
                except Exception:
                    pass
            for ip_v in iocs.get("ips", []):
                cls._add_ip(ips, ip_v, "APK Embedded IP Indicator")

            # Signing Certificate Subject
            sig = apk.get("signing_info") or {}
            subj = sig.get("subject")
            if subj and isinstance(subj, str):
                cls._add_name(names, subj[:50], "APK Code Signing Signer")

        # -------------------------------------------------------------
        # 8c. Extract from Java Info (job.java_info)
        # -------------------------------------------------------------
        java_data = getattr(job, "java_info", None) or analysis_data.get("java")
        if isinstance(java_data, dict):
            j_iocs = java_data.get("iocs") or {}
            for u in j_iocs.get("urls", []):
                try:
                    parsed = urlparse(u)
                    host = parsed.hostname or (parsed.netloc.split(":")[0].strip())
                    if host:
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                            cls._add_ip(ips, host, "Java Network Target IP")
                        else:
                            cls._add_domain(domains, host, "Java Network Target Domain")
                except Exception:
                    pass
            for ip_v in j_iocs.get("ips", []):
                cls._add_ip(ips, ip_v, "Java Network Target IP")

        # -------------------------------------------------------------
        # 9. Extract from URLs (job.urls)
        # -------------------------------------------------------------
        urls = getattr(job, "urls", []) or []
        for u_item in urls:
            u_str = u_item.get("url") if isinstance(u_item, dict) else str(u_item)
            if not u_str:
                continue
            try:
                parsed = urlparse(u_str)
                host = parsed.hostname or (parsed.netloc.split(":")[0].strip())
                if host:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                        cls._add_ip(ips, host, "URL Target Host")
                    else:
                        cls._add_domain(domains, host, "URL Target Domain")
            except Exception:
                pass

        # -------------------------------------------------------------
        # 10. Universal Regex Pattern Matching Across Text Corpus
        # -------------------------------------------------------------
        # Emails
        for em in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', full_corpus):
            cls._add_email(emails, em, "Extracted Text / String Pattern")

        # IPs (IPv4)
        raw_ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', full_corpus)
        for ip_candidate in raw_ips:
            cls._add_ip(ips, ip_candidate, "Extracted Payload / String")

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|ai|se|de|uk|ru|cn|info|biz|co|me|top|xyz|online|site|club|cloud|dev|tech|app|internal|corp|local|lan)\b'
        for dom_candidate in re.findall(domain_pattern, full_corpus, re.IGNORECASE):
            cls._add_domain(domains, dom_candidate, "Extracted String Domain Pattern")

        # Hostnames (e.g. DESKTOP-ABC1234, WIN-SRV01, WS-FINANCE, WIN-FINANCE-01)
        hostname_pattern = r'\b(?:DESKTOP|LAPTOP|WIN|SRV|SERVER|DC|WS|PC|NODE|VM)(?:-[A-Za-z0-9_]+)+\b'
        for host_candidate in re.findall(hostname_pattern, full_corpus, re.IGNORECASE):
            cls._add_hostname(hostnames, host_candidate, "Host Naming Convention Pattern")

        # Hostnames (.local, .corp, .internal)
        local_host_pattern = r'\b([A-Za-z0-9_-]{2,25}\.(?:local|corp|internal|lan|intranet))\b'
        for lh_candidate in re.findall(local_host_pattern, full_corpus, re.IGNORECASE):
            cls._add_hostname(hostnames, lh_candidate, "Internal Workstation / Network Host")

        # Explicit host/workstation contextual mentions
        for host_mention in re.findall(r'\b(?:workstation|computer|host(?:name)?)\s*[:= ]\s*([A-Za-z0-9_-]{2,30})\b', full_corpus, re.IGNORECASE):
            cls._add_hostname(hostnames, host_mention, "Workstation / Machine Mention")

        # User directory paths (Windows & Linux/macOS)
        user_path_pattern = r'(?:[C-Zc-z]:[\\/]Users[\\/]|/(?:home|Users)/)([^\\/ \r\n"\'<>]+)'
        for u_match in re.findall(user_path_pattern, full_corpus):
            cls._add_username(usernames, u_match, "Filesystem User Profile Path")

        # Explicit user / account mentions in logs / text / scripts
        for u_mention in re.findall(r'\b(?:user(?:name)?|account|logon user|logged on user|login|identity)\s*[:= ]\s*([A-Za-z0-9._-]{3,30})\b', full_corpus, re.IGNORECASE):
            cls._add_username(usernames, u_mention, "User Account Mention")

        # -------------------------------------------------------------
        # 11. Keywords & Watchlist Words Extraction
        # -------------------------------------------------------------
        # A. Findings with category == "warninglist" or watchlist titles
        for f in findings:
            cat = str(getattr(f, "category", "") if hasattr(f, "category") else (f.get("category") if isinstance(f, dict) else "")).lower()
            title = str(getattr(f, "title", "") if hasattr(f, "title") else (f.get("title") if isinstance(f, dict) else ""))
            details = getattr(f, "details", {}) if hasattr(f, "details") else (f.get("details") if isinstance(f, dict) else {})
            severity = str(getattr(f, "severity", "") if hasattr(f, "severity") else (f.get("severity") if isinstance(f, dict) else "high")).lower()

            if cat in ("warninglist", "watchlist") or "warninglist" in title.lower():
                r_name = details.get("rule_name") or details.get("pattern") or title.replace("Warninglist Rule Triggered: ", "").strip()
                det_val = details.get("detected_value") or r_name
                cls._add_keyword(keywords, det_val, r_name, severity, "Watchlist Rule Match")
            elif cat in ("sensitive_data", "credential", "keyword"):
                k_val = details.get("matched_keyword") or details.get("keyword") or title
                cls._add_keyword(keywords, k_val, title, severity, "Sensitive Keyword Finding")

        # B. Directly scan text corpus against active warninglist rules in settings_store
        try:
            warning_rules = settings_store.get_warning_rules() or []
            for r in warning_rules:
                if not r.get("enabled", True):
                    continue
                pat = (r.get("pattern") or "").strip()
                if not pat:
                    continue
                is_regex = bool(r.get("is_regex", False))
                r_name = r.get("name") or pat
                sev = str(r.get("severity", "medium")).lower()

                matched = False
                matched_val = pat
                if is_regex:
                    try:
                        m = re.search(pat, full_corpus, re.IGNORECASE)
                        if m:
                            matched = True
                            matched_val = m.group(0)
                    except Exception:
                        pass
                else:
                    if pat.lower() in full_corpus.lower():
                        matched = True
                        matched_val = pat

                if matched:
                    cls._add_keyword(keywords, matched_val, r_name, sev, "Configured Watchlist Rule")
        except Exception as e:
            logger.debug(f"EntityExtractor error scanning warning rules: {e}")

        # Common sensitive security watchlist words if present in corpus
        sensitive_patterns = [
            ("api_key", "API Key Marker", "high"),
            ("private key", "Private Key Header", "critical"),
            ("BEGIN RSA PRIVATE KEY", "RSA Private Key", "critical"),
            ("BEGIN OPENSSH PRIVATE KEY", "SSH Private Key", "critical"),
            ("password", "Plaintext Password Marker", "medium"),
            ("confidential", "Confidentiality Marker", "low"),
            ("secret_key", "Secret Key Credential", "high"),
            ("bearer token", "Bearer Auth Token", "high"),
        ]
        for term, label_t, sev_t in sensitive_patterns:
            if re.search(r'\b' + re.escape(term) + r'\b', full_corpus, re.IGNORECASE):
                cls._add_keyword(keywords, term, label_t, sev_t, "Sensitive Security Keyword")

        return {
            "emails": list(emails.values()),
            "domains": list(domains.values()),
            "keywords": list(keywords.values()),
            "ips": list(ips.values()),
            "hostnames": list(hostnames.values()),
            "usernames": list(usernames.values()),
            "names": list(names.values()),
        }

    # =========================================================================
    # Helpers & Validation
    # =========================================================================

    @classmethod
    def _add_email(cls, m: Dict[str, Dict[str, Any]], email: str, source: str, risk: str = "clean") -> None:
        clean = email.strip().lower()
        if not clean or len(clean) > 80 or len(clean) < 6:
            return
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', clean):
            return
        # Exclude common false positives
        if any(clean.endswith(ext) for ext in (".png", ".jpg", ".gif", ".exe", ".dll", ".zip")):
            return

        if clean not in m:
            m[clean] = {
                "value": clean,
                "label": clean,
                "type": "email",
                "risk": risk,
                "sources": set(),
            }
        m[clean]["sources"].add(source)

    @classmethod
    def _add_domain(cls, m: Dict[str, Dict[str, Any]], domain: str, source: str, risk: str = "clean") -> None:
        clean = domain.strip().lower().rstrip(".)/:\",'")
        if not clean or len(clean) > 90 or len(clean) < 4 or "." not in clean:
            return
        # Skip IP addresses in domain extractor
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', clean):
            return
        # Skip file extensions
        for ext in INVALID_DOMAIN_SUFFIXES:
            if clean.endswith(ext):
                return
        # Strip leading subdomains / protocol artifacts
        clean = clean.lstrip("*.")

        if clean not in m:
            m[clean] = {
                "value": clean,
                "label": clean,
                "type": "domain",
                "risk": risk,
                "sources": set(),
            }
        m[clean]["sources"].add(source)

    @classmethod
    def _add_keyword(cls, m: Dict[str, Dict[str, Any]], value: str, rule_name: str, severity: str, source: str) -> None:
        val_clean = value.strip()
        if not val_clean or len(val_clean) > 80:
            return
        key = f"{rule_name.lower()}::{val_clean.lower()}"
        if key not in m:
            risk = "critical" if severity in ("critical", "high") else ("warning" if severity == "medium" else "clean")
            m[key] = {
                "value": val_clean,
                "rule_name": rule_name,
                "label": f"Watchlist: {val_clean[:24]}",
                "full_label": f"Watchlist Rule: {rule_name} ('{val_clean}')",
                "type": "keyword",
                "severity": severity,
                "risk": risk,
                "sources": set(),
            }
        m[key]["sources"].add(source)

    @classmethod
    def _add_ip(cls, m: Dict[str, Dict[str, Any]], ip: str, source: str, risk: str = "clean") -> None:
        clean = ip.strip()
        if not clean or len(clean) > 45:
            return
        try:
            ip_obj = ipaddress.ip_address(clean)
            if ip_obj.is_unspecified or ip_obj.is_loopback:
                # Still allow loopback or skip
                return
            is_private = ip_obj.is_private
        except ValueError:
            return

        if clean not in m:
            m[clean] = {
                "value": clean,
                "label": clean,
                "type": "ip",
                "is_private": is_private,
                "risk": "info" if is_private else risk,
                "sources": set(),
            }
        m[clean]["sources"].add(source)

    @classmethod
    def _add_hostname(cls, m: Dict[str, Dict[str, Any]], hostname: str, source: str, risk: str = "clean") -> None:
        clean = hostname.strip()
        if not clean or len(clean) > 60 or clean.lower() in ("-", "none", "null", "localhost", "workgroup"):
            return
        key = clean.upper()
        if key not in m:
            m[key] = {
                "value": clean,
                "label": f"Host: {clean}",
                "type": "hostname",
                "risk": risk,
                "sources": set(),
            }
        m[key]["sources"].add(source)

    @classmethod
    def _add_username(cls, m: Dict[str, Dict[str, Any]], username: str, source: str) -> None:
        clean = username.strip()
        if not clean or len(clean) > 50 or clean.lower() in IGNORED_SYSTEM_USERS:
            return
        # If it looks like a person's full name with space, don't treat purely as username if it has a personal name format
        key = clean.lower()
        is_privileged = key in ("administrator", "root", "svc_admin", "domain admins", "admin")
        risk = "critical" if is_privileged else "clean"

        if key not in m:
            m[key] = {
                "value": clean,
                "label": f"User: {clean}",
                "type": "user",
                "risk": risk,
                "sources": set(),
            }
        m[key]["sources"].add(source)

    @classmethod
    def _add_name(cls, m: Dict[str, Dict[str, Any]], name: str, source: str, role: str = "Author / Contact") -> None:
        clean = name.strip()
        if not clean or len(clean) > 60 or len(clean) < 2:
            return
        if clean.lower() in NON_PERSON_SOFTWARE_NAMES:
            return
        # If it contains digits only, or is an IP/URL/hash, skip
        if re.match(r'^\d+$', clean) or re.match(r'^[a-fA-F0-9]{32,64}$', clean) or clean.startswith("http"):
            return

        key = clean.lower()
        if key not in m:
            m[key] = {
                "value": clean,
                "label": f"Name: {clean}",
                "type": "name",
                "role": role,
                "risk": "clean",
                "sources": set(),
            }
        m[key]["sources"].add(source)

    @classmethod
    def _process_author_field(
        cls,
        raw_val: str,
        field_name: str,
        names: Dict[str, Dict[str, Any]],
        usernames: Dict[str, Dict[str, Any]],
        emails: Dict[str, Dict[str, Any]]
    ) -> None:
        val = raw_val.strip()
        # Case 1: Name <email@domain.com>
        m_angle = re.match(r'^([^<]+)<([^>]+)>', val)
        if m_angle:
            disp = m_angle.group(1).strip()
            em = m_angle.group(2).strip()
            if disp:
                cls._add_name(names, disp, f"Metadata: {field_name}")
            if em:
                cls._add_email(emails, em, f"Metadata: {field_name}")
            return

        # Case 2: Pure email
        if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', val):
            cls._add_email(emails, val, f"Metadata: {field_name}")
            return

        # Case 3: Multiple authors separated by comma or semicolon
        if "," in val or ";" in val:
            for part in re.split(r'[,;]', val):
                p_clean = part.strip()
                if p_clean:
                    cls._process_author_field(p_clean, field_name, names, usernames, emails)
            return

        # Case 4: Software / application name
        if val.lower() in NON_PERSON_SOFTWARE_NAMES:
            return

        # Case 5: Looks like personal name (e.g. 1-4 words)
        words = val.split()
        if 1 <= len(words) <= 4:
            cls._add_name(names, val, f"Metadata: {field_name}")
            # If single word, could also be a system username
            if len(words) == 1 and len(val) >= 3:
                cls._add_username(usernames, val, f"Metadata: {field_name}")

    @classmethod
    def _process_email_address_header(
        cls,
        header_val: Any,
        role: str,
        emails: Dict[str, Dict[str, Any]],
        names: Dict[str, Dict[str, Any]]
    ) -> None:
        if not header_val:
            return
        val_str = str(header_val).strip()

        # Parse angle brackets "Display Name <user@domain.com>"
        for match in re.finditer(r'(?:([^<>\r\n]+)\s*)?<([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>', val_str):
            disp = (match.group(1) or "").strip().strip('"\'')
            em = match.group(2).strip().lower()
            if em:
                cls._add_email(emails, em, role)
            if disp and disp.lower() != em.lower():
                cls._add_name(names, disp, f"{role} Display Name")

        # Also fallback regex findall for plain emails without angle brackets
        for em in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', val_str):
            cls._add_email(emails, em, role)
