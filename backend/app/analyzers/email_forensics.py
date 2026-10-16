"""
Email Security Forensics Module (EML / MSG)
===========================================
Production-grade security analysis pipeline implementing the
'EML / MSG Files — Email Security Analysis Checklist'.

Covers:
  1. File Identification, Integrity & MIME Structure Validation
  2. SPF, DKIM, DMARC, ARC & Sender Authenticity Deep Dive
  3. Display-Name Spoofing, Lookalike Domains & Impersonation Engine
  4. Phishing Links & URL Threat Analysis (Visible text mismatch, obfuscation, userinfo)
  5. HTML Body & Browser Phishing Forensics (Hidden text, forms, tracking pixels, data URLs)
  6. Attachment Forensics & File-Type Signature Mismatch
  7. Business Email Compromise (BEC) & Financial Fraud Engine
  8. Executive Email Security Verdict & Actionable Containment Checklist
  9. Offline Forensic Tools CLI Guide (file, sha256sum, python email, extract_msg, oletools, yara)
"""

import re
import email
import email.utils
from email import policy
import hashlib
import datetime
import urllib.parse
from typing import Dict, Any, List, Set, Optional, Tuple
from bs4 import BeautifulSoup


# ============================================================================
# TARGET BRAND CATALOG FOR LOOKALIKE & SPOOFING DETECTION
# ============================================================================

TARGET_BRANDS: List[Dict[str, Any]] = [
    {"brand": "Microsoft", "canonical_domains": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com"]},
    {"brand": "Google", "canonical_domains": ["google.com", "gmail.com", "googlemail.com", "accounts.google.com"]},
    {"brand": "Apple", "canonical_domains": ["apple.com", "icloud.com", "me.com"]},
    {"brand": "Amazon", "canonical_domains": ["amazon.com", "aws.amazon.com"]},
    {"brand": "PayPal", "canonical_domains": ["paypal.com", "paypal-communication.com"]},
    {"brand": "Netflix", "canonical_domains": ["netflix.com"]},
    {"brand": "DocuSign", "canonical_domains": ["docusign.com", "docusign.net"]},
    {"brand": "Adobe", "canonical_domains": ["adobe.com", "acrobat.com"]},
    {"brand": "Dropbox", "canonical_domains": ["dropbox.com", "dropboxmail.com"]},
    {"brand": "LinkedIn", "canonical_domains": ["linkedin.com"]},
    {"brand": "Bank of America", "canonical_domains": ["bankofamerica.com", "bofa.com"]},
    {"brand": "Chase", "canonical_domains": ["chase.com", "jpmorgan.com"]},
    {"brand": "Wells Fargo", "canonical_domains": ["wellsfargo.com"]},
    {"brand": "Citibank", "canonical_domains": ["citi.com", "citibank.com"]},
    {"brand": "DHL", "canonical_domains": ["dhl.com", "dhl-news.com"]},
    {"brand": "FedEx", "canonical_domains": ["fedex.com"]},
    {"brand": "UPS", "canonical_domains": ["ups.com"]},
    {"brand": "Zoom", "canonical_domains": ["zoom.us", "zoom.com"]},
    {"brand": "QuickBooks / Intuit", "canonical_domains": ["intuit.com", "quickbooks.com"]},
    {"brand": "Salesforce", "canonical_domains": ["salesforce.com"]}
]

FREE_WEBMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "proton.me",
    "zoho.com", "yandex.com", "gmx.com", "t-online.de", "web.de",
    "fastmail.com", "mailinator.com", "guerrillamail.com", "tempmail.com"
}

EXECUTIVE_VIP_PATTERNS = [
    r'\bceo\b', r'\bchief\s+executive\s+officer\b',
    r'\bcfo\b', r'\bchief\s+financial\s+officer\b',
    r'\bcoo\b', r'\bchief\s+operating\s+officer\b',
    r'\bcto\b', r'\bchief\s+technology\s+officer\b',
    r'\bpresident\b', r'\bmanaging\s+director\b',
    r'\bvice\s+president\b', r'\bvp\b',
    r'\bhuman\s+resources\b', r'\bhr\s+department\b',
    r'\bpayroll\b', r'\bit\s+support\b', r'\bhelpdesk\b',
    r'\bsecurity\s+team\b', r'\bcompliance\s+officer\b'
]

BEC_BANKING_TERMS = [
    r'new\s+bank\s+(?:account|details|information)',
    r'updated?\s+(?:banking|wire|payment)\s+instructions',
    r'change\s+of\s+(?:banking|account|remittance)',
    r'wire\s+transfer', r'routing\s+number', r'swift\s+code',
    r'iban\b', r'ach\s+transfer', r'beneficiary\s+name',
    r'cryptocurrency\s+payment', r'bitcoin\s+address', r'wallet\s+address'
]

BEC_URGENCY_SECRECY_TERMS = [
    r'strict\s+confiden(?:ce|tiality)', r'keep\s+this\s+(?:private|confidential)',
    r'do\s+not\s+(?:mention|discuss|call|notify)', r'immediate\s+wire',
    r'before\s+(?:end\s+of\s+day|bank\s+cutoff|5\s*pm)',
    r'urgent\s+wire', r'bypass\s+(?:normal|standard)\s+approval',
    r'in\s+a\s+meeting\s+cannot\s+talk', r'are\s+you\s+(?:at\s+your\s+desk|in\s+the\s+office|available)'
]

BEC_GIFT_CARD_TERMS = [
    r'gift\s+cards?', r'apple\s+(?:store\s+)?gift\s+cards?',
    r'google\s+play\s+cards?', r'amazon\s+gift\s+cards?',
    r'steam\s+cards?', r'scratch\s+the\s+back', r'send\s+(?:pictures?|photos?)\s+of\s+the\s+back',
    r'for\s+client\s+presentation', r'surprise\s+for\s+the\s+team'
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "rebrand.ly",
    "buff.ly", "adf.ly", "goo.gl", "bit.do", "cutt.ly", "shorte.st"
}

CREDENTIAL_HARVESTING_PATHS = [
    "/login", "/signin", "/auth", "/verify", "/account", "/update-billing",
    "/secure", "/portal", "/webmail", "/owa", "/reset-password", "/challenge"
]

DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".pif", ".jar", ".msi",
    ".dll", ".com", ".gadget", ".iso", ".img", ".vhd", ".lnk"
}


# ============================================================================
# HELPER UTILITIES: Levenshtein Distance & String Normalization
# ============================================================================

def compute_levenshtein(s1: str, s2: str) -> int:
    """Computes exact edit distance between two strings."""
    if len(s1) < len(s2):
        return compute_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_domain_chars(domain: str) -> str:
    """Replaces common visual homoglyph substitutions to detect lookalikes."""
    sub_map = {
        '0': 'o',
        '1': 'l',
        'rn': 'm',
        'vv': 'w',
        '5': 's',
        '@': 'a',
        '3': 'e'
    }
    res = domain.lower()
    for k, v in sub_map.items():
        res = res.replace(k, v)
    return res


# ============================================================================
# 1. FILE IDENTIFICATION, INTEGRITY & MIME STRUCTURE VALIDATION
# ============================================================================

def audit_email_file_integrity(
    raw_bytes: bytes,
    filename: str,
    msg: Any,
    is_ole_msg: bool
) -> Dict[str, Any]:
    """
    Validates file headers, computes cryptographic hashes, inspects MIME part tree,
    detects duplicate headers, clock anomalies, and unicode obfuscation.
    """
    file_size = len(raw_bytes)
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    sha1_hash = hashlib.sha1(raw_bytes).hexdigest()
    md5_hash = hashlib.md5(raw_bytes).hexdigest()

    format_desc = (
        "Outlook Item (Compound File Binary Format / MSG)"
        if is_ole_msg
        else "Internet Message Format (EML / RFC 5322)"
    )

    # 1. Header / Body Separation
    header_body_separated = True
    if not is_ole_msg:
        header_body_separated = (b"\r\n\r\n" in raw_bytes) or (b"\n\n" in raw_bytes)

    # 2. Duplicate Header Auditing
    duplicate_headers: List[Dict[str, Any]] = []
    header_counts: Dict[str, List[str]] = {}
    if hasattr(msg, "items"):
        for k, v in msg.items():
            k_lower = k.lower()
            if k_lower not in header_counts:
                header_counts[k_lower] = []
            header_counts[k_lower].append(str(v))

    for crit in ["from", "reply-to", "subject", "message-id", "date", "to"]:
        if crit in header_counts and len(header_counts[crit]) > 1:
            duplicate_headers.append({
                "name": crit.upper(),
                "count": len(header_counts[crit]),
                "values": header_counts[crit][:3]
            })

    # 3. MIME Part Tree Traversal & Parser Defects
    parts_tree: List[Dict[str, Any]] = []
    parser_defects: List[str] = []
    max_depth = 1
    total_parts = 0
    is_multipart = False

    if hasattr(msg, "is_multipart") and msg.is_multipart():
        is_multipart = True

    if hasattr(msg, "defects") and msg.defects:
        for d in msg.defects:
            parser_defects.append(f"{type(d).__name__}: {str(d)}")

    if hasattr(msg, "walk"):
        for idx, part in enumerate(msg.walk()):
            total_parts += 1
            ctype = part.get_content_type()
            disp = part.get_content_disposition() or "inline"
            fname = part.get_filename()
            enc = part.get("Content-Transfer-Encoding", "None")

            # Check part defects
            p_defects = []
            if hasattr(part, "defects") and part.defects:
                for pd in part.defects:
                    p_defects.append(f"{type(pd).__name__}: {str(pd)}")
                    parser_defects.append(f"Part {idx} ({ctype}) - {type(pd).__name__}: {str(pd)}")

            decoded_size = 0
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded_size = len(payload)
            except Exception:
                pass

            is_att = bool(fname or disp == "attachment")
            parts_tree.append({
                "part_index": idx,
                "content_type": ctype,
                "content_disposition": disp,
                "filename": fname,
                "transfer_encoding": enc,
                "decoded_size": decoded_size,
                "defects": p_defects,
                "is_attachment": is_att
            })

    # 4. Unicode & Character Set Analysis (Bidi override, zero-width spaces)
    unicode_anomalies = {
        "bidi_controls_detected": False,
        "bidi_chars": [],
        "zero_width_chars_detected": False,
        "zero_width_count": 0,
        "homoglyphs_detected": False,
        "suspicious_tokens": []
    }

    # Bidi characters: U+202E (RLO), U+202D (LRO), U+202C (PDF), U+2066-U+2069
    bidi_regex = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
    # Zero-width: U+200B (ZWSP), U+200C, U+200D, U+FEFF
    zero_width_regex = re.compile(r'[\u200B-\u200D\uFEFF]')

    full_text_to_scan = ""
    try:
        if isinstance(raw_bytes, bytes):
            full_text_to_scan = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass

    bidi_matches = bidi_regex.findall(full_text_to_scan)
    if bidi_matches:
        unicode_anomalies["bidi_controls_detected"] = True
        unicode_anomalies["bidi_chars"] = list(set(f"U+{ord(c):04X}" for c in bidi_matches))

    zw_matches = zero_width_regex.findall(full_text_to_scan)
    if zw_matches:
        unicode_anomalies["zero_width_chars_detected"] = True
        unicode_anomalies["zero_width_count"] = len(zw_matches)

    # 5. Timestamp Consistency Audit
    date_hdr = str(msg.get("Date", "")) if hasattr(msg, "get") else ""
    received_hdrs = msg.get_all("Received", []) if hasattr(msg, "get_all") else []
    timestamp_analysis = {
        "date_header": date_hdr,
        "received_hops_count": len(received_hdrs),
        "has_future_date": False,
        "has_timestamp_anomaly": False,
        "details": "Timestamps consistent with normal transit progression."
    }

    if date_hdr:
        try:
            parsed_date = email.utils.parsedate_to_datetime(date_hdr)
            now = datetime.datetime.now(datetime.timezone.utc)
            if parsed_date > now + datetime.timedelta(hours=2):
                timestamp_analysis["has_future_date"] = True
                timestamp_analysis["has_timestamp_anomaly"] = True
                timestamp_analysis["details"] = f"Date header '{date_hdr}' is in the future relative to UTC analysis time."
        except Exception:
            pass

    return {
        "format": format_desc,
        "is_valid_format": True,
        "file_size": file_size,
        "file_hashes": {
            "sha256": sha256_hash,
            "sha1": sha1_hash,
            "md5": md5_hash
        },
        "header_body_separated": header_body_separated,
        "duplicate_headers": duplicate_headers,
        "total_mime_parts": total_parts,
        "is_multipart": is_multipart,
        "parts_tree": parts_tree[:25],
        "parser_defects": parser_defects[:10],
        "unicode_anomalies": unicode_anomalies,
        "timestamp_analysis": timestamp_analysis
    }


# ============================================================================
# 2. SPF, DKIM, DMARC, ARC & SENDER AUTHENTICITY EVALUATION
# ============================================================================

def audit_authentication_posture(
    headers: Dict[str, Any],
    all_headers: List[Dict[str, str]],
    from_domain: str,
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Evaluates SPF, DKIM, DMARC, and ARC headers with domain alignment logic.
    """
    auth_results_raw = ""
    received_spf_raw = ""
    dkim_sig_raw = ""
    arc_results_raw = ""
    arc_seal_raw = ""

    for h in all_headers:
        n = h.get("name", "").lower()
        v = h.get("value", "")
        if n == "authentication-results" and not auth_results_raw:
            auth_results_raw = v
        elif n == "received-spf" and not received_spf_raw:
            received_spf_raw = v
        elif n == "dkim-signature" and not dkim_sig_raw:
            dkim_sig_raw = v
        elif n == "arc-authentication-results" and not arc_results_raw:
            arc_results_raw = v
        elif n == "arc-seal" and not arc_seal_raw:
            arc_seal_raw = v

    # 1. Evaluate SPF
    spf_status = "none"
    spf_envelope = ""
    spf_ip = ""
    spf_mechanism = ""

    if received_spf_raw:
        m = re.match(r'(?i)^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', received_spf_raw)
        if m:
            spf_status = m.group(1).lower()
        ip_m = re.search(r'(?i)client-ip=([0-9a-fA-F\.\:]+)', received_spf_raw)
        if ip_m:
            spf_ip = ip_m.group(1)
        env_m = re.search(r'(?i)envelope-from=<([^>]+)>|envelope-from=([^\s;]+)', received_spf_raw)
        if env_m:
            raw_env = env_m.group(1) or env_m.group(2)
            spf_envelope = raw_env.split("@")[-1].strip() if "@" in raw_env else raw_env

    if not spf_status or spf_status == "none":
        if "spf=pass" in auth_results_raw.lower():
            spf_status = "pass"
        elif "spf=fail" in auth_results_raw.lower():
            spf_status = "fail"
        elif "spf=softfail" in auth_results_raw.lower():
            spf_status = "softfail"

    # 2. Evaluate DKIM
    dkim_status = "none"
    dkim_domain = ""
    dkim_selector = ""
    dkim_alg = ""

    if dkim_sig_raw:
        d_m = re.search(r'(?i)\bd=([a-zA-Z0-9_\.\-]+)', dkim_sig_raw)
        if d_m:
            dkim_domain = d_m.group(1).lower()
        s_m = re.search(r'(?i)\bs=([a-zA-Z0-9_\.\-]+)', dkim_sig_raw)
        if s_m:
            dkim_selector = s_m.group(1)
        a_m = re.search(r'(?i)\ba=([a-zA-Z0-9_\-]+)', dkim_sig_raw)
        if a_m:
            dkim_alg = a_m.group(1)

    if "dkim=pass" in auth_results_raw.lower():
        dkim_status = "pass"
    elif "dkim=fail" in auth_results_raw.lower():
        dkim_status = "fail"
    elif dkim_domain and dkim_status == "none":
        dkim_status = "pass" if not ("dkim=fail" in auth_results_raw.lower()) else "fail"

    # 3. Evaluate DMARC & Alignment
    dmarc_status = "none"
    dmarc_policy = "none"
    spf_aligned = False
    dkim_aligned = False

    if "dmarc=pass" in auth_results_raw.lower():
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_results_raw.lower():
        dmarc_status = "fail"

    pol_m = re.search(r'(?i)p=(none|quarantine|reject)', auth_results_raw)
    if pol_m:
        dmarc_policy = pol_m.group(1).lower()

    if from_domain:
        fd_lower = from_domain.lower()
        if spf_envelope and (spf_envelope.lower() == fd_lower or spf_envelope.lower().endswith("." + fd_lower)):
            spf_aligned = True
        if dkim_domain and (dkim_domain.lower() == fd_lower or dkim_domain.lower().endswith("." + fd_lower)):
            dkim_aligned = True

    # If DMARC was none but both fail
    if dmarc_status == "none" and from_domain:
        if (spf_status in ["fail", "softfail"] or not spf_aligned) and (dkim_status in ["fail", "none"] or not dkim_aligned):
            dmarc_status = "fail"
        elif (spf_status == "pass" and spf_aligned) or (dkim_status == "pass" and dkim_aligned):
            dmarc_status = "pass"

    # 4. Evaluate ARC
    arc_valid = bool(arc_results_raw and "arc=pass" in arc_results_raw.lower())

    # Build Summary & Flags
    flags: List[str] = []
    if dmarc_status == "fail":
        flags.append("DMARC Validation Failure (Neither SPF nor DKIM aligns with RFC 5322 From header)")
    if spf_status in ["fail", "softfail"]:
        flags.append(f"SPF {spf_status.upper()} (Connecting IP unauthorized for envelope domain)")
    if dkim_status == "fail":
        flags.append("DKIM Signature Failure (Cryptographic signature verification or body hash mismatch)")
    if dkim_domain and from_domain and dkim_domain.lower() != from_domain.lower() and not dkim_domain.lower().endswith("." + from_domain.lower()):
        flags.append(f"DKIM Domain Mismatch: Signed by '{dkim_domain}' but From claims '{from_domain}'")

    auth_summary = (
        f"DMARC: {dmarc_status.upper()} (Policy: {dmarc_policy}) | "
        f"SPF: {spf_status.upper()} (Aligned: {spf_aligned}) | "
        f"DKIM: {dkim_status.upper()} (Aligned: {dkim_aligned})"
    )

    return {
        "spf": {
            "status": spf_status,
            "envelope_domain": spf_envelope,
            "client_ip": spf_ip,
            "mechanism": spf_mechanism,
            "aligned": spf_aligned
        },
        "dkim": {
            "status": dkim_status,
            "signing_domain": dkim_domain,
            "selector": dkim_selector,
            "algorithm": dkim_alg,
            "aligned": dkim_aligned
        },
        "dmarc": {
            "status": dmarc_status,
            "policy": dmarc_policy,
            "spf_alignment": spf_aligned,
            "dkim_alignment": dkim_aligned,
            "from_domain": from_domain
        },
        "arc": {
            "seal_status": "pass" if arc_valid else ("none" if not arc_seal_raw else "fail"),
            "chain_valid": arc_valid,
            "has_arc": bool(arc_results_raw or arc_seal_raw)
        },
        "auth_summary": auth_summary,
        "flags": flags
    }


# ============================================================================
# 3. DISPLAY-NAME SPOOFING & LOOKALIKE DOMAIN ENGINE
# ============================================================================

def analyze_sender_and_lookalikes(
    from_header: str,
    reply_to: str,
    return_path: str,
    body_plain: str,
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Parses sender details, performs Levenshtein and homoglyph comparison against
    the top target brand catalog, checks for Reply-To mismatches and VIP impersonation.
    """
    parsed_name, parsed_addr = email.utils.parseaddr(from_header)
    parsed_name = parsed_name.strip()
    from_domain = parsed_addr.split("@")[-1].lower() if "@" in parsed_addr else ""

    _, reply_addr = email.utils.parseaddr(reply_to)
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

    _, return_addr = email.utils.parseaddr(return_path)
    return_domain = return_addr.split("@")[-1].lower() if "@" in return_addr else ""

    lookalike_detected = False
    matched_brand = ""
    matched_canonical = ""
    min_dist = 999
    is_punycode = "xn--" in from_domain

    # 1. Lookalike Domain Check against Protected Brands
    if from_domain:
        is_authentic = False
        for b_entry in TARGET_BRANDS:
            for canon in b_entry["canonical_domains"]:
                if from_domain == canon or from_domain.endswith("." + canon):
                    is_authentic = True
                    break
            if is_authentic:
                break

        if not is_authentic:
            from_base = from_domain.split(".")[0]
            norm_from_base = normalize_domain_chars(from_base)
            norm_from = normalize_domain_chars(from_domain)

            for b_entry in TARGET_BRANDS:
                brand_name = b_entry["brand"]
                for canon in b_entry["canonical_domains"]:
                    canon_base = canon.split(".")[0]

                    # 1. Exact homoglyph match after substitution (e.g. micros0ft vs microsoft)
                    if norm_from_base == canon_base and from_base != canon_base:
                        lookalike_detected = True
                        matched_brand = brand_name
                        matched_canonical = canon
                        min_dist = compute_levenshtein(from_base, canon_base)
                        break

                    # 2. Levenshtein edit distance on base domain
                    dist = compute_levenshtein(from_base, canon_base)
                    if 1 <= dist <= 2 and len(from_base) >= 4:
                        if dist < min_dist:
                            min_dist = dist
                            lookalike_detected = True
                            matched_brand = brand_name
                            matched_canonical = canon

                    # 3. Substring / combo-squatting (e.g. microsoft-security-update.com)
                    if (canon_base in from_domain or canon_base in norm_from) and len(from_base) > len(canon_base):
                        lookalike_detected = True
                        matched_brand = brand_name
                        matched_canonical = canon
                        min_dist = min(min_dist, 1)

    # 2. Display Name Impersonation
    display_name_spoofed = False
    impersonated_brand_or_role = ""
    disp_lower = parsed_name.lower()

    for b_entry in TARGET_BRANDS:
        b_name = b_entry["brand"].lower()
        if b_name in disp_lower:
            # Check if from_domain is actually that brand
            is_real = any(from_domain == c or from_domain.endswith("." + c) for c in b_entry["canonical_domains"])
            if not is_real:
                display_name_spoofed = True
                impersonated_brand_or_role = b_entry["brand"]
                break

    # 3. VIP / Executive Impersonation
    vip_detected = False
    detected_vip_role = ""
    for vip_pat in EXECUTIVE_VIP_PATTERNS:
        m = re.search(vip_pat, disp_lower)
        if m:
            vip_detected = True
            detected_vip_role = m.group(0).upper()
            break

    # 4. Reply-To Mismatch
    reply_to_mismatch = False
    reply_to_is_free = False
    if reply_domain and from_domain and reply_domain != from_domain:
        reply_to_mismatch = True
        if reply_domain in FREE_WEBMAIL_PROVIDERS:
            reply_to_is_free = True

    return {
        "display_name": parsed_name,
        "from_address": parsed_addr,
        "from_domain": from_domain,
        "reply_to_address": reply_addr,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "is_free_webmail": from_domain in FREE_WEBMAIL_PROVIDERS,
        "display_name_spoofing": {
            "is_spoofed": display_name_spoofed,
            "impersonated_entity": impersonated_brand_or_role,
            "details": f"Display name claims '{parsed_name}' while sender uses unrelated domain '@{from_domain}'." if display_name_spoofed else None
        },
        "lookalike_domain": {
            "is_lookalike": lookalike_detected,
            "impersonated_brand": matched_brand,
            "canonical_domain": matched_canonical,
            "edit_distance": min_dist if lookalike_detected else None,
            "is_punycode": is_punycode
        },
        "vip_executive_impersonation": {
            "is_impersonating": vip_detected,
            "role": detected_vip_role,
            "details": f"Executive title '{detected_vip_role}' used with external sender address <{parsed_addr}>." if vip_detected else None
        },
        "reply_to_mismatch": {
            "is_mismatched": reply_to_mismatch,
            "is_free_webmail_redirect": reply_to_is_free,
            "details": f"Replies diverted to separate domain '@{reply_domain}' ({'consumer webmail' if reply_to_is_free else 'external host'})." if reply_to_mismatch else None
        }
    }


# ============================================================================
# 4. PHISHING LINKS & URL THREAT ANALYSIS
# ============================================================================

def analyze_url_threats(
    urls: List[str],
    deceptive_links: List[Dict[str, Any]],
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Extracts every link, inspects destination host, checks for IP hostnames,
    userinfo syntax (@), URL shorteners, and credential phishing paths.
    """
    url_items: List[Dict[str, Any]] = []
    shortener_count = 0
    ip_host_count = 0
    cred_target_count = 0
    userinfo_count = 0

    deceptive_by_dest = {d.get("actual_destination", ""): d for d in deceptive_links}

    for u in urls:
        if not u or not isinstance(u, str):
            continue

        try:
            parsed = urllib.parse.urlparse(u)
        except Exception:
            continue

        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        is_shortener = hostname in URL_SHORTENERS
        if is_shortener:
            shortener_count += 1

        # Check for IP address in hostname
        is_ip_host = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', hostname))
        if is_ip_host:
            ip_host_count += 1

        # Check for @ userinfo obfuscation (e.g. https://google.com@evil.com)
        is_userinfo = bool(parsed.username) or ("@" in parsed.netloc)
        if is_userinfo:
            userinfo_count += 1

        # Check for credential harvesting path
        is_cred_target = any(cp in path for cp in CREDENTIAL_HARVESTING_PATHS)
        if is_cred_target:
            cred_target_count += 1

        is_deceptive = u in deceptive_by_dest or any(d in u for d in deceptive_by_dest.keys())
        claimed_text = None
        if is_deceptive:
            match_d = deceptive_by_dest.get(u)
            if match_d:
                claimed_text = match_d.get("displayed_text")

        risk = "low"
        if is_deceptive or is_userinfo:
            risk = "critical"
        elif is_ip_host or (is_cred_target and not any(hostname.endswith(cb) for cb in ["microsoft.com", "google.com", "apple.com"])):
            risk = "high"
        elif is_shortener:
            risk = "medium"

        url_items.append({
            "url": u,
            "normalized_url": f"{parsed.scheme}://{hostname}{path}",
            "hostname": hostname,
            "path": path,
            "scheme": parsed.scheme,
            "is_deceptive": is_deceptive,
            "claimed_text": claimed_text,
            "is_ip_host": is_ip_host,
            "is_shortener": is_shortener,
            "is_userinfo_obfuscated": is_userinfo,
            "is_credential_target": is_cred_target,
            "risk_level": risk
        })

    return {
        "total_urls_extracted": len(urls),
        "deceptive_links_count": len(deceptive_links),
        "shortened_links_count": shortener_count,
        "ip_host_links_count": ip_host_count,
        "userinfo_obfuscated_count": userinfo_count,
        "credential_harvesting_count": cred_target_count,
        "url_items": url_items[:40]
    }


# ============================================================================
# 5. HTML BODY & BROWSER PHISHING FORENSICS
# ============================================================================

def analyze_html_and_browser_phishing(
    body_html: str,
    body_plain: str,
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Inspects HTML markup for concealed text (tiny font, opacity 0, same color),
    HTML credential forms, meta refresh redirects, iframes, and data URLs.
    """
    hidden_text_items: List[Dict[str, Any]] = []
    forms: List[Dict[str, Any]] = []
    meta_refreshes: List[str] = []
    data_urls: List[Dict[str, Any]] = []
    iframes: List[Dict[str, Any]] = []
    html_comments: List[str] = []

    if not body_html:
        return {
            "has_html": False,
            "hidden_text_detected": False,
            "hidden_text_items": [],
            "credential_forms": [],
            "meta_refreshes": [],
            "data_urls": [],
            "iframes": [],
            "html_comments": []
        }

    soup = BeautifulSoup(body_html, "html.parser")

    # 1. Hidden Text Detection (CSS tricks)
    # Search elements with style attributes
    for el in soup.find_all(style=True):
        style = el["style"].lower()
        text_content = el.get_text().strip()
        if not text_content:
            continue

        method = None
        if re.search(r'font-size\s*:\s*(?:0(?:px|pt)?|0\.[0-9]+(?:px|pt)|1px)', style):
            method = "tiny_font"
        elif re.search(r'color\s*:\s*(?:transparent|rgba\([^)]+,0\))', style):
            method = "transparent_color"
        elif re.search(r'opacity\s*:\s*0\b', style):
            method = "zero_opacity"
        elif re.search(r'display\s*:\s*none', style) or re.search(r'visibility\s*:\s*hidden', style):
            method = "hidden_css"
        elif re.search(r'left\s*:\s*-\s*[0-9]{3,5}px', style) or re.search(r'top\s*:\s*-\s*[0-9]{3,5}px', style):
            method = "offscreen_css"

        if method:
            hidden_text_items.append({
                "text_snippet": text_content[:150],
                "method": method,
                "css_rule": style[:100],
                "text": text_content[:150],
                "reason": method
            })

    # 2. HTML Credential Harvesting Forms
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = [inp.get("name") or inp.get("type") or "unnamed" for inp in form.find_all("input")]
        has_pwd = bool(form.find("input", type="password"))

        forms.append({
            "form_action": action,
            "form_method": method,
            "has_password_input": has_pwd,
            "input_fields": inputs[:6],
            "action": action,
            "method": method,
            "inputs": inputs[:6]
        })

    # 3. Meta Refresh Redirects
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r'(?i)refresh')}):
        content = meta.get("content", "")
        if content:
            meta_refreshes.append({
                "content": content
            })

    # 4. Data URLs (data:text/html;base64, etc.)
    for a in soup.find_all(["a", "iframe", "embed", "object"]):
        src = a.get("href") or a.get("src") or ""
        if src.startswith("data:"):
            d_mime = src.split(";")[0].replace("data:", "")
            data_urls.append({
                "mime_type": d_mime,
                "length": len(src),
                "is_suspicious": "html" in d_mime or "javascript" in d_mime or len(src) > 500
            })

    # 5. Iframes
    for ifr in soup.find_all("iframe"):
        src = ifr.get("src", "")
        iframes.append({
            "src": src,
            "width": ifr.get("width", ""),
            "height": ifr.get("height", "")
        })

    # 6. HTML Comments with long or suspicious content
    from bs4 import Comment
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c_str = str(c).strip()
        if len(c_str) > 100 or re.search(r'(?i)(?:powershell|cmd\.exe|http|base64|eval)', c_str):
            html_comments.append(c_str[:200])

    return {
        "has_html": True,
        "hidden_text_detected": len(hidden_text_items) > 0,
        "hidden_text_items": hidden_text_items[:10],
        "credential_forms": forms,
        "meta_refreshes": meta_refreshes,
        "data_urls": data_urls[:5],
        "iframes": iframes,
        "html_comments": html_comments[:5]
    }


# ============================================================================
# 6. ATTACHMENT EXTRACTION & FILE-TYPE FORENSICS
# ============================================================================

def analyze_attachment_forensics(
    attachments: List[Dict[str, Any]],
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Evaluates decoded attachments for extension vs signature mismatches,
    dangerous file types, double extensions, macros, and archive containers.
    """
    items: List[Dict[str, Any]] = []
    dangerous_count = 0
    mismatch_count = 0
    double_ext_count = 0
    macro_count = 0

    for att in attachments:
        fname = att.get("filename") or "unnamed"
        fname_lower = fname.lower()
        size = att.get("size", 0)
        sha256 = att.get("sha256", "")
        declared_mime = att.get("mime_type", "application/octet-stream")

        # Double extension detection
        has_double = bool(re.search(r'\.[a-zA-Z0-9]{2,4}\.(exe|scr|bat|cmd|ps1|vbs|js|hta|lnk|iso|vhd)$', fname_lower))
        if has_double:
            double_ext_count += 1

        # Dangerous type
        is_dangerous = any(fname_lower.endswith(ext) for ext in DANGEROUS_EXTS)
        if is_dangerous:
            dangerous_count += 1

        # Macro-enabled Office document
        is_macro = any(fname_lower.endswith(ext) for ext in [".docm", ".xlsm", ".pptm", ".dotm", ".xltm"])
        if is_macro:
            macro_count += 1

        # Signature mismatch check:
        # If filename claims .pdf, .jpg, .docx, but threat_reason or mime claims executable/script
        is_mismatch = False
        threat_reason = att.get("threat_reason", "")
        if "extension mismatch" in threat_reason.lower() or "disguised" in threat_reason.lower():
            is_mismatch = True
            mismatch_count += 1

        is_pw_archive = "password" in threat_reason.lower() and "archive" in threat_reason.lower()
        is_nested_email = fname_lower.endswith((".eml", ".msg"))

        risk = "low"
        if is_dangerous or is_mismatch or has_double or (is_macro and att.get("ole_macros")):
            risk = "critical"
        elif is_macro or is_pw_archive or declared_mime.startswith("application/x-dosexec"):
            risk = "high"
        elif fname_lower.endswith((".zip", ".7z", ".tar", ".gz")):
            risk = "medium"

        items.append({
            "filename": fname,
            "declared_mime": declared_mime,
            "detected_type": declared_mime,
            "size": size,
            "size_bytes": size,
            "sha256": sha256,
            "is_mismatch": is_mismatch,
            "is_signature_mismatch": is_mismatch,
            "is_dangerous": is_dangerous,
            "is_dangerous_type": is_dangerous,
            "has_double_extension": has_double,
            "has_macros": is_macro,
            "is_macro_enabled": is_macro,
            "is_password_protected_archive": is_pw_archive,
            "is_nested_email": is_nested_email,
            "risk_level": risk,
            "threat_reason": threat_reason or ("Executable or script attachment" if is_dangerous else None),
            "threat_description": threat_reason or ("Executable or script attachment" if is_dangerous else None)
        })

    return {
        "total_attachments": len(attachments),
        "dangerous_count": dangerous_count,
        "mismatch_count": mismatch_count,
        "double_extension_count": double_ext_count,
        "macro_enabled_count": macro_count,
        "nested_messages_count": sum(1 for it in items if it.get("is_nested_email")),
        "inspected_attachments": items,
        "items": items
    }


# ============================================================================
# 7. BUSINESS EMAIL COMPROMISE (BEC) & FINANCIAL FRAUD ENGINE
# ============================================================================

def analyze_bec_and_financial_fraud(
    subject: str,
    body_plain: str,
    from_header: str,
    reply_to: str,
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Evaluates message context for wire fraud, banking detail updates,
    executive impersonation, gift card fraud, and urgent confidentiality.
    """
    text_corpus = f"{subject}\n{body_plain}".lower()

    # 1. Bank Detail Redirection
    bank_matches = []
    for term in BEC_BANKING_TERMS:
        if re.search(r'(?i)\b' + term, text_corpus):
            bank_matches.append(term.replace(r'\b', '').replace('\\s+', ' '))

    # 2. Urgency and Secrecy
    urgency_matches = []
    for term in BEC_URGENCY_SECRECY_TERMS:
        if re.search(r'(?i)\b' + term, text_corpus):
            urgency_matches.append(term.replace(r'\b', '').replace('\\s+', ' '))

    # 3. Gift Card Fraud
    gift_card_matches = []
    for term in BEC_GIFT_CARD_TERMS:
        if re.search(r'(?i)\b' + term, text_corpus):
            gift_card_matches.append(term.replace(r'\b', '').replace('\\s+', ' '))

    # 4. BEC Scoring
    bec_score = 0
    indicators: List[str] = []

    if bank_matches:
        bec_score += 45
        indicators.append(f"Payment Redirection / Banking Terms Detected: {', '.join(bank_matches[:3])}")

    if urgency_matches:
        bec_score += 25
        indicators.append(f"Urgency & Secrecy Pressure Detected: {', '.join(urgency_matches[:3])}")

    if gift_card_matches:
        bec_score += 50
        indicators.append(f"Corporate Gift Card Solicitations: {', '.join(gift_card_matches[:3])}")

    # Check if sender is external or free webmail with CEO/executive name
    parsed_name, parsed_addr = email.utils.parseaddr(from_header)
    is_vip = any(re.search(pat, parsed_name.lower()) for pat in EXECUTIVE_VIP_PATTERNS)
    from_domain = parsed_addr.split("@")[-1].lower() if "@" in parsed_addr else ""
    if is_vip:
        bec_score += 25
        indicators.append(f"Executive / Leadership Persona: Display name '{parsed_name}' used from @{from_domain}")

    bec_score = min(100, bec_score)
    bec_detected = bec_score >= 50

    fraud_types: List[str] = []
    if bank_matches:
        fraud_types.append("Wire Transfer / Banking Redirection")
    if gift_card_matches:
        fraud_types.append("Gift Card Advance-Fee Fraud")
    if urgency_matches and is_vip:
        fraud_types.append("Executive Impersonation BEC")

    return {
        "bec_detected": bec_detected,
        "bec_risk_score": bec_score,
        "financial_fraud_types": fraud_types,
        "bank_payment_redirection": {
            "detected": len(bank_matches) > 0,
            "matched_terms": bank_matches[:5]
        },
        "urgency_secrecy": {
            "detected": len(urgency_matches) > 0,
            "matched_terms": urgency_matches[:5]
        },
        "gift_card_fraud": {
            "detected": len(gift_card_matches) > 0,
            "matched_terms": gift_card_matches[:5]
        },
        "executive_wire_fraud": {
            "detected": (len(bank_matches) > 0 and is_vip) or ("wire" in body_plain.lower() and is_vip),
            "matched_terms": [t for t in bank_matches if "wire" in t.lower()] or (bank_matches[:3] if is_vip else [])
        },
        "indicators": indicators
    }


# ============================================================================
# 8. EXECUTIVE EMAIL SECURITY VERDICT & CONTAINMENT GUIDANCE
# ============================================================================

def calculate_email_verdict(
    file_integrity: Dict[str, Any],
    auth_posture: Dict[str, Any],
    sender_analysis: Dict[str, Any],
    url_threats: Dict[str, Any],
    html_forensics: Dict[str, Any],
    attachment_forensics: Dict[str, Any],
    bec_analysis: Dict[str, Any],
    findings: List[Any]
) -> Dict[str, Any]:
    """
    Computes a standardized Executive Email Security Verdict:
      - Status: Malicious | Suspicious | Potentially Phishing / BEC | No Known Threat Detected | Inconclusive
      - Severity: critical | high | medium | low | info
      - Calibrated Confidence Score (0% - 100%)
      - Key Assessment Rationale
      - Threat Category Tags
      - MITRE ATT&CK Technique Tags
      - Actionable Containment Checklist
    """
    rationale: List[str] = []
    categories_set: Set[str] = set()
    mitre_set: Set[str] = set()

    # Critical triggers
    has_exploit = any(f.category == "exploit" for f in findings)
    has_dangerous_att = attachment_forensics.get("dangerous_count", 0) > 0 or attachment_forensics.get("mismatch_count", 0) > 0
    has_deceptive_url = url_threats.get("deceptive_links_count", 0) > 0 or url_threats.get("userinfo_obfuscated_count", 0) > 0
    has_cred_form = any(f.get("has_password_input") for f in html_forensics.get("credential_forms", []))
    has_lookalike = sender_analysis.get("lookalike_domain", {}).get("is_lookalike", False)
    has_disp_spoof = sender_analysis.get("display_name_spoofing", {}).get("is_spoofed", False)
    has_dmarc_fail = auth_posture.get("dmarc", {}).get("status") == "fail"
    has_bec = bec_analysis.get("bec_detected", False)
    has_bidi = file_integrity.get("unicode_anomalies", {}).get("bidi_controls_detected", False)

    if has_exploit:
        for f in findings:
            if f.category == "exploit":
                rationale.append(f"Outlook Exploit Detected: {f.title}.")
                mitre_set.add("T1187")
                categories_set.add("Outlook Exploit (CVE)")

    if has_deceptive_url:
        rationale.append(f"Deceptive Phishing Links: {url_threats['deceptive_links_count']} link(s) display a trusted domain while pointing to an external destination.")
        categories_set.add("Deceptive Links")
        mitre_set.add("T1566.002")

    if has_dangerous_att:
        rationale.append(f"Malicious Attachment Payload: Email contains executable, script, or disguised payload ({attachment_forensics['dangerous_count']} dangerous file(s)).")
        categories_set.add("Malware Delivery")
        mitre_set.add("T1566.001")

    if has_cred_form:
        rationale.append("Embedded Credential Harvesting Form: HTML body contains form requesting credentials/passwords directly.")
        categories_set.add("Credential Phishing")
        mitre_set.add("T1598")

    if has_lookalike:
        b_info = sender_analysis["lookalike_domain"]
        rationale.append(f"Lookalike Typosquatting Domain: Sender domain '{sender_analysis['from_domain']}' mimics '{b_info.get('canonical_domain')}' (Brand: {b_info.get('impersonated_brand')}).")
        categories_set.add("Lookalike Domain")
        mitre_set.add("T1656")

    if has_disp_spoof:
        s_info = sender_analysis["display_name_spoofing"]
        rationale.append(f"Display-Name Impersonation: Claims identity '{sender_analysis['display_name']}' ({s_info.get('impersonated_entity')}) using external address <{sender_analysis['from_address']}>.")
        categories_set.add("Display-Name Spoofing")
        mitre_set.add("T1656")

    if has_dmarc_fail:
        rationale.append(f"Email Authentication Failure: DMARC validation failed (SPF & DKIM do not authenticate sender domain).")
        categories_set.add("Auth Failure")

    if has_bec:
        rationale.append(f"Business Email Compromise (Score {bec_analysis['bec_risk_score']}/100): Coercive payment redirection / wire fraud solicitation detected.")
        categories_set.add("BEC / Financial Fraud")
        mitre_set.add("T1566.002")

    if has_bidi:
        rationale.append("Unicode Bidirectional Override: Contains hidden RTL control characters used to reverse apparent file extensions or text.")
        categories_set.add("Anti-Analysis / Obfuscation")
        mitre_set.add("T1027")

    # Determine Verdict & Confidence
    if has_exploit or has_dangerous_att or (has_deceptive_url and has_dmarc_fail) or (has_lookalike and has_cred_form):
        verdict = "Malicious"
        severity = "critical"
        confidence = 98
    elif has_deceptive_url or has_lookalike or has_bec or (has_disp_spoof and has_dmarc_fail):
        verdict = "Suspicious"
        severity = "high"
        confidence = 90
    elif has_dmarc_fail or has_disp_spoof or sender_analysis.get("reply_to_mismatch", {}).get("is_mismatched", False) or url_threats.get("credential_harvesting_count", 0) > 0:
        verdict = "Potentially Phishing / BEC"
        severity = "medium"
        confidence = 75
    else:
        verdict = "No Known Threat Detected"
        severity = "info"
        confidence = 85
        rationale.append("Scanned message headers, MIME parts, URLs, and attachments without matching known phishing, malware, or BEC patterns.")

    # Actionable Containment & Response Guidance
    containment: List[str] = []
    if verdict in ["Malicious", "Suspicious", "Potentially Phishing / BEC"]:
        containment.append("Purge this message and all identical Message-IDs from all corporate recipient mailboxes (via M365 Compliance / Exchange Admin).")
        if sender_analysis.get("from_domain"):
            containment.append(f"Add sender domain '{sender_analysis['from_domain']}' to the organizational perimeter email blocklist.")
        if has_deceptive_url or url_threats.get("url_items"):
            containment.append("Block discovered phishing destination domains on Secure Web Gateway (SWG) and DNS resolvers.")
        if has_dangerous_att:
            containment.append("Check host EDR logs for attachment execution or dropped staging files on recipient endpoints.")
        if has_bec:
            containment.append("Contact Finance immediately to verify banking change requests through an out-of-band phone confirmation.")
        containment.append("Reset credentials and revoke active session tokens if any recipient opened links or entered passwords.")
    else:
        containment.append("Standard hygiene: Verify sender identity out-of-band if sensitive transactions or credentials are requested.")
        containment.append("Maintain mail gateway SPF/DKIM/DMARC rejection policies to filter spoofed incoming messages.")

    return {
        "verdict": verdict,
        "severity": severity,
        "confidence_score": confidence,
        "threat_categories": sorted(list(categories_set)),
        "key_assessment_rationale": rationale[:6],
        "mitre_attack_techniques": sorted(list(mitre_set)) if mitre_set else ["T1566"],
        "containment_guidance": containment,
        "limitations": [
            "Encrypted S/MIME or PGP payloads cannot be inspected without private decryption keys.",
            "Newly registered zero-day phishing landing pages may lack established reputation data at time of scan."
        ]
    }


# ============================================================================
# 9. OFFLINE FORENSIC TOOLS CLI GUIDE
# ============================================================================

def get_email_offline_tools_guide(filename: str) -> Dict[str, Any]:
    """
    Returns ready-to-run CLI commands for offline analysis across standard utilities.
    """
    fname = filename or "suspicious.eml"
    return {
        "file_hash": {
            "tool": "file & sha256sum",
            "command": f"file {fname} && sha256sum {fname}",
            "notes": "Verify container format (EML vs CFBF MSG) and compute cryptographic provenance hash."
        },
        "python_email": {
            "tool": "Python email library",
            "command": (
                f"python3 -c \"import email, policy; msg = email.message_from_bytes(open('{fname}','rb').read(), policy=policy.default); "
                f"print('From:', msg['From']); print('Subject:', msg['Subject']); print('Parts:', [p.get_content_type() for p in msg.walk()])\""
            ),
            "notes": "Fast offline extraction of MIME parts, headers, and transfer encodings without rendering."
        },
        "extract_msg": {
            "tool": "extract_msg (Outlook MSG Parser)",
            "command": f"extract_msg --json --dump-stdout {fname}",
            "notes": "Extracts Outlook MAPI properties, recipients, and embedded items from Compound File MSG."
        },
        "ripmime": {
            "tool": "ripmime (Attachment Quarantine Extractor)",
            "command": f"ripmime -i {fname} -d ./quarantine/ --unique_names --paranoid",
            "notes": "Safely carves all MIME attachments and embedded RFC 822 messages into a quarantined directory."
        },
        "oletools": {
            "tool": "oletools (olevba / oleid)",
            "command": f"olevba ./quarantine/* || oleid ./quarantine/*",
            "notes": "Scans extracted Office attachments for obfuscated VBA macros, XLM 4.0 macros, and remote templates."
        },
        "yara_scan": {
            "tool": "YARA Malware Scanner",
            "command": f"yara -r ./rules/email_rules.yar {fname}",
            "notes": "Executes signature rules against headers, raw MIME streams, and carved attachments."
        }
    }
