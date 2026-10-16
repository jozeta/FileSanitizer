import re
import math
import hashlib
import binascii
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from app.analyzers.base import Finding


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates byte-level Shannon entropy between 0.000 and 8.000."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def format_hex_preview(raw_bytes: bytes, max_len: int = 256) -> str:
    """Formats bytes into standard 16-bytes per line hex offset + hex + ascii dump."""
    lines = []
    chunk = raw_bytes[:max_len]
    for i in range(0, len(chunk), 16):
        block = chunk[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in block)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in block)
        lines.append(f"{i:04x}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)


DANGEROUS_ACROBAT_JS_APIS = [
    {
        "pattern": r"(?i)\bapp\.launchURL\b",
        "api": "app.launchURL()",
        "risk": "critical",
        "description": "Launches external URL schemes or Windows protocol handlers (e.g. cmd:, powershell:, ms-msdt:, or file:), leading to process execution (CVE-2023-38836).",
        "mitre": "T1204"
    },
    {
        "pattern": r"(?i)\butil\.readFileIntoStream\b",
        "api": "util.readFileIntoStream()",
        "risk": "critical",
        "description": "Reads arbitrary local filesystem files into memory streams, weaponized in zero-day exfiltration chains.",
        "mitre": "T1005"
    },
    {
        "pattern": r"(?i)\bSOAP\.(?:connect|request)\b",
        "api": "SOAP.request() / connect()",
        "risk": "critical",
        "description": "Sends raw SOAP XML requests over the network, used to exfiltrate stolen files or trigger internal network SSRF.",
        "mitre": "T1048"
    },
    {
        "pattern": r"(?i)\bRSS\.addFeed\b",
        "api": "RSS.addFeed()",
        "risk": "high",
        "description": "Registers external RSS feeds, forcing unauthenticated HTTP callbacks to attacker command-and-control servers.",
        "mitre": "T1071"
    },
    {
        "pattern": r"(?i)\bthis\.exportDataObject\b",
        "api": "this.exportDataObject()",
        "risk": "high",
        "description": "Extracts and launches embedded file attachments directly onto the host filesystem (malware dropper behavior).",
        "mitre": "T1105"
    },
    {
        "pattern": r"(?i)\bthis\.importDataObject\b",
        "api": "this.importDataObject()",
        "risk": "high",
        "description": "Imports external data objects or scripts dynamically into the document container at runtime.",
        "mitre": "T1059"
    },
    {
        "pattern": r"(?i)\bthis\.getURL\b",
        "api": "this.getURL()",
        "risk": "high",
        "description": "Foxit Reader API capable of launching external applications or opening remote addresses without confirmation (CVE-2017-10951).",
        "mitre": "T1204"
    },
    {
        "pattern": r"(?i)\bgetPageNthWord\b",
        "api": "getPageNthWord()",
        "risk": "high",
        "description": "Scrapes document page text word-by-word programmatically, indicative of document credential/data harvesting.",
        "mitre": "T1005"
    },
    {
        "pattern": r"(?i)\bsubmitForm\b",
        "api": "submitForm()",
        "risk": "high",
        "description": "Transmits form field data or document contents to external HTTP endpoints in the background.",
        "mitre": "T1048"
    },
    {
        "pattern": r"(?i)\bapp\.media\.getURLData\b",
        "api": "app.media.getURLData()",
        "risk": "high",
        "description": "Fetches external media streams over HTTP, capable of SSRF or out-of-band data exfiltration.",
        "mitre": "T1071"
    },
    {
        "pattern": r"(?i)\beval\s*\(",
        "api": "eval()",
        "risk": "high",
        "description": "Evaluates dynamic JavaScript code strings at runtime to evade static pattern matchers and signatures.",
        "mitre": "T1027"
    },
    {
        "pattern": r"(?i)\bunescape\s*\(",
        "api": "unescape()",
        "risk": "medium",
        "description": "Unpacks URL-encoded or Unicode binary shellcode strings (e.g. %u9090) into raw memory.",
        "mitre": "T1027"
    },
    {
        "pattern": r"(?i)new\s+(?:ArrayBuffer|Uint8Array|Float64Array)\s*\(",
        "api": "TypedArray (ArrayBuffer/Uint8Array)",
        "risk": "high",
        "description": "Allocates large typed memory buffers indicative of heap grooming and memory spraying exploits (CVE-2021-28550).",
        "mitre": "T1055"
    }
]


def deobfuscate_and_analyze_javascript(js_code: str) -> Dict[str, Any]:
    """
    Deobfuscates JavaScript extracted from PDF streams and identifies high-risk APIs.
    Decodes unescape, String.fromCharCode, hex escapes, and string concatenation.
    """
    if not js_code or not js_code.strip():
        return {
            "has_javascript": False,
            "deobfuscated_code": "",
            "deobfuscated_applied": False,
            "dangerous_apis": [],
            "shellcode_indicators": []
        }

    original_code = js_code
    deobf = original_code

    # 1. String literal concatenation: "a" + "b" -> "ab"
    prev = ""
    while prev != deobf:
        prev = deobf
        deobf = re.sub(r'["\']\s*\+\s*["\']', '', deobf)

    # 2. String.fromCharCode(97, 98, 99) -> "abc"
    def _from_char_code_sub(match):
        nums_str = match.group(1)
        chars = []
        for x in nums_str.split(','):
            x = x.strip()
            if x.isdigit():
                try:
                    c = chr(int(x))
                    chars.append(c if 32 <= ord(c) <= 126 or c in "\r\n\t" else f"\\x{ord(c):02x}")
                except Exception:
                    pass
        return '"' + "".join(chars) + '"'

    deobf = re.sub(r'String\.fromCharCode\s*\(\s*([0-9,\s]+)\s*\)', _from_char_code_sub, deobf)

    # 3. Unicode escape %uXXXX -> \uXXXX (or ascii if printable)
    def _unicode_unescape_sub(match):
        hex_val = match.group(1)
        try:
            val = int(hex_val, 16)
            if 32 <= val <= 126:
                return chr(val)
            return f"\\u{hex_val}"
        except Exception:
            return match.group(0)

    deobf = re.sub(r'(?i)%u([0-9a-f]{4})', _unicode_unescape_sub, deobf)

    # 4. Hex escape %XX -> char (if printable) or \xXX
    def _hex_unescape_sub(match):
        hex_val = match.group(1)
        try:
            val = int(hex_val, 16)
            if 32 <= val <= 126:
                return chr(val)
            return f"\\x{hex_val}"
        except Exception:
            return match.group(0)

    deobf = re.sub(r'(?i)%([0-9a-f]{2})', _hex_unescape_sub, deobf)

    # 5. \xXX literals in strings
    def _hex_literal_sub(match):
        hex_val = match.group(1)
        try:
            val = int(hex_val, 16)
            if 32 <= val <= 126 and chr(val) not in ['"', "'", '\\']:
                return chr(val)
            return match.group(0)
        except Exception:
            return match.group(0)

    deobf = re.sub(r'\\x([0-9a-fA-F]{2})', _hex_literal_sub, deobf)

    # Detect dangerous Acrobat JS APIs
    detected_apis = []
    for item in DANGEROUS_ACROBAT_JS_APIS:
        if re.search(item["pattern"], deobf) or re.search(item["pattern"], original_code):
            detected_apis.append({
                "api": item["api"],
                "risk": item["risk"],
                "description": item["description"],
                "mitre": item["mitre"]
            })

    # Detect Shellcode patterns (NOP sleds, repeated pointers, unicode sleds)
    shellcode_indicators = []
    if re.search(r'(?:\\u9090|%u9090|\x90{16,})', original_code) or re.search(r'(?:\\u9090|%u9090|\x90{16,})', deobf):
        shellcode_indicators.append("NOP Sled detected in script payload (\x90 * 16+ or %u9090)")
    if re.search(r'(?:%u0c0c%u0c0c|\\u0c0c\\u0c0c|0x0c0c0c0c)', original_code) or re.search(r'(?:%u0c0c%u0c0c|\\u0c0c\\u0c0c|0x0c0c0c0c)', deobf):
        shellcode_indicators.append("Heap spray address target pointer detected (0x0c0c0c0c / %u0c0c)")
    if re.search(r'(?:%u4141%u4141|\\u4141\\u4141|AAAA{8,})', original_code):
        shellcode_indicators.append("Buffer overflow padding / sled pattern detected (0x41414141 / 'AAAA')")

    return {
        "has_javascript": True,
        "deobfuscated_code": deobf,
        "deobfuscated_applied": deobf.strip() != original_code.strip(),
        "dangerous_apis": detected_apis,
        "shellcode_indicators": shellcode_indicators
    }


def inspect_pdf_structure_and_overlay(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Performs deep container and byte-level structural forensics:
    - PDF header offset validation & polyglot detection
    - %%EOF count and revision boundaries
    - Trailing overlay data past final %%EOF
    """
    total_size = len(raw_bytes)
    header_offset = raw_bytes.find(b"%PDF-")
    is_polyglot = False
    polyglot_type = ""

    if header_offset > 0:
        is_polyglot = True
        prefix = raw_bytes[:header_offset]
        if prefix.startswith(b"PK\x03\x04"):
            polyglot_type = "ZIP / JAR Archive"
        elif prefix.startswith(b"Rar!\x1a\x07"):
            polyglot_type = "RAR Archive"
        elif prefix.startswith(b"MZ"):
            polyglot_type = "Windows PE Executable"
        elif prefix.startswith(b"\x7fELF"):
            polyglot_type = "Linux ELF Binary"
        elif re.match(rb'^\s*<(!DOCTYPE\s+html|html)', prefix, re.IGNORECASE):
            polyglot_type = "HTML / Web Document"
        elif prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
            polyglot_type = "7-Zip Archive"
        else:
            polyglot_type = f"Prepended Binary Padding / Wrapper ({header_offset} bytes)"

    # Enumerate %%EOF markers
    eof_offsets = [m.start() for m in re.finditer(rb'%%EOF', raw_bytes)]
    startxref_offsets = [m.start() for m in re.finditer(rb'startxref\b', raw_bytes)]
    eof_count = len(eof_offsets)

    # Check for trailing overlay past the last %%EOF
    has_overlay = False
    overlay_size = 0
    overlay_entropy = 0.0
    overlay_hex = ""
    overlay_threat = "none"
    overlay_desc = ""

    if eof_offsets:
        last_eof_end = eof_offsets[-1] + len(b"%%EOF")
        if last_eof_end < total_size:
            raw_trailing = raw_bytes[last_eof_end:]
            # Strip trailing null bytes, newlines, carriage returns, spaces
            stripped_trailing = raw_trailing.strip(b"\r\n\x00\t ")
            if len(stripped_trailing) >= 16:
                has_overlay = True
                overlay_size = len(stripped_trailing)
                overlay_entropy = calculate_shannon_entropy(stripped_trailing)
                overlay_hex = format_hex_preview(stripped_trailing, max_len=256)

                if stripped_trailing.startswith(b"MZ"):
                    overlay_threat = "critical"
                    overlay_desc = "Appended Windows PE Executable (Dropper / Overlay Payload)"
                elif stripped_trailing.startswith(b"PK\x03\x04"):
                    overlay_threat = "high"
                    overlay_desc = "Appended ZIP / JAR Archive Container"
                elif stripped_trailing.startswith(b"7z\xbc\xaf\x27\x1c"):
                    overlay_threat = "high"
                    overlay_desc = "Appended 7-Zip Compressed Archive"
                elif stripped_trailing.startswith(b"Rar!\x1a\x07"):
                    overlay_threat = "high"
                    overlay_desc = "Appended RAR Archive"
                elif overlay_entropy > 7.5:
                    overlay_threat = "high"
                    overlay_desc = "High-entropy encrypted, packed, or compressed payload"
                elif b"powershell" in stripped_trailing.lower() or b"cmd.exe" in stripped_trailing.lower():
                    overlay_threat = "high"
                    overlay_desc = "Appended command-line / script execution payload"
                else:
                    overlay_threat = "medium"
                    overlay_desc = f"Extraneous binary data appended past %%EOF ({overlay_size} bytes)"

    return {
        "total_size": total_size,
        "header_offset": header_offset,
        "is_polyglot": is_polyglot,
        "polyglot_type": polyglot_type,
        "eof_count": eof_count,
        "eof_offsets": eof_offsets,
        "startxref_offsets": startxref_offsets,
        "has_overlay": has_overlay,
        "overlay_size": overlay_size,
        "overlay_entropy": overlay_entropy,
        "overlay_hex": overlay_hex,
        "overlay_threat": overlay_threat,
        "overlay_desc": overlay_desc
    }


def inspect_digital_signatures(doc: Any, raw_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Parses digital signatures (/Type /Sig) in the document.
    Validates /ByteRange coverage to detect Shadow Attacks (post-signature incremental modification).
    """
    signatures: List[Dict[str, Any]] = []
    total_bytes = len(raw_bytes)

    try:
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                obj_text = doc.xref_object(xref)
                if "/Type /Sig" in obj_text or "/Type/Sig" in obj_text:
                    # Extract SubFilter
                    subfilter = ""
                    sf_m = re.search(r'/SubFilter\s*/([A-Za-z0-9_\.]+)', obj_text)
                    if sf_m:
                        subfilter = sf_m.group(1)

                    # Extract Name / Signer
                    signer = ""
                    name_m = re.search(r'/Name\s*\(([^)]+)\)', obj_text)
                    if name_m:
                        signer = name_m.group(1)

                    # Extract Reason
                    reason = ""
                    reason_m = re.search(r'/Reason\s*\(([^)]+)\)', obj_text)
                    if reason_m:
                        reason = reason_m.group(1)

                    # Extract Date / M
                    date_val = ""
                    date_m = re.search(r'/M\s*\(([^)]+)\)', obj_text)
                    if date_m:
                        date_val = date_m.group(1)

                    # Extract ByteRange [offset1 len1 offset2 len2]
                    byte_range = []
                    br_m = re.search(r'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', obj_text)
                    has_shadow_attack = False
                    shadow_bytes_count = 0
                    if br_m:
                        byte_range = [int(br_m.group(1)), int(br_m.group(2)), int(br_m.group(3)), int(br_m.group(4))]
                        covered_end = byte_range[2] + byte_range[3]
                        if covered_end < total_bytes:
                            diff = total_bytes - covered_end
                            if diff > 100:  # Allow minimal newline slack
                                has_shadow_attack = True
                                shadow_bytes_count = diff

                    signatures.append({
                        "xref": xref,
                        "subfilter": subfilter or "Unknown Signature Filter",
                        "signer": signer or "Unspecified Signer",
                        "reason": reason or "Unspecified Reason",
                        "date": date_val or "No timestamp recorded",
                        "byte_range": byte_range,
                        "has_shadow_attack": has_shadow_attack,
                        "shadow_bytes_count": shadow_bytes_count
                    })
            except Exception:
                pass
    except Exception:
        pass

    return signatures


def inspect_concealed_content(doc: Any, raw_text: str) -> Dict[str, Any]:
    """
    Detects concealed, hidden, and deceptive visual content:
    - White-on-white / zero-contrast hidden text
    - Tiny sub-pixel text (< 1.0 pt)
    - Off-page rendering coordinates (outside MediaBox)
    - Invisible text rendering mode (3 Tr)
    - Phishing Hyperlink Mismatch (display link domain differs from actual destination URL)
    - Optional Content Groups (OCG / hidden layers)
    """
    white_text_spans: List[Dict[str, Any]] = []
    tiny_font_spans: List[Dict[str, Any]] = []
    off_page_spans: List[Dict[str, Any]] = []
    deceptive_links: List[Dict[str, Any]] = []
    has_invisible_render_mode = False

    try:
        for page_idx, page in enumerate(doc):
            p_num = page_idx + 1
            p_rect = page.rect

            # 1. Text Spans Inspection
            try:
                text_dict = page.get_text("dict")
                for block in text_dict.get("blocks", []):
                    if "lines" in block:
                        for line in block["lines"]:
                            for span in line.get("spans", []):
                                txt = span.get("text", "").strip()
                                if not txt or len(txt) < 2:
                                    continue
                                sz = span.get("size", 12.0)
                                col = span.get("color", 0)
                                bbox = span.get("bbox", (0, 0, 0, 0))

                                # A. Tiny Font (< 1.0 pt)
                                if sz < 1.0:
                                    tiny_font_spans.append({
                                        "page": p_num,
                                        "text": txt[:80],
                                        "size": round(sz, 2),
                                        "font": span.get("font", "unknown"),
                                        "bbox": [round(c, 1) for c in bbox]
                                    })

                                # B. White-on-white text (color 0xFFFFFF or RGB near 255)
                                # Color in fitz is an sRGB integer 0xRRGGBB
                                if col == 0xFFFFFF or col == 16777215:
                                    white_text_spans.append({
                                        "page": p_num,
                                        "text": txt[:80],
                                        "color_hex": "#FFFFFF",
                                        "size": round(sz, 2),
                                        "font": span.get("font", "unknown"),
                                        "bbox": [round(c, 1) for c in bbox]
                                    })
                                elif col > 0:
                                    r = (col >> 16) & 0xFF
                                    g = (col >> 8) & 0xFF
                                    b = col & 0xFF
                                    if r >= 250 and g >= 250 and b >= 250:
                                        white_text_spans.append({
                                            "page": p_num,
                                            "text": txt[:80],
                                            "color_hex": f"#{r:02x}{g:02x}{b:02x}",
                                            "size": round(sz, 2),
                                            "font": span.get("font", "unknown"),
                                            "bbox": [round(c, 1) for c in bbox]
                                        })

                                # C. Off-page rendering
                                if bbox[0] < p_rect.x0 - 5 or bbox[1] < p_rect.y0 - 5 or bbox[2] > p_rect.x1 + 5 or bbox[3] > p_rect.y1 + 5:
                                    off_page_spans.append({
                                        "page": p_num,
                                        "text": txt[:80],
                                        "size": round(sz, 2),
                                        "bbox": [round(c, 1) for c in bbox],
                                        "page_rect": [round(p_rect.x0, 1), round(p_rect.y0, 1), round(p_rect.x1, 1), round(p_rect.y1, 1)]
                                    })
            except Exception:
                pass

            # 2. Page Contents Stream check for text rendering mode 3 (3 Tr)
            try:
                contents_xref_list = page.get_contents()
                if contents_xref_list:
                    for c_xref in contents_xref_list:
                        c_bytes = doc.xref_stream(c_xref)
                        if c_bytes and re.search(rb'\b3\s+Tr\b', c_bytes):
                            has_invisible_render_mode = True
                            break
            except Exception:
                pass

            # 3. Deceptive Link Phishing Mismatch Analysis
            try:
                links = page.get_links()
                for link in links:
                    dest_uri = link.get("uri")
                    from_rect = link.get("from")
                    if dest_uri and from_rect:
                        # Extract visual text in this link's bounding box
                        visible_txt = page.get_text("text", clip=from_rect).strip()
                        # If visible text contains http://, https://, or a domain-like pattern
                        domain_m = re.search(r'(?i)(?:https?://)?([a-zA-Z0-9_\.\-]+\.[a-zA-Z]{2,})', visible_txt)
                        dest_domain_m = re.search(r'(?i)(?:https?://)?([a-zA-Z0-9_\.\-]+\.[a-zA-Z]{2,})', dest_uri)

                        if domain_m and dest_domain_m:
                            display_domain = domain_m.group(1).lower().rstrip('/')
                            target_domain = dest_domain_m.group(1).lower().rstrip('/')

                            # Normalize subdomains (e.g. www.)
                            norm_disp = re.sub(r'^www\.', '', display_domain)
                            norm_target = re.sub(r'^www\.', '', target_domain)

                            if norm_disp != norm_target and not norm_target.endswith('.' + norm_disp):
                                deceptive_links.append({
                                    "page": p_num,
                                    "display_text": visible_txt[:100],
                                    "display_domain": display_domain,
                                    "destination_uri": dest_uri,
                                    "target_domain": target_domain,
                                    "rect": [round(from_rect.x0, 1), round(from_rect.y0, 1), round(from_rect.x1, 1), round(from_rect.y1, 1)]
                                })
            except Exception:
                pass
    except Exception:
        pass

    # 4. Optional Content Groups (OCG)
    has_ocg = bool(re.search(r'(?i)/OCProperties\b|/OCGs\b', raw_text))
    ocg_layers: List[str] = []
    if has_ocg:
        try:
            layers = doc.get_ocgs()
            for k, v in layers.items():
                if isinstance(v, dict):
                    ocg_layers.append(v.get("name", f"Layer {k}"))
        except Exception:
            pass

    return {
        "white_text_count": len(white_text_spans),
        "white_text_spans": white_text_spans[:25],
        "tiny_font_count": len(tiny_font_spans),
        "tiny_font_spans": tiny_font_spans[:25],
        "off_page_count": len(off_page_spans),
        "off_page_spans": off_page_spans[:25],
        "has_invisible_render_mode": has_invisible_render_mode,
        "deceptive_link_count": len(deceptive_links),
        "deceptive_links": deceptive_links,
        "has_ocg": has_ocg,
        "ocg_layers": ocg_layers
    }


def inspect_action_chains(doc: Any, raw_text: str) -> List[Dict[str, Any]]:
    """
    Constructs an interactive manifest of automatic actions, document event hooks,
    and chained execution triggers across Catalog, Pages, Annotations, and Forms.
    """
    actions: List[Dict[str, Any]] = []

    # 1. Document Catalog /OpenAction
    oa_m = re.search(r'/OpenAction\s*(?:<<([^>]+)>>|\[([0-9\s/A-Za-z]+)\]|(\d+\s+\d+\s+R))', raw_text)
    if oa_m:
        val = oa_m.group(1) or oa_m.group(2) or oa_m.group(3) or ""
        act_type = "Navigation / View"
        if "/Launch" in val:
            act_type = "OS Process Launch (/Launch)"
        elif "/JavaScript" in val or "/JS" in val:
            act_type = "Execute JavaScript (/JS)"
        elif "/URI" in val:
            act_type = "Navigate to External URI (/URI)"
        elif "/SubmitForm" in val:
            act_type = "Exfiltrate Form (/SubmitForm)"

        actions.append({
            "trigger_hook": "Document Open (/OpenAction)",
            "scope": "Document Catalog",
            "action_type": act_type,
            "severity": "critical" if "/Launch" in val else "high" if ("/JS" in val or "/JavaScript" in val or "/SubmitForm" in val) else "medium",
            "raw_snippet": val[:120].strip()
        })

    # 2. Additional Actions (/AA) in Catalog or Pages
    aa_blocks: List[str] = []
    for aa_match in re.finditer(r'/AA\s*<<', raw_text):
        start = aa_match.end()
        depth = 1
        pos = start
        while pos < len(raw_text) and depth > 0:
            if raw_text[pos:pos+2] == '<<':
                depth += 1
                pos += 2
            elif raw_text[pos:pos+2] == '>>':
                depth -= 1
                pos += 2
            else:
                pos += 1
        aa_blocks.append(raw_text[start:pos-2 if depth == 0 else min(pos, start + 2000)])

    events = [
        ("/E", "Mouse Cursor Hover / Enter (/E)", "high"),
        ("/X", "Mouse Cursor Exit (/X)", "medium"),
        ("/D", "Mouse Button Down / Click (/D)", "high"),
        ("/U", "Mouse Button Up / Release (/U)", "medium"),
        ("/PV", "Page Viewport Visible (/PV)", "high"),
        ("/PI", "Page Viewport Invisible (/PI)", "medium"),
        ("/O", "Page Opened (/O)", "high"),
        ("/C", "Page Closed (/C)", "medium"),
        ("/WC", "Document Will Close (/WC)", "high"),
        ("/WS", "Document Will Save (/WS)", "high"),
        ("/DS", "Document Did Save (/DS)", "high"),
        ("/WP", "Document Will Print (/WP)", "high"),
        ("/DP", "Document Did Print (/DP)", "high"),
        ("/K", "Form Field Keystroke (/K)", "medium"),
        ("/V", "Form Field Validate (/V)", "high"),
        ("/C", "Form Field Calculate (/C)", "high"),
    ]

    for block in aa_blocks:
        for k, label, sev in events:
            if re.search(rf'{k}\s*<<', block) or re.search(rf'{k}\s*\d+\s+\d+\s+R', block):
                act_type = "Interactive Event Action"
                if "/Launch" in block:
                    act_type = "Launch Process (/Launch)"
                    sev = "critical"
                elif "/JavaScript" in block or "/JS" in block:
                    act_type = "Execute JavaScript (/JS)"
                elif "/URI" in block:
                    act_type = "Navigate External URI (/URI)"

                actions.append({
                    "trigger_hook": label,
                    "scope": "Event Lifecycle (/AA)",
                    "action_type": act_type,
                    "severity": sev,
                    "raw_snippet": block[:120].strip()
                })

    # 3. Chained /Next Actions
    next_m = re.findall(r'/Next\s*(?:<<[^>]+>>|\[[^\]]+\]|\d+\s+\d+\s+R)', raw_text)
    for nm in next_m:
        actions.append({
            "trigger_hook": "Sequential Chained Action (/Next)",
            "scope": "Action Sequence",
            "action_type": "Chained Execution Hook",
            "severity": "medium",
            "raw_snippet": nm[:100].strip()
        })

    return actions[:30]


def carve_and_inspect_attachments(doc: Any, raw_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Extracts embedded attachments from /EmbeddedFiles and /EF dictionaries.
    Inspects binary signatures (PE executables, scripts, LNK, archives) and assigns threat verdicts.
    """
    carved_files: List[Dict[str, Any]] = []

    try:
        count = doc.embfile_count()
        for idx in range(count):
            try:
                info = doc.embfile_info(idx)
                raw_name = info.get("filename") or f"attachment_{idx}.bin"
                payload = doc.embfile_get(idx)
                if not payload:
                    continue

                sha256_hash = hashlib.sha256(payload).hexdigest()
                size = len(payload)

                # Classify payload
                is_threat = False
                threat_level = "neutral"
                classification = "Data / Document Attachment"

                # Check PE executable
                if payload.startswith(b"MZ") and b"PE\x00\x00" in payload[:1024]:
                    is_threat = True
                    threat_level = "critical"
                    classification = "Windows PE Executable (EXE/DLL)"
                # Check Windows Shell Link LNK
                elif payload.startswith(b"\x4C\x00\x00\x00\x01\x14\x02\x00"):
                    is_threat = True
                    threat_level = "critical"
                    classification = "Windows Shell Link (.lnk)"
                # Check Batch Scripts
                elif raw_name.lower().endswith(('.bat', '.cmd')) or re.search(rb'(?i)^\s*@(echo\s+off|rem\b|set\b)', payload):
                    is_threat = True
                    threat_level = "critical"
                    classification = "Windows Batch Script (BAT/CMD)"
                # Check PowerShell Scripts
                elif raw_name.lower().endswith('.ps1') or re.search(rb'(?i)(?:invoke-expression|invoke-webrequest|start-process|\$null\s*=\b)', payload):
                    is_threat = True
                    threat_level = "critical"
                    classification = "PowerShell Script (PS1)"
                # Check VBScript / JS / HTA
                elif raw_name.lower().endswith(('.vbs', '.vbe', '.js', '.jse', '.hta', '.wsf')) or re.search(rb'(?i)(?:wscript\.shell|createobject\(|eval\()', payload):
                    is_threat = True
                    threat_level = "critical"
                    classification = "Windows Script Host (VBS/JS/HTA)"
                # Check Office Macro Packages
                elif payload.startswith(b"PK\x03\x04") and (b"vbaProject.bin" in payload or raw_name.lower().endswith(('.docm', '.xlsm', '.pptm'))):
                    is_threat = True
                    threat_level = "critical"
                    classification = "Weaponized Office Macro Document"
                # Check Archives
                elif payload.startswith(b"PK\x03\x04"):
                    threat_level = "suspicious"
                    classification = "ZIP / Archive Container"
                elif payload.startswith(b"7z\xbc\xaf\x27\x1c"):
                    threat_level = "suspicious"
                    classification = "7-Zip Compressed Archive"
                elif payload.startswith(b"Rar!\x1a\x07"):
                    threat_level = "suspicious"
                    classification = "RAR Compressed Archive"
                elif raw_name.lower().endswith(('.exe', '.dll', '.scr', '.pif', '.cpl')):
                    is_threat = True
                    threat_level = "critical"
                    classification = "Dangerous Executable Extension"

                carved_files.append({
                    "id": idx,
                    "filename": raw_name,
                    "size": size,
                    "size_formatted": f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B",
                    "sha256": sha256_hash,
                    "classification": classification,
                    "is_threat": is_threat,
                    "threat_level": threat_level,
                    "description": info.get("desc", ""),
                    "hex_preview": format_hex_preview(payload[:64], max_len=64)
                })
            except Exception:
                pass
    except Exception:
        pass

    return carved_files
