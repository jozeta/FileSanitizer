import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set, Optional
import fitz

from app.core.logging_config import logger

# Canonical Didier Stevens PDFiD token keys + extended modern exploit tokens
PDFID_TAGS = [
    "/Page",
    "/Encrypt",
    "/ObjStm",
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/AcroForm",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFiles",
    "/XFA",
    "/URI",
    "/GoToE",
    "/GoToR",
    "/SubmitForm",
    "/ImportData",
    "/Thread",
    "/AF",
    "/FontMatrix",
    "/Colors"
]

TOKEN_THREAT_SUMMARIES = {
    "/JS": "Embedded JavaScript execution block. Exploitable for client-side code execution or browser API misuse.",
    "/JavaScript": "Embedded JavaScript action catalog. Detonates automated scripts inside the PDF engine.",
    "/OpenAction": "Automatic execution trigger detonating immediately upon opening the document without user consent.",
    "/AA": "Additional Actions (/PV, /PC, /E, /WC, /WS, /DP, /WP). Auto-executes scripts on page view, hover, or close.",
    "/Launch": "Operating system process launch action. Can execute local binaries or trigger remote downloads.",
    "/GoToE": "Embedded file navigation. Frequently exploited with UNC paths to force NTLM authentication leaks (CVE-2018-4993).",
    "/GoToR": "Remote document jump. Forces external document fetching and leaks network/proxy telemetry.",
    "/SubmitForm": "Form data submission hook. Flags 256 exfiltrates the entire PDF document; targets external endpoints.",
    "/ImportData": "External data import trigger. Imports remote XML/FDF payloads or executes malicious FormCalc.",
    "/Thread": "Article thread navigation action. Remote FileSpec targets trigger silent background network connections.",
    "/XFA": "XML Forms Architecture dynamic template. Prone to XXE injection, FormCalc Post() exfiltration, and stylesheet injections.",
    "/AcroForm": "Interactive form dictionary. Frequently used to stage base64 payloads, malicious fields, or submit actions.",
    "/EmbeddedFiles": "Document attachments and embedded binaries. Frequently bundles droppers, malware, or polyglots.",
    "/RichMedia": "RichMedia annotation (Flash, 3D, HTML). Exploitable for Content Security Policy bypass (CVE-2022-28244).",
    "/JBIG2Decode": "JBIG2 stream filter. Historically targeted for memory corruption exploits (e.g. FORCEDENTRY, CVE-2021-30860).",
    "/URI": "External hyperlink or web navigation. Exploited for phone-home tracking, SSRF, or UNC credential theft.",
    "/AF": "PDF 2.0 Associated Files array. Encapsulates external scripts, HTML, or attachments in modern PDF specs.",
    "/ObjStm": "Object Stream compression. Obfuscates and clusters internal PDF objects away from basic regex scanners.",
    "/Encrypt": "Document encryption structure. May conceal malicious payload objects from static inspection.",
    "/FontMatrix": "Type1 PostScript FontMatrix coordinate transform array. Target of CVE-2024-4367 sandbox breakout.",
    "/Colors": "Color component depth field. Potential CVE-2009-3459 integer overflow trigger if value exceeds 2^24.",
    "/Page": "Page object descriptor defining document layout and visual pages."
}


def deobfuscate_pdf_name(name: str) -> str:
    """
    Didier Stevens PDFiD hex de-obfuscation:
    In PDF names, '#xx' encodes a byte (e.g. '/J#61vaScript' -> '/JavaScript').
    Malware authors use this to evade simple signature string searches.
    """
    def _hex_sub(match):
        hex_val = match.group(1)
        try:
            return chr(int(hex_val, 16))
        except Exception:
            return match.group(0)

    return re.sub(r'#([0-9a-fA-F]{2})', _hex_sub, name)


class DidierPDFAnalyzer:
    """
    Incorporates Didier Stevens' PDF analysis algorithms (PDFiD / stream inspection)
    and AnalyzePDF capabilities for high-precision exploit detection and artifact inspection.
    """

    @classmethod
    def scan_file(cls, file_path: Path) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        raw_text = raw_bytes.decode('latin-1', errors='ignore')

        # 1. Didier Stevens PDFiD Tag Counting & Hex-Obfuscation Analysis
        tag_counts: Dict[str, int] = {tag: 0 for tag in PDFID_TAGS}
        obfuscated_tags: Dict[str, int] = {tag: 0 for tag in PDFID_TAGS}
        obfuscated_samples: Dict[str, List[str]] = {tag: [] for tag in PDFID_TAGS}
        token_occurrences: Dict[str, List[Dict[str, Any]]] = {tag: [] for tag in PDFID_TAGS}

        # Pattern matches /Name including potential #xx hex escapes
        name_pattern = re.compile(r'/([A-Za-z0-9#_]+)')
        for match in name_pattern.finditer(raw_text):
            raw_name = "/" + match.group(1)
            decoded_name = deobfuscate_pdf_name(raw_name)

            for tag in PDFID_TAGS:
                if decoded_name == tag or decoded_name.startswith(tag + "/") or decoded_name.startswith(tag + " ") or decoded_name.startswith(tag + ">>"):
                    tag_counts[tag] += 1
                    is_obf = "#" in raw_name
                    if is_obf:
                        obfuscated_tags[tag] += 1
                        if raw_name not in obfuscated_samples[tag] and len(obfuscated_samples[tag]) < 10:
                            obfuscated_samples[tag].append(raw_name)

                    # Extract context snippet around match
                    start_pos = max(0, match.start() - 60)
                    end_pos = min(len(raw_text), match.end() + 140)
                    snippet = raw_text[start_pos:end_pos].strip()

                    # Try to extract meaningful parameter / value
                    extracted_val = ""
                    val_match = re.search(r'\(([^)]+)\)', raw_text[match.end():match.end() + 160])
                    if val_match:
                        extracted_val = val_match.group(1).strip()
                    elif re.search(r'<<(.*?)>>', raw_text[match.start():match.start() + 200], re.DOTALL):
                        dict_match = re.search(r'<<(.*?)>>', raw_text[match.start():match.start() + 200], re.DOTALL)
                        if dict_match:
                            extracted_val = dict_match.group(0).strip()[:100]

                    if len(token_occurrences[tag]) < 25:
                        token_occurrences[tag].append({
                            "token": tag,
                            "raw_token": raw_name,
                            "is_obfuscated": is_obf,
                            "snippet": snippet,
                            "extracted_value": extracted_val,
                            "threat_summary": TOKEN_THREAT_SUMMARIES.get(tag, "PDF dictionary artifact")
                        })

        # Check for /Colors > 2^24 vulnerability pattern (CVE-2009-3459)
        colors_vuln = bool(re.search(r'/Colors\s+([0-9]{8,})', raw_text))

        # Check for suspicious stream filters
        has_jbig2 = tag_counts.get("/JBIG2Decode", 0) > 0
        has_launch = tag_counts.get("/Launch", 0) > 0
        has_aa = tag_counts.get("/AA", 0) > 0
        has_openaction = tag_counts.get("/OpenAction", 0) > 0
        has_js = (tag_counts.get("/JS", 0) + tag_counts.get("/JavaScript", 0)) > 0
        has_obfuscation = any(cnt > 0 for cnt in obfuscated_tags.values())

        # 2. JavaScript Code Extraction from Document Objects & PyMuPDF
        extracted_js_list = []
        try:
            doc = fitz.open(file_path)
            # PyMuPDF 1.18+ exposes document-level JavaScript via doc.get_js()
            if hasattr(doc, "get_js"):
                doc_js = doc.get_js()
                if doc_js:
                    extracted_js_list.append({
                        "name": "Document Catalog JS",
                        "xref": 0,
                        "code": doc_js
                    })

            # Scan object streams for /JS and extract stream contents
            for xref in range(1, doc.xref_length()):
                try:
                    obj_text = doc.xref_object(xref)
                    deobf_obj = deobfuscate_pdf_name(obj_text)

                    # Check for token occurrences with xref correlation
                    for tag in PDFID_TAGS:
                        if tag in deobf_obj:
                            # Attach xref to matching occurrence
                            for occ in token_occurrences.get(tag, []):
                                if occ.get("xref") is None and (occ["raw_token"] in obj_text or tag in deobf_obj):
                                    occ["xref"] = xref

                    if "/JS" in deobf_obj or "/JavaScript" in deobf_obj:
                        # Attempt to extract stream or string
                        stream_bytes = doc.xref_stream(xref)
                        if stream_bytes:
                            js_str = stream_bytes.decode('latin-1', errors='ignore')
                            if len(js_str.strip()) > 3:
                                extracted_js_list.append({
                                    "name": f"Object Stream {xref}",
                                    "xref": xref,
                                    "code": js_str
                                })
                        else:
                            # Might be inline string /JS (code)
                            str_m = re.search(r'/JS\s*\((.*?)\)', obj_text, re.DOTALL)
                            if str_m and len(str_m.group(1).strip()) > 3:
                                extracted_js_list.append({
                                    "name": f"Object #{xref} Inline JS",
                                    "xref": xref,
                                    "code": str_m.group(1).strip()
                                })
                except Exception:
                    pass

            doc.close()
        except Exception as e:
            logger.debug(f"PyMuPDF JS extraction note: {e}")

        # If PyMuPDF did not catch raw streams, check regex matches in raw_text
        if not extracted_js_list and has_js:
            raw_js_matches = re.findall(r'/JS\s*\((.*?)\)(?:/|>>|\s)', raw_text, re.DOTALL)
            for i, raw_m in enumerate(raw_js_matches):
                if raw_m.strip():
                    extracted_js_list.append({
                        "name": f"Inline Script {i+1}",
                        "xref": None,
                        "code": raw_m.strip()
                    })

        combined_js_code = "\n\n// --- Next Script Stream ---\n\n".join(
            item["code"] for item in extracted_js_list
        ) if extracted_js_list else ""

        # Construct structured per-token details for frontend interactive inspection
        token_details = {}
        for tag in PDFID_TAGS:
            count = tag_counts.get(tag, 0)
            obf_count = obfuscated_tags.get(tag, 0)
            token_details[tag] = {
                "token": tag,
                "count": count,
                "obfuscated_count": obf_count,
                "obfuscated_samples": obfuscated_samples.get(tag, []),
                "threat_summary": TOKEN_THREAT_SUMMARIES.get(tag, "PDF token artifact"),
                "occurrences": token_occurrences.get(tag, [])
            }

        return {
            "pdfid_counts": tag_counts,
            "obfuscated_tags": obfuscated_tags,
            "obfuscated_samples": obfuscated_samples,
            "pdfid_token_details": token_details,
            "has_hex_obfuscation": has_obfuscation,
            "colors_overflow_vuln": colors_vuln,
            "has_launch": has_launch,
            "has_automatic_action": has_aa or has_openaction,
            "has_javascript": has_js or bool(combined_js_code),
            "extracted_scripts_count": len(extracted_js_list),
            "extracted_js_modules": extracted_js_list,
            "combined_js_code": combined_js_code
        }
