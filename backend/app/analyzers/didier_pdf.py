import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set
import fitz

from app.core.logging_config import logger

# Canonical Didier Stevens PDFiD token keys
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
    "/URI"
]

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
    and AnalyzePDF capabilities for high-precision exploit detection.
    """

    @classmethod
    def scan_file(cls, file_path: Path) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        raw_text = raw_bytes.decode('latin-1', errors='ignore')

        # 1. Didier Stevens PDFiD Tag Counting & Hex-Obfuscation Analysis
        tag_counts = {}
        obfuscated_tags = {}

        for tag in PDFID_TAGS:
            tag_counts[tag] = 0
            obfuscated_tags[tag] = 0

        # Pattern matches /Name including potential #xx hex escapes
        name_pattern = re.compile(r'/([A-Za-z0-9#_]+)')
        for match in name_pattern.finditer(raw_text):
            raw_name = "/" + match.group(1)
            decoded_name = deobfuscate_pdf_name(raw_name)

            for tag in PDFID_TAGS:
                if decoded_name == tag or decoded_name.startswith(tag + "/") or decoded_name.startswith(tag + " ") or decoded_name.startswith(tag + ">>"):
                    tag_counts[tag] += 1
                    if "#" in raw_name:
                        obfuscated_tags[tag] += 1

        # Check for /Colors > 2^24 vulnerability pattern (CVE-2009-3459)
        colors_vuln = bool(re.search(r'/Colors\s+([0-9]{8,})', raw_text))

        # Check for suspicious stream filters
        has_jbig2 = tag_counts.get("/JBIG2Decode", 0) > 0
        has_launch = tag_counts.get("/Launch", 0) > 0
        has_aa = tag_counts.get("/AA", 0) > 0
        has_openaction = tag_counts.get("/OpenAction", 0) > 0
        has_js = (tag_counts.get("/JS", 0) + tag_counts.get("/JavaScript", 0)) > 0
        has_obfuscation = any(cnt > 0 for cnt in obfuscated_tags.values())

        # 2. JavaScript Code Extraction from Document
        extracted_js_list = []
        try:
            doc = fitz.open(file_path)
            # PyMuPDF 1.18+ exposes document-level JavaScript via doc.get_js()
            if hasattr(doc, "get_js"):
                doc_js = doc.get_js()
                if doc_js:
                    extracted_js_list.append({
                        "name": "Document Catalog JS",
                        "code": doc_js
                    })

            # Scan object streams for /JS and extract stream contents
            for xref in range(1, doc.xref_length()):
                try:
                    obj_text = doc.xref_object(xref)
                    if "/JS" in obj_text or "/JavaScript" in obj_text:
                        # Attempt to extract stream or string
                        stream_bytes = doc.xref_stream(xref)
                        if stream_bytes:
                            js_str = stream_bytes.decode('latin-1', errors='ignore')
                            if len(js_str.strip()) > 5:
                                extracted_js_list.append({
                                    "name": f"Object Stream {xref}",
                                    "code": js_str
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
                        "code": raw_m.strip()
                    })

        combined_js_code = "\n\n// --- Next Script Stream ---\n\n".join(
            item["code"] for item in extracted_js_list
        ) if extracted_js_list else ""

        return {
            "pdfid_counts": tag_counts,
            "obfuscated_tags": obfuscated_tags,
            "has_hex_obfuscation": has_obfuscation,
            "colors_overflow_vuln": colors_vuln,
            "has_launch": has_launch,
            "has_automatic_action": has_aa or has_openaction,
            "has_javascript": has_js or bool(combined_js_code),
            "extracted_scripts_count": len(extracted_js_list),
            "extracted_js_modules": extracted_js_list,
            "combined_js_code": combined_js_code
        }
