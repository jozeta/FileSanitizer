import datetime
import re
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from app.analyzers.base import Finding

class MetadataField(BaseModel):
    name: str
    value: str
    is_sensitive: bool = False
    category: str = "general"  # general, document, location, camera, embedded

class StructuredMetadata(BaseModel):
    general: List[MetadataField] = Field(default_factory=list)
    document: List[MetadataField] = Field(default_factory=list)
    location: List[MetadataField] = Field(default_factory=list)
    camera: List[MetadataField] = Field(default_factory=list)
    embedded: List[MetadataField] = Field(default_factory=list)
    forensic_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    total_fields: int = 0
    sensitive_count: int = 0

# Magic byte signatures database: MIME type → (hex signature, description)
_MAGIC_BYTE_MAP: dict = {
    "image/jpeg":                       ("FF D8 FF",           "JPEG image — JFIF/EXIF header (ISO 10918-1)"),
    "image/png":                        ("89 50 4E 47 0D 0A 1A 0A", "PNG image — Portable Network Graphics (RFC 2083)"),
    "image/gif":                        ("47 49 46 38",        "GIF image — Graphics Interchange Format 87a/89a"),
    "image/tiff":                       ("49 49 2A 00",        "TIFF image — Tagged Image File Format (little-endian)"),
    "image/bmp":                        ("42 4D",              "BMP image — Windows Bitmap (Device-Independent Bitmap)"),
    "image/webp":                       ("52 49 46 46 ?? ?? ?? ?? 57 45 42 50", "WebP image — RIFF container with WEBP FourCC"),
    "image/svg+xml":                    ("3C 73 76 67 / 3C 3F 78 6D 6C", "SVG — XML-based Scalable Vector Graphics"),
    "application/pdf":                  ("%PDF- (25 50 44 46 2D)", "PDF — Portable Document Format header (ISO 32000)"),
    "application/zip":                  ("50 4B 03 04",        "ZIP archive — PKWARE Local File Header signature"),
    "application/x-7z-compressed":      ("37 7A BC AF 27 1C",  "7-Zip archive — 7z self-extracting/compressed container"),
    "application/gzip":                 ("1F 8B",              "GZIP — GNU compressed data (RFC 1952)"),
    "application/x-tar":                ("75 73 74 61 72 (offset 257)", "TAR archive — POSIX ustar magic at byte offset 257"),
    "application/x-ole-storage":        ("D0 CF 11 E0 A1 B1 1A E1", "OLE Compound File — Microsoft Office 97-2003 container (CFBF)"),
    "application/vnd.ms-outlook":       ("D0 CF 11 E0 A1 B1 1A E1", "OLE Compound File — Microsoft Outlook MSG (MAPI/CFBF format)"),
    "application/rtf":                  ("{\\rtf (7B 5C 72 74 66)", "RTF — Rich Text Format document header"),
    "application/x-dosexec":            ("4D 5A (MZ)",         "PE/COFF — Windows Portable Executable MZ header (DOS stub)"),
    "application/x-executable":         ("7F 45 4C 46 (ELF)",  "ELF — Executable and Linkable Format (Linux/Unix binary)"),
    "application/x-mach-binary":        ("CF FA ED FE / CA FE BA BE", "Mach-O — Apple macOS/iOS executable (64-bit / Fat binary)"),
    "application/x-sharedlib":          ("7F 45 4C 46",        "ELF Shared Library — Linux/Unix dynamic shared object (.so)"),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":  ("50 4B 03 04", "DOCX — OOXML Word document (ZIP + [Content_Types].xml)"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":        ("50 4B 03 04", "XLSX — OOXML Excel workbook (ZIP + xl/workbook.xml)"),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation":("50 4B 03 04", "PPTX — OOXML PowerPoint presentation (ZIP + ppt/presentation.xml)"),
    "application/vnd.ms-excel":         ("D0 CF 11 E0 A1 B1 1A E1", "XLS — Legacy Excel workbook (OLE Compound File)"),
    "application/vnd.ms-powerpoint":    ("D0 CF 11 E0 A1 B1 1A E1", "PPT — Legacy PowerPoint file (OLE Compound File)"),
    "application/msword":               ("D0 CF 11 E0 A1 B1 1A E1", "DOC — Legacy Word document (OLE Compound File)"),
    "text/html":                        ("3C 68 74 6D 6C / 3C 21 44", "HTML — HyperText Markup Language (ASCII/UTF-8 text)"),
    "text/plain":                       ("(UTF-8 text / no magic)", "Plain text — No fixed magic bytes; identified by printable ASCII/UTF-8 content"),
    "text/csv":                         ("(CSV text / no magic)",   "CSV — Comma-Separated Values; text format, identified by content structure"),
    "text/javascript":                  ("(text/script)",       "JavaScript — Plain text script, no fixed magic bytes"),
    "application/x-shellscript":        ("23 21 (shebang)",    "Shell script — Starts with shebang line (#!/bin/sh, #!/bin/bash, etc.)"),
    "application/x-powershell":         ("(text/script)",       "PowerShell script — Plain text with .ps1 extension, no fixed magic bytes"),
    "message/rfc822":                   ("(RFC 2822 headers)",  "Email — RFC 2822 message; identified by MIME headers (From:, Subject:, etc.)"),
    "application/x-bzip2":              ("42 5A 68",            "BZIP2 — BZ2 compressed archive (BZh magic header)"),
    "application/x-rar-compressed":     ("52 61 72 21 1A 07",   "RAR archive — Roshal ARchive (RAR 5.0 signature)"),
}

def _get_magic_byte_info(mime_type: str) -> str:
    """Return a human-readable magic byte signature string for a given MIME type."""
    entry = _MAGIC_BYTE_MAP.get(mime_type)
    if not entry:
        return ""
    hex_sig, description = entry
    return f"{hex_sig} → {description}"


def _parse_metadata_timestamp(val: str) -> Optional[datetime.datetime]:
    """Parse various metadata timestamp formats (PDF D: prefix, ISO, EXIF)."""
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    if val.startswith("D:"):
        digits = re.sub(r'[^0-9]', '', val[2:])
        if len(digits) >= 8:
            try:
                y = int(digits[:4])
                m = int(digits[4:6])
                d = int(digits[6:8])
                h = int(digits[8:10]) if len(digits) >= 10 else 0
                minute = int(digits[10:12]) if len(digits) >= 12 else 0
                sec = int(digits[12:14]) if len(digits) >= 14 else 0
                return datetime.datetime(y, m, d, h, minute, sec)
            except Exception:
                pass

    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.datetime.strptime(val[:19], fmt[:len(val[:19])])
        except Exception:
            pass
    return None


def detect_metadata_anomalies(doc_meta: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    """Inspect document metadata for timestomping, epoch zeroing, and suspicious author fingerprints."""
    anomalies: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    created_raw = ""
    modified_raw = ""
    author_raw = ""
    producer_raw = ""

    for k, v in doc_meta.items():
        k_lower = k.lower()
        if any(term in k_lower for term in ["created", "creation_date", "creationdate", "datetimeoriginal"]):
            created_raw = str(v)
        elif any(term in k_lower for term in ["modified", "mod_date", "modificationdate", "lastmodified"]):
            modified_raw = str(v)
        elif any(term in k_lower for term in ["author", "creator", "artist"]):
            author_raw = str(v)
        elif any(term in k_lower for term in ["producer", "software", "application"]):
            producer_raw = str(v)

    dt_created = _parse_metadata_timestamp(created_raw)
    dt_modified = _parse_metadata_timestamp(modified_raw)
    now = datetime.datetime.utcnow()

    # 1. Timestomping: Created > Modified
    if dt_created and dt_modified and dt_created > dt_modified:
        anomaly = {
            "type": "timestomping_reversed",
            "title": "Timestomping Anomaly: Creation Date Posterior to Modification Date",
            "details": f"Created: {created_raw} vs Modified: {modified_raw}",
            "severity": "high"
        }
        anomalies.append(anomaly)
        findings.append(Finding(
            category="metadata",
            severity="high",
            title="Metadata Timestomping Anomaly: Created Date is Newer than Modified Date",
            description=(
                f"Document timestamp analysis revealed that the recorded creation timestamp ({created_raw}) "
                f"is after the last modification timestamp ({modified_raw}). In forensic timeline analysis, "
                "this inconsistency is a primary indicator of timestomping or anti-forensic metadata manipulation."
            ),
            details=anomaly
        ))

    # 2. Future Timestamps
    for label, raw, dt in [("Creation Date", created_raw, dt_created), ("Modification Date", modified_raw, dt_modified)]:
        if dt and dt > (now + datetime.timedelta(days=1)):
            anomaly = {
                "type": "timestomping_future",
                "title": f"Future Timestamp Detected in {label}",
                "details": f"{label}: {raw} (Current UTC: {now.strftime('%Y-%m-%d')})",
                "severity": "high"
            }
            anomalies.append(anomaly)
            findings.append(Finding(
                category="metadata",
                severity="high",
                title=f"Metadata Timestomping Anomaly: {label} Set in Future",
                description=f"Document {label.lower()} '{raw}' is set in the future. Suggests intentional clock skew or timestomping.",
                details=anomaly
            ))

    # 3. Anachronistic / Epoch default timestamps
    for label, raw, dt in [("Creation Date", created_raw, dt_created), ("Modification Date", modified_raw, dt_modified)]:
        if dt and dt.year < 1995:
            anomaly = {
                "type": "epoch_reset",
                "title": f"Anachronistic / Epoch Reset in {label} ({dt.year})",
                "details": f"{label}: {raw}",
                "severity": "medium"
            }
            anomalies.append(anomaly)
            findings.append(Finding(
                category="metadata",
                severity="medium",
                title=f"Metadata Anomaly: Default Epoch Reset in {label} ({dt.year})",
                description=f"Document {label.lower()} '{raw}' dates back to {dt.year} (pre-1995 or zero-epoch FILETIME/Unix default).",
                details=anomaly
            ))

    # 4. Generic Author Profiling
    clean_author = author_raw.strip().lower()
    if clean_author in ["administrator", "admin", "user", "root", "template", "default", "guest", "owner"]:
        anomaly = {
            "type": "generic_author",
            "title": f"Generic System Author Account: '{author_raw}'",
            "details": f"Author field: {author_raw}",
            "severity": "medium"
        }
        anomalies.append(anomaly)
        findings.append(Finding(
            category="metadata",
            severity="medium",
            title=f"Author Profile Anomaly: Generic Account '{author_raw}'",
            description=(
                f"Document author is set to generic default account '{author_raw}'. "
                "Attackers frequently build malicious documents in fresh unconfigured VMs or sandbox containers."
            ),
            details=anomaly
        ))

    # 5. Weaponized Builder Tools / Script Generators
    SUSPICIOUS_PRODUCERS = ["metasploit", "empire", "cobalt", "wkhtmltopdf", "pdfkit", "reportlab", "dompdf", "mpdf", "tcpdf", "python", "poi"]
    for sp in SUSPICIOUS_PRODUCERS:
        if sp in producer_raw.lower():
            anomaly = {
                "type": "scripted_producer",
                "title": f"Scripted Document Generator: '{producer_raw}'",
                "details": f"Producer: {producer_raw}",
                "severity": "medium"
            }
            anomalies.append(anomaly)
            findings.append(Finding(
                category="metadata",
                severity="medium",
                title=f"Generator Anomaly: Document Produced by Scripting Tool '{producer_raw}'",
                description=f"Document software/producer matches automated generator toolkit '{producer_raw}'.",
                details=anomaly
            ))
            break

    return anomalies, findings


class MetadataExtractor:
    @classmethod
    def consolidate(
        cls,
        filename: str,
        file_size: int,
        mime_type: str,
        hashes: Dict[str, str],
        analysis_data: Dict[str, Any]
    ) -> StructuredMetadata:
        general: List[MetadataField] = []
        document: List[MetadataField] = []
        location: List[MetadataField] = []
        camera: List[MetadataField] = []
        embedded: List[MetadataField] = []

        # 1. General
        general.append(MetadataField(name="Filename", value=filename, category="general"))
        general.append(MetadataField(name="File Size", value=f"{file_size:,} bytes", category="general"))
        general.append(MetadataField(name="MIME Type", value=mime_type, category="general"))
        magic_byte_info = _get_magic_byte_info(mime_type)
        if magic_byte_info:
            general.append(MetadataField(
                name="Magic Byte Signature",
                value=magic_byte_info,
                category="general"
            ))
        general.append(MetadataField(name="SHA-256", value=hashes.get("sha256", "N/A"), category="general"))
        general.append(MetadataField(name="MD5", value=hashes.get("md5", "N/A"), category="general"))

        # 2. Location (GPS)
        image_data = analysis_data.get("image", {})
        if image_data.get("has_gps") and image_data.get("gps_coordinates"):
            coords = image_data["gps_coordinates"]
            location.append(MetadataField(
                name="GPS Coordinates",
                value=coords.get("readable", "Present"),
                is_sensitive=True,
                category="location"
            ))
            if coords.get("location_name") and coords.get("city") != "Unknown City":
                location.append(MetadataField(
                    name="Resolved Location",
                    value=coords["location_name"],
                    is_sensitive=True,
                    category="location"
                ))
            if coords.get("city") and coords.get("city") != "Unknown City":
                location.append(MetadataField(
                    name="City",
                    value=coords["city"],
                    is_sensitive=True,
                    category="location"
                ))
            if coords.get("country") and coords.get("country") != "Unknown Country":
                location.append(MetadataField(
                    name="Country",
                    value=coords["country"],
                    is_sensitive=True,
                    category="location"
                ))
            location.append(MetadataField(
                name="Latitude",
                value=str(coords.get("latitude", "")),
                is_sensitive=True,
                category="location"
            ))
            location.append(MetadataField(
                name="Longitude",
                value=str(coords.get("longitude", "")),
                is_sensitive=True,
                category="location"
            ))

        # 3. Document / Author
        doc_meta = {}
        pdf_data = analysis_data.get("pdf", {})
        if pdf_data.get("metadata"):
            doc_meta.update(pdf_data["metadata"])

        office_data = analysis_data.get("office", {})
        if office_data.get("metadata"):
            doc_meta.update(office_data["metadata"])

        if image_data.get("author_info"):
            doc_meta.update(image_data["author_info"])

        for k, v in doc_meta.items():
            if v and str(v).strip():
                k_lower = k.lower()
                has_url = "http://" in str(v) or "https://" in str(v)
                is_sens = any(term in k_lower for term in ["author", "creator", "modifier", "lastmodified", "producer"]) or has_url
                document.append(MetadataField(
                    name=k.capitalize(),
                    value=str(v),
                    is_sensitive=is_sens,
                    category="document"
                ))

        # 4. Camera Hardware / Software
        cam_info = image_data.get("camera_info", {})
        for k, v in cam_info.items():
            is_sens = (k in ["BodySerialNumber", "Software"])
            camera.append(MetadataField(
                name=k,
                value=str(v),
                is_sensitive=is_sens,
                category="camera"
            ))

        # 5. Embedded Content Summary
        urls = analysis_data.get("urls", [])
        embedded.append(MetadataField(
            name="External URLs",
            value=f"{len(urls)} discovered",
            is_sensitive=(len(urls) > 0),
            category="embedded"
        ))

        has_js = (
            pdf_data.get("has_javascript") or
            analysis_data.get("active_content", {}).get("has_javascript")
        )
        embedded.append(MetadataField(
            name="JavaScript",
            value="DETECTED" if has_js else "NO",
            is_sensitive=bool(has_js),
            category="embedded"
        ))

        has_macros = office_data.get("has_macros", False)
        embedded.append(MetadataField(
            name="VBA Macros",
            value="DETECTED" if has_macros else "NO",
            is_sensitive=bool(has_macros),
            category="embedded"
        ))

        has_att = (
            pdf_data.get("has_embedded_files") or
            office_data.get("has_embedded_files") or
            office_data.get("has_ole_objects")
        )
        att_count = len(pdf_data.get("embedded_files", [])) + len(office_data.get("ole_objects", []))
        embedded.append(MetadataField(
            name="Attachments / OLE Objects",
            value=f"{att_count} found" if has_att else "0",
            is_sensitive=bool(has_att),
            category="embedded"
        ))

        # 6. Detect Forensic Anomaly indicators
        anomalies, _ = detect_metadata_anomalies(doc_meta)

        all_fields = general + document + location + camera + embedded
        total = len(all_fields)
        sens = sum(1 for f in all_fields if f.is_sensitive)

        return StructuredMetadata(
            general=general,
            document=document,
            location=location,
            camera=camera,
            embedded=embedded,
            forensic_anomalies=anomalies,
            total_fields=total,
            sensitive_count=sens
        )
