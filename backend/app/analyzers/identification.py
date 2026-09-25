import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
import puremagic

# Known signatures mapping for reliable identification
FILE_SIGNATURES = [
    # Images
    (b"\xFF\xD8\xFF", "image/jpeg", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
    (b"II*\x00", "image/tiff", "tiff"),
    (b"MM\x00*", "image/tiff", "tiff"),
    (b"BM", "image/bmp", "bmp"),
    # Documents
    (b"%PDF-", "application/pdf", "pdf"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/x-ole-storage", "doc"),  # OLE Compound File (legacy Office)
    (b"{\\rtf", "application/rtf", "rtf"),
    # Archives / OpenXML
    (b"PK\x03\x04", "application/zip", "zip"),  # Also base for docx, xlsx, pptx, odt, etc.
    (b"7z\xBC\xAF\x27\x1C", "application/x-7z-compressed", "7z"),
    (b"\x1F\x8B", "application/gzip", "gz"),
    # Executables / High Risk
    (b"MZ", "application/x-dosexec", "exe"),
    (b"\x7fELF", "application/x-executable", "elf"),
    (b"\xCA\xFE\xBA\xBE", "application/x-mach-binary", "macho"),
    (b"\xCF\xFA\xED\xFE", "application/x-mach-binary", "macho"),
]

def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 in chunks to handle large files safely."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
    }

def detect_file_type(file_path: Path, filename: str) -> Tuple[str, str, str]:
    """
    Detect true MIME type and extension using magic bytes first, puremagic second,
    and fall back to header content analysis.
    Returns: (detected_mime, detected_category, signature_description)
    """
    with open(file_path, "rb") as f:
        header = f.read(512)

    # Check WEBP
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp", "image", "WebP Image"

    # Check TAR (ustar marker at offset 257)
    with open(file_path, "rb") as f:
        tar_header = f.read(265)
        if len(tar_header) >= 265 and tar_header[257:262] == b"ustar":
            return "application/x-tar", "archive", "TAR Archive"

    # Check known byte signatures
    for sig, mime, ext in FILE_SIGNATURES:
        if header.startswith(sig):
            # Differentiate OpenXML (docx, xlsx, pptx) from plain zip if PK header
            if mime == "application/zip":
                openxml_type = inspect_zip_type(file_path)
                if openxml_type:
                    return openxml_type

            category = categorize_mime(mime)
            return mime, category, f"Magic Bytes: {ext.upper()}"

    # Check text / XML / SVG / HTML
    text_check = inspect_text_type(header)
    if text_check:
        return text_check

    # Fall back to puremagic library if available
    try:
        matches = puremagic.magic_file(str(file_path))
        if matches:
            top_match = matches[0]
            cat = categorize_mime(top_match.mime_type)
            return top_match.mime_type, cat, top_match.name
    except Exception:
        pass

    # Fallback to extension based detection
    guessed, _ = mimetypes.guess_type(filename)
    if guessed:
        return guessed, categorize_mime(guessed), "Extension-based fallback"

    return "application/octet-stream", "binary", "Unknown Binary Data"

def inspect_zip_type(file_path: Path) -> Optional[Tuple[str, str, str]]:
    """Inspect ZIP file contents safely to distinguish Office OpenXML formats."""
    import zipfile
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            namelist = set(zf.namelist())
            if "[Content_Types].xml" in namelist:
                if any(n.startswith("word/") for n in namelist):
                    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "office", "Microsoft Word (DOCX)"
                if any(n.startswith("xl/") for n in namelist):
                    return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "office", "Microsoft Excel (XLSX)"
                if any(n.startswith("ppt/") for n in namelist):
                    return "application/vnd.openxmlformats-officedocument.presentationml.presentation", "office", "Microsoft PowerPoint (PPTX)"
            elif "mimetype" in namelist:
                try:
                    with zf.open("mimetype") as mf:
                        m_content = mf.read().decode('ascii', errors='ignore').strip()
                        if "opendocument.text" in m_content:
                            return "application/vnd.oasis.opendocument.text", "office", "OpenDocument Text (ODT)"
                        if "opendocument.spreadsheet" in m_content:
                            return "application/vnd.oasis.opendocument.spreadsheet", "office", "OpenDocument Spreadsheet (ODS)"
                        if "opendocument.presentation" in m_content:
                            return "application/vnd.oasis.opendocument.presentation", "office", "OpenDocument Presentation (ODP)"
                except Exception:
                    pass
    except Exception:
        pass
    return None

def inspect_text_type(header: bytes) -> Optional[Tuple[str, str, str]]:
    """Determine if a text-like file is SVG, HTML, XML, JSON, or plain text."""
    try:
        snippet = header.decode('utf-8', errors='ignore').strip().lower()
        if "<svg" in snippet or ('xmlns="http://www.w3.org/2000/svg"' in snippet):
            return "image/svg+xml", "svg", "Scalable Vector Graphics (SVG)"
        if snippet.startswith("<!doctype html") or "<html" in snippet:
            return "text/html", "html", "HTML Document"
        if snippet.startswith("<?xml"):
            if "<svg" in snippet:
                return "image/svg+xml", "svg", "Scalable Vector Graphics (SVG)"
            return "application/xml", "text", "XML Document"
        if snippet.startswith("{") or snippet.startswith("["):
            return "application/json", "text", "JSON Document"
    except Exception:
        pass
    return None

def categorize_mime(mime: str) -> str:
    """Group MIME types into primary application categories."""
    if mime.startswith("image/"):
        if mime == "image/svg+xml":
            return "svg"
        return "image"
    if mime == "application/pdf":
        return "pdf"
    if any(office_sub in mime for office_sub in [
        "wordprocessing", "spreadsheet", "presentation", "msword", "vnd.ms-excel",
        "vnd.ms-powerpoint", "opendocument", "ole-storage", "rtf"
    ]):
        return "office"
    if mime in ["application/zip", "application/x-tar", "application/x-7z-compressed", "application/gzip"]:
        return "archive"
    if mime == "text/html":
        return "html"
    if mime.startswith("text/") or mime in ["application/json", "application/xml", "text/csv"]:
        return "text"
    if mime in ["application/x-dosexec", "application/x-executable", "application/x-mach-binary"]:
        return "executable"
    return "binary"

class IdentificationAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "IdentificationAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings = []
        hashes = calculate_hashes(file_path)
        detected_mime, category, description = detect_file_type(file_path, filename)

        # Check for extension spoofing / MIME mismatch
        name_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        expected_mime, _ = mimetypes.guess_type(filename)

        is_mismatch = False
        if expected_mime and detected_mime != expected_mime:
            # Tolerable differences (e.g. zip vs docx, jpeg vs jpg)
            is_benign = (
                (expected_mime == "application/zip" and category == "office") or
                (detected_mime.startswith("image/jpeg") and expected_mime.startswith("image/jpeg")) or
                (category == "text" and expected_mime.startswith("text/"))
            )
            if not is_benign:
                is_mismatch = True
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="MIME Type Confusion / Extension Mismatch Detected",
                    description=(
                        f"The file extension suggests '{name_ext}' ({expected_mime}), "
                        f"but binary signature analysis identified it as '{detected_mime}' ({description}). "
                        "This is a common tactic to conceal malicious executables or payloads."
                    ),
                    details={
                        "claimed_extension": name_ext,
                        "expected_mime": expected_mime,
                        "detected_mime": detected_mime,
                    }
                ))

        # Check if detected as executable binary
        if category == "executable":
            findings.append(Finding(
                category="structure",
                severity="critical",
                title="Executable Binary Detected",
                description=f"File contains executable binary headers ({description}).",
                details={"detected_mime": detected_mime}
            ))

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data={
                "hashes": hashes,
                "detected_mime": detected_mime,
                "category": category,
                "description": description,
                "is_mismatch": is_mismatch,
                "file_size": file_path.stat().st_size
            }
        )
