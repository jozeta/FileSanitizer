import re
import urllib.parse
import mimetypes
from typing import Dict, Any, Tuple, Optional
import httpx

from app.config import settings
from app.core.logging_config import logger
from app.core.file_isolation import sanitize_filename
from app.network.ssrf import validate_url_for_ssrf
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.identification import (
    categorize_mime,
    FILE_SIGNATURES,
    inspect_text_type,
    inspect_zip_type
)

SUPPORTED_CATEGORIES = {"image", "pdf", "office", "archive", "svg", "html", "text"}

SUPPORTED_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif",
    # Documents
    ".pdf",
    # Office
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp",
    # Archives
    ".zip", ".7z", ".tar", ".gz", ".tgz",
    # Vector / Active Web
    ".svg", ".html", ".htm",
    # Plain Text / Data
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md"
}

class URLFetcherException(Exception):
    def __init__(self, message: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

class URLFileFetcher:
    """
    Secure remote file fetcher with:
    1. Scheme and SSRF validation (pre-request and per-redirect).
    2. URL threat reputation & malware/scam watchlist scanning.
    3. Supported file format verification.
    4. Streaming download with size limit (100MB) and strict timeouts.
    """

    @classmethod
    def fetch(cls, url: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """
        Validates reputation and SSRF, streams the file safely, verifies format,
        and returns: (file_bytes, filename, reputation_data)
        """
        url = url.strip()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ["http", "https"]:
            raise URLFetcherException("Unsupported URL scheme. Only HTTP and HTTPS protocols are permitted.", 400)

        # 1. SSRF Validation on destination
        is_safe, ssrf_reason, ips = validate_url_for_ssrf(url)
        if not is_safe:
            raise URLFetcherException(f"Destination blocked by SSRF security policy: {ssrf_reason}", 400, {"ssrf_reason": ssrf_reason})

        # 2. URL Reputation & Watchlist Check for Malware / Scams
        reputation = URLAnalyzer.analyze_url(url)
        if reputation.get("risk") == "MALICIOUS":
            indicators = reputation.get("indicators", ["Identified on security watchlists as malicious/scam"])
            raise URLFetcherException(
                f"URL rejected by security policy: Identified on security watchlists as malicious or scam ({', '.join(indicators)}).",
                400,
                {"reputation": reputation}
            )

        # 3. Stream download with redirect SSRF validation
        max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
        current_url = url
        redirect_hops = 0
        max_redirects = 5
        file_bytes = bytearray()
        content_disposition = None
        content_type = None

        headers = {
            "User-Agent": "FileSanitizer-SecurityScanner/1.0 (+https://filesanitizer.local)",
            "Accept": "*/*"
        }

        with httpx.Client(timeout=15.0, verify=True, follow_redirects=False) as client:
            while redirect_hops <= max_redirects:
                if redirect_hops > 0:
                    r_safe, r_reason, _ = validate_url_for_ssrf(current_url)
                    if not r_safe:
                        raise URLFetcherException(f"Redirect target blocked by SSRF policy: {r_reason}", 400)

                try:
                    with client.stream("GET", current_url, headers=headers) as response:
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location")
                            if not location:
                                raise URLFetcherException("Redirect response missing Location header.", 400)
                            current_url = urllib.parse.urljoin(current_url, location)
                            redirect_hops += 1
                            continue

                        if response.status_code != 200:
                            raise URLFetcherException(f"Failed to download remote file: HTTP {response.status_code} {response.reason_phrase}", 400)

                        content_disposition = response.headers.get("content-disposition")
                        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()

                        for chunk in response.iter_bytes(chunk_size=65536):
                            file_bytes.extend(chunk)
                            if len(file_bytes) > max_bytes:
                                raise URLFetcherException(
                                    f"Remote file exceeds maximum allowed limit of {settings.MAX_FILE_SIZE_MB} MB.",
                                    413
                                )

                        break
                except httpx.RequestError as e:
                    raise URLFetcherException(f"Network error while downloading remote file: {e}", 400)

            if redirect_hops > max_redirects:
                raise URLFetcherException("Exceeded maximum allowable redirect hops.", 400)

        raw_bytes = bytes(file_bytes)
        if not raw_bytes:
            raise URLFetcherException("The downloaded file is empty (0 bytes).", 400)

        # 4. Determine safe filename
        filename = cls._determine_filename(current_url, content_disposition, content_type, raw_bytes)

        # 5. Verify format is in supported categories
        category, detected_mime = cls._verify_supported_format(filename, content_type, raw_bytes)
        if category not in SUPPORTED_CATEGORIES:
            raise URLFetcherException(
                f"Unsupported file format '{detected_mime}' (category: '{category}'). "
                f"FileSanitizer supports: PDF, Office documents (DOCX, XLSX, PPTX), Images, Archives, SVG, HTML, and Data files.",
                400,
                {"detected_mime": detected_mime, "category": category}
            )

        logger.info(f"Successfully fetched remote file '{filename}' ({len(raw_bytes)} bytes) from URL '{url}' (MIME: {detected_mime})")
        return raw_bytes, filename, reputation

    @classmethod
    def _determine_filename(
        cls,
        final_url: str,
        content_disposition: Optional[str],
        content_type: Optional[str],
        raw_bytes: bytes
    ) -> str:
        """Derive a safe filename from Content-Disposition, URL path, or MIME/magic fallback."""
        name = ""

        # Try Content-Disposition
        if content_disposition:
            m = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';\r\n]+)["\']?', content_disposition, re.IGNORECASE)
            if m:
                name = m.group(1).strip()

        # Try URL path
        if not name:
            parsed = urllib.parse.urlparse(final_url)
            path = parsed.path.rstrip("/")
            if path:
                base = path.split("/")[-1]
                if base:
                    name = urllib.parse.unquote(base)

        if not name:
            name = "downloaded_file"

        # Check if extension is missing or unknown
        has_ext = "." in name and not name.startswith(".")
        if not has_ext:
            # Guess extension from content_type or magic bytes
            ext = cls._guess_extension(content_type, raw_bytes)
            name = f"{name}{ext}"

        return sanitize_filename(name)

    @classmethod
    def _guess_extension(cls, content_type: Optional[str], raw_bytes: bytes) -> str:
        """Guess extension from content_type or magic bytes."""
        header = raw_bytes[:512]

        if header.startswith(b"%PDF-"):
            return ".pdf"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png"
        if header.startswith(b"\xFF\xD8\xFF"):
            return ".jpg"
        if header.startswith(b"GIF8"):
            return ".gif"
        if header.startswith(b"BM"):
            return ".bmp"
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return ".webp"
        if header.startswith(b"PK\x03\x04"):
            return ".zip"
        if header.startswith(b"7z\xBC\xAF\x27\x1C"):
            return ".7z"
        if header.startswith(b"\x1F\x8B"):
            return ".gz"
        if b"<svg" in header.lower():
            return ".svg"
        if b"<html" in header.lower() or b"<!doctype html" in header.lower():
            return ".html"

        if content_type:
            guessed = mimetypes.guess_extension(content_type)
            if guessed:
                return guessed

        return ".bin"

    @classmethod
    def _verify_supported_format(
        cls,
        filename: str,
        content_type: Optional[str],
        raw_bytes: bytes
    ) -> Tuple[str, str]:
        """Detect category and true MIME to ensure it is supported."""
        header = raw_bytes[:512]

        # 1. Magic bytes check
        if header.startswith(b"%PDF-"):
            return "pdf", "application/pdf"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image", "image/png"
        if header.startswith(b"\xFF\xD8\xFF"):
            return "image", "image/jpeg"
        if header.startswith(b"GIF8"):
            return "image", "image/gif"
        if header.startswith(b"BM"):
            return "image", "image/bmp"
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return "image", "image/webp"

        # Check executables (reject)
        if header.startswith(b"MZ") or header.startswith(b"\x7fELF") or header.startswith(b"\xCA\xFE\xBA\xBE"):
            return "executable", "application/x-executable"

        # Check Zip / OpenXML
        if header.startswith(b"PK\x03\x04"):
            # Check if OpenXML by inspecting inner paths
            import zipfile
            import io
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                    names = set(zf.namelist())
                    if "[Content_Types].xml" in names:
                        if any(n.startswith("word/") for n in names):
                            return "office", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        if any(n.startswith("xl/") for n in names):
                            return "office", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        if any(n.startswith("ppt/") for n in names):
                            return "office", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    return "archive", "application/zip"
            except Exception:
                return "archive", "application/zip"

        if header.startswith(b"7z\xBC\xAF\x27\x1C"):
            return "archive", "application/x-7z-compressed"
        if header.startswith(b"\x1F\x8B"):
            return "archive", "application/gzip"
        if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            return "office", "application/x-ole-storage"
        if header.startswith(b"{\\rtf"):
            return "office", "application/rtf"

        # Text / XML / HTML / SVG
        text_check = inspect_text_type(header)
        if text_check:
            mime, cat, _ = text_check
            return cat, mime

        # Extension-based fallback
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        if ext in SUPPORTED_EXTENSIONS:
            guessed_mime, _ = mimetypes.guess_type(filename)
            if guessed_mime:
                cat = categorize_mime(guessed_mime)
                return cat, guessed_mime

        if content_type:
            cat = categorize_mime(content_type)
            return cat, content_type

        return "unsupported", "application/octet-stream"
