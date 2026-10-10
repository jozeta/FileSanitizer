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

from app.analyzers.domain_analyzer import DomainAnalyzer

SUPPORTED_CATEGORIES = {
    "image", "pdf", "office", "archive", "svg", "html", "text",
    "executable", "script", "email", "domain"
}

SUPPORTED_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif",
    # Documents
    ".pdf",
    # Office
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp",
    # Archives, Extensions & Java
    ".zip", ".7z", ".tar", ".gz", ".tgz", ".crx", ".jar",
    # Vector / Active Web
    ".svg", ".html", ".htm",
    # Plain Text / Data
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md",
    # Executables & Binaries
    ".exe", ".dll", ".elf", ".macho", ".app",
    # Scripts
    ".ps1", ".psm1", ".sh", ".bash", ".vbs", ".vbe", ".vba", ".bat", ".cmd", ".js", ".php",
    ".applescript", ".scpt",
    # Emails
    ".eml", ".msg", ".mbox"
}

class FetchResult(tuple):
    """
    Backwards-compatible 3-tuple (raw_bytes, filename, reputation)
    with optional screenshot_bytes, domain_info, and is_domain_target attributes.
    """
    def __new__(
        cls,
        raw_bytes: bytes,
        filename: str,
        reputation: Dict[str, Any],
        screenshot_bytes: Optional[bytes] = None,
        domain_info: Optional[Dict[str, Any]] = None,
        is_domain_target: bool = False
    ):
        obj = super().__new__(cls, (raw_bytes, filename, reputation))
        obj.screenshot_bytes = screenshot_bytes
        obj.domain_info = domain_info
        obj.is_domain_target = is_domain_target
        return obj

    @property
    def raw_bytes(self) -> bytes:
        return self[0]

    @property
    def filename(self) -> str:
        return self[1]

    @property
    def reputation(self) -> Dict[str, Any]:
        return self[2]

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
    def _fetch_screenshot_bytes(cls, url: str) -> Optional[bytes]:
        """Fetch live browser screenshot from the isolated browser container."""
        if not settings.SCREENSHOT_ENABLED:
            return None
        is_safe, _, _ = validate_url_for_ssrf(url)
        if not is_safe:
            return None
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    settings.BROWSER_SERVICE_URL,
                    json={"url": url},
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200 and resp.content and resp.content.startswith(b"\x89PNG"):
                    return resp.content
        except Exception as e:
            logger.debug(f"Screenshot capture error for {url}: {e}")
        return None

    @classmethod
    def _build_domain_report_html(cls, domain: str, domain_info: Dict[str, Any], html_body: str = "") -> bytes:
        dns_recs = domain_info.get("dns_records", {})
        whois_data = domain_info.get("whois", {})
        punycode = domain_info.get("punycode_analysis", {})
        co_hosted = domain_info.get("co_hosted_domains", [])
        
        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Domain &amp; Infrastructure Intelligence: {domain}</title>
</head>
<body>
    <h1>Domain &amp; Infrastructure Intelligence Report</h1>
    <div id="target-info">
        <p><strong>Target:</strong> {domain}</p>
        <p><strong>Registrar:</strong> {whois_data.get('registrar', 'Unknown')}</p>
        <p><strong>Created:</strong> {whois_data.get('registration_date', 'Unknown')}</p>
        <p><strong>Age (Days):</strong> {whois_data.get('domain_age_days', 'Unknown')}</p>
        <p><strong>Unicode Homograph:</strong> {punycode.get('unicode_rendered', domain)}</p>
    </div>
    <div id="dns-records">
        <p><strong>A:</strong> {', '.join(str(x.get('ip', x) if isinstance(x, dict) else x) for x in dns_recs.get('a', []))}</p>
        <p><strong>AAAA:</strong> {', '.join(str(x.get('ip', x) if isinstance(x, dict) else x) for x in dns_recs.get('aaaa', []))}</p>
        <p><strong>MX:</strong> {', '.join(str(x.get('exchange', x) if isinstance(x, dict) else x) for x in dns_recs.get('mx', []))}</p>
        <p><strong>NS:</strong> {', '.join(str(x.get('target', x) if isinstance(x, dict) else x) for x in dns_recs.get('ns', []))}</p>
    </div>
    <div id="captured-content">
        <h3>Live Page Content</h3>
        {html_body[:50000] if html_body else '<p>No HTML body retrieved.</p>'}
    </div>
</body>
</html>"""
        return doc.encode("utf-8")

    @classmethod
    def fetch(cls, url: str) -> FetchResult:
        """
        Validates reputation and SSRF, streams the file or captures domain intelligence/screenshot safely,
        verifies format, and returns: FetchResult(file_bytes, filename, reputation_data, screenshot_bytes, domain_info)
        """
        url_input = url.strip()
        if not url_input:
            raise URLFetcherException("URL, domain, or IP address cannot be empty.", 400)

        # Normalize bare domain or IP address without scheme
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_input):
            url_input = "https://" + url_input

        parsed = urllib.parse.urlparse(url_input)
        if parsed.scheme.lower() not in ["http", "https"]:
            raise URLFetcherException("Unsupported URL scheme. Only HTTP and HTTPS protocols are permitted.", 400)

        domain_name = parsed.hostname or ""
        is_ip = DomainAnalyzer._is_ip_address(domain_name)

        # Check for Chrome or Edge Web Store Extension URLs
        ext_id = None
        m_chrome = re.search(r'(?:chromewebstore\.google\.com|chrome\.google\.com/webstore)/detail/(?:[^/]+/)?([a-z]{32})', url_input, re.I)
        if m_chrome:
            ext_id = m_chrome.group(1).lower()
        else:
            m_edge = re.search(r'microsoftedge\.microsoft\.com/addons/detail/(?:[^/]+/)?([a-z]{32})', url_input, re.I)
            if m_edge:
                ext_id = m_edge.group(1).lower()

        current_url = url_input
        is_extension_store = bool(ext_id)
        if is_extension_store:
            # Download CRX package directly from Google Update Service
            current_url = f"https://clients2.google.com/service/update2/crx?response=redirect&prodversion=114.0&acceptformat=crx2,crx3&x=id%3D{ext_id}%26uc"

        # Check if the target is a domain/infrastructure inspection vs a downloadable file resource
        last_segment = (parsed.path or "").rstrip("/").split("/")[-1]
        has_file_extension = "." in last_segment and not last_segment.startswith(".")
        is_domain_target = (not is_extension_store) and (is_ip or not parsed.path or parsed.path == "/" or not has_file_extension)

        # 1. SSRF Validation on destination (protect internal infrastructure)
        is_safe, ssrf_reason, ips = validate_url_for_ssrf(current_url)
        if not is_safe:
            if is_domain_target and "DNS resolution failed" in (ssrf_reason or ""):
                domain_info = DomainAnalyzer.analyze(domain_name, deep=True) if domain_name else {}
                report_bytes = cls._build_domain_report_html(domain_name, domain_info)
                target_name = sanitize_filename(domain_name) if domain_name else "network_target"
                reputation = URLAnalyzer.analyze_url(url_input)
                logger.info(f"Analyzed non-resolving domain target '{target_name}' (Punycode/Homograph/WHOIS analysis)")
                return FetchResult(report_bytes, target_name, reputation, None, domain_info, is_domain_target=True)
            raise URLFetcherException(f"Destination blocked by SSRF security policy: {ssrf_reason}", 400, {"ssrf_reason": ssrf_reason})

        # 2. URL Reputation & Watchlist Check (Recorded as findings; does NOT block analysis!)
        reputation = URLAnalyzer.analyze_url(url_input)

        # 3. Domain & IP Target Inspection Mode
        # If user submits a domain, IP, or web root rather than a downloadable file path:
        if is_domain_target:
            domain_info = DomainAnalyzer.analyze(domain_name, deep=True) if domain_name else {}
            screenshot_bytes = cls._fetch_screenshot_bytes(url_input)
            report_bytes = cls._build_domain_report_html(domain_name, domain_info)
            target_name = sanitize_filename(domain_name) if domain_name else "network_target"
            logger.info(f"Analyzed remote domain/IP target '{target_name}' (screenshot captured: {bool(screenshot_bytes)})")
            return FetchResult(report_bytes, target_name, reputation, screenshot_bytes, domain_info, is_domain_target=True)

        # 4. Stream download for Remote Files
        screenshot_bytes: Optional[bytes] = None
        domain_info = DomainAnalyzer.analyze(domain_name) if domain_name else {}
        if not is_extension_store:
            screenshot_bytes = cls._fetch_screenshot_bytes(url_input)

        max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
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
                            # If remote returned non-200, fallback to domain intelligence target
                            report_bytes = cls._build_domain_report_html(domain_name, domain_info)
                            target_name = sanitize_filename(domain_name) if domain_name else "network_target"
                            return FetchResult(report_bytes, target_name, reputation, screenshot_bytes, domain_info, is_domain_target=True)

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
                    # On network error downloading remote file, provide domain report
                    report_bytes = cls._build_domain_report_html(domain_name, domain_info)
                    target_name = sanitize_filename(domain_name) if domain_name else "network_target"
                    return FetchResult(report_bytes, target_name, reputation, screenshot_bytes, domain_info, is_domain_target=True)

            if redirect_hops > max_redirects:
                raise URLFetcherException("Exceeded maximum allowable redirect hops.", 400)

        raw_bytes = bytes(file_bytes)
        if not raw_bytes:
            report_bytes = cls._build_domain_report_html(domain_name, domain_info)
            target_name = sanitize_filename(domain_name) if domain_name else "network_target"
            return FetchResult(report_bytes, target_name, reputation, screenshot_bytes, domain_info, is_domain_target=True)

        # 5. Determine safe filename
        if is_extension_store:
            filename = f"{ext_id}.crx"
        elif "html" in (content_type or "") and not content_disposition:
            # HTML page returned without disposition -> domain/website inspection target
            target_name = sanitize_filename(domain_name) if domain_name else "web_target"
            raw_bytes = cls._build_domain_report_html(domain_name, domain_info, raw_bytes.decode("utf-8", errors="ignore"))
            return FetchResult(raw_bytes, target_name, reputation, screenshot_bytes, domain_info, is_domain_target=True)
        else:
            filename = cls._determine_filename(current_url, content_disposition, content_type, raw_bytes)

        # 6. Verify format is in supported categories
        category, detected_mime = cls._verify_supported_format(filename, content_type, raw_bytes)
        if category not in SUPPORTED_CATEGORIES:
            raise URLFetcherException(
                f"Unsupported file format '{detected_mime}' (category: '{category}'). "
                f"FileSanitizer supports all standard documents, archives, images, executables, scripts, and email messages.",
                400,
                {"detected_mime": detected_mime, "category": category}
            )

        logger.info(f"Successfully fetched remote file/domain '{filename}' ({len(raw_bytes)} bytes) from URL '{url}' (MIME: {detected_mime})")
        return FetchResult(raw_bytes, filename, reputation, screenshot_bytes, domain_info, is_domain_target=False)

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
            if b"META-INF/MANIFEST.MF" in raw_bytes[:1024]:
                return ".jar"
            return ".zip"
        if header.startswith(b"7z\xBC\xAF\x27\x1C"):
            return ".7z"
        if header.startswith(b"\x1F\x8B"):
            return ".gz"
        if b"<svg" in header.lower():
            return ".svg"
        if b"<html" in header.lower() or b"<!doctype html" in header.lower():
            return ".html"

        if header.startswith(b"MZ"):
            return ".exe"
        if header.startswith(b"\x7fELF"):
            return ".elf"
        if header.startswith(b"Cr24"):
            return ".crx"
        if header.startswith(b"Osas") or header.startswith(b"Fasf"):
            return ".scpt"

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

        # 0. Domain & Network Intelligence Target Check
        if b"Domain &amp; Infrastructure Intelligence" in raw_bytes[:512] or b"Domain & Infrastructure Intelligence" in raw_bytes[:512]:
            return "domain", "text/x-domain-intelligence"

        # Check JAR archive
        if filename.lower().endswith(".jar"):
            return "archive", "application/java-archive"

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

        # Check Chrome extension package
        if header.startswith(b"Cr24") or filename.lower().endswith(".crx"):
            return "archive", "application/x-chrome-extension"

        # Check executables
        if header.startswith(b"MZ") or header.startswith(b"\x7fELF") or header.startswith(b"\xCA\xFE\xBA\xBE") or header.startswith(b"\xCF\xFA\xED\xFE"):
            return "executable", "application/x-executable"

        # Check AppleScript
        if filename.lower().endswith((".applescript", ".scpt", ".scptd")) or header.startswith(b"Osas") or header.startswith(b"Fasf"):
            return "script", "application/x-applescript"

        # Check Zip / OpenXML / JAR
        if header.startswith(b"PK\x03\x04"):
            import zipfile
            import io
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                    names = set(zf.namelist())
                    if "META-INF/MANIFEST.MF" in names or filename.lower().endswith(".jar"):
                        return "archive", "application/java-archive"
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
