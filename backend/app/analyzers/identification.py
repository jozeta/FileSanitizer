import hashlib
import mimetypes
import struct
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
    (b"Rar!\x1A\x07\x00", "application/x-rar-compressed", "rar"),  # RAR 1.5 - 4.x
    (b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed", "rar"),  # RAR 5.0+
    (b"Rar!\x1A\x07", "application/x-rar-compressed", "rar"),
    (b"\x1F\x8B", "application/gzip", "gz"),
    # Executables / High Risk
    (b"MZ", "application/x-dosexec", "exe"),
    (b"\x7fELF", "application/x-executable", "elf"),
    (b"\xCA\xFE\xBA\xBE", "application/x-mach-binary", "macho"),
    (b"\xCF\xFA\xED\xFE", "application/x-mach-binary", "macho"),
    # Extensions & AppleScript
    (b"Cr24", "application/x-chrome-extension", "crx"),
    (b"Osas", "application/x-applescript", "scpt"),
    (b"Fasf", "application/x-applescript", "scpt"),
    (b"Fasd", "application/x-applescript", "scpt"),
    (b"Fas7", "application/x-applescript", "scpt"),
    (b"FasU", "application/x-applescript", "scpt"),
    (b"ToyS", "application/x-applescript", "scpt"),
    (b"SCPT", "application/x-applescript", "scpt"),
    # Network Packet Captures (PCAP / PCAPNG)
    (b"\xD4\xC3\xB2\xA1", "application/vnd.tcpdump.pcap", "pcap"),
    (b"\xA1\xB2\xC3\xD4", "application/vnd.tcpdump.pcap", "pcap"),
    (b"\x4D\x3C\xB2\xA1", "application/vnd.tcpdump.pcap", "pcap"),
    (b"\xA1\xB2\x3C\x4D", "application/vnd.tcpdump.pcap", "pcap"),
    (b"\x0A\x0D\x0D\x0A", "application/x-pcapng", "pcapng"),
    # Windows Event Log (EVTX)
    (b"ElfFile\x00", "application/x-windows-event-log", "evtx"),
    # Windows Shell Link Shortcut (LNK)
    (b"\x4C\x00\x00\x00\x01\x14\x02\x00", "application/x-ms-shortcut", "lnk"),
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

    res = {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "ssdeep": "",
        "tlsh": ""
    }

    try:
        from app.analyzers.fuzzy_hasher import FuzzyHasher
        with open(file_path, "rb") as f:
            data = f.read(65536)  # Sample first 64KB for instantaneous fuzzy hash calculation
        fuzzy = FuzzyHasher.analyze_bytes(data)
        res["ssdeep"] = fuzzy.get("ssdeep", "")
        res["tlsh"] = fuzzy.get("tlsh", "")
    except Exception:
        pass

    return res

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

    # Check Java Class (.class) vs Mach-O Fat Binary (both start with 0xCAFEBABE)
    if header.startswith(b"\xCA\xFE\xBA\xBE"):
        is_java_class = filename.lower().endswith(".class")
        if not is_java_class and len(header) >= 8:
            major = struct.unpack_from(">H", header, 6)[0]
            if 45 <= major <= 70:
                is_java_class = True
        if is_java_class:
            return "application/x-java-class", "java", "Java Bytecode Class File (CLASS)"

    # Check Dalvik Executable (.dex)
    if header.startswith((b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00")) or filename.lower().endswith(".dex"):
        return "application/x-dex", "apk", "Dalvik Executable Bytecode (DEX)"

    # Check Android Application Package by extension (.apk, .aab, .xapk)
    if filename.lower().endswith((".apk", ".aab", ".xapk")):
        return "application/vnd.android.package-archive", "apk", "Android Application Package (APK)"

    # Check known byte signatures
    for sig, mime, ext in FILE_SIGNATURES:
        if header.startswith(sig):
            # Differentiate OpenXML (docx, xlsx, pptx) from plain zip if PK header
            if mime == "application/zip":
                openxml_type = inspect_zip_type(file_path)
                if openxml_type:
                    return openxml_type

            # Differentiate Outlook MSG from legacy Office doc if OLE header
            if mime == "application/x-ole-storage" and filename.lower().endswith(".msg"):
                return "application/vnd.ms-outlook", "email", "Outlook Message (MSG)"

            category = categorize_mime(mime)
            return mime, category, f"Magic Bytes: {ext.upper()}"


    # Check Scripts (.ps1, .vbs, .vba, .sh, .js, .php, .cmd, .bat, .wsf, .hta)
    script_check = inspect_script_type(file_path, header, filename)
    if script_check:
        return script_check

    # Check text / XML / SVG / HTML
    text_check = inspect_text_type(header)
    if text_check:
        return text_check

    # Check Email messages (.eml, .msg, .mbox, RFC 822)
    email_check = inspect_email_type(file_path, header, filename)
    if email_check:
        return email_check

    # Check Network Packet Captures (.pcap, .pcapng, .cap)
    fn_lower = filename.lower()
    if fn_lower.endswith((".pcap", ".cap")):
        return "application/vnd.tcpdump.pcap", "pcap", "Network Packet Capture (PCAP)"
    if fn_lower.endswith(".pcapng"):
        return "application/x-pcapng", "pcap", "PCAP Next Generation (PCAPNG)"

    # Check Windows Event Logs (.evtx)
    if fn_lower.endswith(".evtx"):
        return "application/x-windows-event-log", "evtx", "Windows Event Log (EVTX)"

    # Check Windows Shell Link Shortcut (.lnk)
    if fn_lower.endswith(".lnk") or header.startswith(b"\x4C\x00\x00\x00\x01\x14\x02\x00"):
        return "application/x-ms-shortcut", "lnk", "Windows Shortcut (LNK)"

    # Check Position-Independent Shellcode (.sc, .shellcode, or binary buffers)
    if fn_lower.endswith((".sc", ".shellcode")):
        return "application/x-shellcode", "executable", "Position-Independent Shellcode Payload (SC)"
    try:
        from app.analyzers.shellcode_analyzer import ShellcodeAnalyzer
        if ShellcodeAnalyzer.is_likely_shellcode(header, filename):
            return "application/x-shellcode", "executable", "Position-Independent Shellcode Payload"
    except Exception:
        pass

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

def inspect_email_type(file_path: Path, header: bytes, filename: str) -> Optional[Tuple[str, str, str]]:
    """Detect RFC 822 / EML email messages by extension or common mail headers."""
    name_lower = filename.lower()
    if name_lower.endswith(".eml") or name_lower.endswith(".msg") or name_lower.endswith(".mbox"):
        return "message/rfc822", "email", "Email Message (RFC 822 / EML)"

    try:
        text_start = header[:512].decode('utf-8', errors='ignore').lower()
        email_header_keys = ["from:", "to:", "subject:", "date:", "received:", "return-path:", "message-id:"]
        matches = sum(1 for k in email_header_keys if k in text_start)
        if matches >= 2:
            return "message/rfc822", "email", "Email Message (RFC 822 / EML)"
    except Exception:
        pass
    return None

def inspect_zip_type(file_path: Path) -> Optional[Tuple[str, str, str]]:
    """Inspect ZIP file contents safely to distinguish Office OpenXML formats."""
    import zipfile
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            namelist = set(zf.namelist())
            fn_lower = file_path.name.lower()
            if "AndroidManifest.xml" in namelist or any(n.endswith(".dex") for n in namelist) or fn_lower.endswith((".apk", ".aab", ".xapk")):
                return "application/vnd.android.package-archive", "apk", "Android Application Package (APK)"
            if any(n.lower().endswith(".evtx") for n in namelist):
                return "application/x-windows-event-log-archive", "evtx", "Windows Event Log Archive (ZIP)"
            if "META-INF/MANIFEST.MF" in namelist or any(n.endswith(".class") for n in namelist) or fn_lower.endswith((".jar", ".war", ".ear")):
                return "application/java-archive", "java", "Java Archive (JAR)"
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
def inspect_script_type(file_path: Path, header: bytes, filename: str) -> Optional[Tuple[str, str, str]]:
    """Detect scripts and command files by extension or shebang headers."""
    name_lower = filename.lower()
    if name_lower.endswith((".ps1", ".psm1", ".psd1")):
        return "text/x-powershell", "script", "PowerShell Script (PS1)"
    if name_lower.endswith((".vbs", ".vbe")):
        return "text/x-vbs", "script", "VBScript File (VBS)"
    if name_lower.endswith(".vba"):
        return "text/x-vba", "script", "Visual Basic for Applications (VBA)"
    if name_lower.endswith(".wsf"):
        return "text/xml", "script", "Windows Script File (WSF)"
    if name_lower.endswith(".hta"):
        return "application/hta", "script", "HTML Application (HTA)"
    if name_lower.endswith((".sh", ".bash", ".zsh")):
        return "application/x-sh", "script", "Unix/Linux Shell Script (SH)"
    if name_lower.endswith((".js", ".jse", ".mjs", ".cjs")):
        return "application/javascript", "script", "JavaScript Script (JS)"
    if name_lower.endswith((".py", ".pyw")):
        return "text/x-python", "script", "Python Script (PY)"
    if name_lower.endswith((".php", ".phtml", ".php4", ".php5", ".php7", ".phps")):
        return "text/x-php", "script", "PHP Hypertext Preprocessor Script (PHP)"
    if name_lower.endswith((".cmd", ".bat")):
        return "application/x-bat", "script", "Windows Batch/Command Script (BAT/CMD)"
    if name_lower.endswith((".applescript", ".applescrip", ".scpt", ".scptd")):
        return "application/x-applescript", "script", "AppleScript Script (OSA)"
    if name_lower.endswith((".rb", ".ruby")):
        return "text/x-ruby", "script", "Ruby Script (RB)"
    if name_lower.endswith((".pl", ".pm")):
        return "text/x-perl", "script", "Perl Script (PL)"
    if name_lower.endswith(".java"):
        return "text/x-java-source", "java", "Java Source Code File (JAVA)"
    if name_lower.endswith(".lua"):
        return "text/x-lua", "script", "Lua Script (LUA)"

    if header.startswith((b"Osas", b"Fasf", b"Fasd", b"Fas7", b"FasU", b"ToyS", b"SCPT")):
        return "application/x-applescript", "script", "Compiled AppleScript (OSA)"

    try:
        snippet = header[:256].decode('utf-8', errors='ignore').strip()
        snippet_lower = snippet.lower()
        if any(snippet_lower.startswith(sb) for sb in [
            "#!/bin/bash", "#!/bin/sh", "#!/usr/bin/env bash", "#!/usr/bin/env sh", "#!/bin/zsh"
        ]):
            return "application/x-sh", "script", "Unix/Linux Shell Script (SH)"
        if any(snippet_lower.startswith(sb) for sb in [
            "#!/usr/bin/env python", "#!/usr/bin/python", "#!/usr/local/bin/python"
        ]):
            return "text/x-python", "script", "Python Script (PY)"
        if any(snippet_lower.startswith(sb) for sb in [
            "#!/usr/bin/env node", "#!/usr/bin/node"
        ]):
            return "application/javascript", "script", "JavaScript Script (JS)"
        if any(snippet_lower.startswith(sb) for sb in [
            "#!/usr/bin/osascript", "#!/usr/bin/env osascript"
        ]) or "tell application \"" in snippet_lower or "display dialog \"" in snippet_lower or "do shell script \"" in snippet_lower:
            return "application/x-applescript", "script", "AppleScript Script (OSA)"
        if "<?php" in snippet_lower:
            return "text/x-php", "script", "PHP Script (PHP)"
        if snippet_lower.startswith("@echo off"):
            return "application/x-bat", "script", "Windows Batch Script (BAT)"
    except Exception:
        pass
    return None

def categorize_mime(mime: str) -> str:
    """Group MIME types into primary application categories."""
    if mime in ["application/vnd.android.package-archive", "application/x-dex"] or "android" in mime:
        return "apk"
    if mime in ["text/x-java-source", "application/x-java-class", "application/java-archive", "application/x-java-archive"] or "java" in mime:
        return "java"
    if mime in [
        "text/x-powershell", "text/x-vbs", "text/x-vba", "application/x-sh",
        "text/x-php", "application/x-bat", "application/hta", "application/x-applescript",
        "text/x-python", "text/x-ruby", "text/x-perl", "text/x-lua",
        "application/javascript", "text/javascript"
    ]:
        return "script"
    if mime in ["message/rfc822", "application/vnd.ms-outlook", "message/delivery-status"] or "email" in mime:
        return "email"
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
    if mime in [
        "application/zip", "application/x-tar", "application/x-7z-compressed", "application/gzip",
        "application/x-rar-compressed", "application/x-rar", "application/vnd.rar",
        "application/x-chrome-extension"
    ]:
        return "archive"
    if mime in ["application/vnd.tcpdump.pcap", "application/x-pcap", "application/x-pcapng"] or "pcap" in mime:
        return "pcap"
    if mime in ["application/x-windows-event-log", "application/x-windows-event-log-archive"] or "evtx" in mime:
        return "evtx"
    if mime in ["application/x-ms-shortcut", "application/x-ms-lnk"]:
        return "lnk"
    if mime == "text/x-domain-intelligence":
        return "domain"
    if mime == "text/html":
        return "html"
    if mime.startswith("text/") or mime in ["application/json", "application/xml", "text/csv"]:
        return "text"
    if mime in ["application/x-dosexec", "application/x-executable", "application/x-mach-binary", "application/x-shellcode"]:
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
                mime_to_ext = {
                    "application/x-dosexec": ".exe",
                    "application/x-elf": ".elf",
                    "application/x-mach-binary": ".macho",
                    "application/pdf": ".pdf",
                    "application/zip": ".zip",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
                    "application/msword": ".doc",
                    "application/vnd.ms-excel": ".xls",
                    "application/vnd.ms-powerpoint": ".ppt",
                    "application/rtf": ".rtf",
                    "text/rtf": ".rtf",
                    "application/vnd.ms-outlook": ".msg",
                    "message/rfc822": ".eml",
                    "text/html": ".html",
                    "image/jpeg": ".jpg",
                    "image/png": ".png",
                    "application/vnd.tcpdump.pcap": ".pcap",
                    "application/x-pcapng": ".pcapng",
                    "application/x-windows-event-log": ".evtx",
                    "application/x-shellscript": ".sh",
                    "application/vnd.android.package-archive": ".apk",
                    "application/x-dex": ".dex",
                    "text/x-java-source": ".java",
                    "application/x-java-class": ".class",
                    "application/java-archive": ".jar",
                }
                suggested_ext = mime_to_ext.get(detected_mime)
                if not suggested_ext:
                    if category == "executable":
                        suggested_ext = ".exe"
                    elif category == "office":
                        suggested_ext = ".docx" if "openxml" in detected_mime else ".doc"
                    elif category == "pdf":
                        suggested_ext = ".pdf"
                    elif category == "image":
                        suggested_ext = ".png"
                    elif category == "evtx":
                        suggested_ext = ".evtx"
                    elif category == "apk":
                        suggested_ext = ".apk"
                    elif category == "java":
                        suggested_ext = ".java"
                    else:
                        suggested_ext = f".{category}"

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
                        "detected_format": description,
                        "suggested_extension": suggested_ext
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
