import os
import re
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import olefile

from app.core.file_isolation import JobWorkspace, sanitize_filename
from app.core.logging_config import logger

def calculate_hashes(data: bytes) -> Tuple[str, str]:
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256

def detect_mime_type_from_bytes(data: bytes, fallback_ext: str = "") -> str:
    """Fast, safe magic byte sniffing."""
    if not data:
        return "application/octet-stream"
    if data.startswith(b"MZ"):
        return "application/x-dosexec"
    if data.startswith(b"\x7fELF"):
        return "application/x-elf"
    if data[:4] in [b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE", b"\xCA\xFE\xBA\xBE"]:
        return "application/x-mach-binary"
    if data.startswith(b"%PDF"):
        return "application/pdf"
    if data.startswith(b"PK\x03\x04"):
        if fallback_ext in [".docx", ".docm"]:
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if fallback_ext in [".xlsx", ".xlsm"]:
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return "application/zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if data.startswith(b"Rar!\x1a\x07"):
        return "application/x-rar-compressed"
    if data.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if b"<html" in data[:512].lower() or b"<!doctype html" in data[:512].lower():
        return "text/html"
    if data.startswith(b"<?xml") or b"<svg" in data[:512].lower():
        return "application/xml"
    if re.search(rb'^#!(?:/bin/|/usr/bin/)(?:bash|sh|python|perl|pwsh)', data):
        return "text/x-shellscript"
    return "application/octet-stream"

def is_payload_dangerous(name: str, mime: str, data: bytes) -> Tuple[bool, str]:
    """Check if embedded item poses a security threat."""
    name_lower = name.lower()

    # Check benign Office printer settings / item props before generic checks
    if name_lower.endswith(".bin"):
        if re.search(r'printersettings\d*\.bin', name_lower) or re.search(r'itemprops\d*\.bin', name_lower):
            if not (data.startswith(b"MZ") or data.startswith(b"\x7fELF") or data[:4] in [b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"]):
                return False, ""

    dangerous_exts = (
        ".exe", ".dll", ".scr", ".sys", ".cpl", ".pif", ".com",
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta",
        ".jar", ".elf", ".dylib", ".iso", ".img", ".vhd"
    )
    if name_lower.endswith(dangerous_exts):
        return True, f"Dangerous executable or script extension ({Path(name_lower).suffix})"

    if data.startswith(b"MZ"):
        return True, "Embedded Windows PE Binary executable (MZ header detected)"
    if data.startswith(b"\x7fELF"):
        return True, "Embedded Linux ELF Binary executable detected"
    if data[:4] in [b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"]:
        return True, "Embedded macOS Mach-O Binary executable detected"

    if mime in ["application/x-dosexec", "application/x-elf", "application/x-mach-binary", "text/x-shellscript"]:
        return True, f"Executable MIME type ({mime})"

    if name_lower.endswith((".docm", ".xlsm", ".pptm", ".dotm", ".xltm")):
        return True, "Macro-enabled Office document payload"

    # If generic .bin has executable or script characteristics
    if name_lower.endswith(".bin"):
        if any(kw in data[:256].lower() for kw in [b"wscript.shell", b"powershell", b"cmd.exe", b"cscript", b"mshta"]):
            return True, "Embedded binary payload containing executable script triggers"

    return False, ""

def format_file_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}" if unit != 'B' else f"{size_bytes} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


class UniversalEmbeddedExtractor:
    """
    Universal extraction engine for nested files and payloads inside:
    - PDFs (Catalog /EmbeddedFiles, /Names, attachments)
    - Office Documents (OLE package objects, embeddings/, vbaProject.bin, oleObject*.bin)
    - Executable Binaries (PE resource directory payloads, nested MZ / zip)
    - Email Messages (.eml, .msg attachments)
    - Archives (Nested archives & extracted files)
    """

    @classmethod
    def extract_all(cls, file_path: Path, filename: str, mime_type: str, category: str, ws: JobWorkspace, password: Optional[str] = None) -> List[Dict[str, Any]]:
        extracted_items: List[Dict[str, Any]] = []

        try:
            if not file_path.exists() or file_path.stat().st_size == 0:
                return []

            # 1. PDF Documents
            if category == "pdf" or filename.lower().endswith(".pdf") or mime_type == "application/pdf":
                cls._extract_pdf_embedded(file_path, ws, extracted_items)

            # 2. Office Documents
            elif category == "office" or filename.lower().endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt")):
                cls._extract_office_embedded(file_path, ws, extracted_items)

            # 3. Executable Binaries
            elif category in ["executable", "binary"] or filename.lower().endswith((".exe", ".dll", ".sys", ".scr", ".elf", ".dylib")):
                cls._extract_binary_embedded(file_path, ws, extracted_items)

            # 4. Email Messages
            elif category == "email" or filename.lower().endswith((".eml", ".msg", ".mbox")):
                cls._extract_email_embedded(file_path, ws, extracted_items)

            # 5. Archive Files
            elif category == "archive" or filename.lower().endswith((".zip", ".tar", ".gz", ".7z", ".rar")):
                cls._extract_archive_embedded(file_path, ws, extracted_items, password=password)

        except Exception as e:
            logger.error(f"UniversalEmbeddedExtractor failure on {filename}: {e}", exc_info=True)

        return extracted_items

    @classmethod
    def _extract_pdf_embedded(cls, file_path: Path, ws: JobWorkspace, items: List[Dict[str, Any]]) -> None:
        try:
            import fitz
            doc = fitz.open(str(file_path))
            count = 0
            try:
                count = doc.embfile_count()
            except Exception:
                pass

            for idx in range(count):
                try:
                    info = doc.embfile_info(idx)
                    raw_name = info.get("filename") or f"embedded_file_{idx}.bin"
                    safe_name = sanitize_filename(raw_name)
                    file_bytes = doc.embfile_get(idx)
                    if not file_bytes:
                        continue

                    disk_name = f"pdf_emb_{len(items)}_{safe_name}"
                    target_path = ws.extracted_dir / disk_name
                    target_path.write_bytes(file_bytes)

                    md5, sha256 = calculate_hashes(file_bytes)
                    detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                    is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                    items.append({
                        "id": len(items),
                        "name": safe_name,
                        "source_type": "pdf_attachment",
                        "parent_format": "PDF Document",
                        "origin_stream": f"/EmbeddedFiles index {idx}",
                        "size": len(file_bytes),
                        "size_formatted": format_file_size(len(file_bytes)),
                        "mime_type": detected_mime,
                        "md5": md5,
                        "sha256": sha256,
                        "is_dangerous": is_dangerous,
                        "threat_reason": reason or ("Embedded attachment inside PDF document" if is_dangerous else ""),
                        "disk_filename": disk_name
                    })
                except Exception as inner_e:
                    logger.debug(f"Error extracting PDF embedded file {idx}: {inner_e}")
            doc.close()
        except Exception as e:
            logger.debug(f"PDF embedded extraction note: {e}")

    @classmethod
    def _extract_office_embedded(cls, file_path: Path, ws: JobWorkspace, items: List[Dict[str, Any]]) -> None:
        # A. OpenXML .docx / .xlsx / .pptx ZIP containers
        if zipfile.is_zipfile(str(file_path)):
            try:
                with zipfile.ZipFile(str(file_path), "r") as zf:
                    for name in zf.namelist():
                        name_lower = name.lower()
                        # Detect embedded OLE packages, binary objects, and embedded files
                        is_embedding = (
                            "embeddings/" in name_lower or
                            "oleobject" in name_lower or
                            name_lower.endswith((".bin", ".exe", ".vbs", ".ps1"))
                        )
                        if is_embedding and not name_lower.endswith("vbaproject.bin"):
                            try:
                                data = zf.read(name)
                                if len(data) < 16:
                                    continue

                                base_filename = Path(name).name
                                # If it's an OLE storage with Ole10Native, parse the inner dropped file!
                                clean_name, file_bytes = cls._unwrap_ole10_native(data, base_filename)
                                safe_name = sanitize_filename(clean_name)

                                disk_name = f"office_emb_{len(items)}_{safe_name}"
                                target_path = ws.extracted_dir / disk_name
                                target_path.write_bytes(file_bytes)

                                md5, sha256 = calculate_hashes(file_bytes)
                                detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                                is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                                items.append({
                                    "id": len(items),
                                    "name": safe_name,
                                    "source_type": "office_embedding",
                                    "parent_format": "Office OpenXML Document",
                                    "origin_stream": name,
                                    "size": len(file_bytes),
                                    "size_formatted": format_file_size(len(file_bytes)),
                                    "mime_type": detected_mime,
                                    "md5": md5,
                                    "sha256": sha256,
                                    "is_dangerous": is_dangerous,
                                    "threat_reason": reason or ("Embedded OLE payload object inside Office document" if is_dangerous else ""),
                                    "disk_filename": disk_name
                                })
                            except Exception as pe:
                                logger.debug(f"Error extracting OpenXML embedding {name}: {pe}")
            except Exception as e:
                logger.debug(f"OpenXML embeddings extraction error: {e}")

        # B. Legacy OLE Compound Files (.doc, .xls, .ppt)
        if olefile.isOleFile(str(file_path)):
            try:
                with olefile.OleFileIO(str(file_path)) as ole:
                    for stream_path in ole.listdir(streams=True, storages=False):
                        s_name = "/".join(stream_path)
                        if "\x01ole10native" in s_name.lower() or "package" in s_name.lower():
                            try:
                                data = ole.openstream(stream_path).read()
                                clean_name, file_bytes = cls._unwrap_ole10_native(data, f"ole_stream_{len(items)}.bin")
                                safe_name = sanitize_filename(clean_name)

                                disk_name = f"ole_emb_{len(items)}_{safe_name}"
                                target_path = ws.extracted_dir / disk_name
                                target_path.write_bytes(file_bytes)

                                md5, sha256 = calculate_hashes(file_bytes)
                                detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                                is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                                items.append({
                                    "id": len(items),
                                    "name": safe_name,
                                    "source_type": "office_ole10_native",
                                    "parent_format": "Legacy Compound OLE Document",
                                    "origin_stream": s_name,
                                    "size": len(file_bytes),
                                    "size_formatted": format_file_size(len(file_bytes)),
                                    "mime_type": detected_mime,
                                    "md5": md5,
                                    "sha256": sha256,
                                    "is_dangerous": is_dangerous,
                                    "threat_reason": reason or "Embedded Native OLE Object package",
                                    "disk_filename": disk_name
                                })
                            except Exception as oe:
                                logger.debug(f"Error parsing legacy OLE stream {s_name}: {oe}")
            except Exception as e:
                logger.debug(f"Legacy OLE extraction note: {e}")

    @classmethod
    def _unwrap_ole10_native(cls, data: bytes, default_name: str) -> Tuple[str, bytes]:
        """
        Extract the original native payload from an Ole10Native stream if formatted,
        otherwise return the raw stream bytes.
        """
        try:
            # Ole10Native header: [4-byte total size] [2-byte flags] [ASCII original filename\0] [ASCII filepath\0] ... [4-byte payload size] [PAYLOAD]
            if len(data) > 12 and data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                # Sub-OLE file
                with olefile.OleFileIO(data) as sub_ole:
                    if sub_ole.exists("\x01Ole10Native"):
                        data = sub_ole.openstream("\x01Ole10Native").read()

            if len(data) > 16:
                # Search for original filename string
                match = re.search(rb'[\x20-\x7E]{3,100}\.[a-zA-Z0-9]{2,5}\x00', data[:256])
                if match:
                    raw_fn = match.group(0).rstrip(b'\x00').decode('ascii', errors='ignore')
                    # Look for embedded payload
                    # Look for MZ header
                    mz_idx = data.find(b"MZ")
                    if mz_idx != -1 and mz_idx < 1024:
                        return raw_fn, data[mz_idx:]
                    # Or look for ZIP header
                    zip_idx = data.find(b"PK\x03\x04")
                    if zip_idx != -1 and zip_idx < 1024:
                        return raw_fn, data[zip_idx:]
                    return raw_fn, data
        except Exception:
            pass
        return default_name, data

    @classmethod
    def _extract_binary_embedded(cls, file_path: Path, ws: JobWorkspace, items: List[Dict[str, Any]]) -> None:
        """Extract embedded PE resources (nested MZ executables, zip archives, high entropy)."""
        try:
            from app.analyzers.executable_analyzer import ExecutableAnalyzer
            import pefile

            with open(file_path, "rb") as f:
                header = f.read(1024)

            if not header.startswith(b"MZ"):
                return

            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

            # 1. PE Resource Directory Extraction
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    type_str = str(pefile.RESOURCE_TYPE.get(res_type.struct.Id, res_type.name or res_type.struct.Id))
                    if hasattr(res_type, "directory"):
                        for res_id in res_type.directory.entries:
                            id_str = str(res_id.name or res_id.struct.Id)
                            res_bytes = ExecutableAnalyzer.dump_resource(file_path, type_str, id_str)
                            if not res_bytes or len(res_bytes) < 16:
                                continue

                            is_mz = res_bytes.startswith(b"MZ")
                            is_zip = res_bytes.startswith(b"PK\x03\x04") or res_bytes.startswith(b"7z\xbc\xaf\x27\x1c")
                            is_ico = res_bytes.startswith(b"\x00\x00\x01\x00") or type_str in ["RT_ICON", "3", "RT_GROUP_ICON", "14"]

                            if is_mz or is_zip or is_ico or len(res_bytes) > 256:
                                ext = ".exe" if is_mz else (".zip" if is_zip else (".ico" if is_ico else ".bin"))
                                safe_name = sanitize_filename(f"res_{type_str}_{id_str}{ext}")
                                disk_name = f"pe_emb_{len(items)}_{safe_name}"
                                target_path = ws.extracted_dir / disk_name
                                target_path.write_bytes(res_bytes)

                                md5, sha256 = calculate_hashes(res_bytes)
                                detected_mime = detect_mime_type_from_bytes(res_bytes, ext)
                                is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, res_bytes)
                                if is_mz:
                                    is_dangerous = True
                                    reason = "Embedded Windows PE (MZ) Executable Payload"

                                items.append({
                                    "id": len(items),
                                    "name": safe_name,
                                    "source_type": "pe_resource",
                                    "parent_format": "Windows Portable Executable (PE)",
                                    "origin_stream": f"Resource Directory: {type_str}/{id_str}",
                                    "size": len(res_bytes),
                                    "size_formatted": format_file_size(len(res_bytes)),
                                    "mime_type": detected_mime,
                                    "md5": md5,
                                    "sha256": sha256,
                                    "is_dangerous": is_dangerous,
                                    "threat_reason": reason or ("Embedded executable payload in PE resource" if is_dangerous else ""),
                                    "disk_filename": disk_name
                                })

            ws.extracted_dir.mkdir(parents=True, exist_ok=True)
            # 2. Binary Overlay & Carved Embedded File Extraction
            overlay_offset = None
            try:
                overlay_offset = pe.get_overlay_data_start_offset()
            except Exception:
                pass

            pe.close()

            raw_bytes = file_path.read_bytes()
            search_start = overlay_offset if (overlay_offset and overlay_offset < len(raw_bytes)) else 1024

            # Search and carve embedded payloads from the overlay or file body
            found_offsets = set()

            # A. Carve Embedded ZIP / OpenXML (DOCX, XLSX)
            idx = search_start
            while True:
                zip_pos = raw_bytes.find(b"PK\x03\x04", idx)
                if zip_pos == -1:
                    break
                idx = zip_pos + 4
                if zip_pos in found_offsets:
                    continue

                try:
                    import io
                    with zipfile.ZipFile(io.BytesIO(raw_bytes[zip_pos:])) as zf:
                        names = set(zf.namelist())
                        if not names:
                            continue
                        # Determine uncompressed size / span
                        calc_size = sum(i.compress_size for i in zf.infolist()) + len(names) * 128 + 256
                        zip_data = raw_bytes[zip_pos:zip_pos + calc_size + 1024]
                        
                        is_docx = "[Content_Types].xml" in names and any(n.startswith("word/") for n in names)
                        is_xlsx = "[Content_Types].xml" in names and any(n.startswith("xl/") for n in names)
                        
                        ext = ".docx" if is_docx else (".xlsx" if is_xlsx else ".zip")
                        base_label = "embedded_doc" if is_docx else ("embedded_sheet" if is_xlsx else "embedded_archive")
                        safe_name = sanitize_filename(f"{base_label}_{len(items)}{ext}")
                        disk_name = f"pe_carved_{len(items)}_{safe_name}"
                        target_path = ws.extracted_dir / disk_name
                        target_path.write_bytes(zip_data)

                        md5, sha256 = calculate_hashes(zip_data)
                        detected_mime = detect_mime_type_from_bytes(zip_data, ext)
                        is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, zip_data)

                        items.append({
                            "id": len(items),
                            "name": safe_name,
                            "source_type": "pe_overlay_carved",
                            "parent_format": "Windows Portable Executable (Overlay)",
                            "origin_stream": f"PE Overlay at offset 0x{zip_pos:X}",
                            "size": len(zip_data),
                            "size_formatted": format_file_size(len(zip_data)),
                            "mime_type": detected_mime,
                            "md5": md5,
                            "sha256": sha256,
                            "is_dangerous": is_dangerous or bool(is_docx or is_xlsx),
                            "threat_reason": reason or "Carved embedded archive/document inside executable overlay",
                            "disk_filename": disk_name
                        })
                        found_offsets.add(zip_pos)
                        idx = zip_pos + len(zip_data)
                except Exception:
                    pass

            # B. Carve Embedded PDF
            idx = search_start
            while True:
                pdf_pos = raw_bytes.find(b"%PDF-", idx)
                if pdf_pos == -1:
                    break
                idx = pdf_pos + 5
                if pdf_pos in found_offsets:
                    continue

                eof_pos = raw_bytes.find(b"%%EOF", pdf_pos)
                pdf_len = (eof_pos + 5 - pdf_pos) if eof_pos != -1 else min(len(raw_bytes) - pdf_pos, 65536)
                pdf_data = raw_bytes[pdf_pos:pdf_pos + pdf_len]

                safe_name = sanitize_filename(f"embedded_document_{len(items)}.pdf")
                disk_name = f"pe_carved_{len(items)}_{safe_name}"
                target_path = ws.extracted_dir / disk_name
                target_path.write_bytes(pdf_data)

                md5, sha256 = calculate_hashes(pdf_data)
                items.append({
                    "id": len(items),
                    "name": safe_name,
                    "source_type": "pe_overlay_carved",
                    "parent_format": "Windows Portable Executable (Overlay)",
                    "origin_stream": f"PE Overlay at offset 0x{pdf_pos:X}",
                    "size": len(pdf_data),
                    "size_formatted": format_file_size(len(pdf_data)),
                    "mime_type": "application/pdf",
                    "md5": md5,
                    "sha256": sha256,
                    "is_dangerous": False,
                    "threat_reason": "Carved embedded PDF document inside executable overlay",
                    "disk_filename": disk_name
                })
                found_offsets.add(pdf_pos)

            # C. Carve Embedded ICO Icon
            idx = search_start
            while True:
                ico_pos = raw_bytes.find(b"\x00\x00\x01\x00", idx)
                if ico_pos == -1:
                    break
                idx = ico_pos + 4
                if ico_pos in found_offsets:
                    continue

                if ico_pos + 6 <= len(raw_bytes):
                    num_images = int.from_bytes(raw_bytes[ico_pos+4:ico_pos+6], 'little')
                    if 1 <= num_images <= 16:
                        # Extract icon data
                        ico_len = min(len(raw_bytes) - ico_pos, 4096)
                        ico_data = raw_bytes[ico_pos:ico_pos + ico_len]
                        safe_name = sanitize_filename(f"embedded_icon_{len(items)}.ico")
                        disk_name = f"pe_carved_{len(items)}_{safe_name}"
                        target_path = ws.extracted_dir / disk_name
                        target_path.write_bytes(ico_data)

                        md5, sha256 = calculate_hashes(ico_data)
                        items.append({
                            "id": len(items),
                            "name": safe_name,
                            "source_type": "pe_overlay_carved",
                            "parent_format": "Windows Portable Executable (Overlay)",
                            "origin_stream": f"PE Overlay at offset 0x{ico_pos:X}",
                            "size": len(ico_data),
                            "size_formatted": format_file_size(len(ico_data)),
                            "mime_type": "image/x-icon",
                            "md5": md5,
                            "sha256": sha256,
                            "is_dangerous": False,
                            "threat_reason": "Carved embedded application icon inside executable overlay",
                            "disk_filename": disk_name
                        })
                        found_offsets.add(ico_pos)

            # D. Text / C2 Payload in Overlay
            if overlay_offset and overlay_offset < len(raw_bytes):
                overlay_data = raw_bytes[overlay_offset:]
                if len(overlay_data) > 64:
                    safe_name = "overlay_payload.bin"
                    disk_name = f"pe_overlay_{len(items)}_{safe_name}"
                    target_path = ws.extracted_dir / disk_name
                    target_path.write_bytes(overlay_data)

                    md5, sha256 = calculate_hashes(overlay_data)
                    detected_mime = detect_mime_type_from_bytes(overlay_data)
                    items.append({
                        "id": len(items),
                        "name": safe_name,
                        "source_type": "pe_overlay_payload",
                        "parent_format": "Windows Portable Executable (Overlay)",
                        "origin_stream": f"PE Overlay starting at 0x{overlay_offset:X} ({len(overlay_data)} bytes)",
                        "size": len(overlay_data),
                        "size_formatted": format_file_size(len(overlay_data)),
                        "mime_type": detected_mime,
                        "md5": md5,
                        "sha256": sha256,
                        "is_dangerous": True,
                        "threat_reason": "High-entropy unmapped overlay payload appended past declared PE image boundaries",
                        "disk_filename": disk_name
                    })
        except Exception as e:
            logger.debug(f"Binary resource embedded extraction note: {e}")

    @classmethod
    def _extract_email_embedded(cls, file_path: Path, ws: JobWorkspace, items: List[Dict[str, Any]]) -> None:
        """Collect attachments already extracted by EmailAnalyzer."""
        try:
            if ws.extracted_dir.exists():
                for f in sorted(ws.extracted_dir.glob("att_*_*")):
                    try:
                        file_bytes = f.read_bytes()
                        orig_name = f.name.split("_", 2)[-1]
                        safe_name = sanitize_filename(orig_name)
                        md5, sha256 = calculate_hashes(file_bytes)
                        detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                        is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                        items.append({
                            "id": len(items),
                            "name": safe_name,
                            "source_type": "email_attachment",
                            "parent_format": "Email Message (.eml / .msg)",
                            "origin_stream": f"Attachment {f.name}",
                            "size": len(file_bytes),
                            "size_formatted": format_file_size(len(file_bytes)),
                            "mime_type": detected_mime,
                            "md5": md5,
                            "sha256": sha256,
                            "is_dangerous": is_dangerous,
                            "threat_reason": reason or ("Dangerous file attachment in email" if is_dangerous else ""),
                            "disk_filename": f.name
                        })
                    except Exception as fe:
                        logger.debug(f"Email attachment indexing error for {f.name}: {fe}")
        except Exception as e:
            logger.debug(f"Email embedded extraction note: {e}")

    @classmethod
    def _extract_archive_embedded(cls, file_path: Path, ws: JobWorkspace, items: List[Dict[str, Any]], password: Optional[str] = None) -> None:
        """Extract archive members for triage and inspection with password and RAR support."""
        # 1. ZIP Archives (with PyZipper AES & ZipCrypto support)
        if zipfile.is_zipfile(str(file_path)):
            zf = None
            try:
                try:
                    import pyzipper
                    zf = pyzipper.AESZipFile(str(file_path), "r")
                except Exception:
                    zf = zipfile.ZipFile(str(file_path), "r")

                from app.core.settings_store import settings_store
                pw_candidates = []
                if password:
                    pw_candidates.append(password)
                for cp in settings_store.get_archive_passwords():
                    if cp not in pw_candidates:
                        pw_candidates.append(cp)

                for info in zf.infolist()[:50]:  # limit to top 50
                    if info.is_dir() or info.file_size == 0 or info.file_size > 25 * 1024 * 1024:
                        continue
                    try:
                        file_bytes = None
                        if info.flag_bits & 0x1:
                            for cand in pw_candidates:
                                try:
                                    pwd_bytes = cand.encode("utf-8")
                                    file_bytes = zf.read(info.filename, pwd=pwd_bytes)
                                    break
                                except Exception:
                                    pass
                        else:
                            file_bytes = zf.read(info.filename)

                        if file_bytes is None:
                            continue

                        raw_name = Path(info.filename).name
                        safe_name = sanitize_filename(raw_name)
                        disk_name = f"zip_emb_{len(items)}_{safe_name}"
                        target_path = ws.extracted_dir / disk_name
                        target_path.write_bytes(file_bytes)

                        dt_str = None
                        if hasattr(info, "date_time") and info.date_time:
                            try:
                                dt = info.date_time
                                dt_str = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}T{dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}Z"
                            except Exception:
                                pass

                        md5, sha256 = calculate_hashes(file_bytes)
                        detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                        is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                        items.append({
                            "id": len(items),
                            "name": safe_name,
                            "source_type": "archive_member",
                            "parent_format": "ZIP Compressed Archive",
                            "origin_stream": info.filename,
                            "size": len(file_bytes),
                            "size_formatted": format_file_size(len(file_bytes)),
                            "mime_type": detected_mime,
                            "md5": md5,
                            "sha256": sha256,
                            "created_date": dt_str,
                            "modified_date": dt_str,
                            "date_time": dt_str,
                            "is_dangerous": is_dangerous,
                            "threat_reason": reason or ("Executable payload in compressed archive" if is_dangerous else ""),
                            "disk_filename": disk_name
                        })
                    except Exception as ze:
                        logger.debug(f"Zip extraction note for {info.filename}: {ze}")
            except Exception as e:
                logger.debug(f"ZIP embedded extraction note: {e}")
            finally:
                if zf:
                    try:
                        zf.close()
                    except Exception:
                        pass
            return

        # 2. RAR Archives
        is_rar = False
        try:
            with open(file_path, "rb") as f:
                sig = f.read(7)
                if sig.startswith(b"Rar!\x1a\x07"):
                    is_rar = True
        except Exception:
            pass
        if not is_rar and str(file_path).lower().endswith(".rar"):
            is_rar = True

        if is_rar:
            rf = None
            try:
                import rarfile
                rf = rarfile.RarFile(str(file_path))
                from app.core.settings_store import settings_store
                rar_candidates = []
                if password:
                    rar_candidates.append(password)
                for cp in settings_store.get_archive_passwords():
                    if cp not in rar_candidates:
                        rar_candidates.append(cp)

                for info in rf.infolist()[:50]:
                    if info.isdir() or info.file_size == 0 or info.file_size > 25 * 1024 * 1024:
                        continue
                    try:
                        file_bytes = None
                        if getattr(info, "flags", 0) & rarfile.RAR_FILE_PASSWORD:
                            for cand in rar_candidates:
                                try:
                                    file_bytes = rf.read(info.filename, pwd=cand)
                                    break
                                except Exception:
                                    pass
                        else:
                            try:
                                file_bytes = rf.read(info.filename, pwd=password)
                            except Exception:
                                for cand in rar_candidates:
                                    try:
                                        file_bytes = rf.read(info.filename, pwd=cand)
                                        break
                                    except Exception:
                                        pass

                        if file_bytes is None:
                            continue

                        raw_name = Path(info.filename).name
                        safe_name = sanitize_filename(raw_name)
                        disk_name = f"rar_emb_{len(items)}_{safe_name}"
                        target_path = ws.extracted_dir / disk_name
                        target_path.write_bytes(file_bytes)

                        dt_str = None
                        if hasattr(info, "date_time") and info.date_time:
                            try:
                                dt = info.date_time
                                dt_str = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}T{dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}Z"
                            except Exception:
                                pass
                        elif hasattr(info, "mtime") and info.mtime:
                            try:
                                from datetime import datetime, timezone
                                dt_str = datetime.fromtimestamp(info.mtime, tz=timezone.utc).isoformat()
                            except Exception:
                                pass

                        md5, sha256 = calculate_hashes(file_bytes)
                        detected_mime = detect_mime_type_from_bytes(file_bytes, Path(safe_name).suffix)
                        is_dangerous, reason = is_payload_dangerous(safe_name, detected_mime, file_bytes)

                        items.append({
                            "id": len(items),
                            "name": safe_name,
                            "source_type": "archive_member",
                            "parent_format": "RAR Compressed Archive",
                            "origin_stream": info.filename,
                            "size": len(file_bytes),
                            "size_formatted": format_file_size(len(file_bytes)),
                            "mime_type": detected_mime,
                            "md5": md5,
                            "sha256": sha256,
                            "created_date": dt_str,
                            "modified_date": dt_str,
                            "date_time": dt_str,
                            "is_dangerous": is_dangerous,
                            "threat_reason": reason or ("Executable payload in RAR archive" if is_dangerous else ""),
                            "disk_filename": disk_name
                        })
                    except Exception as re_err:
                        logger.debug(f"RAR extraction note for {info.filename}: {re_err}")
            except Exception as e:
                logger.debug(f"RAR embedded extraction note: {e}")
            finally:
                if rf:
                    try:
                        rf.close()
                    except Exception:
                        pass
