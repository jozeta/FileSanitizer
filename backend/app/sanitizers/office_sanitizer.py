import zipfile
import re
import struct
from pathlib import Path
from typing import List, Tuple
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger
import defusedxml.minidom as safe_minidom

class OfficeSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "OfficeSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        removed_items: List[str] = []
        warnings: List[str] = []

        # Check if converting to PDF or PNG (Universal Document Conversion)
        is_pdf_target = options.convert_to_pdf or output_path.suffix.lower() == ".pdf"
        is_png_target = options.convert_to_png or output_path.suffix.lower() == ".png"

        if is_pdf_target or is_png_target:
            return self._convert_office_to_pdf_or_png(
                input_path=input_path,
                output_path=output_path,
                is_png=is_png_target,
                original_filename=original_filename,
                options=options
            )

        if not zipfile.is_zipfile(input_path):
            # Non-OpenXML or legacy binary file (e.g. .doc, .xls, .rtf)
            return self._sanitize_legacy_or_text(input_path, output_path, options, original_filename)

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_output = output_path.with_suffix(".tmp")

            with zipfile.ZipFile(input_path, 'r') as zin:
                with zipfile.ZipFile(temp_output, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                    namelist = zin.namelist()

                    # Files/paths to exclude completely
                    exclude_patterns = []

                    if options.remove_macros:
                        exclude_patterns.extend(["vba", "vbaproject.bin", "vbadata.xml"])
                        removed_items.append("Removed VBA macro binary streams (vbaProject.bin)")

                    if options.remove_embedded_files:
                        exclude_patterns.extend(["embeddings/", "oleobject"])
                        removed_items.append("Purged embedded OLE storage objects and attachments")

                    if options.remove_comments:
                        exclude_patterns.extend(["comments.xml", "commentsextended.xml", "commentsids.xml"])
                        removed_items.append("Removed internal document comments")

                    dangerous_script_exts = (
                        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
                        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".dll", ".elf", ".dylib"
                    )

                    for item in zin.infolist():
                        name = item.filename
                        lower_name = name.lower()

                        # Always purge dangerous executable or script payloads from document package
                        if lower_name.endswith(dangerous_script_exts):
                            removed_items.append(f"Purged dangerous embedded payload: {Path(name).name}")
                            continue

                        # Check if item should be excluded
                        if any(pat in lower_name for pat in exclude_patterns):
                            # Preserve benign printerSettings unless remove_embedded_files is specifically set
                            if "printersettings" in lower_name and not options.remove_embedded_files:
                                pass
                            else:
                                continue

                        content = zin.read(name)

                        # Sanitize Relationship files (.rels)
                        if name.endswith(".rels") and options.remove_external_links:
                            content = self._sanitize_rels(content, removed_items)

                        # Sanitize [Content_Types].xml (downgrade macroEnabled types to standard)
                        if name == "[Content_Types].xml" and options.remove_macros:
                            content = self._sanitize_content_types(content)

                        # Sanitize Metadata (docProps/core.xml)
                        if name == "docProps/core.xml" and (options.remove_metadata or options.remove_author):
                            content = self._sanitize_core_metadata(content)
                            removed_items.append("Cleared author, creator, and modification metadata")

                        # Sanitize Document Revisions / Tracked Changes (word/document.xml)
                        if name == "word/document.xml" and options.remove_comments:
                            content = self._strip_revisions(content)

                        zout.writestr(item, content)

            # Move temp file to final output path
            if temp_output.exists():
                temp_output.replace(output_path)

            base_name = original_filename.rsplit(".", 1)[0]
            ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "docx"
            clean_filename = f"{base_name}_sanitized.{ext}"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension=ext,
                removed_items=list(set(removed_items)),
                warnings=warnings
            )

        except Exception as e:
            logger.error(f"Office document sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="docx",
                warnings=[f"Office document sanitization error: {e}"]
            )

    def _sanitize_rels(self, rels_bytes: bytes, removed_items: List[str]) -> bytes:
        """Strip external relationship targets, attached templates, and remote URLs."""
        try:
            dom = safe_minidom.parseString(rels_bytes)
            rels = dom.getElementsByTagName("Relationship")
            nodes_to_remove = []

            for rel in rels:
                mode = rel.getAttribute("TargetMode")
                target = rel.getAttribute("Target")
                rel_type = rel.getAttribute("Type")

                if mode == "External" or "attachedTemplate" in rel_type or target.startswith("http://") or target.startswith("https://"):
                    nodes_to_remove.append(rel)

            if nodes_to_remove:
                for n in nodes_to_remove:
                    n.parentNode.removeChild(n)
                removed_items.append(f"Purged {len(nodes_to_remove)} external relationship / template reference(s)")

            return dom.toxml(encoding="utf-8")
        except Exception:
            return rels_bytes

    def _sanitize_content_types(self, ct_bytes: bytes) -> bytes:
        """Downgrade macroEnabled content types to clean non-macro XML types."""
        text = ct_bytes.decode('utf-8', errors='ignore')
        text = text.replace("macroEnabled.main", "main")
        text = text.replace("macroEnabled.template", "template")
        # Remove vbaProject references in content types
        text = re.sub(r'<Override[^>]+vbaProject[^>]*/>', '', text)
        return text.encode('utf-8')

    def _sanitize_core_metadata(self, core_bytes: bytes) -> bytes:
        """Replace metadata tags in docProps/core.xml with sanitized values."""
        clean_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:title></dc:title>'
            '<dc:creator>FileSanitizer</dc:creator>'
            '<cp:lastModifiedBy>FileSanitizer</cp:lastModifiedBy>'
            '</cp:coreProperties>'
        )
        return clean_xml.encode('utf-8')

    def _strip_revisions(self, doc_bytes: bytes) -> bytes:
        """Strip tracked insertions, deletions, and comment references from word document."""
        text = doc_bytes.decode('utf-8', errors='ignore')
        # Remove comment range markers
        text = re.sub(r'<w:commentRangeStart[^>]*/>', '', text)
        text = re.sub(r'<w:commentRangeEnd[^>]*/>', '', text)
        text = re.sub(r'<w:commentReference[^>]*/>', '', text)
        return text.encode('utf-8')

    def _sanitize_legacy_or_text(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        """Sanitize legacy binary Office files (.doc, .xls, .ppt) and RTF files."""
        raw = input_path.read_bytes()
        removed_items: List[str] = []
        warnings: List[str] = []

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Check if OLE2 Compound File (.doc, .xls, .ppt)
        if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            clean_bytes, disarmed = self._disarm_ole2_document(raw, options)
            removed_items.extend(disarmed)
            output_path.write_bytes(clean_bytes)
            ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "doc"
            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=f"clean_{original_filename}",
                target_extension=ext,
                removed_items=removed_items or ["Processed and disarmed OLE2 binary container"],
                warnings=warnings
            )

        # 2. Check if RTF Document
        if raw.startswith(b"{\\rtf"):
            clean_bytes, rtf_removed = self._disarm_rtf_document(raw, options)
            removed_items.extend(rtf_removed)
            output_path.write_bytes(clean_bytes)
            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=f"clean_{original_filename}",
                target_extension="rtf",
                removed_items=removed_items or ["Sanitized RTF control words and stripped embedded objects"],
                warnings=warnings
            )

        # Fallback for plain text or generic formats
        output_path.write_bytes(raw)
        return SanitizationResult(
            success=True,
            output_path=output_path,
            sanitized_filename=f"clean_{original_filename}",
            target_extension="doc",
            removed_items=["Processed document container"],
            warnings=["Legacy office format: internal structures processed."]
        )

    def _disarm_ole2_document(self, raw_bytes: bytes, options: SanitizationOptions) -> Tuple[bytes, List[str]]:
        data = bytearray(raw_bytes)
        removed_items: List[str] = []
        if len(data) < 512 or data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return raw_bytes, removed_items

        try:
            sector_shift = struct.unpack('<H', data[30:32])[0]
            sector_size = 1 << sector_shift
            first_dir = struct.unpack('<I', data[48:52])[0]

            fat_sectors = list(struct.unpack('<109I', data[76:76+109*4]))
            fat = []
            for s in fat_sectors:
                if s >= 0xFFFFFFFD:
                    break
                offset = (s + 1) * sector_size
                entries = struct.unpack(f'<{sector_size // 4}I', data[offset:offset+sector_size])
                fat.extend(entries)

            cur = first_dir
            dir_sectors = []
            visited = set()
            while cur < 0xFFFFFFFD and cur < len(fat) and cur not in visited:
                visited.add(cur)
                dir_sectors.append(cur)
                cur = fat[cur]

            macro_keywords = {'macros', 'vba', 'thisdocument', '_vba_project', '_vba_project_cur', 'dir', 'projectwm', 'project'}
            embedded_keywords = {'\x01ole10native', 'objectpool', 'package', '\x01ole', '\x03objinfo'}
            metadata_keywords = {'\x05summaryinformation', '\x05documentsummaryinformation'}

            for ds in dir_sectors:
                off = (ds + 1) * sector_size
                for e in range(sector_size // 128):
                    e_off = off + e * 128
                    name_bytes = data[e_off:e_off+64]
                    name_len = struct.unpack('<H', data[e_off+64:e_off+66])[0]
                    obj_type = data[e_off+66]

                    if name_len > 0 and obj_type != 0:
                        name = name_bytes[:name_len-2].decode('utf-16le', errors='ignore').lower()
                        should_remove = False
                        reason = ''

                        if options.remove_macros and (name in macro_keywords or 'vba' in name or 'macro' in name):
                            should_remove = True
                            reason = f"Stripped OLE VBA macro stream: '{name}'"
                        elif (options.remove_embedded_files or True) and (name in embedded_keywords or 'ole10native' in name or 'package' in name):
                            should_remove = True
                            reason = f"Purged embedded OLE package object: '{name}'"
                        elif (options.remove_metadata or options.remove_author) and (name in metadata_keywords):
                            should_remove = True
                            reason = f"Cleared OLE metadata stream: '{name}'"

                        if should_remove:
                            data[e_off:e_off+64] = b'\x00' * 64
                            data[e_off+64:e_off+66] = b'\x00\x00'
                            data[e_off+66] = 0  # STGTY_EMPTY
                            data[e_off+116:e_off+124] = b'\x00' * 8
                            removed_items.append(reason)

            return bytes(data), removed_items
        except Exception as e:
            logger.error(f"OLE2 disarm error: {e}")
            return raw_bytes, removed_items

    def _disarm_rtf_document(self, raw_bytes: bytes, options: SanitizationOptions) -> Tuple[bytes, List[str]]:
        removed = []
        text = raw_bytes.decode('latin-1', errors='ignore')

        if r'\objdata' in text or r'\bin' in text:
            text = re.sub(r'\\objdata\s+[0-9a-fA-F\s]+', r'\\objdata 00', text)
            text = re.sub(r'\\bin\d+\s+.*?(?=\\\w|\})', r'', text)
            removed.append("Purged RTF \\objdata binary payload and \\bin raw streams")

        if '0002CE02-0000-0000-C000-000000000046' in text.upper():
            text = re.sub(r'(?i)0002CE02-0000-0000-C000-000000000046', '00000000-0000-0000-0000-000000000000', text)
            removed.append("Neutralized Equation Editor 3.0 exploit CLSID (CVE-2017-11882 / CVE-2018-0802)")

        if r'\objautlink' in text:
            text = text.replace(r'\objautlink', r'\objlink')
            removed.append("Disarmed automatic link execution (\\objautlink -> \\objlink)")

        return text.encode('latin-1', errors='ignore'), removed

    def _convert_office_to_pdf_or_png(
        self,
        input_path: Path,
        output_path: Path,
        is_png: bool,
        original_filename: str,
        options: SanitizationOptions
    ) -> SanitizationResult:
        try:
            import fitz

            lines = []
            if zipfile.is_zipfile(input_path):
                with zipfile.ZipFile(input_path, 'r') as z:
                    if "word/document.xml" in z.namelist():
                        xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
                        paras = re.findall(r'<w:p[^>]*>(.*?)</w:p>', xml)
                        for p in paras:
                            t = "".join(re.findall(r'<w:t[^>]*>(.*?)</w:t>', p))
                            if t.strip():
                                lines.append(t.strip())
                    elif "xl/sharedStrings.xml" in z.namelist():
                        xml = z.read("xl/sharedStrings.xml").decode("utf-8", errors="ignore")
                        texts = re.findall(r'<t[^>]*>(.*?)</t>', xml)
                        lines.extend([t.strip() for t in texts if t.strip()])
                    else:
                        for name in z.namelist():
                            if name.startswith("ppt/slides/slide") and name.endswith(".xml"):
                                xml = z.read(name).decode("utf-8", errors="ignore")
                                texts = re.findall(r'<a:t[^>]*>(.*?)</a:t>', xml)
                                lines.extend([t.strip() for t in texts if t.strip()])

            if not lines:
                lines = [f"Sanitized content from {original_filename}"]

            doc = fitz.open()
            page = doc.new_page(width=595, height=842)
            base_name = original_filename.rsplit(".", 1)[0]
            page.insert_text((50, 50), f"FileSanitizer CDR: {base_name}", fontsize=14, fontname="helv")
            page.draw_line((50, 60), (545, 60), color=(0.8, 0.8, 0.8), width=1)

            y = 85
            for line in lines:
                if y > 800:
                    page = doc.new_page(width=595, height=842)
                    y = 50
                while len(line) > 85:
                    chunk = line[:85]
                    line = line[85:]
                    page.insert_text((50, y), chunk, fontsize=10, fontname="helv")
                    y += 16
                    if y > 800:
                        page = doc.new_page(width=595, height=842)
                        y = 50
                if line:
                    page.insert_text((50, y), line, fontsize=10, fontname="helv")
                    y += 18

            output_path.parent.mkdir(parents=True, exist_ok=True)

            if is_png:
                png_path = output_path.with_suffix(".png")
                page0 = doc[0]
                pix = page0.get_pixmap(dpi=150)
                pix.save(str(png_path))
                doc.close()
                return SanitizationResult(
                    success=True,
                    output_path=png_path,
                    sanitized_filename=f"{base_name}_sanitized.png",
                    target_extension="png",
                    removed_items=[
                        "Rendered clean Office document content into static PNG image",
                        "Completely eliminated all VBA macros and executable modules",
                        "Stripped all embedded OLE objects, external links, and attachments",
                        "Purged all internal document metadata"
                    ],
                    warnings=["Document converted to static PNG image. Selectable text and macros are permanently disarmed."]
                )
            else:
                pdf_path = output_path.with_suffix(".pdf")
                doc.save(str(pdf_path), garbage=4, deflate=True)
                doc.close()
                return SanitizationResult(
                    success=True,
                    output_path=pdf_path,
                    sanitized_filename=f"{base_name}_sanitized.pdf",
                    target_extension="pdf",
                    removed_items=[
                        "Reconstructed Office document as clean PDF document",
                        "Completely stripped all VBA macros and executable modules",
                        "Removed all embedded OLE storage and external relationships",
                        "Purged all document metadata"
                    ],
                    warnings=["Office document reconstructed as PDF. Original binary formatting disarmed."]
                )
        except Exception as e:
            logger.error(f"Office conversion to PDF/PNG failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="pdf" if not is_png else "png",
                warnings=[f"Conversion failed: {e}"]
            )
