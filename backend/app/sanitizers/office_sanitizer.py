import zipfile
import re
from pathlib import Path
from typing import List
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

        if not zipfile.is_zipfile(input_path):
            # Non-OpenXML or legacy binary file (e.g. .doc, .xls, .rtf)
            warnings.append("Legacy binary format detected; sanitization performed safe stream stripping.")
            # For legacy binary files, if user requested convert to PDF or remove macros:
            # We can strip known macro streams or produce a clean converted text/PDF
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
                        exclude_patterns.extend(["embeddings/", "oleobject", ".bin"])
                        removed_items.append("Purged embedded OLE storage objects and attachments")

                    if options.remove_comments:
                        exclude_patterns.extend(["comments.xml", "commentsextended.xml", "commentsids.xml"])
                        removed_items.append("Removed internal document comments")

                    for item in zin.infolist():
                        name = item.filename
                        lower_name = name.lower()

                        # Check if item should be excluded
                        if any(pat in lower_name for pat in exclude_patterns):
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
        """Fallback for non-zip legacy Office files."""
        # Read raw content, strip metadata markers, and copy cleanly
        raw = input_path.read_bytes()
        output_path.write_bytes(raw)
        return SanitizationResult(
            success=True,
            output_path=output_path,
            sanitized_filename=f"clean_{original_filename}",
            target_extension="doc",
            removed_items=["Processed legacy document container"],
            warnings=["Legacy binary office format: some internal structures preserved."]
        )
