import re
from pathlib import Path
from typing import Dict, Any, List, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.core.logging_config import logger
import fitz

class PDFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "PDFAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {}

        try:
            doc = fitz.open(file_path)
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to parse PDF document: {e}",
                findings=[Finding(
                    category="structure",
                    severity="high",
                    title="Malformed PDF Document",
                    description=f"PDF parser failed to process file structure: {e}"
                )],
                data={}
            )

        try:
            page_count = doc.page_count
            is_encrypted = doc.is_encrypted
            metadata = doc.metadata or {}

            # Read raw content for low-level structural tokens and exploit indicators
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            raw_text = raw_bytes.decode('latin-1', errors='ignore')

            # 1. Structural tokens check
            has_js = bool(re.search(r'/(?:JavaScript|JS)\b', raw_text))
            has_launch = bool(re.search(r'/Launch\b', raw_text))
            has_open_action = bool(re.search(r'/OpenAction\b', raw_text))
            has_embedded_files = bool(re.search(r'/(?:EmbeddedFiles|EF)\b', raw_text)) or doc.embfile_count() > 0
            has_acroform = bool(re.search(r'/AcroForm\b', raw_text))
            has_xfa = bool(re.search(r'/XFA\b', raw_text))
            has_richmedia = bool(re.search(r'/(?:RichMedia|Screen|Movie)\b', raw_text))

            # Incremental updates check (count of %%EOF markers)
            eof_count = len(re.findall(r'%%EOF', raw_text))

            # 2. Extract Embedded Files Details
            embedded_files_list = []
            try:
                for i in range(doc.embfile_count()):
                    info = doc.embfile_info(i)
                    embedded_files_list.append(info.get("filename", f"attachment_{i}"))
            except Exception:
                pass

            # 3. Extract Links and Annotations from pages
            annot_count = 0
            for page in doc:
                try:
                    # Page links
                    links = page.get_links()
                    for link in links:
                        uri = link.get("uri")
                        if uri:
                            urls.add(uri)
                    # Page annots
                    annots = list(page.annots())
                    annot_count += len(annots)
                    # Extract text URLs
                    page_text = page.get_text()
                    urls.update(extract_clean_urls(page_text))
                except Exception:
                    pass

            # Also find raw URI actions in PDF bytes
            for raw_uri in re.findall(r'/URI\s*\(([^)]+)\)', raw_text):
                urls.update(extract_clean_urls(raw_uri))

            # Also extract URLs embedded within document metadata
            if metadata:
                for m_val in metadata.values():
                    if m_val and isinstance(m_val, str):
                        urls.update(extract_clean_urls(m_val))

            # 4. Generate Security Findings
            if is_encrypted:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="PDF Encryption / Password Protection Detected",
                    description="The PDF is encrypted. Encrypted streams can hinder security inspection."
                ))

            if has_launch:
                findings.append(Finding(
                    category="structure",
                    severity="critical",
                    title="Suspicious /Launch Action Detected",
                    description=(
                        "The document contains a /Launch action. Launch actions can trigger local command "
                        "execution or launch external programs, posing a severe exploit risk."
                    )
                ))

            if has_js:
                findings.append(Finding(
                    category="javascript",
                    severity="high",
                    title="JavaScript Detected in PDF",
                    description=(
                        "Active JavaScript was discovered within PDF objects or actions. "
                        "JavaScript in PDFs is frequently abused for heap-spraying, sandbox escapes, or phishing."
                    )
                ))

            if has_open_action:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="Automatic /OpenAction Trigger Detected",
                    description="The document specifies an action that runs automatically upon opening."
                ))

            if has_embedded_files:
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="Embedded Files / Attachments Detected",
                    description=f"PDF contains {len(embedded_files_list) or 'one or more'} embedded file attachments.",
                    details={"files": embedded_files_list}
                ))

            if has_xfa:
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="XML Forms Architecture (XFA) Detected",
                    description=(
                        "Document contains dynamic XFA forms. XFA has historically been a significant "
                        "vector for remote code execution vulnerabilities in PDF readers."
                    )
                ))
            elif has_acroform:
                findings.append(Finding(
                    category="structure",
                    severity="low",
                    title="Interactive AcroForm Detected",
                    description="Document contains interactive form fields."
                ))

            if has_richmedia:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="Embedded Media Objects Detected",
                    description="Document contains embedded rich media, screen, or movie annotations."
                ))

            if eof_count > 1:
                findings.append(Finding(
                    category="structure",
                    severity="low",
                    title=f"Multiple Incremental Updates ({eof_count} revisions)",
                    description=(
                        "Document contains multiple incremental updates (revisions). "
                        "Incremental updates can mask previous content modifications or shadow attacks."
                    ),
                    details={"revision_count": eof_count}
                ))

            # Metadata findings
            meta_count = sum(1 for v in metadata.values() if v)
            if meta_count > 0:
                findings.append(Finding(
                    category="metadata",
                    severity="low",
                    title=f"Document Metadata Present ({meta_count} fields)",
                    description=f"PDF contains author, creator, or timestamp metadata.",
                    details=metadata
                ))

            if urls:
                findings.append(Finding(
                    category="url",
                    severity="medium" if len(urls) > 5 else "low",
                    title=f"{len(urls)} External URL(s) Discovered in PDF",
                    description=f"Discovered {len(urls)} external links across document pages and stream actions.",
                    details={"urls": list(urls)[:20]}
                ))

            data = {
                "page_count": page_count,
                "is_encrypted": is_encrypted,
                "metadata": metadata,
                "has_javascript": has_js,
                "has_launch_action": has_launch,
                "has_open_action": has_open_action,
                "has_embedded_files": has_embedded_files,
                "embedded_files": embedded_files_list,
                "has_acroform": has_acroform,
                "has_xfa": has_xfa,
                "has_richmedia": has_richmedia,
                "annotation_count": annot_count,
                "incremental_updates": eof_count,
                "urls": list(urls)
            }

            return AnalyzerResult(
                analyzer_name=self.name,
                success=True,
                findings=findings,
                data=data
            )
        finally:
            doc.close()
