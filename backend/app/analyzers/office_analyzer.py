import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger
from oletools.olevba import VBA_Parser
import defusedxml.minidom as safe_minidom

URL_REGEX = re.compile(
    r'(?:https?|ftp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+',
    re.IGNORECASE
)

class OfficeAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "OfficeAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {
            "has_macros": False,
            "macro_details": [],
            "has_activex": False,
            "activex_objects": [],
            "has_ole_objects": False,
            "ole_objects": [],
            "has_external_relationships": False,
            "external_relationships": [],
            "has_embedded_files": False,
            "embedded_files": [],
            "has_comments": False,
            "has_revisions": False,
            "metadata": {},
            "urls": []
        }

        # 1. Macro Analysis via oletools VBA_Parser (without code execution)
        try:
            vba_parser = VBA_Parser(str(file_path))
            if vba_parser.detect_vba_macros():
                data["has_macros"] = True
                macro_analysis = []
                try:
                    results = vba_parser.analyze_macros()
                    for kw_type, keyword, description in results:
                        macro_analysis.append({
                            "type": kw_type,
                            "keyword": keyword,
                            "description": description
                        })
                except Exception as e:
                    logger.debug(f"Error analyzing macro keywords: {e}")

                data["macro_details"] = macro_analysis

                # High severity finding with prominent MACROS DETECTED badge
                findings.append(Finding(
                    category="macro",
                    severity="critical",
                    title="MACROS DETECTED",
                    description=(
                        "Document contains active Visual Basic for Applications (VBA) macros. "
                        "Macros can execute arbitrary operating system commands, drop ransomware, or exfiltrate files. "
                        "FileSanitizer strictly prevents macro execution."
                    ),
                    details={"macro_findings_count": len(macro_analysis), "findings": macro_analysis[:10]}
                ))
            vba_parser.close()
        except Exception as e:
            logger.debug(f"VBA parsing exception (file may not be OLE/VBA): {e}")

        # 2. OpenXML Inspection (DOCX, XLSX, PPTX, etc.)
        if zipfile.is_zipfile(file_path):
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    namelist = zf.namelist()

                    # Check for embedded objects, ActiveX, OLE streams
                    for name in namelist:
                        lower_name = name.lower()
                        if "vba" in lower_name or lower_name.endswith(".bin"):
                            if "vbaproject" in lower_name and not data["has_macros"]:
                                data["has_macros"] = True
                                findings.append(Finding(
                                    category="macro",
                                    severity="critical",
                                    title="MACROS DETECTED",
                                    description="Document contains embedded vbaProject binary stream."
                                ))
                        if "activex" in lower_name:
                            data["has_activex"] = True
                            data["activex_objects"].append(name)
                        if "oleobject" in lower_name or "embeddings" in lower_name:
                            data["has_ole_objects"] = True
                            data["ole_objects"].append(name)
                            data["has_embedded_files"] = True
                            data["embedded_files"].append(name)
                        if "comments" in lower_name:
                            data["has_comments"] = True

                    # Inspect relationship files for external links and remote template injection
                    for name in namelist:
                        if name.endswith(".rels"):
                            try:
                                rel_bytes = zf.read(name)
                                dom = safe_minidom.parseString(rel_bytes)
                                for rel in dom.getElementsByTagName("Relationship"):
                                    target_mode = rel.getAttribute("TargetMode")
                                    target = rel.getAttribute("Target")
                                    rel_type = rel.getAttribute("Type")

                                    if target_mode == "External" or target.startswith("http://") or target.startswith("https://"):
                                        data["has_external_relationships"] = True
                                        data["external_relationships"].append({
                                            "source": name,
                                            "type": rel_type,
                                            "target": target
                                        })
                                        urls.add(target)
                            except Exception:
                                pass

                    # Check for tracked changes / revisions in Word
                    if "word/document.xml" in namelist:
                        try:
                            doc_xml = zf.read("word/document.xml").decode('utf-8', errors='ignore')
                            if "<w:ins " in doc_xml or "<w:del " in doc_xml:
                                data["has_revisions"] = True
                            # Extract text URLs from document.xml
                            for u in URL_REGEX.findall(doc_xml):
                                urls.add(u)
                        except Exception:
                            pass

                    # Extract metadata from docProps/core.xml & app.xml
                    if "docProps/core.xml" in namelist:
                        try:
                            core_bytes = zf.read("docProps/core.xml")
                            dom = safe_minidom.parseString(core_bytes)
                            meta = {}
                            for elem in ["dc:creator", "cp:lastModifiedBy", "dcterms:created", "dcterms:modified", "dc:title"]:
                                nodes = dom.getElementsByTagName(elem)
                                if nodes and nodes[0].firstChild:
                                    field = elem.split(":")[-1]
                                    meta[field] = nodes[0].firstChild.nodeValue
                            data["metadata"] = meta
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Error inspecting OpenXML structure: {e}")

        # Findings for ActiveX and OLE
        if data["has_activex"]:
            findings.append(Finding(
                category="structure",
                severity="high",
                title="ActiveX Controls Detected",
                description="Document contains embedded ActiveX controls. ActiveX controls can be leveraged for code execution.",
                details={"activex_controls": data["activex_objects"]}
            ))

        if data["has_ole_objects"]:
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Embedded OLE Objects Detected",
                description="Document contains embedded OLE storage objects or embedded binary packages.",
                details={"ole_objects": data["ole_objects"]}
            ))

        if data["has_external_relationships"]:
            # Check specifically for remote template injection
            template_injection = any("attachedTemplate" in r.get("type", "") for r in data["external_relationships"])
            if template_injection:
                findings.append(Finding(
                    category="structure",
                    severity="critical",
                    title="Remote Template Injection Detected",
                    description=(
                        "Document contains an external attached template reference. "
                        "Attackers use remote templates to fetch malicious macro templates dynamically when opened."
                    ),
                    details={"relationships": data["external_relationships"]}
                ))
            else:
                findings.append(Finding(
                    category="url",
                    severity="medium",
                    title=f"External Document Relationships Found ({len(data['external_relationships'])})",
                    description="Document references external resources or links.",
                    details={"relationships": data["external_relationships"][:10]}
                ))

        if data["has_comments"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title="Document Comments Present",
                description="Internal author comments discovered in document markup."
            ))

        if data["has_revisions"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title="Tracked Changes / Revisions Present",
                description="Document contains tracked changes or deleted text history."
            ))

        if data["metadata"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title=f"Office Document Metadata ({len(data['metadata'])} fields)",
                description="Author and modification timestamps found in document properties.",
                details=data["metadata"]
            ))

        data["urls"] = list(urls)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
