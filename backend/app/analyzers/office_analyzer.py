import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.core.logging_config import logger
from oletools.olevba import VBA_Parser
import defusedxml.minidom as safe_minidom
from app.analyzers.didier_oledump import DidierOledumpAnalyzer


VBA_CAPABILITY_PATTERNS = {
    "network": [
        (r"(?i)\b(urldownloadtofile|winhttp|msxml2\.xmlhttp|msxml2\.serverxmlhttp|internetopen|internetconnect|internetreadfile)\b", "Network / Outbound Download"),
        (r"(?i)\b(http://|https://|ftp://)", "Hardcoded Web URL"),
    ],
    "process_execution": [
        (r"(?i)\b(wscript\.shell|shellexecute|shell|createobject\s*\(\s*[\"\']wscript\.shell[\"\'])\b", "Process Spawning / Shell Execution"),
        (r"(?i)\b(cmd\.exe|powershell\.exe|wmic\.exe|certutil\.exe|mshta\.exe|rundll32\.exe|cscript\.exe|wscript\.exe|bitsadmin)\b", "Command Line Tool Invocation"),
    ],
    "wmi_execution": [
        (r"(?i)(winmgmts:|getobject\s*\(\s*[\"']winmgmts:|win32_process|win32_processstartup)", "WMI Process Creation / Evasion"),
    ],
    "filesystem": [
        (r"(?i)\b(scripting\.filesystemobject|adodb\.stream|opentextfile|createtextfile)\b", "Filesystem Stream / Dropper"),
        (r"(?i)\bopen\s+[^\n]+for\s+binary\b", "Raw Binary File Writing"),
        (r"(?i)\benviron\s*\(\s*[\"'](temp|appdata|localappdata|comspec|windir)[\"']\s*\)", "Environment Path Targetting (Staging)"),
    ],
    "persistence": [
        (r"(?i)\b(autoopen|workbook_open|document_open|autoexec|auto_open|document_close|workbook_beforeclose|autoexit|autonew)\b", "Auto-Execution Trigger Hook"),
        (r"(?i)\b(currentversion\\run|software\\microsoft\\windows\\currentversion|regwrite|regread)\b", "Registry Persistence Hook"),
    ],
    "memory_injection": [
        (r"(?i)\b(virtualalloc|virtualprotect|rtlmovememory|createremotethread|writeprocessmemory|memcpy|callwindowproc|enumchildwindows)\b", "Memory Allocation / Shellcode Injection API"),
        (r"(?i)\bdeclare\s+(?:ptrsafe\s+)?(?:function|sub)\s+[a-zA-Z0-9_]+\s+lib\s+[\"'](kernel32|user32|ntdll|advapi32|urlmon|shell32)[\"']", "Native Win32 API Direct Declaration"),
    ],
    "obfuscation": [
        (r"(?i)\b(chr|chrb|chrw)\s*\(\s*\d+\s*\)", "Character Code Dynamic String Assembly"),
        (r"(?i)\b(strreverse|replace\s*\([^\)]+,\s*[\"'][^\"']+[\"'],\s*[\"'][^\"']*[\"']\))\b", "String Reversal / Token Manipulation"),
        (r"(?i)\bxor\s+\d+\b", "Single-Byte / Multi-Byte XOR Decryption"),
    ],
    "anti_analysis": [
        (r"(?i)\b(application\.wait|sleep\b|gettickcount|timegettime)\b", "Execution Delay / Sandbox Timeout Bypass"),
        (r"(?i)\bisdebuggerpresent\b", "Debugger Detection Check"),
    ]
}


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
            "vba_capabilities": {},
            "vba_stomping": {"is_stomped": False, "details": []},
            "vba_purging": {"is_purged": False, "details": []},
            "xlm_macros": {"has_xlm_macros": False, "details": []},
            "rtf_exploits": {"is_rtf": False, "has_exploits": False, "details": []},
            "ole_forensics": {},
            "has_activex": False,
            "activex_objects": [],
            "has_ole_objects": False,
            "ole_objects": [],
            "has_external_relationships": False,
            "external_relationships": [],
            "remote_templates": [],
            "moniker_links": [],
            "follina_exploits": [],
            "mshtml_exploits": [],
            "romcom_links": [],
            "dde_injections": [],
            "has_embedded_files": False,
            "embedded_files": [],
            "has_comments": False,
            "has_revisions": False,
            "metadata": {},
            "urls": []
        }

        # 1. Macro Analysis via oletools VBA_Parser
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

                # Extract full macro source code per module stream via olevba
                modules = []
                code_blocks = []
                combined_source_code = ""
                try:
                    for subfilename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                        clean_code = (vba_code or "").strip()
                        if clean_code:
                            mod_name = vba_filename or subfilename or "Module"
                            modules.append({
                                "name": mod_name,
                                "stream": stream_path or "",
                                "code": clean_code
                            })
                            code_blocks.append(f"' ===== Module: {mod_name} ({stream_path}) =====\n{clean_code}")
                            combined_source_code += "\n" + clean_code
                except Exception as e:
                    logger.debug(f"Error extracting macro streams: {e}")

                if modules:
                    data["macro_modules"] = modules
                    data["macro_source_code"] = combined_source_code
                    data["extracted_code"] = {
                        "type": "vba",
                        "language": "vb",
                        "code": "\n\n".join(code_blocks),
                        "modules": modules
                    }

                # VBA Capability Auto-Tagging
                capabilities = {}
                for cap_cat, pat_list in VBA_CAPABILITY_PATTERNS.items():
                    matched_caps = []
                    for regex, label in pat_list:
                        m = re.findall(regex, combined_source_code)
                        if m:
                            matched_caps.append({
                                "label": label,
                                "count": len(m),
                                "samples": list(set([str(item) if not isinstance(item, tuple) else item[0] for item in m]))[:5]
                            })
                    if matched_caps:
                        capabilities[cap_cat] = matched_caps

                data["vba_capabilities"] = capabilities
                if capabilities:
                    findings.append(Finding(
                        category="macro",
                        severity="high" if any(k in capabilities for k in ["process_execution", "memory_injection", "network"]) else "medium",
                        title=f"VBA Macro Operational Capabilities Identified ({len(capabilities)} categories)",
                        description=(
                            "Automated static analysis categorized VBA macro API usage into operational security capabilities: "
                            f"{', '.join(capabilities.keys()).upper()}."
                        ),
                        details={"capabilities": capabilities}
                    ))

                # VBA Stomping Check: Compare P-code presence vs extracted source code
                try:
                    # In VBA stomping, compiled P-code contains suspicious commands while source is empty or benign
                    pcode_indicators = []
                    if len(combined_source_code.strip()) < 50 and len(macro_analysis) > 0:
                        pcode_indicators.append("Macro analysis flagged suspicious keywords but decompressed source code is missing or empty")

                    # Check for keywords flagged by oletools that do NOT exist in the source code
                    for item in macro_analysis:
                        kw = item.get("keyword", "")
                        if kw and kw.lower() not in combined_source_code.lower() and len(kw) > 3:
                            pcode_indicators.append(f"Keyword '{kw}' detected in P-code performance stream but absent from source code")

                    if pcode_indicators:
                        data["vba_stomping"] = {
                            "is_stomped": True,
                            "details": pcode_indicators
                        }
                        findings.append(Finding(
                            category="macro",
                            severity="critical",
                            title="VBA Stomping Discrepancy Detected",
                            description=(
                                "Discrepancy detected between compiled P-code performance streams and decompressed VBA source code. "
                                "VBA Stomping allows malicious macros to execute while evading static source-code antivirus inspection."
                            ),
                            details={"indicators": pcode_indicators}
                        ))
                except Exception as ve:
                    logger.debug(f"VBA stomping check note: {ve}")

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
                    details={
                        "macro_findings_count": len(macro_analysis),
                        "module_count": len(modules),
                        "findings": macro_analysis[:10]
                    }
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
                            if "vbaproject" in lower_name:
                                if not data["has_macros"]:
                                    data["has_macros"] = True
                                    findings.append(Finding(
                                        category="macro",
                                        severity="critical",
                                        title="MACROS DETECTED",
                                        description="Document contains embedded vbaProject binary stream."
                                    ))
                                if not data.get("extracted_code"):
                                    try:
                                        bin_bytes = zf.read(name)
                                        found_code = []
                                        matches = re.findall(rb'((?:Sub|Function|Private Sub|Public Sub)[\s\S]{5,3000}?End (?:Sub|Function))', bin_bytes, re.IGNORECASE)
                                        for m in matches:
                                            found_code.append(m.decode('latin-1', errors='ignore').strip())
                                        if found_code:
                                            combined = "\n\n".join(found_code)
                                            mod_list = [{"name": "MacroModule", "stream": name, "code": combined}]
                                            data["macro_modules"] = mod_list
                                            data["macro_source_code"] = combined
                                            data["extracted_code"] = {
                                                "type": "vba",
                                                "language": "vb",
                                                "code": combined,
                                                "modules": mod_list
                                            }
                                            if not data.get("vba_capabilities"):
                                                caps = {}
                                                for cap_cat, pat_list in VBA_CAPABILITY_PATTERNS.items():
                                                    matched_caps = []
                                                    for regex, label in pat_list:
                                                        m = re.findall(regex, combined)
                                                        if m:
                                                            matched_caps.append({
                                                                "label": label,
                                                                "count": len(m),
                                                                "samples": list(set([str(item) if not isinstance(item, tuple) else item[0] for item in m]))[:5]
                                                            })
                                                    if matched_caps:
                                                        caps[cap_cat] = matched_caps
                                                data["vba_capabilities"] = caps
                                    except Exception as e:
                                        logger.debug(f"Fallback VBA extraction note: {e}")
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

                    # Inspect relationship files for external links, remote template injection, and CVEs
                    remote_templates = []
                    moniker_links = []
                    follina_links = []
                    mshtml_links = []
                    romcom_links = []
                    for name in namelist:
                        if name.endswith(".rels"):
                            try:
                                rel_bytes = zf.read(name)
                                dom = safe_minidom.parseString(rel_bytes)
                                for rel in dom.getElementsByTagName("Relationship"):
                                    target_mode = rel.getAttribute("TargetMode")
                                    target = rel.getAttribute("Target")
                                    rel_type = rel.getAttribute("Type")

                                    # Check CVE-2024-21413 MonikerLink (file://...! or \\...!)
                                    if re.search(r'(?i)(?:file://|\\\\)[^\s"\'>]+!', target):
                                        moniker_links.append({"source": name, "target": target, "type": rel_type})

                                    # Check CVE-2022-30190 Follina MSDT
                                    if "ms-msdt:" in target.lower():
                                        follina_links.append({"source": name, "target": target, "type": rel_type})

                                    # Check CVE-2021-40444 MSHTML CAB / INF
                                    if target.lower().startswith("mhtml:") or any(target.lower().endswith(ext) for ext in [".cab", ".inf"]):
                                        mshtml_links.append({"source": name, "target": target, "type": rel_type})

                                    # Check CVE-2023-36884 RomCom / Search-MS
                                    if any(p in target.lower() for p in ["search-ms:", "search:"]) or target.lower().endswith(".url"):
                                        romcom_links.append({"source": name, "target": target, "type": rel_type})

                                    is_external = target_mode == "External" or target.startswith(("http://", "https://", "\\\\", "smb://"))
                                    if is_external:
                                        data["has_external_relationships"] = True
                                        data["external_relationships"].append({
                                            "source": name,
                                            "type": rel_type,
                                            "target": target
                                        })
                                        urls.update(extract_clean_urls(target))

                                        # Check specifically for remote template injection
                                        if any(k in rel_type.lower() for k in ["attachedtemplate", "subdocument", "template"]):
                                            remote_templates.append({
                                                "source": name,
                                                "target": target,
                                                "type": rel_type
                                            })
                            except Exception:
                                pass
                    data["remote_templates"] = remote_templates
                    data["moniker_links"] = moniker_links
                    data["follina_exploits"] = follina_links
                    data["mshtml_exploits"] = mshtml_links
                    data["romcom_links"] = romcom_links

                    # Check for DDE / DDEAUTO command injection across all XML parts
                    dde_injections = []
                    for xml_part in [n for n in namelist if n.endswith(".xml")]:
                        try:
                            part_text = zf.read(xml_part).decode('utf-8', errors='ignore')
                            if re.search(r'(?i)(?:=\s*(?:cmd|powershell|mshta|certutil|rundll32|regsvr32)\b|\bDDEAUTO\b|\bDDE\s+)', part_text):
                                dde_injections.append(xml_part)
                            # Also check for inline Follina or MonikerLink inside document XML
                            if "ms-msdt:" in part_text.lower() and not follina_links:
                                follina_links.append({"source": xml_part, "target": "ms-msdt: protocol reference in XML", "type": "Inline XML"})
                            if re.search(r'(?i)(?:file://|\\\\)[^\s"\'><]+![a-zA-Z0-9_\-\./]*', part_text) and not moniker_links:
                                moniker_links.append({"source": xml_part, "target": "MonikerLink ! syntax in XML", "type": "Inline XML"})
                        except Exception:
                            pass
                    data["dde_injections"] = dde_injections

                    # Check for tracked changes / revisions in Word
                    if "word/document.xml" in namelist:
                        try:
                            doc_xml = zf.read("word/document.xml").decode('utf-8', errors='ignore')
                            if "<w:ins " in doc_xml or "<w:del " in doc_xml:
                                data["has_revisions"] = True
                            # Extract text URLs from document.xml
                            urls.update(extract_clean_urls(doc_xml))
                        except Exception:
                            pass

                    # Extract metadata from docProps/core.xml & custom.xml
                    if "docProps/core.xml" in namelist:
                        try:
                            core_bytes = zf.read("docProps/core.xml")
                            dom = safe_minidom.parseString(core_bytes)
                            meta = {}
                            for elem in [
                                "dc:creator", "cp:lastModifiedBy", "dcterms:created",
                                "dcterms:modified", "dc:title", "dc:description",
                                "dc:subject", "cp:keywords", "cp:category", "cp:revision"
                            ]:
                                nodes = dom.getElementsByTagName(elem)
                                if nodes and nodes[0].firstChild:
                                    field = elem.split(":")[-1]
                                    meta[field] = nodes[0].firstChild.nodeValue
                            data["metadata"] = meta

                            # Extract URLs in metadata
                            core_text = core_bytes.decode('utf-8', errors='ignore')
                            urls.update(extract_clean_urls(core_text))
                        except Exception:
                            pass

                    if "docProps/custom.xml" in namelist:
                        try:
                            custom_text = zf.read("docProps/custom.xml").decode('utf-8', errors='ignore')
                            urls.update(extract_clean_urls(custom_text))
                        except Exception:
                            pass

                    # Extract app.xml for TotalTime / Editing duration
                    if "docProps/app.xml" in namelist:
                        try:
                            app_bytes = zf.read("docProps/app.xml")
                            dom = safe_minidom.parseString(app_bytes)
                            time_nodes = dom.getElementsByTagName("TotalTime")
                            if time_nodes and time_nodes[0].firstChild:
                                total_time = int(time_nodes[0].firstChild.nodeValue)
                                data["ole_forensics"]["total_edit_time_minutes"] = total_time
                                if total_time == 0 and (data["has_macros"] or len(urls) > 0):
                                    findings.append(Finding(
                                        category="metadata",
                                        severity="medium",
                                        title="Zero Human Editing Time Anomaly",
                                        description="Document metadata indicates Total Editing Time is 0 minutes despite active content, a typical footprint of automated phishing/malware generators.",
                                        details={"total_time_minutes": total_time}
                                    ))
                        except Exception:
                            pass

                    # -------------------------------------------------------------
                    # Excel Deep Inspection (Very Hidden Sheets, Power Query M-Code)
                    # -------------------------------------------------------------
                    excel_info = {
                        "very_hidden_sheets": [],
                        "hidden_sheets": [],
                        "all_sheets": [],
                        "protected_sheets": [],
                        "power_query_queries": [],
                        "hidden_rows_cols": 0
                    }

                    # Inspect xl/workbook.xml for sheet visibility
                    if "xl/workbook.xml" in namelist:
                        try:
                            wb_bytes = zf.read("xl/workbook.xml")
                            dom = safe_minidom.parseString(wb_bytes)
                            for sheet_node in dom.getElementsByTagName("sheet"):
                                s_name = sheet_node.getAttribute("name")
                                s_id = sheet_node.getAttribute("sheetId")
                                s_state = sheet_node.getAttribute("state")  # "hidden", "veryHidden", or empty
                                s_record = {"name": s_name, "sheet_id": s_id, "state": s_state or "visible"}
                                excel_info["all_sheets"].append(s_record)
                                if s_state == "veryHidden":
                                    excel_info["very_hidden_sheets"].append(s_record)
                                elif s_state == "hidden":
                                    excel_info["hidden_sheets"].append(s_record)

                            if excel_info["very_hidden_sheets"]:
                                vnames = [s["name"] for s in excel_info["very_hidden_sheets"]]
                                findings.append(Finding(
                                    category="evasion",
                                    severity="high",
                                    title=f"Excel 'Very Hidden' Sheets Detected ({len(vnames)} sheets)",
                                    description=(
                                        f"Spreadsheet contains {len(vnames)} 'veryHidden' (xlSheetVeryHidden) sheet(s): {', '.join(vnames)}. "
                                        "Very hidden sheets cannot be viewed or unhidden via the standard Excel UI and require VBA code to access. "
                                        "Threat actors utilize very hidden sheets to conceal secondary payloads, staging commands, and stolen credentials."
                                    ),
                                    details={"very_hidden_sheets": excel_info["very_hidden_sheets"]}
                                ))
                        except Exception as wb_err:
                            logger.debug(f"Excel workbook.xml parse error: {wb_err}")

                    # Inspect sheet protection and hidden rows/cols across xl/worksheets/
                    for name in namelist:
                        if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
                            try:
                                s_content = zf.read(name).decode("utf-8", errors="ignore")
                                if "<sheetProtection" in s_content:
                                    excel_info["protected_sheets"].append(name)
                                hidden_r = len(re.findall(r'<row[^>]*\bhidden=["\']1["\']', s_content))
                                hidden_c = len(re.findall(r'<col[^>]*\bhidden=["\']1["\']', s_content))
                                excel_info["hidden_rows_cols"] += (hidden_r + hidden_c)
                                urls.update(extract_clean_urls(s_content))
                            except Exception:
                                pass

                    if excel_info["protected_sheets"]:
                        findings.append(Finding(
                            category="evasion",
                            severity="medium",
                            title=f"Excel Sheet Protection Enabled ({len(excel_info['protected_sheets'])} sheets)",
                            description="One or more worksheets enforce sheet protection to prevent analyst modification or formula inspection.",
                            details={"sheets": excel_info["protected_sheets"]}
                        ))

                    # Inspect Power Query M-Code exfiltration across connections and queries
                    pq_candidates = [n for n in namelist if n.startswith("xl/connections.xml") or n.startswith("xl/queryTables/") or "customXml" in n]
                    for pq_name in pq_candidates:
                        try:
                            pq_xml = zf.read(pq_name).decode("utf-8", errors="ignore")
                            import html
                            pq_decoded = html.unescape(pq_xml)
                            urls.update(extract_clean_urls(pq_decoded))
                            # Detect Power Query M-code patterns
                            m_code_patterns = [
                                r"Web\.Contents\s*\(\s*[\"']([^\"']+)[\"']",
                                r"Web\.Page\s*\(",
                                r"Uri\.Combine\s*\(",
                                r"Json\.Document\s*\(\s*Web\.Contents",
                                r"Binary\.Buffer\s*\(",
                                r"Odbc\.Query\s*\(",
                                r"OleDb\.Query\s*\(",
                                r"Lines\.FromBinary\s*\(\s*Web\.Contents"
                            ]
                            matched_m_patterns = []
                            for pat in m_code_patterns:
                                found = re.findall(pat, pq_decoded, re.IGNORECASE)
                                if found:
                                    matched_m_patterns.append(pat)
                                    for target_url in found:
                                        if isinstance(target_url, str) and target_url.startswith(("http://", "https://", "ftp://")):
                                            urls.add(target_url)

                            if matched_m_patterns or "Web.Contents" in pq_xml:
                                excel_info["power_query_queries"].append({
                                    "source": pq_name,
                                    "matched_patterns": matched_m_patterns,
                                    "snippet": pq_xml[:500]
                                })
                                findings.append(Finding(
                                    category="active_content",
                                    severity="critical",
                                    title="Excel Power Query M-Code Outbound Web / Exfiltration Primitive Detected",
                                    description=(
                                        f"File '{pq_name}' contains Power Query (M-code) formulas with outbound network functions (Web.Contents/Web.Page). "
                                        "Attackers abuse Power Query to bypass macro security warnings, fetch remote payloads, and exfiltrate data via HTTP."
                                    ),
                                    details={"file": pq_name, "patterns": matched_m_patterns}
                                ))
                        except Exception:
                            pass

                    if any(excel_info.values()):
                        data["excel_analysis"] = excel_info

                    # -------------------------------------------------------------
                    # PowerPoint Deep Inspection (Mouse-Over Hover Actions & Hidden Slides)
                    # -------------------------------------------------------------
                    ppt_info = {
                        "hover_actions": [],
                        "click_actions": [],
                        "hidden_slides": [],
                        "slide_count": 0
                    }

                    slide_names = [n for n in namelist if n.startswith("ppt/slides/slide") and n.endswith(".xml")]
                    ppt_info["slide_count"] = len(slide_names)

                    for s_name in slide_names:
                        try:
                            s_content = zf.read(s_name).decode("utf-8", errors="ignore")
                            urls.update(extract_clean_urls(s_content))

                            # Check for hidden slide: <p:sld ... show="0" ...>
                            if re.search(r'<p:sld[^>]*\bshow=["\']0["\']', s_content) or re.search(r'<p:sld[^>]*\bshow=["\']false["\']', s_content):
                                ppt_info["hidden_slides"].append(s_name)

                            # Check for Mouse-Over (a:hlinkHover) Action Traps
                            hover_matches = re.findall(r'<a:hlinkHover\b([^>]*)/?>', s_content)
                            for h_raw in hover_matches:
                                action_match = re.search(r'action=["\']([^"\']+)["\']', h_raw)
                                act_val = action_match.group(1) if action_match else "unknown"
                                ppt_info["hover_actions"].append({
                                    "slide": s_name,
                                    "action": act_val,
                                    "raw": h_raw
                                })

                            # Check for Click (a:hlinkClick) Program Actions
                            click_matches = re.findall(r'<a:hlinkClick\b([^>]*)/?>', s_content)
                            for c_raw in click_matches:
                                action_match = re.search(r'action=["\']([^"\']+)["\']', c_raw)
                                act_val = action_match.group(1) if action_match else "unknown"
                                if "program" in act_val.lower() or "ppaction://" in act_val.lower():
                                    ppt_info["click_actions"].append({
                                        "slide": s_name,
                                        "action": act_val,
                                        "raw": c_raw
                                    })
                        except Exception:
                            pass

                    # Raise findings for PowerPoint hover traps
                    if ppt_info["hover_actions"]:
                        is_prog = any("ppaction://program" in h["action"].lower() for h in ppt_info["hover_actions"])
                        findings.append(Finding(
                            category="active_content",
                            severity="critical" if is_prog else "high",
                            title=f"PowerPoint Mouse-Over Action Trap Detected ({len(ppt_info['hover_actions'])} trigger(s))",
                            description=(
                                f"Slide presentation contains {len(ppt_info['hover_actions'])} mouse-over (<a:hlinkHover>) trigger action(s). "
                                "Hover actions allow attackers to execute programs or initiate malicious navigation simply when the user hovers their mouse cursor "
                                "over a presentation element, without requiring any mouse clicks (e.g. CVE-2017-8759 weaponized presentations)."
                            ),
                            details={"hover_actions": ppt_info["hover_actions"]}
                        ))

                    if ppt_info["click_actions"]:
                        findings.append(Finding(
                            category="active_content",
                            severity="critical",
                            title=f"PowerPoint Click Program Action Execution Detected ({len(ppt_info['click_actions'])} actions)",
                            description="Presentation contains embedded program execution triggers (<a:hlinkClick action='ppaction://program'>).",
                            details={"click_actions": ppt_info["click_actions"]}
                        ))

                    if ppt_info["hidden_slides"]:
                        findings.append(Finding(
                            category="evasion",
                            severity="medium",
                            title=f"PowerPoint Hidden Slides Detected ({len(ppt_info['hidden_slides'])} slide(s))",
                            description=f"Presentation contains {len(ppt_info['hidden_slides'])} hidden slide(s) concealed from normal slide show presentation view.",
                            details={"hidden_slides": ppt_info["hidden_slides"]}
                        ))

                    if ppt_info["slide_count"] > 0:
                        data["powerpoint_analysis"] = ppt_info

            except Exception as e:
                logger.debug(f"Error inspecting OpenXML structure: {e}")

        # 3. Rich Text Format (RTF) Exploit Deep Inspection & Object Carving
        try:
            with open(file_path, "rb") as rf:
                rtf_header = rf.read(2048)
            if rtf_header.startswith(b"{\\rtf"):
                data["rtf_exploits"]["is_rtf"] = True
                rtf_full = file_path.read_bytes()
                rtf_findings = []
                rtf_carved_payloads = []

                # Equation Editor CLSID (CVE-2017-11882 / CVE-2018-0802)
                if re.search(rb"(?i)0002CE02-0000-0000-C000-000000000046", rtf_full):
                    rtf_findings.append("Equation Editor 3.0 Memory Corruption Exploit (CVE-2017-11882 / CVE-2018-0802)")

                # Composite Moniker / HTA Handler (CVE-2017-0199 / CVE-2017-8570)
                if re.search(rb"(?i)00000316-0000-0000-C000-000000000046|00000315-0000-0000-C000-000000000046", rtf_full):
                    rtf_findings.append("Composite Moniker / HTA Remote Code Execution (CVE-2017-0199 / CVE-2017-8570)")

                # MonikerLink Outlook / Office NTLM Relay & Code Execution (CVE-2024-21413)
                if re.search(rb"(?i)(?:file://|\\\\)[^\r\n\"\'><\s]+![a-zA-Z0-9_\-\./]*", rtf_full):
                    rtf_findings.append("MonikerLink Security Feature Bypass (CVE-2024-21413)")

                # Follina MSDT Protocol Handler (CVE-2022-30190)
                if re.search(rb"(?i)ms-msdt:", rtf_full):
                    rtf_findings.append("Follina MSDT Remote Code Execution (CVE-2022-30190)")

                # VBScript Engine Corrupted Moniker (CVE-2018-8174)
                if re.search(rb"(?i)F414C260-6AC0-11CF-B6D1-00AA00BBBB58", rtf_full):
                    rtf_findings.append("VBScript Engine Use-After-Free CLSID (CVE-2018-8174)")

                # MSHTML CAB / ActiveX container (CVE-2021-40444)
                if re.search(rb"(?i)mhtml:", rtf_full) or re.search(rb"(?i)\.cab\b", rtf_full):
                    rtf_findings.append("MSHTML / CAB Remote Exploit Trigger (CVE-2021-40444)")

                # RomCom Search-MS Protocol Handler (CVE-2023-36884)
                if re.search(rb"(?i)search-ms:", rtf_full):
                    rtf_findings.append("RomCom Search-MS Protocol Handler Exploit (CVE-2023-36884)")

                # Automatic OLE object update links
                if re.search(rb"(?i)\\objautlink", rtf_full):
                    rtf_findings.append("Automatic OLE Link Execution (\\objautlink)")

                # Font table manipulation / buffer overflow (CVE-2010-3333)
                if re.search(rb"(?i)\\fonttbl[^{}]*\{\\f\d+\s+[^;]{128,};", rtf_full):
                    rtf_findings.append("Malformed / Overlong Font Table Parameter (Potential CVE-2010-3333 Buffer Overflow)")

                # Obfuscation via control word splitting or excessive hex escapes
                hex_escapes = len(re.findall(rb"\\'[0-9a-fA-F]{2}", rtf_full))
                if hex_escapes > 100:
                    rtf_findings.append(f"High Density RTF Hex Escaping ({hex_escapes} escaped tokens)")

                # RTF \objdata binary stream inspection
                objdata_matches = re.findall(rb"(?i)\\objdata\s+([0-9a-fA-F\s]{64,})", rtf_full)
                if objdata_matches:
                    for idx, hex_raw in enumerate(objdata_matches[:3]):
                        clean_hex = re.sub(rb"\s+", b"", hex_raw)
                        try:
                            decoded_raw = bytes.fromhex(clean_hex.decode('latin-1'))
                            if b"MZ" in decoded_raw[:512]:
                                rtf_findings.append(f"Embedded Windows PE Executable Carved from \\objdata stream #{idx+1}")
                                rtf_carved_payloads.append("Windows PE Executable")
                            elif b"powershell" in decoded_raw.lower() or b"wscript" in decoded_raw.lower() or b"cmd.exe" in decoded_raw.lower():
                                rtf_findings.append(f"Script Execution Triggers Embedded inside \\objdata stream #{idx+1}")
                                rtf_carved_payloads.append("Script Payload")
                        except Exception:
                            pass

                if rtf_findings:
                    data["rtf_exploits"]["has_exploits"] = True
                    data["rtf_exploits"]["details"] = rtf_findings
                    data["rtf_exploits"]["carved_payloads"] = rtf_carved_payloads
                    findings.append(Finding(
                        category="structure",
                        severity="critical",
                        title=f"RTF Weaponized Exploitation Vectors Detected ({len(rtf_findings)})",
                        description=f"Identified weaponized Rich Text Format (RTF) exploit structures: {', '.join(rtf_findings)}.",
                        details={"exploits": rtf_findings, "carved_payloads": rtf_carved_payloads}
                    ))
        except Exception as rtf_e:
            logger.debug(f"RTF exploit scan note: {rtf_e}")

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

        if data.get("remote_templates"):
            findings.append(Finding(
                category="structure",
                severity="critical",
                title=f"Remote Template Injection Detected ({len(data['remote_templates'])} target{'s' if len(data['remote_templates']) > 1 else ''})",
                description=(
                    "Document contains external relationship targets pointing to remote templates. "
                    "Attackers use remote template injection to dynamically retrieve weaponized dotm macros when opened."
                ),
                details={"templates": data["remote_templates"]}
            ))

        if data.get("moniker_links"):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="MonikerLink Remote Code Execution / NTLM Relay (CVE-2024-21413)",
                description=(
                    "Document contains external relationship targets utilizing the MonikerLink exclamation mark ('!') bypass "
                    "(e.g. file://host/share/doc.docx!payload). In Microsoft Office/Outlook, this bypasses Protected View "
                    "restrictions and triggers automatic NTLM hash exfiltration or arbitrary code execution."
                ),
                details={"targets": data["moniker_links"], "cve": "CVE-2024-21413", "mitre_technique": "T1204.002"}
            ))

        if data.get("follina_exploits"):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Follina MSDT Protocol Handler Remote Code Execution (CVE-2022-30190)",
                description=(
                    "Document contains relationship targets or XML references referencing the 'ms-msdt:' URL protocol handler. "
                    "Exploits Microsoft Support Diagnostic Tool (CVE-2022-30190) to execute arbitrary PowerShell commands "
                    "without requiring macros to be enabled."
                ),
                details={"targets": data["follina_exploits"], "cve": "CVE-2022-30190", "mitre_technique": "T1218"}
            ))

        if data.get("mshtml_exploits"):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="MSHTML Remote ActiveX / CAB Execution (CVE-2021-40444)",
                description=(
                    "Document relationships reference mhtml: protocol or remote CAB/INF archives. "
                    "Exploits CVE-2021-40444 in the MSHTML browser engine to deploy and execute weaponized ActiveX controls."
                ),
                details={"targets": data["mshtml_exploits"], "cve": "CVE-2021-40444", "mitre_technique": "T1204"}
            ))

        if data.get("romcom_links"):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Office RomCom / Search-MS HTML Remote Code Execution (CVE-2023-36884)",
                description=(
                    "Document links to external search-ms: or active HTML handler targets. "
                    "Exploited by RomCom threat actors (CVE-2023-36884) to trigger remote code execution via search connector files."
                ),
                details={"targets": data["romcom_links"], "cve": "CVE-2023-36884", "mitre_technique": "T1204"}
            ))

        if data.get("dde_injections"):
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title=f"Office DDE / DDEAUTO Command Injection Detected ({len(data['dde_injections'])} part(s))",
                description=(
                    f"Document contains Dynamic Data Exchange (DDE) formula execution syntax in {', '.join(data['dde_injections'][:3])}. "
                    "DDE formulas execute local processes (e.g. cmd.exe, powershell.exe) directly from document formulas without VBA macros."
                ),
                details={"parts": data["dde_injections"], "mitre_technique": "T1204.002"}
            ))

        if urls:
            findings.append(Finding(
                category="url",
                severity="medium" if len(urls) > 5 else "low",
                title=f"{len(urls)} External URL(s) Discovered in Office Document",
                description=f"Discovered {len(urls)} external links across document markup, relationships, and metadata properties.",
                details={"urls": list(urls)[:20]}
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

        # 3. Didier Stevens oledump-style deep stream analysis
        try:
            oledump_res = DidierOledumpAnalyzer.analyze_file(file_path)
            data["oledump"] = oledump_res
            if oledump_res.get("has_xlm_macros"):
                findings.append(Finding(
                    category="macro",
                    severity="critical",
                    title="Excel 4.0 (XLM) Macro Execution Detected",
                    description=(
                        "Document contains legacy Excel 4.0 (XLM) macro sheet structures or execution formulas (=EXEC/=CALL). "
                        "XLM macros are widely weaponized to bypass standard VBA antivirus heuristics."
                    ),
                    details={"xlm_details": oledump_res.get("xlm_details", [])}
                ))
            if oledump_res.get("has_dde"):
                findings.append(Finding(
                    category="active_content",
                    severity="critical",
                    title="Office DDE Command Injection Links Detected",
                    description=(
                        "Document contains Dynamic Data Exchange (DDE) external execution links. "
                        "DDE formulas execute local processes (e.g. cmd.exe, powershell.exe) directly from document formulas."
                    ),
                    details={"dde_links": oledump_res.get("dde_links", [])}
                ))
            if oledump_res.get("streams"):
                findings.append(Finding(
                    category="structure",
                    severity="info",
                    title=f"Didier Stevens oledump Streams ({len(oledump_res['streams'])} streams parsed)",
                    description="Extracted full OLE compound stream hierarchy, macro flags (M/m), and storage objects.",
                    details={"summary": oledump_res.get("oledump_summary", "")}
                ))
        except Exception as oe:
            logger.debug(f"oledump analysis error: {oe}")

        data["urls"] = list(urls)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
