"""
Automated Detection Rule Generator.
Synthesizes production-ready Microsoft Sentinel (KQL) detection queries and
compiled YARA rules strictly from forensic indicators, file signatures,
extracted IOCs, and MITRE ATT&CK techniques identified during analysis.

STRICT CONSTRAINT: Supports ONLY Microsoft Sentinel KQL and YARA rules.
"""

import re
import datetime
from typing import Dict, Any, List, Optional, Set


class DetectionRuleGenerator:
    """Generates Microsoft Sentinel KQL queries and YARA rules for analyzed artifacts."""

    @classmethod
    def generate_all(cls, job: Any) -> Dict[str, Any]:
        """Generate both Sentinel KQL query set and YARA rule from a JobModel or job dict."""
        data = cls._normalize_job_data(job)
        yara_rule = cls.generate_yara(data)
        sentinel_kql = cls.generate_sentinel_kql(data)

        return {
            "yara_rule": yara_rule,
            "sentinel_kql": sentinel_kql,
            "indicators_used": cls._collect_summary_indicators(data),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    @classmethod
    def _normalize_job_data(cls, job: Any) -> Dict[str, Any]:
        """Normalize job whether passed as JobModel instance or dict."""
        if hasattr(job, "model_dump"):
            return job.model_dump()
        if hasattr(job, "__dict__"):
            return dict(job.__dict__)
        if isinstance(job, dict):
            return dict(job)
        return {}

    @classmethod
    def _collect_summary_indicators(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        hashes = data.get("hashes", {}) or {}
        urls = [u.get("url") if isinstance(u, dict) else str(u) for u in data.get("urls", [])][:10]

        ips = set()
        domains = set()
        pcap = data.get("pcap_info") or {}
        for ep in pcap.get("top_endpoints", []):
            if not ep.get("is_private") and ep.get("ip"):
                ips.add(ep["ip"])
        for dq in pcap.get("dns_queries", []):
            if dq.get("domain"):
                domains.add(dq["domain"])

        for u in urls:
            m = re.search(r'https?://([^/:\s]+)', u)
            if m:
                host = m.group(1)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    ips.add(host)
                elif "." in host:
                    domains.add(host)

        mitre_ids = [m.get("technique_id") for m in data.get("mitre_attack", []) if m.get("technique_id")]

        return {
            "sha256": hashes.get("sha256"),
            "md5": hashes.get("md5"),
            "imphash": hashes.get("imphash") or (data.get("binary_info") or {}).get("imphash"),
            "rich_header_hash": hashes.get("rich_header_hash") or (data.get("binary_info") or {}).get("rich_header_hash"),
            "domains": sorted(list(domains))[:10],
            "ips": sorted(list(ips))[:10],
            "urls": urls[:10],
            "mitre_techniques": sorted(list(set(mitre_ids)))[:8]
        }

    # =========================================================================
    # 1. YARA Rule Synthesizer
    # =========================================================================
    @classmethod
    def generate_yara(cls, data: Dict[str, Any]) -> str:
        filename = data.get("original_filename") or data.get("filename") or "analyzed_artifact"
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', filename)
        if clean_name and clean_name[0].isdigit():
            clean_name = f"Sample_{clean_name}"
        clean_name = clean_name.strip('_') or "Artifact_Sample"

        hashes = data.get("hashes", {}) or {}
        sha256 = hashes.get("sha256", "")
        md5 = hashes.get("md5", "")
        category = data.get("category", "unknown")
        mime = data.get("mime_type", "application/octet-stream")
        file_size = data.get("file_size", 0)

        mitre_list = [m.get("technique_id") for m in data.get("mitre_attack", []) if m.get("technique_id")]
        mitre_str = ", ".join(sorted(list(set(mitre_list)))[:5]) if mitre_list else "None"
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

        # Collect strings from indicators
        string_definitions: List[Tuple[str, str, str]] = []  # (var_name, string_spec, comment)
        conditions: List[str] = []

        # 1. File Magic Header condition
        if category in ["executable", "binary"] or mime == "application/x-dosexec":
            conditions.append("uint16(0) == 0x5A4D")  # MZ header
        elif category == "pdf" or mime == "application/pdf":
            conditions.append("uint32(0) == 0x25504446")  # %PDF
        elif category in ["office", "archive"] and mime in ["application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.presentationml.presentation"]:
            conditions.append("uint32(0) == 0x04034B50")  # PK..
        elif category == "lnk" or mime == "application/x-ms-shortcut":
            string_definitions.append(("$lnk_magic", "{ 4C 00 00 00 01 14 02 00 }", "LNK ShellLinkHeader GUID"))
            conditions.append("$lnk_magic at 0")

        # 2. Cryptographic and Fuzzy Hash Strings (for reference/matching)
        if sha256:
            string_definitions.append(("$hash_sha256", f'"{sha256}" nocase ascii wide', "Cryptographic SHA256 reference"))

        # 3. PE Binaries & Imphash
        b_info = data.get("binary_info") or {}
        imphash = hashes.get("imphash") or b_info.get("imphash")
        rich_hash = hashes.get("rich_header_hash") or b_info.get("rich_header_hash")

        if imphash:
            string_definitions.append(("$imphash", f'"{imphash}" nocase ascii wide', "Import Table Hash (Imphash)"))

        if rich_hash:
            string_definitions.append(("$rich_hash", f'"{rich_hash}" nocase ascii wide', "Rich Header Cleartext MD5"))

        # 4. Suspicious Win32 APIs
        susp_apis = b_info.get("suspicious_apis", [])
        if susp_apis:
            for s in susp_apis[:6]:
                api_name = s.get("api") if isinstance(s, dict) else str(s)
                vname = f"$api_{re.sub(r'[^a-zA-Z0-9_]', '_', api_name)}"
                string_definitions.append((vname, f'"{api_name}" fullword ascii', "Suspicious Win32 API import"))

        # 5. LNK command lines & LOLBins
        lnk_info = data.get("lnk_info") or {}
        if lnk_info:
            t_and_p = lnk_info.get("targets_and_paths", {})
            args = t_and_p.get("arguments", "")
            if args:
                # Find key command terms
                for kw in ["powershell", "cmd.exe", "mshta", "rundll32", "certutil", "-encodedcommand", "-w hidden", "windowstyle hidden"]:
                    if kw in args.lower():
                        vname = f"$cmd_{re.sub(r'[^a-zA-Z0-9_]', '_', kw)}"
                        string_definitions.append((vname, f'"{kw}" nocase ascii wide', "LNK command parameter"))
            if lnk_info.get("overlay"):
                conditions.append("filesize > 4096")

        # 6. Script Triage strings
        script_info = data.get("script_triage") or {}
        for feat in script_info.get("features_detected", [])[:4]:
            if isinstance(feat, dict) and feat.get("pattern"):
                pat_str = feat["pattern"]
                vname = f"$script_kw_{len(string_definitions)}"
                string_definitions.append((vname, f'"{pat_str}" nocase ascii wide', feat.get("name", "Suspicious pattern")))

        # 7. Office (VBA, Power Query, PowerPoint Action Settings)
        office_info = data.get("office_info") or {}
        xl_info = office_info.get("excel_analysis") or {}
        if xl_info.get("very_hidden_sheets"):
            string_definitions.append(("$xl_very_hidden", '"state=\\"veryHidden\\"" ascii wide', "Excel Very Hidden sheet attribute"))
        if xl_info.get("power_query_queries"):
            string_definitions.append(("$xl_power_query", '"Web.Contents(" ascii wide', "Power Query M-Code exfiltration function"))

        ppt_info = office_info.get("powerpoint_analysis") or {}
        if ppt_info.get("hover_actions"):
            string_definitions.append(("$ppt_hover_action", '"a:hlinkHover" ascii wide', "PowerPoint mouse-over trigger"))
            string_definitions.append(("$ppt_ppaction_prog", '"ppaction://program" nocase ascii wide', "PowerPoint program execution action"))

        # 8. Extracted URLs and C2 domains
        extracted_iocs = cls._collect_summary_indicators(data)
        for idx, dom in enumerate(extracted_iocs.get("domains", [])[:3]):
            string_definitions.append((f"$c2_domain_{idx+1}", f'"{dom}" nocase ascii wide', "Discovered network C2 domain"))
        for idx, ip_str in enumerate(extracted_iocs.get("ips", [])[:3]):
            string_definitions.append((f"$c2_ip_{idx+1}", f'"{ip_str}" ascii wide', "Discovered network target IP"))

        # Deduplicate string variable names
        unique_strings = []
        seen_vars = set()
        for vname, spec, comm in string_definitions:
            if vname not in seen_vars:
                seen_vars.add(vname)
                unique_strings.append((vname, spec, comm))

        # Size condition
        if file_size > 0:
            min_size = max(50, int(file_size * 0.4))
            max_size = int(file_size * 3.5)
            conditions.append(f"filesize < {max_size}")

        # String matching conditions
        non_magic_strings = [v for v, _, _ in unique_strings if not v.endswith("_magic")]
        if len(non_magic_strings) >= 4:
            conditions.append(f"2 of ({', '.join(non_magic_strings)})")
        elif non_magic_strings:
            conditions.append(f"any of ({', '.join(non_magic_strings)})")
        else:
            conditions.append("any of them")

        cond_str = " and\n        ".join(conditions) if conditions else "any of them"

        rule_body = [
            f"/*",
            f"   YARA Automated Threat Signature",
            f"   Target: {filename}",
            f"   Category: {category} ({mime})",
            f"   SHA-256: {sha256 or 'N/A'}",
            f"   ATT&CK: {mitre_str}",
            f"   Generated: {date_str} by FileSanitizer Defense Platform",
            f"*/",
            f"",
            f"rule Detect_{clean_name}",
            f"{{",
            f"    meta:",
            f'        description = "Automated detection signature for {filename}"',
            f'        author = "FileSanitizer Autonomous Threat Analysis"',
            f'        date = "{date_str}"',
            f'        hash_sha256 = "{sha256}"',
            f'        hash_md5 = "{md5}"',
            f'        category = "{category}"',
            f'        mitre_attck = "{mitre_str}"',
            f'        tlp = "TLP:AMBER"',
            f"",
            f"    strings:"
        ]

        for vname, spec, comm in unique_strings:
            rule_body.append(f"        {vname} = {spec} // {comm}")

        if not unique_strings:
            rule_body.append(f'        $dummy_sig = "{sha256[:16]}" ascii')

        rule_body.extend([
            f"",
            f"    condition:",
            f"        {cond_str}",
            f"}}"
        ])

        return "\n".join(rule_body)

    # =========================================================================
    # 2. Microsoft Sentinel KQL Synthesizer
    # =========================================================================
    @classmethod
    def generate_sentinel_kql(cls, data: Dict[str, Any]) -> Dict[str, str]:
        filename = data.get("original_filename") or data.get("filename") or "analyzed_artifact"
        clean_filename = re.sub(r'["\\]', '', filename)
        hashes = data.get("hashes", {}) or {}
        sha256 = hashes.get("sha256", "")
        md5 = hashes.get("md5", "")
        sha1 = hashes.get("sha1", "")
        category = data.get("category", "unknown")

        iocs = cls._collect_summary_indicators(data)
        domains = iocs.get("domains", [])
        ips = iocs.get("ips", [])
        urls = iocs.get("urls", [])

        # Process Creation (DeviceProcessEvents / SecurityEvent 4688)
        proc_clauses = []
        if sha256:
            proc_clauses.append(f'SHA256 == "{sha256}"')
        if md5:
            proc_clauses.append(f'MD5 == "{md5}"')
        if clean_filename:
            proc_clauses.append(f'FileName =~ "{clean_filename}"')

        # Command line arguments from LNK or script
        lnk_info = data.get("lnk_info") or {}
        args = (lnk_info.get("targets_and_paths") or {}).get("arguments", "")
        if args and len(args) > 5:
            safe_snippet = re.sub(r'["\\]', '', args[:80].strip())
            proc_clauses.append(f'ProcessCommandLine has "{safe_snippet}"')

        proc_filter = " or ".join(proc_clauses) if proc_clauses else 'FileName != ""'

        kql_process_mde = f"""// Microsoft Defender for Endpoint - Process Execution Hunting
// Target Artifact: {clean_filename} | SHA256: {sha256}
DeviceProcessEvents
| where Timestamp > ago(14d)
| where {proc_filter}
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, MD5
| sort by Timestamp desc
"""

        kql_security_event = f"""// Windows Event Log 4688 - Process Creation Auditing
// Target Artifact: {clean_filename}
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4688
| where CommandLine has "{clean_filename}" or NewProcessName has "{clean_filename}"
| project TimeGenerated, Computer, SubjectAccount, NewProcessName, CommandLine, ParentProcessName
| sort by TimeGenerated desc
"""

        # File Creation / Modification Events (DeviceFileEvents)
        file_clauses = []
        if sha256:
            file_clauses.append(f'SHA256 == "{sha256}"')
        if md5:
            file_clauses.append(f'MD5 == "{md5}"')
        if clean_filename:
            file_clauses.append(f'FileName =~ "{clean_filename}"')

        file_filter = " or ".join(file_clauses) if file_clauses else 'FileName != ""'

        kql_file_events = f"""// Microsoft Sentinel - File Creation and Modification Hunting
DeviceFileEvents
| where Timestamp > ago(30d)
| where {file_filter}
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, RequestAccountName, InitiatingProcessFileName, SHA256, MD5
| sort by Timestamp desc
"""

        # Network C2 & Beaconing Connection Events (DeviceNetworkEvents / CommonSecurityLog)
        net_clauses = []
        if ips:
            ip_str_list = ", ".join(f'"{ip}"' for ip in ips)
            net_clauses.append(f'RemoteIP in ({ip_str_list})')
        if domains:
            dom_str_list = ", ".join(f'"{d}"' for d in domains)
            net_clauses.append(f'RemoteUrl has_any ({dom_str_list})')

        net_filter = " or ".join(net_clauses) if net_clauses else 'RemotePort in (443, 80, 8080)'

        kql_network_events = f"""// Microsoft Sentinel - Outbound C2 Network & Threat Beaconing Hunting
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where {net_filter}
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
"""

        # Email Gateway Hunting (EmailEvents / EmailAttachmentInfo)
        kql_email = f"""// Microsoft Defender for Office 365 - Email Inbound Gateway Threat Hunting
EmailEvents
| where Timestamp > ago(30d)
| join kind=inner (
    EmailAttachmentInfo
    | where SHA256 == "{sha256}" or FileName =~ "{clean_filename}"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, FileName, FileSize, SHA256
| sort by Timestamp desc
"""

        # Production Scheduled Analytics Rule (SIEM Alert Generation with Entity Mapping)
        kql_analytics_rule = f"""// Production Microsoft Sentinel Analytics Rule (Scheduled Alert Template)
// Rule Name: FileSanitizer Threat Hunting Alert - {clean_filename}
// Severity: High | Tactict: Execution, Defense Evasion
let target_hash = "{sha256}";
let target_name = "{clean_filename}";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where SHA256 == target_hash or FileName =~ target_name
    | extend AlertType = "ProcessExecution", TargetDevice = DeviceName, TargetUser = AccountName, ArtifactIndicator = FileName
),
(
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where SHA256 == target_hash or FileName =~ target_name
    | extend AlertType = "FileCreation", TargetDevice = DeviceName, TargetUser = RequestAccountName, ArtifactIndicator = FileName
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where InitiatingProcessSHA256 == target_hash or {net_filter}
    | extend AlertType = "C2Communication", TargetDevice = DeviceName, TargetUser = InitiatingProcessAccountName, ArtifactIndicator = tostring(RemoteIP)
)
| project Timestamp, AlertType, TargetDevice, TargetUser, ArtifactIndicator, ActionType
// Entity Mapping for Microsoft Sentinel Incident Graph
| extend HostCustomEntity = TargetDevice
| extend AccountCustomEntity = TargetUser
| extend FileHashCustomEntity = target_hash
"""

        return {
            "mde_process_creation": kql_process_mde.strip(),
            "windows_event_4688": kql_security_event.strip(),
            "mde_file_events": kql_file_events.strip(),
            "mde_network_c2": kql_network_events.strip(),
            "email_gateway": kql_email.strip(),
            "sentinel_analytics_rule": kql_analytics_rule.strip()
        }
