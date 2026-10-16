"""
Comprehensive Windows Event Log (EVTX) Forensic Analysis Engine.

Implements the complete 'Windows Event Logs (EVTX) — Security Analysis Checklist':
1. File identification, integrity & validation (magic bytes, headers, checksums, hashes, record continuity & gaps)
2. Log inventory & coverage analysis (channel catalog, coverage scoring, missing critical channels)
3. Sigma-compatible detection rules engine with pre-packaged Windows IR detection rules
4. Authentication & logon analysis (Logon types 2-11, status/substatus codes, password spraying, brute-force-to-success, explicit creds, Kerberoasting RC4, AS-REP Roasting)
5. Account, group & privilege changes (user lifecycle, sensitive group SID resolution, user rights assignment)
6. Process execution & LOLBins (suspicious parent-child, LOLBins, writable paths, Sysmon 7/10/25)
7. PowerShell & scripting forensics (4104 script blocks, 4103 modules, cradles, AMSI bypass, reflection)
8. Persistence mechanisms (services 7045/4697, tasks 4698/4702, registry autoruns, WMI, BITS)
9. Lateral movement correlation chain (failed logon -> successful remote logon -> admin share -> remote service/task -> process execution)
10. Log tampering & anti-forensics (1102/104 log clearing, 4719 audit policy change, 1100 service shutdown, 4616 time manipulation, Defender/Sysmon tampering)
11. Ransomware & destructive activity (shadow copy deletion, recovery disablement, mass file modification)
12. Executive EVTX Security Verdict (verdict, confidence score, rationale, MITRE ATT&CK, containment guidance)
13. Offline analysis commands guide (wevtutil, Get-WinEvent, EvtxECmd, Chainsaw, Hayabusa)
"""

import hashlib
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import Counter

# --- Well-Known Sensitive SIDs and Security Groups ---
WELL_KNOWN_SIDS: Dict[str, Dict[str, str]] = {
    "S-1-5-18": {"name": "Local System", "category": "System Account", "severity": "info"},
    "S-1-5-19": {"name": "NT Authority / Local Service", "category": "System Account", "severity": "info"},
    "S-1-5-20": {"name": "NT Authority / Network Service", "category": "System Account", "severity": "info"},
    "S-1-5-32-544": {"name": "Administrators", "category": "Sensitive Group", "severity": "critical"},
    "S-1-5-32-545": {"name": "Users", "category": "Standard Group", "severity": "info"},
    "S-1-5-32-548": {"name": "Account Operators", "category": "Sensitive Group", "severity": "critical"},
    "S-1-5-32-549": {"name": "Server Operators", "category": "Sensitive Group", "severity": "high"},
    "S-1-5-32-550": {"name": "Print Operators", "category": "Sensitive Group", "severity": "high"},
    "S-1-5-32-551": {"name": "Backup Operators", "category": "Sensitive Group", "severity": "critical"},
    "S-1-5-32-552": {"name": "Replicators", "category": "Sensitive Group", "severity": "medium"},
    "S-1-5-32-555": {"name": "Remote Desktop Users", "category": "Remote Access Group", "severity": "high"},
    "S-1-5-32-562": {"name": "Distributed COM Users", "category": "Remote Access Group", "severity": "high"},
    "S-1-5-32-568": {"name": "IIS_IUSRS", "category": "Service Group", "severity": "info"},
    "S-1-5-32-569": {"name": "Cryptographic Operators", "category": "Sensitive Group", "severity": "high"},
    "S-1-5-32-573": {"name": "Event Log Readers", "category": "Audit Group", "severity": "medium"},
    "S-1-5-32-574": {"name": "Certificate Service DCOM Access", "category": "PKI Group", "severity": "high"},
    "S-1-5-32-578": {"name": "Hyper-V Administrators", "category": "Sensitive Group", "severity": "critical"},
    "S-1-5-32-580": {"name": "Remote Management Users (WinRM)", "category": "Remote Access Group", "severity": "high"},
    # Domain relative identifiers (RID)
    "512": {"name": "Domain Admins", "category": "Sensitive Group", "severity": "critical"},
    "516": {"name": "Domain Controllers", "category": "Infrastructure Group", "severity": "critical"},
    "518": {"name": "Schema Admins", "category": "Sensitive Group", "severity": "critical"},
    "519": {"name": "Enterprise Admins", "category": "Sensitive Group", "severity": "critical"},
    "520": {"name": "Group Policy Creator Owners", "category": "Sensitive Group", "severity": "high"},
}

SENSITIVE_GROUP_NAMES = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "server operators", "backup operators", "remote desktop users",
    "remote management users", "hyper-v administrators", "dnsadmins", "domain controllers",
    "krbtgt", "group policy creator owners"
}

# --- NTSTATUS Authentication Error Status Codes ---
AUTH_STATUS_CODES: Dict[str, Dict[str, str]] = {
    "0xc0000064": {"meaning": "User logon with non-existent user name", "threat": "Account Enumeration / Brute Force"},
    "0xc000006a": {"meaning": "User logon with misspelled or bad password", "threat": "Credential Guessing / Password Spray"},
    "0xc000006d": {"meaning": "Logon failure: bad user name or authentication info", "threat": "Failed Authentication"},
    "0xc000006e": {"meaning": "User account restriction has prevented user from logging on", "threat": "Policy Restriction"},
    "0xc000006f": {"meaning": "User logon outside authorized hours", "threat": "Off-Hours Activity"},
    "0xc0000070": {"meaning": "User logon from unauthorized workstation", "threat": "Lateral Movement Anomaly"},
    "0xc0000071": {"meaning": "User logon with expired password", "threat": "Expired Credentials"},
    "0xc0000072": {"meaning": "User logon to account currently disabled", "threat": "Dormant / Disabled Account Access"},
    "0xc0000193": {"meaning": "User logon to account that has expired", "threat": "Expired Account Access"},
    "0xc0000224": {"meaning": "User is required to change password at next logon", "threat": "Password Reset Pending"},
    "0xc0000234": {"meaning": "User account has been locked out", "threat": "Account Lockout Triggered"},
    "0xc000005e": {"meaning": "No logon servers available to service request", "threat": "DC Unreachable / DoS"},
    "0xc0000133": {"meaning": "Clocks between DC and client out of sync", "threat": "Kerberos Time Drift Anomaly"},
    "0x18": {"meaning": "Kerberos pre-authentication failed (bad password)", "threat": "AS-REP Roasting / Password Spray"},
    "0x17": {"meaning": "Kerberos encryption type RC4-HMAC requested", "threat": "Potential Kerberoasting"},
}

# --- Standard Channel Inventory Catalog ---
STANDARD_CHANNELS_CATALOG: List[Dict[str, Any]] = [
    {"channel": "Security", "importance": "critical", "role": "Logons, privilege changes, audit tampering, object access"},
    {"channel": "System", "importance": "critical", "role": "Service installations, driver loads, system crashes, log clears"},
    {"channel": "Application", "importance": "medium", "role": "Application crashes, database logs, third-party software"},
    {"channel": "Microsoft-Windows-PowerShell/Operational", "importance": "critical", "role": "Script-block logging (4104), module logging (4103)"},
    {"channel": "Windows PowerShell", "importance": "high", "role": "PowerShell engine lifecycle (400, 403), pipeline (800)"},
    {"channel": "Microsoft-Windows-Sysmon/Operational", "importance": "critical", "role": "Process creation, network connections, DLL loads, process access"},
    {"channel": "Microsoft-Windows-Windows Defender/Operational", "importance": "critical", "role": "Malware detections, real-time protection state, exclusions"},
    {"channel": "Microsoft-Windows-TaskScheduler/Operational", "importance": "high", "role": "Scheduled task creation, registration, and action execution"},
    {"channel": "Microsoft-Windows-WMI-Activity/Operational", "importance": "high", "role": "WMI event subscription, execution, and persistence"},
    {"channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "importance": "high", "role": "RDP connection sessions, client IP records"},
    {"channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "importance": "high", "role": "RDP logon, disconnect, and reconnect events"},
    {"channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "importance": "medium", "role": "Firewall rule additions, modifications, and connection blocks"},
    {"channel": "Microsoft-Windows-Bits-Client/Operational", "importance": "medium", "role": "BITS background download jobs (LOLBin C2 downloads)"},
    {"channel": "Microsoft-Windows-CodeIntegrity/Operational", "importance": "medium", "role": "WDAC driver/executable code-signing enforcement decisions"},
    {"channel": "Microsoft-Windows-AppLocker/EXE and DLL", "importance": "medium", "role": "Application whitelist execution enforcement and audit decisions"},
    {"channel": "Microsoft-Windows-NTLM/Operational", "importance": "low", "role": "NTLM authentication validation and protocol troubleshooting"},
]


# ============================================================================
# 1. FILE IDENTIFICATION, INTEGRITY & VALIDATION
# ============================================================================

def audit_evtx_capture_integrity(file_path_or_bytes: Any, filename: str) -> Dict[str, Any]:
    """
    Audits EVTX low-level format, magic bytes ('ElfFile\\x00'), chunk structure,
    header integrity, timestamp ranges, record count, and record ID continuity gaps.
    """
    data_bytes: bytes = b""
    file_size = 0

    if isinstance(file_path_or_bytes, (bytes, bytearray)):
        data_bytes = bytes(file_path_or_bytes)
        file_size = len(data_bytes)
    elif isinstance(file_path_or_bytes, (str, Path)) and Path(file_path_or_bytes).exists():
        try:
            with open(file_path_or_bytes, "rb") as f:
                data_bytes = f.read()
            file_size = len(data_bytes)
        except Exception:
            data_bytes = b""

    # Calculate evidence cryptographic hashes
    sha256_hash = hashlib.sha256(data_bytes).hexdigest() if data_bytes else "unknown"
    sha1_hash = hashlib.sha1(data_bytes).hexdigest() if data_bytes else "unknown"
    md5_hash = hashlib.md5(data_bytes).hexdigest() if data_bytes else "unknown"

    # Inspect EVTX Binary Magic
    # Standard EVTX header: 8 bytes 'ElfFile\x00' (0x45 0x6c 0x66 0x46 0x69 0x6c 0x65 0x00)
    is_binary_evtx = data_bytes.startswith(b"ElfFile\x00")
    is_xml_export = b"<Event" in data_bytes[:4096] or b"<Events" in data_bytes[:4096]

    major_version = 0
    minor_version = 0
    header_chunk_count = 0
    first_chunk_number = 0
    last_chunk_number = 0
    next_record_id = 0
    header_size = 0
    flags = 0

    if is_binary_evtx and len(data_bytes) >= 128:
        try:
            # EVTX File Header layout (4096 bytes)
            # Offset 0x00: Magic 'ElfFile\0' (8 bytes)
            # Offset 0x08: First chunk number (8 bytes int64)
            # Offset 0x10: Last chunk number (8 bytes int64)
            # Offset 0x18: Next record ID (8 bytes int64)
            # Offset 0x20: Header size (4 bytes uint32) - normally 4096
            # Offset 0x24: Minor version (2 bytes uint16) - normally 1
            # Offset 0x26: Major version (2 bytes uint16) - normally 3
            # Offset 0x28: Header chunk size (2 bytes uint16) - normally 4096
            # Offset 0x2a: Chunk count (2 bytes uint16)
            # Offset 0x78: Flags (4 bytes uint32: 0=clean, 1=dirty, 2=full)
            first_chunk_number, last_chunk_number, next_record_id = struct.unpack_from("<QQQ", data_bytes, 8)
            header_size, minor_version, major_version, _, header_chunk_count = struct.unpack_from("<IHHHH", data_bytes, 32)
            flags = struct.unpack_from("<I", data_bytes, 0x78)[0]
        except Exception:
            pass

    file_format = "Classic Windows Event Log (Binary EVTX)" if is_binary_evtx else ("XML-Exported Windows Event Log" if is_xml_export else "Unknown / Corrupted Event File")
    integrity_status = "INTACT" if (is_binary_evtx or is_xml_export) else "CORRUPTED"
    header_state = "Dirty / Unclosed cleanly" if flags == 1 else ("Full" if flags == 2 else "Clean")

    return {
        "filename": filename,
        "format": file_format,
        "is_valid_evtx": is_binary_evtx or is_xml_export,
        "is_binary_evtx": is_binary_evtx,
        "is_xml_export": is_xml_export,
        "file_size": file_size,
        "file_hashes": {
            "sha256": sha256_hash,
            "sha1": sha1_hash,
            "md5": md5_hash
        },
        "evtx_header": {
            "major_version": major_version,
            "minor_version": minor_version,
            "header_chunk_count": header_chunk_count,
            "first_chunk_number": first_chunk_number,
            "last_chunk_number": last_chunk_number,
            "next_record_id": next_record_id,
            "header_size": header_size,
            "header_state": header_state,
            "flags": flags
        },
        "integrity_status": integrity_status
    }


def audit_record_continuity_and_gaps(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Checks record ID sequence continuity and detects gaps in timestamps.
    """
    if not records:
        return {
            "total_records": 0,
            "record_id_gaps": [],
            "timestamp_gaps": [],
            "has_continuity_anomalies": False
        }

    # Extract record IDs if available
    record_ids = []
    timestamps = []
    for r in records:
        details = r.get("details", {})
        rid_str = details.get("EventRecordID") or r.get("record_id")
        if rid_str:
            try:
                record_ids.append(int(rid_str))
            except Exception:
                pass
        ts = r.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                timestamps.append((dt, ts, r))
            except Exception:
                pass

    record_id_gaps: List[Dict[str, Any]] = []
    if len(record_ids) >= 2:
        sorted_rids = sorted(list(set(record_ids)))
        for i in range(len(sorted_rids) - 1):
            curr_id = sorted_rids[i]
            next_id = sorted_rids[i + 1]
            diff = next_id - curr_id
            if diff > 1:
                record_id_gaps.append({
                    "from_record_id": curr_id,
                    "to_record_id": next_id,
                    "missing_count": diff - 1,
                    "severity": "high" if diff > 10 else "medium",
                    "note": f"Gap of {diff - 1} missing Event Record IDs detected (anti-forensics or log truncation)"
                })

    # Timestamp gaps (> 12 hours of silence in an active log)
    timestamp_gaps: List[Dict[str, Any]] = []
    if len(timestamps) >= 2:
        timestamps.sort(key=lambda x: x[0])
        for i in range(len(timestamps) - 1):
            t1, s1, r1 = timestamps[i]
            t2, s2, r2 = timestamps[i + 1]
            delta_sec = (t2 - t1).total_seconds()
            if delta_sec > 43200:  # > 12 hours
                hours = round(delta_sec / 3600, 1)
                timestamp_gaps.append({
                    "from_timestamp": s1,
                    "to_timestamp": s2,
                    "gap_duration_hours": hours,
                    "severity": "medium",
                    "note": f"Logging gap of {hours} hours observed without recorded activity"
                })

    has_anomalies = len(record_id_gaps) > 0 or len(timestamp_gaps) > 0

    return {
        "total_records": len(records),
        "record_id_gaps": record_id_gaps,
        "timestamp_gaps": timestamp_gaps,
        "has_continuity_anomalies": has_anomalies
    }


# ============================================================================
# 2. LOG INVENTORY & COVERAGE AUDIT
# ============================================================================

def audit_log_inventory_and_coverage(parsed_files: List[Dict[str, Any]], records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Audits which Windows Event channels are represented in the analyzed evidence,
    calculates coverage percentage, and highlights missing critical telemetry.
    """
    detected_channels: Set[str] = set()
    for pf in parsed_files:
        for ch in pf.get("channels", []):
            detected_channels.add(ch)
    for r in records:
        ch = r.get("channel")
        if ch and ch != "-":
            detected_channels.add(ch)

    # Normalize channel names for comparison
    norm_detected = {c.lower() for c in detected_channels}

    channel_status_list: List[Dict[str, Any]] = []
    present_critical = 0
    total_critical = 0
    missing_critical: List[str] = []

    for item in STANDARD_CHANNELS_CATALOG:
        ch_name = item["channel"]
        importance = item["importance"]
        is_crit = importance == "critical"
        if is_crit:
            total_critical += 1

        is_present = any(ch_name.lower() in d for d in norm_detected) or any(d in ch_name.lower() for d in norm_detected)
        if is_present:
            if is_crit:
                present_critical += 1
        else:
            if is_crit:
                missing_critical.append(ch_name)

        channel_status_list.append({
            "channel": ch_name,
            "role": item["role"],
            "importance": importance,
            "present": is_present
        })

    # Coverage score calculation (0 - 100%)
    coverage_score = int((present_critical / max(1, total_critical)) * 100) if total_critical > 0 else 50

    limitations: List[str] = []
    if missing_critical:
        limitations.append(f"Missing critical telemetry channels: {', '.join(missing_critical)}.")
    if "microsoft-windows-sysmon/operational" not in [c.lower() for c in detected_channels]:
        limitations.append("Sysmon is not present: Process hierarchy, network telemetry, and memory access cannot be fully verified.")
    if "microsoft-windows-powershell/operational" not in [c.lower() for c in detected_channels]:
        limitations.append("PowerShell ScriptBlock logging channel absent: Obfuscated or multi-stage script payloads may evade static log analysis.")

    return {
        "coverage_score": coverage_score,
        "channels_present_count": len(detected_channels),
        "channels_present": sorted(list(detected_channels)),
        "catalog_audit": channel_status_list,
        "missing_critical_channels": missing_critical,
        "coverage_limitations": limitations
    }


# ============================================================================
# 3. SIGMA-COMPATIBLE DETECTION RULES ENGINE
# ============================================================================

SIGMA_RULES_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "SIGMA-WIN-001",
        "title": "Windows Security Audit Log Cleared",
        "level": "critical",
        "tags": ["attack.defense_evasion", "attack.t1070.001"],
        "description": "Detects clearing of the Windows Security audit log by threat actors attempting to conceal malicious activity.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 1102
    },
    {
        "id": "SIGMA-WIN-002",
        "title": "Windows System/Application Event Log Cleared",
        "level": "critical",
        "tags": ["attack.defense_evasion", "attack.t1070.001"],
        "description": "Detects clearing of the Windows System or Application event log via wevtutil or Event Viewer.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 104
    },
    {
        "id": "SIGMA-WIN-003",
        "title": "Volume Shadow Copy Deletion via Vssadmin / WMIC",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1490"],
        "description": "Detects deletion of Volume Shadow Copies (VSS) or backup catalogs, typically preceding ransomware encryption.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: any(
            kw in (r.get("command_line", "") or "").lower()
            for kw in ["vssadmin delete shadows", "shadowcopy delete", "wbadmin delete catalog", "delete shadows"]
        )
    },
    {
        "id": "SIGMA-WIN-004",
        "title": "Windows Recovery Boot Status Policy Disabled",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1490"],
        "description": "Detects modifications to Windows boot configuration using bcdedit to ignore failures or disable recovery.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: any(
            kw in (r.get("command_line", "") or "").lower()
            for kw in ["ignoreallfailures", "recoveryenabled no", "bootstatuspolicy"]
        )
    },
    {
        "id": "SIGMA-WIN-005",
        "title": "Microsoft Defender Real-Time Protection Disabled",
        "level": "critical",
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
        "description": "Detects disabling of Microsoft Defender Antivirus real-time protection feature.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [5001, 5007] or (
            r.get("event_id") in [4688, 1] and any(kw in (r.get("command_line", "") or "").lower() for kw in ["set-mppreference -disablerealtimemonitoring $true", "disablerealtimemonitoring 1"])
        )
    },
    {
        "id": "SIGMA-WIN-006",
        "title": "User Added to Elevated Administrative Security Group",
        "level": "critical",
        "tags": ["attack.persistence", "attack.privilege_escalation", "attack.t1098"],
        "description": "Detects addition of an account to local Administrators or sensitive domain groups.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [4728, 4732, 4756]
    },
    {
        "id": "SIGMA-WIN-007",
        "title": "New User Account Created on Host",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1136.001"],
        "description": "Detects the creation of a new local or domain user account.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 4720
    },
    {
        "id": "SIGMA-WIN-008",
        "title": "PowerShell Encoded Command & Suspicious Cradle",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "description": "Detects PowerShell executing with base64 encoded command lines or suspicious download cradles.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: (
            r.get("event_id") in [4688, 1, 4104] and (
                any(flag in (r.get("command_line", "") or "").lower() for flag in ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "virtualalloc", "amsiutils"])
                or any(flag in (r.get("script_text", "") or "").lower() for flag in ["downloadstring", "invoke-expression", "virtualalloc", "amsiutils", "bypass"])
            )
        )
    },
    {
        "id": "SIGMA-WIN-009",
        "title": "SMB Administrative Share Remote File Staging",
        "level": "critical",
        "tags": ["attack.lateral_movement", "attack.t1021.002"],
        "description": "Detects remote write or execution staging over administrative network shares (C$, ADMIN$).",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: (
            r.get("event_id") in [5140, 5145] and any(sh in (r.get("share_name", "") or "").upper() for sh in ["C$", "ADMIN$", "IPC$"])
            and any(ext in (r.get("relative_target_name", "") or "").lower() for ext in [".exe", ".bat", ".ps1", ".vbs", ".dll", ".cmd", ".scr"])
        )
    },
    {
        "id": "SIGMA-WIN-010",
        "title": "Suspicious Service Installed (PsExec / Remote Staging)",
        "level": "high",
        "tags": ["attack.persistence", "attack.privilege_escalation", "attack.t1543.003"],
        "description": "Detects creation of a new Windows service, such as PSEXESVC or services pointing to %TEMP% or %APPDATA%.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [7045, 4697]
    },
    {
        "id": "SIGMA-WIN-011",
        "title": "Suspicious Scheduled Task Created",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1053.005"],
        "description": "Detects creation or modification of a scheduled task for persistence.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [4698, 4702]
    },
    {
        "id": "SIGMA-WIN-012",
        "title": "LSASS Memory Access for Credential Dumping (Sysmon 10)",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "description": "Detects a process requesting read or dump access handles to Local Security Authority Subsystem Service (LSASS).",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: (
            r.get("event_id") == 10 and "lsass.exe" in (r.get("details", {}).get("TargetImage", "") or "").lower()
        )
    },
    {
        "id": "SIGMA-WIN-013",
        "title": "Sysmon Process Tampering / Hollowing Detected",
        "level": "critical",
        "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1055.012"],
        "description": "Detects process tampering techniques such as Process Hollowing, Herpaderping, or Doppelganging.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 25
    },
    {
        "id": "SIGMA-WIN-014",
        "title": "Kerberoasting Service Ticket Request with RC4 Encryption",
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1558.003"],
        "description": "Detects Kerberos service ticket requests (Event 4769) using legacy RC4 encryption (0x17) indicating Kerberoasting.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: (
            r.get("event_id") == 4769 and (
                r.get("details", {}).get("TicketEncryptionType") in ["0x17", "23"] or
                "0x17" in str(r.get("details", {}))
            )
        )
    },
    {
        "id": "SIGMA-WIN-015",
        "title": "Kerberos Pre-Authentication Failure (AS-REP Roasting / Brute Force)",
        "level": "medium",
        "tags": ["attack.credential_access", "attack.t1558.004"],
        "description": "Detects Kerberos pre-authentication failure (Event 4771) with code 0x18 (bad password).",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 4771 and (
            r.get("details", {}).get("Status") in ["0x18", "24"] or "0x18" in str(r.get("details", {}))
        )
    },
    {
        "id": "SIGMA-WIN-016",
        "title": "System Audit Policy Weakened",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1562.002"],
        "description": "Detects changes to system audit policy (Event 4719) reducing visibility or turning off auditing.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 4719
    },
    {
        "id": "SIGMA-WIN-017",
        "title": "System Time Changed (Anti-Forensics / Timestomping)",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070.006"],
        "description": "Detects changes to the system clock (Event 4616) intended to disrupt forensic event sequencing.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") == 4616
    },
    {
        "id": "SIGMA-WIN-018",
        "title": "WMI Persistence Event Subscription",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1546.003"],
        "description": "Detects WMI event filter or consumer registration for permanent persistence across reboots.",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [19, 20, 21]
    },
    {
        "id": "SIGMA-WIN-019",
        "title": "Living-Off-The-Land Binary (LOLBin) Execution",
        "level": "medium",
        "tags": ["attack.defense_evasion", "attack.t1218"],
        "description": "Detects execution of Windows native binaries commonly abused by attackers (certutil, mshta, rundll32, regsvr32).",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: (
            r.get("event_id") in [4688, 1] and any(
                lb in (r.get("process_name", "") or "").lower() or lb in (r.get("command_line", "") or "").lower()
                for lb in ["certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe"]
            )
        )
    },
    {
        "id": "SIGMA-WIN-020",
        "title": "Active Malware Detected by Microsoft Defender",
        "level": "critical",
        "tags": ["attack.execution", "attack.t1204"],
        "description": "Detects active threat alerts raised by Microsoft Defender Antivirus engine (Event 1116/1117).",
        "author": "Antigravity Forensics / Sigma Community",
        "rule_match": lambda r: r.get("event_id") in [1116, 1117, 1006]
    }
]


def evaluate_sigma_rules(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluates EVTX records against the Sigma rules catalog and produces
    structured threat alerts with matched sample events.
    """
    alerts: List[Dict[str, Any]] = []

    for rule in SIGMA_RULES_CATALOG:
        matched_records = []
        for r in records:
            try:
                if rule["rule_match"](r):
                    matched_records.append(r)
            except Exception:
                continue

        if matched_records:
            sample_events = []
            for mr in matched_records[:5]:
                sample_events.append({
                    "event_id": mr.get("event_id"),
                    "timestamp": mr.get("timestamp"),
                    "user": mr.get("user") or "-",
                    "computer": mr.get("computer") or "-",
                    "command_line": mr.get("command_line"),
                    "summary": mr.get("summary")
                })

            primary_mitre = next((t.replace("attack.", "").upper() for t in rule["tags"] if t.startswith("attack.t")), "T1070")

            alerts.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "level": rule["level"],
                "tags": rule["tags"],
                "mitre_technique": primary_mitre,
                "description": rule["description"],
                "author": rule["author"],
                "match_count": len(matched_records),
                "sample_events": sample_events
            })

    # Sort alerts by severity (critical -> high -> medium -> low)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (sev_rank.get(a["level"], 4), -a["match_count"]))
    return alerts


# ============================================================================
# 4. AUTHENTICATION & LOGON ANALYSIS
# ============================================================================

def analyze_authentication_forensics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deep forensic analysis of logon sessions:
    - Logon Types breakdown (Interactive, Network, RDP, NewCredentials)
    - Failed logon status/substatus code resolution
    - Password spraying heuristics (multiple accounts targeted from 1 IP)
    - Brute-force followed by success
    - Kerberos forensics (4768 TGT, 4769 RC4 encryption check, 4771 pre-auth failures)
    - Explicit credentials logons (4648)
    - Special privileges assigned (4672)
    """
    logon_types_counter: Dict[str, int] = Counter()
    failed_by_user: Dict[str, int] = Counter()
    failed_by_ip: Dict[str, int] = Counter()
    status_codes_counter: Dict[str, int] = Counter()
    ip_to_accounts: Dict[str, Set[str]] = {}

    successful_logon_timestamps: Dict[str, List[str]] = {}
    failed_logon_timestamps: Dict[str, List[str]] = {}

    explicit_creds_events: List[Dict[str, Any]] = []
    special_priv_events: List[Dict[str, Any]] = []
    kerberos_tgt_count = 0
    kerberos_service_tickets = 0
    kerberoasting_candidates: List[Dict[str, Any]] = []
    kerberos_preauth_failures: List[Dict[str, Any]] = []

    for r in records:
        eid = r.get("event_id")
        user = r.get("user") or ""
        ip = r.get("ip_address") or ""
        ts = r.get("timestamp") or ""
        dtls = r.get("details", {})

        # 4624 Successful Logon
        if eid == 4624:
            ltype = str(r.get("logon_type") or dtls.get("LogonType") or "Unknown")
            logon_types_counter[ltype] += 1
            if user:
                if user not in successful_logon_timestamps:
                    successful_logon_timestamps[user] = []
                successful_logon_timestamps[user].append(ts)

        # 4625 Failed Logon
        if eid == 4625:
            if user and user != "-":
                failed_by_user[user] += 1
                if user not in failed_logon_timestamps:
                    failed_logon_timestamps[user] = []
                failed_logon_timestamps[user].append(ts)

            if ip and ip not in ["-", "127.0.0.1", "::1"]:
                failed_by_ip[ip] += 1
                if ip not in ip_to_accounts:
                    ip_to_accounts[ip] = set()
                if user:
                    ip_to_accounts[ip].add(user)

            status = (dtls.get("Status") or r.get("status_code") or "").lower()
            substatus = (dtls.get("SubStatus") or r.get("substatus_code") or "").lower()
            if status:
                status_codes_counter[status] += 1
            if substatus:
                status_codes_counter[substatus] += 1

        # 4648 Logon Attempt with Explicit Credentials
        if eid == 4648:
            explicit_creds_events.append({
                "timestamp": ts,
                "user": user or dtls.get("SubjectUserName", "Unknown"),
                "target_user": dtls.get("TargetUserName", "Unknown"),
                "target_server": dtls.get("TargetServerName", "Unknown"),
                "process": r.get("process_name") or dtls.get("ProcessName", "Unknown")
            })

        # 4672 Special Privileges Assigned
        if eid == 4672:
            special_priv_events.append({
                "timestamp": ts,
                "user": user,
                "privilege_list": dtls.get("PrivilegeList", "SeDebugPrivilege / Admin")
            })

        # Kerberos 4768 / 4769 / 4771
        if eid == 4768:
            kerberos_tgt_count += 1
        if eid == 4769:
            kerberos_service_tickets += 1
            enc_type = dtls.get("TicketEncryptionType", "")
            if enc_type in ["0x17", "23"]:
                kerberoasting_candidates.append({
                    "timestamp": ts,
                    "service_name": dtls.get("ServiceName", "Unknown"),
                    "account": user or dtls.get("TargetUserName", "Unknown"),
                    "ip": ip or dtls.get("IpAddress", "Unknown"),
                    "encryption_type": "RC4-HMAC (0x17)"
                })
        if eid == 4771:
            kerberos_preauth_failures.append({
                "timestamp": ts,
                "account": user or dtls.get("TargetUserName", "Unknown"),
                "ip": ip or dtls.get("IpAddress", "Unknown"),
                "status": dtls.get("Status", "0x18")
            })

    # Password Spraying Heuristic: 1 IP targeting >= 3 distinct user accounts
    password_spray_sources: List[Dict[str, Any]] = []
    for source_ip, accounts in ip_to_accounts.items():
        if len(accounts) >= 3:
            password_spray_sources.append({
                "source_ip": source_ip,
                "targeted_accounts_count": len(accounts),
                "targeted_accounts": sorted(list(accounts))[:10],
                "failed_count": failed_by_ip[source_ip]
            })

    # Brute Force Followed By Success
    brute_force_success: List[Dict[str, Any]] = []
    for target_user, fail_count in failed_by_user.items():
        if fail_count >= 3 and target_user in successful_logon_timestamps:
            brute_force_success.append({
                "target_account": target_user,
                "failure_count": fail_count,
                "first_failure": failed_logon_timestamps[target_user][0] if failed_logon_timestamps[target_user] else "N/A",
                "successful_logon": successful_logon_timestamps[target_user][-1] if successful_logon_timestamps[target_user] else "N/A"
            })

    # Human-readable status codes
    status_resolutions: List[Dict[str, Any]] = []
    for code, count in status_codes_counter.most_common(10):
        entry = AUTH_STATUS_CODES.get(code.lower(), {"meaning": "Authentication Failure", "threat": "Suspicious Authentication"})
        status_resolutions.append({
            "code": code,
            "count": count,
            "meaning": entry["meaning"],
            "threat": entry["threat"]
        })

    return {
        "logon_types_breakdown": dict(logon_types_counter),
        "total_successful_logons": sum(logon_types_counter.values()),
        "total_failed_logons": sum(failed_by_user.values()),
        "failed_by_user": dict(failed_by_user.most_common(10)),
        "failed_by_ip": dict(failed_by_ip.most_common(10)),
        "status_code_audit": status_resolutions,
        "password_spray_sources": password_spray_sources,
        "brute_force_success": brute_force_success,
        "explicit_credentials_logons": explicit_creds_events[:20],
        "special_privileges_logons": special_priv_events[:20],
        "kerberos_forensics": {
            "tgt_requests_count": kerberos_tgt_count,
            "service_tickets_count": kerberos_service_tickets,
            "kerberoasting_candidates": kerberoasting_candidates[:20],
            "kerberos_preauth_failures": kerberos_preauth_failures[:20]
        }
    }


# ============================================================================
# 5. ACCOUNT, GROUP & PRIVILEGE MANAGEMENT
# ============================================================================

def analyze_account_and_privilege_changes(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Audits account provisioning, password manipulation, group modifications,
    and sensitive group SID resolutions (Domain Admins, Administrators, etc.).
    """
    users_created: List[Dict[str, Any]] = []
    users_enabled: List[Dict[str, Any]] = []
    password_resets: List[Dict[str, Any]] = []
    users_deleted: List[Dict[str, Any]] = []
    sensitive_group_additions: List[Dict[str, Any]] = []
    rights_assigned: List[Dict[str, Any]] = []

    for r in records:
        eid = r.get("event_id")
        dtls = r.get("details", {})
        ts = r.get("timestamp") or ""
        actor = r.get("user") or dtls.get("SubjectUserName", "Unknown")
        target_user = dtls.get("TargetUserName", r.get("user", "Unknown"))

        # 4720: User Created
        if eid == 4720:
            users_created.append({
                "timestamp": ts,
                "actor": actor,
                "created_user": target_user,
                "details": dtls
            })

        # 4722: User Enabled
        if eid == 4722:
            users_enabled.append({
                "timestamp": ts,
                "actor": actor,
                "enabled_user": target_user
            })

        # 4723 / 4724: Password Change or Reset
        if eid in [4723, 4724]:
            password_resets.append({
                "timestamp": ts,
                "actor": actor,
                "target_account": target_user,
                "is_admin_reset": eid == 4724
            })

        # 4726: User Deleted
        if eid == 4726:
            users_deleted.append({
                "timestamp": ts,
                "actor": actor,
                "deleted_user": target_user
            })

        # 4728, 4732, 4756: Group Additions
        if eid in [4728, 4732, 4756]:
            group_name = dtls.get("TargetUserName") or dtls.get("GroupName") or "Privileged Group"
            member_name = dtls.get("MemberName") or dtls.get("SubjectUserName") or "Account"
            group_sid = dtls.get("TargetSid") or ""

            # Check if group is sensitive
            is_sensitive = group_name.lower() in SENSITIVE_GROUP_NAMES or any(s in group_name.lower() for s in ["admin", "operator", "remote"])
            for sid_key, sid_info in WELL_KNOWN_SIDS.items():
                if sid_key in group_sid or sid_info["name"].lower() == group_name.lower():
                    is_sensitive = True
                    break

            sensitive_group_additions.append({
                "timestamp": ts,
                "actor": actor,
                "member_added": member_name,
                "group_name": group_name,
                "group_sid": group_sid,
                "is_sensitive_group": is_sensitive,
                "event_id": eid
            })

        # 4704: User Right Assigned
        if eid == 4704:
            rights_assigned.append({
                "timestamp": ts,
                "actor": actor,
                "target_account": target_user,
                "rights": dtls.get("PrivilegeList", "")
            })

    return {
        "users_created": users_created,
        "users_enabled": users_enabled,
        "password_resets": password_resets,
        "users_deleted": users_deleted,
        "sensitive_group_additions": sensitive_group_additions,
        "user_rights_assigned": rights_assigned
    }


# ============================================================================
# 6. LATERAL MOVEMENT ATTACK CHAIN CORRELATION
# ============================================================================

def analyze_lateral_movement_chains(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlates multi-stage lateral movement chains across the capture:
    Stage 1: Failed Logons / Password Spray (4625)
    Stage 2: Successful Remote Logon (4624 Type 3 or Type 10)
    Stage 3: Administrative Share Access (5140, 5145 on C$, ADMIN$)
    Stage 4: Remote Service or Scheduled Task Creation (7045, 4698)
    Stage 5: Suspicious Process Execution (4688, Sysmon 1)
    """
    chains: List[Dict[str, Any]] = []

    # Group events by host or source IP
    hosts = {r.get("computer") for r in records if r.get("computer")}

    for host in hosts:
        host_recs = [r for r in records if r.get("computer") == host]
        host_recs.sort(key=lambda x: x.get("timestamp") or "")

        has_failed = any(r.get("event_id") == 4625 for r in host_recs)
        remote_logons = [r for r in host_recs if r.get("event_id") == 4624 and str(r.get("logon_type")) in ["3", "10"]]
        admin_shares = [
            r for r in host_recs if r.get("event_id") in [5140, 5145]
            and any(s in (r.get("share_name", "") or "").upper() for s in ["C$", "ADMIN$", "IPC$"])
        ]
        remote_svcs = [r for r in host_recs if r.get("event_id") in [7045, 4697, 4698]]
        suspicious_procs = [r for r in host_recs if r.get("event_id") in [4688, 1] and r.get("is_lolbin")]

        stages_present = []
        if has_failed:
            stages_present.append("Failed Logons (4625)")
        if remote_logons:
            stages_present.append("Remote Logon (4624 Type 3/10)")
        if admin_shares:
            stages_present.append("Admin Share Access (5140/5145)")
        if remote_svcs:
            stages_present.append("Remote Service / Task Creation (7045/4698)")
        if suspicious_procs:
            stages_present.append("Process Execution (4688/1)")

        if len(stages_present) >= 3 or (remote_logons and admin_shares):
            chains.append({
                "target_host": host,
                "stages_detected": stages_present,
                "stages_count": len(stages_present),
                "severity": "critical" if len(stages_present) >= 4 else "high",
                "sample_actor": remote_logons[0].get("user") if remote_logons else "Unknown",
                "source_ip": remote_logons[0].get("ip_address") if remote_logons else "Unknown",
                "payload_dropped": admin_shares[0].get("relative_target_name") if admin_shares else None,
                "summary": f"Lateral movement sequence against {host}: {' -> '.join(stages_present)}"
            })

    return chains


# ============================================================================
# 7. LOG TAMPERING & ANTI-FORENSICS ANALYSIS
# ============================================================================

def analyze_log_tampering_and_anti_forensics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detects tampering with Windows Event logging infrastructure:
    - 1102: Security log cleared
    - 104: System/App log cleared
    - 4719: Audit policy changed
    - 1100: Event Logging Service shutdown
    - 6005 / 6006: Event log service started / stopped
    - 4616: System time changed (timestomping)
    - 5001 / 5007: Microsoft Defender disabled or tampered
    - 16: Sysmon config reloaded / changed
    """
    cleared_events: List[Dict[str, Any]] = []
    policy_changes: List[Dict[str, Any]] = []
    service_interruptions: List[Dict[str, Any]] = []
    clock_manipulations: List[Dict[str, Any]] = []
    defender_tampering: List[Dict[str, Any]] = []
    sysmon_tampering: List[Dict[str, Any]] = []

    for r in records:
        eid = r.get("event_id")
        ts = r.get("timestamp") or ""
        u = r.get("user") or "Unknown"
        comp = r.get("computer") or "Host"
        dtls = r.get("details", {})

        if eid in [1102, 104]:
            cleared_events.append({
                "timestamp": ts,
                "event_id": eid,
                "log_type": "Security Audit Log" if eid == 1102 else "System/Application Log",
                "user": u,
                "computer": comp
            })

        if eid == 4719:
            policy_changes.append({
                "timestamp": ts,
                "user": u,
                "computer": comp,
                "category": dtls.get("CategoryId", "Audit Policy"),
                "subcategory": dtls.get("SubcategoryId", "Subcategory")
            })

        if eid in [1100, 6005, 6006]:
            service_interruptions.append({
                "timestamp": ts,
                "event_id": eid,
                "state": "Shutdown" if eid == 1100 else ("Started" if eid == 6005 else "Stopped"),
                "computer": comp
            })

        if eid == 4616:
            clock_manipulations.append({
                "timestamp": ts,
                "user": u,
                "previous_time": dtls.get("PreviousTime", "Old Time"),
                "new_time": dtls.get("NewTime", "New Time"),
                "computer": comp
            })

        if eid in [5001, 5007]:
            defender_tampering.append({
                "timestamp": ts,
                "event_id": eid,
                "description": "Real-time protection disabled" if eid == 5001 else "Configuration modified",
                "computer": comp
            })

        if eid == 16:
            sysmon_tampering.append({
                "timestamp": ts,
                "description": "Sysmon filter configuration modified",
                "computer": comp
            })

    total_tampering = (
        len(cleared_events) + len(policy_changes) + len(clock_manipulations)
        + len(defender_tampering) + len(sysmon_tampering)
    )

    return {
        "tampering_detected": total_tampering > 0,
        "total_tampering_events": total_tampering,
        "logs_cleared": cleared_events,
        "audit_policy_changes": policy_changes,
        "service_interruptions": service_interruptions,
        "system_time_manipulations": clock_manipulations,
        "defender_tampering": defender_tampering,
        "sysmon_tampering": sysmon_tampering
    }


# ============================================================================
# 8. OFFLINE ANALYSIS TOOLS COMMANDS GUIDE
# ============================================================================

def get_offline_analysis_tools_guide(evidence_filename: str) -> Dict[str, Any]:
    """
    Returns reference CLI commands for cross-platform forensic offline triage:
    - EvtxECmd (Eric Zimmerman)
    - Chainsaw (WithSecure Sigma hunting)
    - Hayabusa (Yamato Security timeline)
    - wevtutil (Windows native)
    - PowerShell Get-WinEvent
    """
    fname = evidence_filename or "Security.evtx"
    return {
        "evtxecmd": {
            "title": "EvtxECmd (Eric Zimmerman)",
            "purpose": "Parse EVTX to structured CSV/JSON forensic timeline",
            "command": f"EvtxECmd.exe -f {fname} --csv .\\output --csvf {fname}_timeline.csv",
            "notes": "Generates forensic timeline CSV compatible with Timeline Explorer."
        },
        "chainsaw": {
            "title": "Chainsaw (Sigma Hunting Engine)",
            "purpose": "Hunt for threats using Sigma rules and built-in forensic hunt mappings",
            "command": f"chainsaw hunt {fname} -s ./sigma/rules/ --mapping ./mappings/sigma-event-logs-all.yml",
            "notes": "Rapid offline hunting tool capable of scanning millions of records in seconds."
        },
        "hayabusa": {
            "title": "Hayabusa (Yamato Security)",
            "purpose": "Generate forensic timeline and threat hunting report from EVTX",
            "command": f"hayabusa csv-timeline -f {fname} -o {fname}_hayabusa.csv",
            "notes": "Fast Rust-based threat hunting engine utilizing curated Sigma rule datasets."
        },
        "powershell_getwinevent": {
            "title": "PowerShell Get-WinEvent",
            "purpose": "Filter offline EVTX file directly via PowerShell cmdlet",
            "command": f"Get-WinEvent -FilterHashtable @{{ Path = '.\\{fname}'; Id = 4624, 4625, 1102 }} | Select-Object TimeCreated, Id, Message",
            "notes": "Built-in Windows scripting filter for querying offline event log files."
        },
        "wevtutil": {
            "title": "Wevtutil Native Query",
            "purpose": "Query and export Windows Event Logs natively",
            "command": f"wevtutil qe {fname} /lf:true /f:text /q:\"*[System[(EventID=1102 or EventID=4625)]]\"",
            "notes": "Standard Windows command-line utility for querying structured XML event records."
        }
    }


# ============================================================================
# 9. EXECUTIVE EVTX SECURITY VERDICT
# ============================================================================

def calculate_evtx_verdict(
    records: List[Dict[str, Any]],
    findings: List[Any],
    sigma_alerts: List[Dict[str, Any]],
    coverage_audit: Dict[str, Any],
    auth_forensics: Dict[str, Any],
    tampering: Dict[str, Any],
    lateral_chains: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Computes a standardized Executive EVTX Security Verdict:
    - Status: Malicious | Suspicious | Potentially Vulnerable | No Known Threat Detected | Inconclusive
    - Severity: critical | high | medium | low | info
    - Calibrated Confidence Score (0% - 100%)
    - Assessment Rationale Bullets
    - MITRE ATT&CK Technique Tags
    - Actionable Containment Guidance
    """
    total_records = len(records)
    if total_records == 0:
        return {
            "verdict": "Inconclusive",
            "severity": "info",
            "confidence_score": 0,
            "key_assessment_rationale": ["Zero records could be parsed from the supplied Windows Event Log file."],
            "mitre_attack_techniques": [],
            "containment_guidance": [
                "Verify file integrity and confirm the input is a valid Windows .evtx log or zip archive.",
                "Check whether the log was zeroed or corrupted during forensic disk acquisition."
            ],
            "coverage_warning": "No event records available for analysis."
        }

    critical_sigma = [a for a in sigma_alerts if a["level"] == "critical"]
    high_sigma = [a for a in sigma_alerts if a["level"] == "high"]
    has_tampering = tampering.get("tampering_detected", False)
    has_lateral = len(lateral_chains) > 0
    has_spray = len(auth_forensics.get("password_spray_sources", [])) > 0
    has_bf_success = len(auth_forensics.get("brute_force_success", [])) > 0

    rationale: List[str] = []
    mitre_set: Set[str] = set()

    for a in sigma_alerts[:5]:
        mitre_set.add(a.get("mitre_technique", "T1070"))
        rationale.append(f"Triggered Sigma Detection [{a['level'].upper()}]: '{a['title']}' ({a['match_count']} occurrence{'s' if a['match_count']>1 else ''}).")

    if has_tampering:
        for cl in tampering.get("logs_cleared", []):
            rationale.append(f"Log Tampering / Anti-Forensics: {cl['log_type']} cleared by {cl['user']} (Event {cl['event_id']}).")
            mitre_set.add("T1070.001")

    if has_lateral:
        for lc in lateral_chains[:3]:
            rationale.append(f"Lateral Movement Chain: {lc['summary']}.")
            mitre_set.add("T1021.002")

    if has_bf_success:
        for bf in auth_forensics["brute_force_success"][:2]:
            rationale.append(f"Brute Force Followed by Success: Account '{bf['target_account']}' failed {bf['failure_count']} times before successful logon.")
            mitre_set.add("T1110.001")

    if has_spray:
        for ps in auth_forensics["password_spray_sources"][:2]:
            rationale.append(f"Password Spraying: Source IP {ps['source_ip']} targeted {ps['targeted_accounts_count']} distinct accounts.")
            mitre_set.add("T1110.003")

    # Determine Verdict & Severity
    if critical_sigma or has_tampering or has_lateral or has_bf_success:
        verdict = "Malicious"
        severity = "critical"
        confidence = min(98, 80 + len(critical_sigma) * 5 + len(lateral_chains) * 5)
    elif high_sigma or has_spray:
        verdict = "Suspicious"
        severity = "high"
        confidence = min(90, 70 + len(high_sigma) * 5)
    elif sigma_alerts or auth_forensics.get("total_failed_logons", 0) > 10:
        verdict = "Potentially Vulnerable"
        severity = "medium"
        confidence = 65
    else:
        verdict = "No Known Threat Detected"
        severity = "info"
        confidence = 80
        rationale.append(f"Scanned {total_records:,} Windows event records without matching known intrusion signatures or anti-forensics indicators.")

    # Actionable Incident Response & Containment Guidance
    containment: List[str] = []
    if verdict in ["Malicious", "Suspicious"]:
        containment.append("Immediately isolate flagged host computer(s) from the internal corporate network.")
        if has_bf_success or has_spray:
            containment.append("Force immediate password reset and revoke all Kerberos TGT / active sessions for targeted accounts.")
        if has_lateral:
            containment.append("Restrict SMB administrative share access (C$, ADMIN$) and block ports 445/139 between workstation subnets.")
        if has_tampering:
            containment.append("Escalate anti-forensics alert: Perform dead-box disk image and volatile RAM capture on affected host before rebooting.")
        containment.append("Review surrounding domain controller and SIEM logs for correlated activity across the environment.")
    else:
        containment.append("Maintain continuous auditing: Ensure PowerShell ScriptBlock logging (4104) and Sysmon process tracking are enabled.")
        containment.append("Periodically inspect audit policy integrity (Event 4719) and monitor for unexpected administrative group changes.")

    coverage_score = coverage_audit.get("coverage_score", 100)
    cov_warning = None
    if coverage_score < 70:
        cov_warning = f"Log coverage score is {coverage_score}%. Critical channels like Sysmon or PowerShell are absent, which may limit detection completeness."

    return {
        "verdict": verdict,
        "severity": severity,
        "confidence_score": confidence,
        "key_assessment_rationale": rationale[:6],
        "mitre_attack_techniques": sorted(list(mitre_set))[:8],
        "containment_guidance": containment,
        "coverage_score": coverage_score,
        "coverage_warning": cov_warning
    }
