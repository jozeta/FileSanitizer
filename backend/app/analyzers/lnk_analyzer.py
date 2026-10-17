"""
Forensic Windows Shell Link (.LNK) Shortcut Analyzer.
Pure-Python parser implementing the official Microsoft [MS-SHLLINK] binary specification.

Inspects:
- Header flags (HasLinkTargetIDList, HasLinkInfo, HasName, HasRelativePath, HasWorkingDir, HasArguments, HasIconLocation, IsUnicode)
- File attributes & show command modes (SW_SHOWNORMAL, SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE)
- Timestamps (CreationTime, AccessTime, WriteTime from Windows FILETIME structs)
- Target file size & icon index
- Shell Item ID List (CLSID, drive letters, folder paths, special shell items)
- LinkInfo (Volume metadata, local base path, network share paths)
- String Data (Description, Relative Path, Working Directory, Command Line Arguments, Icon Location)
- ExtraData blocks (EnvironmentVariableDataBlock, ConsoleDataBlock, TrackerDataBlock, KnownFolderDataBlock)
- Trailing / Overlay Data (appended shellcode, embedded scripts, CAB/ZIP archives)
- Threat heuristics (PowerShell/CMD invocation, download cradles, LOLBins, icon spoofing, stealth window modes)
"""

import struct
import datetime
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.analyzers.deobfuscator import Deobfuscator
from app.core.logging_config import logger


# Windows FILETIME epoch is Jan 1, 1601. Unix epoch is Jan 1, 1970.
# Difference in 100-nanosecond intervals: 116444736000000000
FILETIME_EPOCH_DIFF = 116444736000000000

def _filetime_to_iso(ft_int: int) -> Optional[str]:
    """Convert a 64-bit Windows FILETIME integer to an ISO 8601 UTC string."""
    if ft_int <= 0 or ft_int == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        # Check within reasonable range (years 1980 to 2100)
        microsecs = (ft_int - FILETIME_EPOCH_DIFF) / 10
        if microsecs < 0:
            return None
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=microsecs)
        if 1980 <= dt.year <= 2100:
            return dt.isoformat()
    except Exception:
        pass
    return None


# LOLBins commonly invoked via malicious LNK files
LOLBINS = {
    "powershell.exe": "PowerShell command execution engine",
    "cmd.exe": "Windows command line interpreter",
    "mshta.exe": "Microsoft HTML Application host (executes HTA/VBScript/JScript)",
    "rundll32.exe": "Executes 32/64-bit DLL exports or malicious scriptlets",
    "cscript.exe": "Command-line script host (VBScript / JScript)",
    "wscript.exe": "Windows-based script host",
    "certutil.exe": "Certificate utility frequently abused as a file downloader / base64 decoder",
    "bitsadmin.exe": "Background Intelligent Transfer Service downloader",
    "regsvr32.exe": "Registers OLE controls / executes remote COM scriptlets (Squiblydoo)",
    "installutil.exe": "Installer tool abused for AppLocker bypass",
    "msiexec.exe": "Windows Installer executing remote MSI packages",
    "curl.exe": "Direct file download utility",
    "wmic.exe": "Windows Management Instrumentation command-line",
}


class LnkAnalyzer(BaseAnalyzer):
    """Forensic [MS-SHLLINK] Windows Shortcut Analyzer and Deobfuscator."""

    @property
    def name(self) -> str:
        return "LnkAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str, disabled_checks: Optional[List[str]] = None) -> AnalyzerResult:
        if disabled_checks is None:
            disabled_checks = []
        findings: List[Finding] = []
        urls: Set[str] = set()

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to read LNK file: {e}",
                findings=[],
                data={}
            )

        if len(raw_bytes) < 76:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message="LNK file is truncated (< 76 bytes required for ShellLinkHeader)",
                findings=[Finding(
                    category="structure",
                    severity="high",
                    title="Malformed / Truncated LNK File",
                    description="File is too small to contain a valid Windows ShellLinkHeader structure."
                )],
                data={}
            )

        # 1. Parse ShellLinkHeader (76 bytes)
        # HeaderSize (4B), LinkCLSID (16B), LinkFlags (4B), FileAttributes (4B),
        # CreationTime (8B), AccessTime (8B), WriteTime (8B),
        # FileSize (4B), IconIndex (4B), ShowCommand (4B), HotKey (2B), Reserved1 (2B), Reserved2 (4B), Reserved3 (4B)
        header_size, clsid_bytes = struct.unpack_from("<I16s", raw_bytes, 0)
        if header_size != 0x0000004C:
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Suspicious LNK Header Size",
                description=f"HeaderSize is {header_size:#x} (expected 0x0000004C). Possible crafted or corrupted LNK format."
            ))

        expected_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        clsid_matches = clsid_bytes == expected_clsid

        link_flags, file_attrs = struct.unpack_from("<II", raw_bytes, 20)
        c_time, a_time, w_time = struct.unpack_from("<QQQ", raw_bytes, 28)
        target_file_size, icon_index, show_command = struct.unpack_from("<III", raw_bytes, 52)

        has_target_id_list = bool(link_flags & 0x00000001)
        has_link_info = bool(link_flags & 0x00000002)
        has_name = bool(link_flags & 0x00000004)
        has_relative_path = bool(link_flags & 0x00000008)
        has_working_dir = bool(link_flags & 0x00000010)
        has_arguments = bool(link_flags & 0x00000020)
        has_icon_location = bool(link_flags & 0x00000040)
        is_unicode = bool(link_flags & 0x00000080)
        has_exp_string = bool(link_flags & 0x00000200)

        show_command_map = {
            1: "SW_SHOWNORMAL (Normal Window)",
            2: "SW_SHOWMINIMIZED (Minimized)",
            3: "SW_SHOWMAXIMIZED (Maximized)",
            7: "SW_SHOWMINNOACTIVE (Hidden / Minimized without Focus - Stealth)"
        }
        show_desc = show_command_map.get(show_command, f"Unknown ({show_command})")

        offset = 76

        # 2. LinkTargetIDList
        id_list_items = []
        if has_target_id_list and offset + 2 <= len(raw_bytes):
            id_list_size = struct.unpack_from("<H", raw_bytes, offset)[0]
            offset += 2
            id_list_bytes = raw_bytes[offset:offset + id_list_size]
            offset += id_list_size
            # Extract printable strings or paths from IDList
            for s in re.findall(b"[\x20-\x7E]{3,}", id_list_bytes):
                try:
                    dec = s.decode("ascii", errors="ignore").strip()
                    if dec and len(dec) >= 3 and not dec.startswith(("{", "(")):
                        id_list_items.append(dec)
                except Exception:
                    pass

        # 3. LinkInfo
        link_info = {}
        if has_link_info and offset + 4 <= len(raw_bytes):
            link_info_size = struct.unpack_from("<I", raw_bytes, offset)[0]
            if offset + link_info_size <= len(raw_bytes):
                li_bytes = raw_bytes[offset:offset + link_info_size]
                offset += link_info_size
                # Extract any ASCII paths in LinkInfo
                for p in re.findall(b"[A-Za-z]:\\\\[\x20-\x7E]{2,}", li_bytes):
                    try:
                        link_info["local_base_path"] = p.decode("ascii", errors="ignore")
                        break
                    except Exception:
                        pass
                for unc in re.findall(b"\\\\\\\\[A-Za-z0-9_.-]+\\\\[\x20-\x7E]{2,}", li_bytes):
                    try:
                        link_info["network_share_path"] = unc.decode("ascii", errors="ignore")
                        break
                    except Exception:
                        pass

        # Helper to read StringData fields
        def read_string_data(buf: bytes, curr_off: int, unicode_mode: bool) -> Tuple[str, int]:
            if curr_off + 2 > len(buf):
                return "", curr_off
            char_count = struct.unpack_from("<H", buf, curr_off)[0]
            curr_off += 2
            if unicode_mode:
                byte_len = char_count * 2
                if curr_off + byte_len > len(buf):
                    return "", curr_off
                val = buf[curr_off:curr_off + byte_len].decode("utf-16le", errors="ignore")
            else:
                byte_len = char_count
                if curr_off + byte_len > len(buf):
                    return "", curr_off
                val = buf[curr_off:curr_off + byte_len].decode("latin-1", errors="ignore")
            return val.strip("\x00"), curr_off + byte_len

        # 4. String Data
        description_str = ""
        relative_path_str = ""
        working_dir_str = ""
        arguments_str = ""
        icon_location_str = ""

        if has_name:
            description_str, offset = read_string_data(raw_bytes, offset, is_unicode)
        if has_relative_path:
            relative_path_str, offset = read_string_data(raw_bytes, offset, is_unicode)
        if has_working_dir:
            working_dir_str, offset = read_string_data(raw_bytes, offset, is_unicode)
        if has_arguments:
            arguments_str, offset = read_string_data(raw_bytes, offset, is_unicode)
        if has_icon_location:
            icon_location_str, offset = read_string_data(raw_bytes, offset, is_unicode)

        # 5. ExtraData Blocks
        extra_blocks = []
        terminal_offset = offset
        while offset + 4 <= len(raw_bytes):
            block_size = struct.unpack_from("<I", raw_bytes, offset)[0]
            if block_size < 4:
                # Terminal block (size 0) or end
                offset += 4
                terminal_offset = offset
                break
            if offset + block_size > len(raw_bytes):
                break
            block_sig = struct.unpack_from("<I", raw_bytes, offset + 4)[0]
            block_bytes = raw_bytes[offset:offset + block_size]

            sig_name = {
                0xA0000001: "EnvironmentVariableDataBlock",
                0xA0000002: "ConsoleDataBlock",
                0xA0000003: "TrackerDataBlock",
                0xA0000004: "ConsoleFEDataBlock",
                0xA0000005: "SpecialFolderDataBlock",
                0xA0000006: "DarwinDataBlock",
                0xA0000007: "IconEnvironmentDataBlock",
                0xA0000008: "ShimDataBlock",
                0xA0000009: "PropertyStoreDataBlock",
                0xA000000A: "VistaAndAboveIDListDataBlock",
                0xA000000B: "KnownFolderDataBlock"
            }.get(block_sig, f"UnknownBlock_{block_sig:#010x}")

            # Extract any embedded strings from extra blocks
            extra_strings = [s.decode("latin-1", errors="ignore") for s in re.findall(b"[\x20-\x7E]{4,}", block_bytes)]

            if "check_extra_data_blocks" not in disabled_checks:
                extra_blocks.append({
                    "signature": f"{block_sig:#010x}",
                    "type": sig_name,
                    "size": block_size,
                    "strings": extra_strings[:5]
                })

            offset += block_size
            terminal_offset = offset

        # 6. Trailing Overlay Data (Appended bytes)
        overlay_size = max(0, len(raw_bytes) - terminal_offset)
        has_overlay = overlay_size > 32 and ("check_overlay_payloads" not in disabled_checks)
        overlay_data = {}
        if has_overlay:
            overlay_bytes = raw_bytes[terminal_offset:]
            overlay_data = {
                "offset": terminal_offset,
                "size": overlay_size,
                "sha256": hashlib.sha256(overlay_bytes).hexdigest(),
                "preview_ascii": overlay_bytes[:256].decode("latin-1", errors="replace"),
                "is_executable": overlay_bytes.startswith(b"MZ"),
                "is_zip": overlay_bytes.startswith(b"PK\x03\x04"),
                "is_powershell": b"powershell" in overlay_bytes.lower() or b"invoke-" in overlay_bytes.lower(),
            }

        # 7. Threat & LOLBin Analysis
        target_binary = relative_path_str or link_info.get("local_base_path", "")
        full_command = f"{target_binary} {arguments_str}".strip()

        detected_lolbins = []
        if "check_lolbins_cradles" not in disabled_checks:
            for lb, desc in LOLBINS.items():
                if lb in full_command.lower():
                    detected_lolbins.append({
                        "binary": lb,
                        "executable": lb,
                        "role": desc,
                        "description": desc
                    })

        # Deobfuscate any Base64 encoded commands in arguments
        deobfuscated_command = ""
        encoded_match = re.search(r'(?i)(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{12,})', full_command) if "check_command_arguments" not in disabled_checks else None
        if encoded_match:
            try:
                import base64
                b64_str = encoded_match.group(1)
                decoded_raw = base64.b64decode(b64_str)
                # Usually utf-16le in powershell
                deobfuscated_command = decoded_raw.decode("utf-16le", errors="ignore")
                if not deobfuscated_command or len(deobfuscated_command.strip()) < 3:
                    deobfuscated_command = decoded_raw.decode("latin-1", errors="ignore")
            except Exception:
                pass

        # Extract URLs from full command, deobfuscated command, description, and raw bytes
        all_text = f"{full_command} {deobfuscated_command} {description_str} {icon_location_str}"
        for u in extract_clean_urls(all_text):
            urls.add(u)
        # Also regex for http/https on raw decoded bytes if present
        if encoded_match:
            try:
                for match_url in re.findall(rb'https?://[a-zA-Z0-9_\-\./~%?&=+#:]+', decoded_raw):
                    clean_u = match_url.decode('latin-1', errors='ignore').strip()
                    if clean_u:
                        urls.add(clean_u)
            except Exception:
                pass

        # Detect Icon Spoofing
        # If target executes powershell/cmd/mshta/cscript/wscript/executable, but icon points to word/excel/pdf/folder
        is_script_target = any(lb in full_command.lower() for lb in ["powershell", "cmd.exe", "mshta", "cscript", "wscript", "rundll32"])
        spoofed_icon = False
        spoof_desc = ""
        icon_lower = icon_location_str.lower()
        if is_script_target:
            if any(term in icon_lower for term in ["shell32.dll", "imageres.dll", "explorer.exe", "pdf", "acrobat", "adobe", "word", "winword", "excel", "document", "folder", "calc.exe", "notepad.exe"]):
                spoofed_icon = True
                spoof_desc = f"Executes script interpreter ('{full_command[:40]}...') but displays benign document/folder icon from '{icon_location_str}' (IconIndex: {icon_index})"

        # 8. Produce Findings
        if detected_lolbins:
            findings.append(Finding(
                category="execution",
                severity="critical",
                title=f"LNK Invokes Living-off-the-Land Binary ({', '.join(b['executable'] for b in detected_lolbins)})",
                description=(
                    f"The shortcut is weaponized to execute LOLBin utilities: {', '.join(b['executable'] for b in detected_lolbins)}. "
                    "This technique is heavily abused by malware (Qakbot, DarkGate, Raspberry Robin) for initial access."
                ),
                details={"lolbins": detected_lolbins, "command": full_command[:250]}
            ))

        if deobfuscated_command:
            findings.append(Finding(
                category="evasion",
                severity="critical",
                title="LNK Encoded PowerShell Payload Deobfuscated",
                description="Discovered Base64 encoded PowerShell command in LNK arguments. Payload was successfully unpacked.",
                details={"deobfuscated_script": deobfuscated_command[:500]}
            ))

        if spoofed_icon:
            findings.append(Finding(
                category="social_engineering",
                severity="high",
                title="LNK Icon Spoofing Detected (Masquerading)",
                description=spoof_desc,
                details={"icon_location": icon_location_str, "icon_index": icon_index}
            ))

        if show_command == 7:
            findings.append(Finding(
                category="evasion",
                severity="high",
                title="Stealth Window Mode (SW_SHOWMINNOACTIVE)",
                description="Shortcut is configured with ShowCommand=7 (SW_SHOWMINNOACTIVE), forcing the process to spawn minimized and without focus to hide console windows from the user.",
                details={"show_command": show_command, "mode": show_desc}
            ))

        if has_overlay:
            ov_type = "PE Executable (MZ)" if overlay_data.get("is_executable") else ("ZIP Container" if overlay_data.get("is_zip") else "Appended Payload Data")
            findings.append(Finding(
                category="structure",
                severity="critical" if overlay_data.get("is_executable") or overlay_data.get("is_powershell") else "high",
                title=f"LNK Trailing Overlay Detected ({ov_type}, {overlay_size:,} bytes)",
                description=(
                    f"Discovered {overlay_size:,} bytes of trailing overlay payload appended after the LNK terminal block. "
                    "Attackers append secondary payloads, scripts, or PE binaries to bypass signature-based gateway filters."
                ),
                details=overlay_data
            ))

        # Check for download cradles
        if any(term in all_text.lower() for term in ["downloadstring", "downloadfile", "iwr", "invoke-webrequest", "webclient", "bitstransfer", "certutil -urlcache"]):
            findings.append(Finding(
                category="network",
                severity="critical",
                title="LNK Network Download Cradle Detected",
                description="Command line arguments contain download cradle primitives to fetch remote stages from the internet.",
                details={"sample": full_command[:200]}
            ))

        # Check for CVE-2024-38217 / CVE-2024-21412 SmartScreen MotW Bypass
        is_motw_bypass = False
        motw_reasons = []
        if relative_path_str.startswith((".\\", "./", "..\\", "../")) or full_command.strip().startswith((".\\", "./")):
            is_motw_bypass = True
            motw_reasons.append("Relative path begins with dot-slash (.\\) or traversal (..\\)")
        if re.search(r'\s{100,}', arguments_str) or (len(arguments_str) > 200 and len(arguments_str) - len(arguments_str.lstrip()) > 100):
            is_motw_bypass = True
            motw_reasons.append("Arguments contain extreme leading whitespace padding to conceal command-line in Explorer properties")
        if "\x00" in arguments_str or "\x00" in relative_path_str:
            is_motw_bypass = True
            motw_reasons.append("Null-byte injection in path or arguments")

        if is_motw_bypass:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Windows SmartScreen Mark-of-the-Web (MotW) Bypass (CVE-2024-38217 / CVE-2024-21412)",
                description=(
                    "Shortcut incorporates dot-slash traversal or excessive argument padding designed to bypass Windows SmartScreen "
                    "Mark-of-the-Web security warnings and conceal execution parameters from the user interface."
                ),
                details={"reasons": motw_reasons, "cve": "CVE-2024-38217", "mitre_technique": "T1553.005"}
            ))

        # Check for CVE-2017-8464 / CVE-2010-2568 (Control Panel Shortcut Remote Code Execution)
        cpl_guid = "ED7BA470-8E54-465E-825C-99712043E01C"
        cpl_binary_guid = b"\x70\xba\x7b\xed\x54\x8e\x5e\x46\x82\x5c\x99\x71\x20\x43\xe0\x1c"
        has_cpl = (cpl_guid.lower() in str(id_list_items).lower()) or (cpl_binary_guid in raw_bytes) or (cpl_guid.lower() in raw_bytes.decode('latin-1', errors='ignore').lower())
        if has_cpl:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Control Panel Shortcut Remote Code Execution (CVE-2017-8464 / CVE-2010-2568)",
                description=(
                    "Shortcut targets the Control Panel Special Folder GUID {ED7BA470-8E54-465E-825C-99712043E01C}. "
                    "In vulnerable Windows systems (Stuxnet vector), rendering this shortcut triggers automatic loading "
                    "and execution of arbitrary DLL payloads without requiring user clicks."
                ),
                details={"guid": cpl_guid, "cve": "CVE-2017-8464", "cve_legacy": "CVE-2010-2568", "mitre_technique": "T1204.002"}
            ))

        # Check for Forced NTLM Authentication via UNC Icon or Target
        unc_icon = icon_location_str.startswith(("\\\\", "//"))
        unc_target = full_command.strip().startswith(("\\\\", "//")) or relative_path_str.startswith(("\\\\", "//"))
        if unc_icon or unc_target:
            unc_source = icon_location_str if unc_icon else (relative_path_str or full_command)
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Forced NetNTLM Authentication via UNC Shortcut Target/Icon (NTLM Relay)",
                description=(
                    f"Shortcut references remote UNC network path '{unc_source[:60]}' for its target or display icon. "
                    "Opening the folder containing this shortcut in Windows Explorer immediately transmits NetNTLM authentication hashes to the remote SMB server."
                ),
                details={"unc_path": unc_source, "mitre_technique": "T1187"}
            ))

        data = {
            "header": {
                "header_size": header_size,
                "clsid_matches": clsid_matches,
                "link_flags": f"{link_flags:#010x}",
                "file_attributes": f"{file_attrs:#010x}",
                "show_command": show_command,
                "show_command_desc": show_desc,
                "target_file_size": target_file_size,
                "icon_index": icon_index,
            },
            "timestamps": {
                "creation_time": _filetime_to_iso(c_time),
                "access_time": _filetime_to_iso(a_time),
                "write_time": _filetime_to_iso(w_time),
            },
            "targets_and_paths": {
                "target_command": full_command,
                "description": description_str,
                "relative_path": relative_path_str,
                "working_directory": working_dir_str,
                "arguments": arguments_str,
                "icon_location": icon_location_str,
                "link_info": link_info,
                "id_list_items": id_list_items[:10],
            },
            "deobfuscated_payload": deobfuscated_command if deobfuscated_command else None,
            "lolbins": detected_lolbins,
            "icon_spoofed": spoofed_icon,
            "icon_spoof_details": spoof_desc if spoofed_icon else None,
            "overlay": overlay_data if has_overlay else None,
            "extra_blocks": extra_blocks,
            "urls": sorted(list(urls))
        }

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
