import math
import struct
import time
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.analyzers.binary_decompiler import BinaryDecompiler
from app.analyzers.api_hashing_detector import ApiHashingDetector
from app.analyzers.xref_engine import XrefEngine
from app.analyzers.call_graph_engine import CallGraphEngine
from app.analyzers.pe_forensics import (
    classify_pe_overlay,
    inspect_dll_forensics,
    inspect_dotnet_assembly,
    inspect_pe_vulnerabilities_and_legacy_crt,
    correlate_pe_capabilities,
    calculate_pe_verdict
)
from app.core.logging_config import logger

SUSPICIOUS_WIN32_APIS = {
    # Memory Injection & Manipulation
    "VirtualAlloc": ("CRITICAL", "Memory allocation (often used for shellcode staging / executable buffers)"),
    "VirtualAllocEx": ("CRITICAL", "Remote process memory allocation (process injection prerequisite)"),
    "VirtualProtect": ("HIGH", "Modifies memory page protections (e.g. RWX executable heap)"),
    "VirtualProtectEx": ("CRITICAL", "Remote process memory protection modification"),
    "WriteProcessMemory": ("CRITICAL", "Writes memory into external process (DLL injection / process hollowing)"),
    "CreateRemoteThread": ("CRITICAL", "Spawns execution thread inside remote target process"),
    "QueueUserAPC": ("CRITICAL", "Asynchronous procedure call injection"),
    "SetThreadContext": ("CRITICAL", "Thread execution context manipulation (process hollowing)"),
    "NtUnmapViewOfSection": ("CRITICAL", "Unmaps process memory (process hollowing technique)"),
    "ZwMapViewOfSection": ("CRITICAL", "Kernel section mapping into target address space"),
    # Process Execution & Dropper Hooks
    "WinExec": ("HIGH", "Executes command-line process"),
    "ShellExecuteA": ("HIGH", "Executes shell commands / external URLs"),
    "ShellExecuteW": ("HIGH", "Executes shell commands / external URLs"),
    "ShellExecuteExA": ("HIGH", "Advanced shell command execution"),
    "ShellExecuteExW": ("HIGH", "Advanced shell command execution"),
    "CreateProcessA": ("HIGH", "Spawns new child process"),
    "CreateProcessW": ("HIGH", "Spawns new child process"),
    "CreateProcessInternalW": ("CRITICAL", "Low-level unhooked process creation"),
    # Anti-Analysis & Evasion
    "IsDebuggerPresent": ("MEDIUM", "Debugger detection / evasion check"),
    "CheckRemoteDebuggerPresent": ("MEDIUM", "Remote debugger evasion check"),
    "NtQueryInformationProcess": ("MEDIUM", "Queries internal process information / debug flags"),
    "OutputDebugStringA": ("LOW", "Debug output tracing"),
    "GetTickCount": ("LOW", "Time measurement check (used for sandbox timing evasion)"),
    "Sleep": ("LOW", "Execution delay (used for sandbox evasion)"),
    # Credential Access & Keylogging
    "GetAsyncKeyState": ("HIGH", "Low-level keystroke state monitoring (keylogger indicator)"),
    "GetKeyState": ("MEDIUM", "Key state query (potential keylogger indicator)"),
    "SetWindowsHookExA": ("HIGH", "Installs global application hook (keylogger / interceptor)"),
    "SetWindowsHookExW": ("HIGH", "Installs global application hook (keylogger / interceptor)"),
    "CryptUnprotectData": ("HIGH", "Decodes DPAPI secrets (browser passwords / credit cards / tokens)"),
    # Persistence & Registry
    "RegSetValueExA": ("MEDIUM", "Writes Windows registry keys (Run keys / persistence)"),
    "RegSetValueExW": ("MEDIUM", "Writes Windows registry keys (Run keys / persistence)"),
    "RegCreateKeyExA": ("MEDIUM", "Creates Windows registry keys"),
    "RegCreateKeyExW": ("MEDIUM", "Creates Windows registry keys"),
    # Network & Payload Downloaders
    "URLDownloadToFileA": ("HIGH", "Downloads remote payload directly to disk"),
    "URLDownloadToFileW": ("HIGH", "Downloads remote payload directly to disk"),
    "InternetOpenA": ("MEDIUM", "Initializes WinINet HTTP connection"),
    "InternetOpenW": ("MEDIUM", "Initializes WinINet HTTP connection"),
    "InternetOpenUrlA": ("HIGH", "Fetches remote URL via WinINet"),
    "InternetOpenUrlW": ("HIGH", "Fetches remote URL via WinINet"),
    "HttpSendRequestA": ("MEDIUM", "Sends outbound HTTP request"),
    "HttpSendRequestW": ("MEDIUM", "Sends outbound HTTP request"),
    "WSAStartup": ("LOW", "Initializes WinSock network socket subsystem"),
}

SUSPICIOUS_LINUX_SYSCALLS = {
    "ptrace": ("HIGH", "Process tracing and anti-debugging / code injection"),
    "mprotect": ("MEDIUM", "Modifies memory page protections (RWX execution)"),
    "execve": ("HIGH", "Direct process execution"),
    "memfd_create": ("CRITICAL", "In-memory file descriptor (fileless payload execution)"),
    "dlopen": ("MEDIUM", "Dynamic shared library loading"),
    "system": ("HIGH", "Executes shell command"),
    "connect": ("MEDIUM", "Outbound network socket connection"),
}

KNOWN_PACKER_SECTIONS = {
    "UPX0": "UPX (Ultimate Packer for eXecutables)",
    "UPX1": "UPX (Ultimate Packer for eXecutables)",
    "UPX2": "UPX (Ultimate Packer for eXecutables)",
    ".aspack": "ASPack Protector",
    "aspack": "ASPack Protector",
    ".mpress1": "MPRESS Packer",
    ".mpress2": "MPRESS Packer",
    ".themida": "Themida / WinLicense Protector",
    ".vmp0": "VMProtect Software Protection",
    ".vmp1": "VMProtect Software Protection",
    ".vmp2": "VMProtect Software Protection",
    "PEC2": "PECompact Crypter",
    ".ndata": "Nullsoft Scriptable Install System (NSIS)",
    "MEW": "MEW Packer",
    "FSG!": "FSG Fast Small Good Packer",
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _run_checksec(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Run checksec v3 (slimm609/checksec) against a binary file and return its JSON output.

    checksec must be installed at /usr/local/bin/checksec (or anywhere on PATH).
    Returns a dict of check results, or None if checksec is not available or fails.
    """
    import subprocess, json, shutil
    checksec_bin = shutil.which("checksec")
    if not checksec_bin:
        return None
    try:
        result = subprocess.run(
            [checksec_bin, "file", "--no-banner", "--no-warnings", "--no-headers",
             "-o", "json", str(file_path)],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout.strip()
        if not raw:
            return None
        parsed = json.loads(raw)
        # checksec returns a list of per-file results; grab the first
        if isinstance(parsed, list) and parsed:
            entry = parsed[0]
            return {
                "binary": entry.get("name", str(file_path)),
                "checks": entry.get("checks", {}),
            }
        return None
    except Exception as exc:
        logger.debug(f"checksec run failed for {file_path}: {exc}")
        return None

class ExecutableAnalyzer(BaseAnalyzer):
    """
    Deep static binary inspection engine (inspired by PE-bear, PEStudio, CFF Explorer, DIE, and pefile):
    - Windows PE (.exe, .dll, .sys, .scr)
    - Linux ELF (.elf, binaries)
    - macOS Mach-O (Mach-O binaries, universal fat slices, .dylib)
    """

    @property
    def name(self) -> str:
        return "ExecutableAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {
            "format": "Unknown Binary",
            "architecture": "Unknown",
            "subsystem": "Unknown",
            "is_packed": False,
            "overall_entropy": 0.0,
            "file_size": 0,
            "size_analysis": {},
            "dos_header": {},
            "file_header": {},
            "optional_header": {},
            "sections": [],
            "imports": {},
            "import_libraries_count": 0,
            "total_imports_count": 0,
            "suspicious_apis": [],
            "exports": [],
            "resources": [],
            "resource_types_count": 0,
            "abnormal_resources": [],
            "version_info": {},
            "manifest": {},
            "rich_header": {},
            "packers_and_compilers": {
                "compiler": "Unknown",
                "packer": None,
                "is_packed": False,
                "detection_details": []
            },
            "strings": {
                "total_count": 0,
                "network": [],
                "file_paths": [],
                "registry": [],
                "commands": [],
                "all_sample": []
            },
            "digital_signature": "Unknown",
            "compiler": "Unknown",
            "overlay_size": 0,
            "urls": [],
            "pe_verdict": {},
            "pe_capabilities": [],
            "dll_forensics": {},
            "dotnet_assembly": {},
            "pe_vulnerabilities": {},
            "overlay_forensics": {}
        }

        try:
            with open(file_path, "rb") as f:
                header = f.read(1024)
                f.seek(0)
                file_bytes = f.read()

            data["file_size"] = len(file_bytes)
            data["overall_entropy"] = calculate_shannon_entropy(file_bytes)

            # 1. Windows PE Detection & Inspection
            if header.startswith(b"MZ"):
                self._inspect_pe(file_path, file_bytes, findings, urls, data)
            # 2. Linux ELF Detection & Inspection
            elif header.startswith(b"\x7fELF"):
                self._inspect_elf(file_path, file_bytes, findings, urls, data)
            # 3. macOS Mach-O Detection & Inspection
            elif header[:4] in [b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE", b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA"]:
                self._inspect_macho(header, file_bytes, findings, urls, data)
            else:
                from app.analyzers.shellcode_analyzer import ShellcodeAnalyzer
                sc_res = ShellcodeAnalyzer.analyze(file_bytes)
                is_sc = sc_res.get("is_shellcode", False) or ShellcodeAnalyzer.is_likely_shellcode(file_bytes, filename)

                data["format"] = f"Position-Independent Shellcode ({sc_res.get('architecture', 'x86')})" if is_sc else "Raw Binary / Data Buffer"
                data["architecture"] = sc_res.get("architecture", "Unknown")
                data["subsystem"] = "Position-Independent Code (PIC)" if is_sc else "Raw Unstructured Data"
                data["packers"] = []
                data["compilers"] = []
                data["detected_tools"] = []
                data["shellcode"] = sc_res
                data["size_analysis"] = {
                    "physical_size": len(file_bytes),
                    "declared_virtual_size": len(file_bytes),
                    "headers_size": 0,
                    "sections_raw_total": len(file_bytes),
                    "has_overlay": False,
                    "overlay_offset": "0x0",
                    "overlay_size": 0,
                    "overlay_entropy": 0.0
                }

                # Disassembly entry
                if sc_res.get("disassembly"):
                    data["disassembly"] = {
                        "entry_point": hex(sc_res.get("nop_sled", {}).get("length", 0)) if sc_res.get("nop_sled", {}).get("detected") else "0x0",
                        "instructions": sc_res.get("disassembly", [])[:100],
                        "suspicious_patterns": sc_res.get("detected_features", [])
                    }

                # Propagate shellcode findings
                for f in sc_res.get("findings", []):
                    findings.append(f)

                # Propagate resolved API hashes to suspicious_apis
                for rh in sc_res.get("resolved_api_hashes", []):
                    data["suspicious_apis"].append({
                        "api": rh["function"],
                        "dll": rh["library"],
                        "severity": "CRITICAL",
                        "description": f"Pre-computed ROR13 API Hash ({rh['hash']}): {rh['description']}"
                    })

                # Propagate network endpoints
                for net in sc_res.get("network_indicators", []):
                    urls.add(f"tcp://{net['ip']}:{net['port']}")

                if data["overall_entropy"] >= 7.2:
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title=f"High Entropy Raw Payload ({data['overall_entropy']}/8.0)",
                        description="File exhibits unusually high entropy indicative of packed, encrypted, or compressed shellcode."
                    ))

            # Extract categorized strings and embedded URLs
            self._extract_rich_strings(file_bytes, urls, findings, data)
            data["urls"] = list(urls)

            return AnalyzerResult(
                analyzer_name=self.name,
                success=True,
                findings=findings,
                data=data
            )
        except Exception as e:
            logger.error(f"ExecutableAnalyzer failure on {filename}: {e}", exc_info=True)
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=str(e),
                findings=findings,
                data=data
            )

    def _inspect_pe(self, file_path: Path, file_bytes: bytes, findings: List[Finding], urls: Set[str], data: Dict[str, Any]) -> None:
        import pefile
        data["format"] = "Windows Portable Executable (PE)"

        try:
            pe = pefile.PE(data=file_bytes, fast_load=False)
        except Exception as e:
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Corrupted or Obfuscated PE Header",
                description=f"PE header parser encountered an anomaly: {e}"
            ))
            return

        # ---------------------------------------------------------------------
        # 1. DOS / MZ Header
        # ---------------------------------------------------------------------
        try:
            dos_dict = pe.DOS_HEADER.dump_dict()
            dos_stub = b""
            if hasattr(pe, "DOS_HEADER") and pe.DOS_HEADER.e_lfanew > 64:
                dos_stub = file_bytes[64 : min(len(file_bytes), pe.DOS_HEADER.e_lfanew)]
            
            stub_text = ""
            try:
                stub_text = re.sub(r'[^\x20-\x7E]+', ' ', dos_stub.decode('latin-1')).strip()
            except Exception:
                pass

            data["dos_header"] = {
                "e_magic": hex(pe.DOS_HEADER.e_magic) + " (MZ)",
                "e_cblp": hex(pe.DOS_HEADER.e_cblp),
                "e_cp": hex(pe.DOS_HEADER.e_cp),
                "e_crlc": hex(pe.DOS_HEADER.e_crlc),
                "e_cparhdr": hex(pe.DOS_HEADER.e_cparhdr),
                "e_minalloc": hex(pe.DOS_HEADER.e_minalloc),
                "e_maxalloc": hex(pe.DOS_HEADER.e_maxalloc),
                "e_ss": hex(pe.DOS_HEADER.e_ss),
                "e_sp": hex(pe.DOS_HEADER.e_sp),
                "e_csum": hex(pe.DOS_HEADER.e_csum),
                "e_ip": hex(pe.DOS_HEADER.e_ip),
                "e_cs": hex(pe.DOS_HEADER.e_cs),
                "e_lfarlc": hex(pe.DOS_HEADER.e_lfarlc),
                "e_ovno": hex(pe.DOS_HEADER.e_ovno),
                "e_oemid": hex(pe.DOS_HEADER.e_oemid),
                "e_oeminfo": hex(pe.DOS_HEADER.e_oeminfo),
                "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
                "stub_message": stub_text or "This program cannot be run in DOS mode."
            }
        except Exception as e:
            logger.debug(f"DOS header extraction error: {e}")

        # ---------------------------------------------------------------------
        # 2. PE File Header (COFF)
        # ---------------------------------------------------------------------
        arch_map = {
            0x014c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0xaa64: "ARM64",
            0x01c0: "ARM",
            0x0200: "Intel Itanium (IA-64)"
        }
        machine_raw = pe.FILE_HEADER.Machine
        arch_str = arch_map.get(machine_raw, f"Unknown ({hex(machine_raw)})")
        data["architecture"] = arch_str

        # Characteristics flags decoding
        char_val = pe.FILE_HEADER.Characteristics
        char_flags = []
        if char_val & 0x0001: char_flags.append("RELOCS_STRIPPED")
        if char_val & 0x0002: char_flags.append("EXECUTABLE_IMAGE")
        if char_val & 0x0004: char_flags.append("LINE_NUMS_STRIPPED")
        if char_val & 0x0008: char_flags.append("LOCAL_SYMS_STRIPPED")
        if char_val & 0x0020: char_flags.append("LARGE_ADDRESS_AWARE")
        if char_val & 0x0100: char_flags.append("32BIT_MACHINE")
        if char_val & 0x0200: char_flags.append("DEBUG_STRIPPED")
        if char_val & 0x1000: char_flags.append("SYSTEM")
        if char_val & 0x2000: char_flags.append("DLL")

        ts = pe.FILE_HEADER.TimeDateStamp
        compile_time_str = "Unknown"
        if ts:
            try:
                compile_time_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ts))
            except Exception:
                pass

        data["file_header"] = {
            "machine": arch_str,
            "machine_hex": hex(machine_raw),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "time_date_stamp": ts,
            "timestamp": compile_time_str,
            "compile_time": compile_time_str,
            "pointer_to_symbol_table": hex(pe.FILE_HEADER.PointerToSymbolTable),
            "number_of_symbols": pe.FILE_HEADER.NumberOfSymbols,
            "size_of_optional_header": pe.FILE_HEADER.SizeOfOptionalHeader,
            "characteristics": char_flags,
            "characteristics_hex": hex(char_val),
            "characteristics_flags": char_flags
        }

        # Anomaly checks on File Header
        if ts:
            cur_year = time.gmtime().tm_year
            compile_year = time.gmtime(ts).tm_year if ts > 0 else 1970
            if compile_year > cur_year + 1:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="Anomalous Future Compilation Timestamp",
                    description=f"PE compilation timestamp is set to future year {compile_year} ({compile_time_str})."
                ))
            elif compile_year < 1995 and ts > 0:
                findings.append(Finding(
                    category="structure",
                    severity="low",
                    title="Suspicious Ancient Compilation Timestamp",
                    description=f"PE timestamp set to pre-modern date {compile_year} ({compile_time_str}), possible timestamp stomping (timestomping)."
                ))

        # ---------------------------------------------------------------------
        # 3. Optional Header & Data Directories
        # ---------------------------------------------------------------------
        subsystem_map = {
            1: "Native Device Driver", 2: "Windows GUI (Graphical Application)",
            3: "Windows Console (CUI)", 7: "POSIX CUI", 9: "Windows CE GUI",
            10: "EFI Application", 11: "EFI Boot Service Driver", 12: "EFI Runtime Driver",
            14: "Xbox Subsystem"
        }
        is_64 = getattr(pe, "OPTIONAL_HEADER", None) and pe.OPTIONAL_HEADER.Magic == 0x20b
        data["subsystem"] = subsystem_map.get(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0), "Unknown") if hasattr(pe, "OPTIONAL_HEADER") else "Unknown"

        data_dirs_list = []
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            dir_names = [
                "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY (CERTIFICATES)",
                "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
                "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR_HEADER (DOTNET)", "RESERVED"
            ]
            for idx, dd in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                name = dir_names[idx] if idx < len(dir_names) else f"DIRECTORY_{idx}"
                data_dirs_list.append({
                    "index": idx,
                    "name": name,
                    "virtual_address": hex(dd.VirtualAddress),
                    "size": dd.Size,
                    "present": dd.VirtualAddress > 0 and dd.Size > 0
                })

        dll_char_val = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0
        dll_char_flags = []
        if dll_char_val & 0x0020: dll_char_flags.append("HIGH_ENTROPY_VA (64-bit ASLR)")
        if dll_char_val & 0x0040: dll_char_flags.append("DYNAMIC_BASE (ASLR)")
        if dll_char_val & 0x0080: dll_char_flags.append("FORCE_INTEGRITY")
        if dll_char_val & 0x0100: dll_char_flags.append("NX_COMPAT (Data Execution Prevention / DEP)")
        if dll_char_val & 0x0200: dll_char_flags.append("NO_ISOLATION")
        if dll_char_val & 0x0400: dll_char_flags.append("NO_SEH")
        if dll_char_val & 0x0800: dll_char_flags.append("NO_BIND")
        if dll_char_val & 0x2000: dll_char_flags.append("WDM_DRIVER")
        if dll_char_val & 0x4000: dll_char_flags.append("GUARD_CF (Control Flow Guard)")
        if dll_char_val & 0x8000: dll_char_flags.append("TERMINAL_SERVER_AWARE")

        entry_point = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0
        ep_sec_name = "Header"
        for sec in pe.sections:
            if sec.VirtualAddress <= entry_point < (sec.VirtualAddress + sec.Misc_VirtualSize):
                ep_sec_name = sec.Name.decode('latin-1', errors='ignore').rstrip('\x00').strip()
                break

        # Checksum calculation
        chksum_header = getattr(pe.OPTIONAL_HEADER, "CheckSum", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0
        chksum_calc = pe.generate_checksum() if hasattr(pe, "generate_checksum") else 0
        chksum_match = (chksum_header == chksum_calc) if chksum_header > 0 else True

        if hasattr(pe, "OPTIONAL_HEADER"):
            data["optional_header"] = {
                "magic": "PE32+ (64-bit)" if is_64 else "PE32 (32-bit)",
                "magic_hex": hex(pe.OPTIONAL_HEADER.Magic),
                "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
                "size_of_code": pe.OPTIONAL_HEADER.SizeOfCode,
                "size_of_initialized_data": pe.OPTIONAL_HEADER.SizeOfInitializedData,
                "size_of_uninitialized_data": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                "address_of_entry_point": hex(entry_point),
                "entry_point_section": ep_sec_name,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "section_alignment": hex(pe.OPTIONAL_HEADER.SectionAlignment),
                "file_alignment": hex(pe.OPTIONAL_HEADER.FileAlignment),
                "operating_system_version": f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}",
                "image_version": f"{pe.OPTIONAL_HEADER.MajorImageVersion}.{pe.OPTIONAL_HEADER.MinorImageVersion}",
                "subsystem_version": f"{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}",
                "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
                "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
                "checksum": hex(chksum_header),
                "checksum_calculated": hex(chksum_calc),
                "checksum_verified": chksum_match,
                "subsystem": data["subsystem"],
                "dll_characteristics": hex(dll_char_val),
                "dll_characteristics_flags": dll_char_flags,
                "data_directories": data_dirs_list
            }

        # Exploit Mitigations & Hardening (PE checksec)
        has_aslr = bool(dll_char_val & 0x0040)
        has_high_entropy = bool(dll_char_val & 0x0020)
        has_dep = bool(dll_char_val & 0x0100)
        has_cfg = bool(dll_char_val & 0x4000)
        has_force_integrity = bool(dll_char_val & 0x0080)
        has_no_seh = bool(dll_char_val & 0x0400)
        has_authenticode = bool(len(data_dirs_list) > 4 and data_dirs_list[4]["present"])

        missing_mitigations = []
        if not has_aslr:
            missing_mitigations.append("No ASLR (DYNAMIC_BASE flag missing)")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="PE Exploit Mitigation Missing: ASLR Disabled",
                description="Binary lacks DYNAMIC_BASE flag. Fixed load address allows reliable ROP gadgets."
            ))
        if not has_dep:
            missing_mitigations.append("No DEP / NX (NX_COMPAT flag missing)")
            findings.append(Finding(
                category="structure",
                severity="high",
                title="PE Exploit Mitigation Missing: DEP / NX Disabled",
                description="Binary lacks NX_COMPAT flag. Executable stack and heap allow direct shellcode execution."
            ))

        pe_mitigations = {
            "has_aslr": has_aslr,
            "has_high_entropy": has_high_entropy,
            "has_dep": has_dep,
            "has_cfg": has_cfg,
            "has_force_integrity": has_force_integrity,
            "has_safeseh": has_no_seh,
            "has_authenticode": has_authenticode,
            "missing_mitigations": missing_mitigations
        }
        data["pe_mitigations"] = pe_mitigations
        data["mitigations"] = {
            "nx": has_dep,
            "pie": has_aslr,
            "relro": False,
            "stack_canary": has_no_seh,
            "stripped": False
        }

        # Compiler & Toolchain Detection
        raw_str = file_bytes.decode('latin-1', errors='ignore')
        detected_compilers = []
        if "Go buildinf:" in raw_str or "runtime.gopanic" in raw_str:
            detected_compilers.append("Go (Golang Toolchain)")
        if "rust_panic" in raw_str or "core::fmt" in raw_str:
            detected_compilers.append("Rust (rustc / LLVM)")
        if "MSVC" in raw_str or "Microsoft Visual C++" in raw_str:
            detected_compilers.append("Microsoft Visual C++ (MSVC)")
        if "GCC: (" in raw_str or "MinGW" in raw_str:
            detected_compilers.append("GNU C Compiler (GCC / MinGW)")
        if "clang version" in raw_str:
            detected_compilers.append("Clang / LLVM")
        if "Borland" in raw_str or "Delphi" in raw_str:
            detected_compilers.append("Borland / Embarcadero Delphi")
        if "PyInstaller" in raw_str or "pyi-windows-shim" in raw_str or "_MEIPASS" in raw_str:
            detected_compilers.append("PyInstaller (Python Executable)")
        if "Inno Setup" in raw_str:
            detected_compilers.append("Inno Setup")
        if "NullsoftInst" in raw_str:
            detected_compilers.append("NSIS Installer")
        if "AutoIt3" in raw_str:
            detected_compilers.append("AutoIt3 Script")

        if detected_compilers:
            data["packers_and_compilers"]["compiler"] = ", ".join(detected_compilers)
            data["compiler"] = ", ".join(detected_compilers)

        # Sandbox Evasion & Anti-Analysis
        evasion_hits = []
        if any(api in raw_str for api in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]):
            evasion_hits.append("Debugger Detection API (IsDebuggerPresent / NtQueryInformationProcess)")
        if any(api in raw_str for api in ["GetTickCount", "QueryPerformanceCounter", "rdtsc"]):
            evasion_hits.append("Sandbox Timing Delay / Evasion (GetTickCount / rdtsc)")
        if any(vm in raw_str for vm in ["VBox", "VMware", "QEMU", "VirtualBox"]):
            evasion_hits.append("Virtual Machine Hypervisor Fingerprinting (VBox/VMware/QEMU)")
        if evasion_hits:
            data["anti_analysis_techniques"] = evasion_hits
            findings.append(Finding(
                category="anti_analysis",
                severity="high",
                title=f"Binary Sandbox Evasion & Anti-Analysis ({len(evasion_hits)} techniques)",
                description=f"Identified sandbox evasion heuristics: {'; '.join(evasion_hits)}.",
                details={"techniques": evasion_hits}
            ))

        # ---------------------------------------------------------------------
        # 4. Sections Inspection (PE-bear / PEStudio style)
        # ---------------------------------------------------------------------
        packed_sections = []
        raw_sections_total = 0
        for sec in pe.sections:
            sec_name = sec.Name.decode('latin-1', errors='ignore').rstrip('\x00').strip()
            sec_data = sec.get_data()
            sec_entropy = calculate_shannon_entropy(sec_data)
            raw_sections_total += sec.SizeOfRawData

            # Characteristic flags
            c = sec.Characteristics
            sec_flags = []
            if c & 0x00000020: sec_flags.append("CNT_CODE")
            if c & 0x00000040: sec_flags.append("CNT_INITIALIZED_DATA")
            if c & 0x00000080: sec_flags.append("CNT_UNINITIALIZED_DATA")
            if c & 0x20000000: sec_flags.append("MEM_EXECUTE")
            if c & 0x40000000: sec_flags.append("MEM_READ")
            if c & 0x80000000: sec_flags.append("MEM_WRITE")
            if c & 0x02000000: sec_flags.append("MEM_DISCARDABLE")
            if c & 0x10000000: sec_flags.append("MEM_SHARED")

            is_wx = bool((c & 0x20000000) and (c & 0x80000000))
            is_entry_sec = (sec_name == ep_sec_name)
            is_known_packer_name = any(sec_name.upper().startswith(p.upper()) for p in KNOWN_PACKER_SECTIONS)
            is_packed_sec = sec_entropy >= 7.2 or is_known_packer_name

            if is_packed_sec:
                packed_sections.append(f"{sec_name} (Entropy: {sec_entropy})")
                data["is_packed"] = True

            sec_info = {
                "name": sec_name or "[unnamed]",
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": sec.Misc_VirtualSize,
                "raw_offset": hex(sec.PointerToRawData),
                "raw_size": sec.SizeOfRawData,
                "entropy": sec_entropy,
                "is_packed": is_packed_sec,
                "is_wx": is_wx,
                "is_entry_point": is_entry_sec,
                "characteristics": hex(c),
                "flags": sec_flags
            }
            data["sections"].append(sec_info)

            if is_wx:
                findings.append(Finding(
                    category="active_content",
                    severity="high",
                    title=f"Writable & Executable Section (W^X Violation): {sec_name}",
                    description=f"Section '{sec_name}' has both write and execute permissions. This is characteristic of self-modifying code or unpackers."
                ))

        if packed_sections:
            findings.append(Finding(
                category="structure",
                severity="critical" if any("UPX" in s for s in packed_sections) else "high",
                title="Packed / High-Entropy Sections Detected",
                description=(
                    f"Executable contains {len(packed_sections)} section(s) with high entropy or packer signatures: "
                    f"{', '.join(packed_sections)}. Packing is used by malware authors to evade signature detection."
                ),
                details={"packed_sections": packed_sections}
            ))

        # ---------------------------------------------------------------------
        # 5. Size Analysis & Overlay Check
        # ---------------------------------------------------------------------
        overlay_offset = None
        if hasattr(pe, "get_overlay_data_start_offset"):
            overlay_offset = pe.get_overlay_data_start_offset()
        elif hasattr(pe, "get_overlay"):
            ov = pe.get_overlay()
            if ov:
                overlay_offset = len(file_bytes) - len(ov)

        overlay_size = 0
        overlay_entropy = 0.0
        overlay_info = {
            "has_overlay": False,
            "size": 0,
            "entropy": 0.0,
            "classified_type": "None",
            "hex_preview": ""
        }
        if overlay_offset:
            overlay_size = max(0, len(file_bytes) - overlay_offset)
            if overlay_size > 0:
                overlay_data = file_bytes[overlay_offset:]
                overlay_entropy = calculate_shannon_entropy(overlay_data)
                data["overlay_size"] = overlay_size
                overlay_info = classify_pe_overlay(overlay_data)

                if overlay_size > 512 or overlay_entropy >= 7.2 or "MZ" in overlay_info["classified_type"]:
                    is_crit = "MZ" in overlay_info["classified_type"] or overlay_entropy >= 7.5
                    findings.append(Finding(
                        category="structure",
                        severity="critical" if is_crit else "medium",
                        title=f"PE Overlay Detected: {overlay_info['classified_type']} ({overlay_size} bytes, Entropy: {overlay_entropy})",
                        description=f"Appended trailing data past declared PE sections. Payload classified as: {overlay_info['classified_type']}.",
                        details=overlay_info
                    ))

        data["overlay_forensics"] = overlay_info
        data["size_analysis"] = {
            "physical_size": len(file_bytes),
            "declared_virtual_size": getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0,
            "headers_size": getattr(pe.OPTIONAL_HEADER, "SizeOfHeaders", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0,
            "sections_raw_total": raw_sections_total,
            "has_overlay": bool(overlay_size > 0),
            "overlay_offset": hex(overlay_offset) if overlay_offset else "0x0",
            "overlay_size": overlay_size,
            "overlay_entropy": overlay_entropy,
            "classified_type": overlay_info.get("classified_type", "None"),
            "hex_preview": overlay_info.get("hex_preview", "")
        }

        # ---------------------------------------------------------------------
        # 6. Imports & Dangerous APIs
        # ---------------------------------------------------------------------
        suspicious_found = []
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('latin-1', errors='ignore') if entry.dll else "Unknown.dll"
                import_list = []
                for imp in entry.imports:
                    total_imports += 1
                    func_name = imp.name.decode('latin-1', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                    import_entry = {
                        "name": func_name,
                        "ordinal": imp.ordinal,
                        "address": hex(imp.address) if imp.address else "0x0",
                        "is_suspicious": False
                    }
                    if func_name in SUSPICIOUS_WIN32_APIS:
                        sev, desc = SUSPICIOUS_WIN32_APIS[func_name]
                        import_entry["is_suspicious"] = True
                        import_entry["severity"] = sev
                        import_entry["description"] = desc
                        suspicious_found.append({
                            "api": func_name,
                            "dll": dll_name,
                            "severity": sev,
                            "description": desc
                        })
                    import_list.append(import_entry)
                data["imports"][dll_name] = import_list

        data["import_libraries_count"] = len(data["imports"])
        data["total_imports_count"] = total_imports
        data["suspicious_apis"] = suspicious_found

        # Fuzzy Hashing: Imphash
        try:
            data["imphash"] = pe.get_imphash()
        except Exception:
            data["imphash"] = None

        # Rich Header Extraction & RichPV / Cleartext MD5 Hash
        try:
            rich_hash = pe.get_rich_header_hash()
            if rich_hash:
                data["rich_header_hash"] = rich_hash
                rich_tools = []
                values = []
                checksum_val = None
                if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                    if isinstance(pe.RICH_HEADER, dict):
                        values = pe.RICH_HEADER.get("values", [])
                        checksum_val = pe.RICH_HEADER.get("checksum")
                    else:
                        values = getattr(pe.RICH_HEADER, "values", [])
                        checksum_val = getattr(pe.RICH_HEADER, "checksum", None)

                for i in range(0, len(values) - 1, 2):
                    comp_id = values[i]
                    count = values[i + 1]
                    prod_id = (comp_id >> 16) & 0xFFFF
                    build_id = comp_id & 0xFFFF
                    rich_tools.append({
                        "comp_id": comp_id,
                        "prod_id": prod_id,
                        "build_id": build_id,
                        "count": count,
                        "hex_id": hex(comp_id)
                    })

                data["rich_header"] = {
                    "md5": rich_hash,
                    "rich_header_hash": rich_hash,
                    "checksum": hex(checksum_val) if checksum_val is not None else None,
                    "tools": rich_tools
                }
                findings.append(Finding(
                    category="structure",
                    severity="info",
                    title=f"PE Rich Header Fingerprint Discovered ({rich_hash[:12]}...)",
                    description=f"Decoded Microsoft Rich Header containing {len(rich_tools)} build environment/tool entries. Cleartext MD5 (RichPV): {rich_hash}",
                    details={"rich_header_hash": rich_hash, "tools_count": len(rich_tools)}
                ))
        except Exception as rich_err:
            logger.debug(f"Rich header parse note: {rich_err}")

        if suspicious_found:
            crit_count = sum(1 for s in suspicious_found if s["severity"] == "CRITICAL")
            high_count = sum(1 for s in suspicious_found if s["severity"] == "HIGH")
            findings.append(Finding(
                category="active_content",
                severity="critical" if crit_count > 0 else ("high" if high_count > 0 else "medium"),
                title=f"Suspicious Win32 APIs Imported ({len(suspicious_found)} suspicious calls)",
                description=(
                    f"Executable imports capabilities for "
                    f"{', '.join(set(s['api'] for s in suspicious_found[:6]))}. "
                    f"These APIs enable memory injection, process execution, or defense evasion."
                ),
                details={"suspicious_apis": suspicious_found}
            ))

        # Anti-Analysis & Evasion Categorization
        anti_debugging = [s["api"] for s in suspicious_found if s["api"] in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"]]
        timing_evasion = [s["api"] for s in suspicious_found if s["api"] in ["Sleep", "GetTickCount", "timeSetEvent", "WaitForSingleObject"]]
        data["anti_analysis"] = {
            "anti_debugging": anti_debugging,
            "timing_evasion": timing_evasion,
            "anti_vm": []
        }
        if anti_debugging:
            findings.append(Finding(
                category="active_content",
                severity="high",
                title=f"Anti-Debugging APIs Detected ({len(anti_debugging)} APIs)",
                description=f"Binary queries debugger status using Win32 APIs: {', '.join(anti_debugging)}.",
                details={"anti_debugging": anti_debugging}
            ))

        # ---------------------------------------------------------------------
        # 7. Exports (parsed before disassembly to enrich decompiler & call graph)
        # ---------------------------------------------------------------------
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode('latin-1', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}"
                data["exports"].append({
                    "name": exp_name,
                    "ordinal": exp.ordinal,
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address) if hasattr(pe, "OPTIONAL_HEADER") else hex(exp.address),
                    "rva": hex(exp.address)
                })

        # Entry Point Disassembly via Capstone
        try:
            import capstone
            ep_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            if ep_rva > 0:
                ep_data = pe.get_data(ep_rva, 512)
                if ep_data:
                    arch_cs = capstone.CS_ARCH_X86
                    mode_cs = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
                    md = capstone.Cs(arch_cs, mode_cs)
                    disasm_insts = []
                    suspicious_patterns = []
                    for i in md.disasm(ep_data, ep_rva):
                        disasm_insts.append({
                            "address": hex(i.address),
                            "mnemonic": i.mnemonic,
                            "op_str": i.op_str,
                            "bytes": i.bytes.hex()
                        })
                        line_str = f"{i.mnemonic} {i.op_str}".lower()
                        if "fs:[0x30]" in line_str or "gs:[0x60]" in line_str:
                            suspicious_patterns.append("PEB Access (fs:[30h]/gs:[60h]) - Dynamic API resolution")
                        elif i.mnemonic in ["syscall", "sysenter"]:
                            suspicious_patterns.append(f"Direct Syscall Invocation ({i.mnemonic})")
                        elif "fnstenv" in line_str:
                            suspicious_patterns.append("FPU GetPC Routine (Shellcode indicator)")
                        if len(disasm_insts) >= 80:
                            break
                    data["disassembly"] = {
                        "entry_point": hex(ep_rva),
                        "instructions": disasm_insts,
                        "suspicious_patterns": list(set(suspicious_patterns))
                    }
                    flat_imports = [
                        {
                            "name": imp.get("name") if isinstance(imp, dict) else getattr(imp, "name", ""),
                            "api": imp.get("name") if isinstance(imp, dict) else getattr(imp, "name", ""),
                            "address": imp.get("address") if isinstance(imp, dict) else getattr(imp, "address", None),
                            "is_suspicious": imp.get("is_suspicious", False) if isinstance(imp, dict) else False
                        }
                        for imp_list in data.get("imports", {}).values()
                        for imp in imp_list
                    ] if isinstance(data.get("imports"), dict) else []

                    try:
                        data["decompilation"] = BinaryDecompiler.decompile_function(
                            instructions=disasm_insts,
                            entry_point=hex(ep_rva),
                            function_name="entry_point",
                            architecture="x86-64" if is_64 else "x86-32",
                            imported_apis=flat_imports,
                            exported_symbols=data.get("exports", [])
                        )
                    except Exception as decomp_err:
                        logger.debug(f"Decompilation note: {decomp_err}")

                    # Scan for Obfuscated / Dynamically Hashed APIs
                    try:
                        api_hashing_matches = ApiHashingDetector.scan_instructions(disasm_insts)
                        if api_hashing_matches:
                            data["api_hashing"] = api_hashing_matches
                            resolved_names = list({m["resolved_api"] for m in api_hashing_matches})
                            findings.append(Finding(
                                category="evasion",
                                severity="high",
                                title=f"Dynamic API Hashing Detected ({len(api_hashing_matches)} APIs)",
                                description=f"Identified obfuscated Win32 APIs dynamically resolved via hashing (MITRE T1027.007): {', '.join(resolved_names[:6])}.",
                                details={"matches": api_hashing_matches}
                            ))
                    except Exception as hash_err:
                        logger.debug(f"API hashing scan note: {hash_err}")
                        api_hashing_matches = []

                    # Generate Cross-References (XREFs)
                    try:
                        data["xrefs"] = XrefEngine.generate_xrefs(
                            instructions=disasm_insts,
                            entry_point=hex(ep_rva),
                            known_strings=data.get("strings", {}).get("items", []),
                            imported_apis=flat_imports,
                            exported_symbols=data.get("exports", [])
                        )
                    except Exception as xref_err:
                        logger.debug(f"XREFs generation note: {xref_err}")

                    # Generate Visual Call Graph Hierarchy
                    try:
                        data["call_graph"] = CallGraphEngine.generate_call_graph(
                            instructions=disasm_insts,
                            entry_point=hex(ep_rva),
                            imported_apis=flat_imports,
                            exported_symbols=data.get("exports", []),
                            api_hashing_matches=data.get("api_hashing", [])
                        )
                    except Exception as cg_err:
                        logger.debug(f"Call Graph generation note: {cg_err}")

                    if suspicious_patterns:
                        findings.append(Finding(
                            category="active_content",
                            severity="high",
                            title=f"Suspicious Entry Point Instructions ({len(suspicious_patterns)} patterns)",
                            description=f"Entry point instructions indicate evasion or shellcode prologue: {', '.join(set(suspicious_patterns))}.",
                            details={"patterns": suspicious_patterns, "instructions": disasm_insts[:10]}
                        ))
        except Exception as cs_e:
            logger.debug(f"Capstone disassembly note: {cs_e}")


        # ---------------------------------------------------------------------
        # 8. Resources & Abnormal Resource Inspection
        # ---------------------------------------------------------------------
        resources_list = []
        abnormal_res = []
        res_types_set = set()

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = pefile.RESOURCE_TYPE.get(res_type.struct.Id, str(res_type.name or res_type.struct.Id))
                res_types_set.add(type_name)

                if hasattr(res_type, "directory"):
                    for res_id in res_type.directory.entries:
                        id_name = str(res_id.name or res_id.struct.Id)
                        if hasattr(res_id, "directory"):
                            for res_lang in res_id.directory.entries:
                                rva = res_lang.data.struct.OffsetToData
                                size = res_lang.data.struct.Size
                                sublang = res_lang.struct.Id
                                raw_res = pe.get_data(rva, size) if size <= 10485760 else b""
                                res_entropy = calculate_shannon_entropy(raw_res)

                                is_mz = raw_res.startswith(b"MZ")
                                is_zip = raw_res.startswith(b"PK\x03\x04") or raw_res.startswith(b"7z\xBC\xAF\x27\x1C")
                                is_high_ent = res_entropy >= 7.2
                                size_pct = round((size / len(file_bytes)) * 100, 1) if len(file_bytes) > 0 else 0

                                r_item = {
                                    "type": type_name,
                                    "name": id_name,
                                    "language": sublang,
                                    "offset": hex(rva),
                                    "size": size,
                                    "size_percent": size_pct,
                                    "entropy": res_entropy,
                                    "is_embedded_pe": is_mz,
                                    "is_embedded_archive": is_zip,
                                    "is_high_entropy": is_high_ent
                                }
                                resources_list.append(r_item)

                                if is_mz:
                                    abnormal_res.append(f"Embedded executable (MZ) in resource {type_name}/{id_name} ({size} bytes)")
                                    findings.append(Finding(
                                        category="structure",
                                        severity="critical",
                                        title=f"Embedded Executable Payload in Resource ({type_name}/{id_name})",
                                        description="Resource contains a nested Windows executable binary (MZ header). Typical of dropper / ransomware staging."
                                    ))
                                elif is_zip:
                                    abnormal_res.append(f"Embedded archive in resource {type_name}/{id_name} ({size} bytes)")
                                elif is_high_ent and size > 4096:
                                    abnormal_res.append(f"High-entropy encrypted/compressed payload in {type_name}/{id_name} ({res_entropy}/8.0)")

        data["resources"] = resources_list
        data["resource_types_count"] = len(res_types_set)
        data["abnormal_resources"] = abnormal_res

        # ---------------------------------------------------------------------
        # 9. Version Info & Manifest Extraction
        # ---------------------------------------------------------------------
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                try:
                                    data["version_info"][k.decode('latin-1')] = v.decode('latin-1')
                                except Exception:
                                    pass

        # ---------------------------------------------------------------------
        # 10. Rich Header (Compilers & Tools)
        # ---------------------------------------------------------------------
        try:
            rich = pe.parse_rich_header()
            if rich:
                tool_list = []
                values = rich.get("values", [])
                for i in range(0, len(values), 2):
                    if i + 1 < len(values):
                        tool_id = values[i] >> 16
                        build_id = values[i] & 0xFFFF
                        count = values[i + 1]
                        tool_list.append({
                            "tool_id": tool_id,
                            "build_id": build_id,
                            "times_used": count
                        })
                data["rich_header"] = {
                    "key": hex(rich.get("key", 0)),
                    "checksum": hex(rich.get("checksum", 0)),
                    "tools_count": len(tool_list),
                    "tools": tool_list
                }
        except Exception:
            pass

        # ---------------------------------------------------------------------
        # 11. Compiler & Packer Detection (DIE / PEiD style)
        # ---------------------------------------------------------------------
        compiler_name = "Unknown"
        packer_name = None
        detection_details = []

        # Check .NET / CLR
        if any(dd.get("name") == "CLR_HEADER (DOTNET)" and dd.get("present") for dd in data_dirs_list):
            compiler_name = ".NET Framework / C# Managed Application"
            detection_details.append("IMAGE_COR20_HEADER (CLR Header) present in Optional Header")
        elif "mscoree.dll" in data["imports"]:
            compiler_name = ".NET Framework Managed Binary"
            detection_details.append("Imports mscoree.dll runtime")

        # Check Linker Version if native
        if compiler_name == "Unknown" and hasattr(pe, "OPTIONAL_HEADER"):
            major_link = pe.OPTIONAL_HEADER.MajorLinkerVersion
            minor_link = pe.OPTIONAL_HEADER.MinorLinkerVersion
            if major_link == 14:
                compiler_name = "Microsoft Visual C++ 2015-2022 (MSVC v14.x)"
            elif major_link == 12:
                compiler_name = "Microsoft Visual C++ 2013 (MSVC v12.0)"
            elif major_link == 11:
                compiler_name = "Microsoft Visual C++ 2012 (MSVC v11.0)"
            elif major_link == 10:
                compiler_name = "Microsoft Visual C++ 2010 (MSVC v10.0)"
            elif major_link == 9:
                compiler_name = "Microsoft Visual C++ 2008 (MSVC v9.0)"
            elif major_link == 8:
                compiler_name = "Microsoft Visual C++ 2005 (MSVC v8.0)"
            elif major_link == 6:
                compiler_name = "Microsoft Visual C++ 6.0"
            elif major_link == 2 and minor_link >= 20:
                compiler_name = "GNU GCC / MinGW Compiler"

        # Check strings for other languages / packers
        if b"rustc" in file_bytes:
            compiler_name = "Rust (rustc)"
            detection_details.append("Contains Rust runtime and standard library signatures")
        elif b"runtime.buildVersion" in file_bytes or b"go.buildid" in file_bytes:
            compiler_name = "Go (Golang)"
            detection_details.append("Contains Golang runtime and build ID metadata")
        elif b"Borland" in file_bytes or b"TApplication" in file_bytes:
            compiler_name = "Borland Delphi / C++ Builder"
            detection_details.append("Contains Delphi VCL runtime signatures")

        # Check packers
        for sec in data["sections"]:
            for sec_key, p_name in KNOWN_PACKER_SECTIONS.items():
                if sec["name"].upper().startswith(sec_key.upper()):
                    packer_name = p_name
                    detection_details.append(f"Section '{sec['name']}' matches packer signature for {p_name}")
                    break

        if b"UPX!" in file_bytes:
            packer_name = "UPX (Ultimate Packer for eXecutables)"
            detection_details.append("Contains UPX! signature marker")
        elif b"_MEI" in file_bytes or b"pyi-windows" in file_bytes:
            packer_name = "PyInstaller Executable Bundle"
            detection_details.append("Contains PyInstaller archive bootloader headers")

        data["packers_and_compilers"] = {
            "compiler": compiler_name,
            "packer": packer_name,
            "is_packed": bool(packer_name or data["is_packed"]),
            "detection_details": detection_details
        }
        data["compiler"] = compiler_name
        data["packers"] = [packer_name] if packer_name else []
        data["compilers"] = [compiler_name] if compiler_name and compiler_name != "Unknown" else []
        data["detected_tools"] = [
            {
                "tool_id": str(t.get("tool_id", "")),
                "compiler": f"Tool ID {t.get('tool_id', '')} (Build {t.get('build_id', '')})",
                "count": t.get("times_used", 0),
                "name": f"MSVC Build {t.get('build_id', '')}"
            }
            for t in data.get("rich_header", {}).get("tools", [])
        ]

        # ---------------------------------------------------------------------
        # 12. Digital Signature / Authenticode Verification
        # ---------------------------------------------------------------------
        security_dir = None
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

        if security_dir and security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            cert_offset = security_dir.VirtualAddress
            cert_size = security_dir.Size
            try:
                from app.analyzers.authenticode_parser import parse_authenticode
                auth_info, auth_findings = parse_authenticode(file_bytes, cert_offset, cert_size)
                findings.extend(auth_findings)
            except Exception as ape:
                logger.debug(f"Authenticode parsing error: {ape}")
                auth_info = {
                    "is_signed": True,
                    "table_offset": hex(cert_offset),
                    "table_size": cert_size,
                    "certificate_type": "PKCS#7 / X.509",
                    "trust_status": "ERROR",
                    "error": str(ape)
                }

            data["authenticode"] = auth_info
            sig_status_label = f"SIGNED ({auth_info.get('trust_status', 'PRESENT')})"
            if auth_info.get("signer_name") and auth_info["signer_name"] != "Unknown":
                sig_status_label += f" - {auth_info['signer_name']}"
            data["digital_signature"] = sig_status_label
            data["digital_signature_valid"] = auth_info.get("has_valid_chain", False)
            if auth_info.get("certificates"):
                leaf = auth_info["certificates"][0]
                data["certificate_details"] = {
                    "subject": leaf.get("display_name"),
                    "issuer": leaf.get("issuer", {}).get("display"),
                    "serial_number": leaf.get("serial_number"),
                    "digest_algorithm": leaf.get("signature_algorithm")
                }
        else:
            data["authenticode"] = {"is_signed": False, "trust_status": "UNSIGNED"}
            data["digital_signature"] = "UNSIGNED (No Authenticode Digital Signature)"
            data["digital_signature_valid"] = False
            findings.append(Finding(
                category="structure",
                severity="low",
                title="Unsigned Executable Binary",
                description="The Windows executable lacks an embedded Authenticode digital signature."
            ))

        # ---------------------------------------------------------------------
        # 13. DLL-Specific Forensics, Exports, Proxy DLL & TLS Callbacks
        # ---------------------------------------------------------------------
        try:
            dll_forensics = inspect_dll_forensics(pe, file_bytes, file_path.name)
            data["dll_forensics"] = dll_forensics
            if dll_forensics.get("has_tls_callbacks"):
                findings.append(Finding(
                    category="active_content",
                    severity="high",
                    title=f"Pre-Execution TLS Callbacks Detected ({len(dll_forensics['tls_callbacks'])} callbacks)",
                    description="PE defines Thread Local Storage (TLS) callbacks that execute before DllMain or the entry point. Attackers commonly abuse TLS callbacks for anti-debugging checks, dynamic unpacking, and stealth initialization.",
                    details={"tls_callbacks": dll_forensics["tls_callbacks"]}
                ))
            if dll_forensics.get("sideloading_risk", {}).get("is_common_target_dll"):
                risk_lvl = dll_forensics["sideloading_risk"]["risk_level"].lower()
                findings.append(Finding(
                    category="structure",
                    severity="critical" if risk_lvl == "critical" else "high",
                    title=f"High-Risk DLL Sideloading Target: {dll_forensics['sideloading_risk']['target_match_name']}",
                    description=f"{dll_forensics['sideloading_risk']['description']} Common host processes: {', '.join(dll_forensics['sideloading_risk']['common_host_processes'])}.",
                    details=dll_forensics["sideloading_risk"]
                ))
            if dll_forensics.get("has_proxy_exports"):
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title=f"Proxy DLL Forwarded Exports ({dll_forensics['forwarded_export_count']} forwarded)",
                    description="DLL forwards legitimate export ordinals/names to external system DLLs while containing local execution code. Classic proxy DLL pattern used in DLL hijacking.",
                    details={"forwarded_exports": dll_forensics["forwarded_exports"][:10]}
                ))
        except Exception as dll_err:
            logger.debug(f"DLL forensics error: {dll_err}")
            data["dll_forensics"] = {"is_dll": False}

        # ---------------------------------------------------------------------
        # 14. .NET / Managed Assembly Forensics
        # ---------------------------------------------------------------------
        try:
            dotnet_info = inspect_dotnet_assembly(pe, file_bytes)
            data["dotnet_assembly"] = dotnet_info
            if dotnet_info.get("is_dotnet"):
                if dotnet_info.get("detected_obfuscators"):
                    findings.append(Finding(
                        category="anti_analysis",
                        severity="high",
                        title=f".NET Obfuscator Detected ({', '.join(dotnet_info['detected_obfuscators'])})",
                        description="Managed .NET assembly is protected with commercial or malware obfuscator to prevent decompilation.",
                        details={"obfuscators": dotnet_info["detected_obfuscators"]}
                    ))
                for sf in dotnet_info.get("suspicious_features", []):
                    if sf["severity"] in ["CRITICAL", "HIGH"]:
                        findings.append(Finding(
                            category="active_content",
                            severity=sf["severity"].lower(),
                            title=f".NET Feature: {sf['api']} ({sf['category']})",
                            description=sf["description"]
                        ))
        except Exception as net_err:
            logger.debug(f".NET forensics error: {net_err}")
            data["dotnet_assembly"] = {"is_dotnet": False}

        # ---------------------------------------------------------------------
        # 15. PE Vulnerability & Legacy CRT Functions Analysis
        # ---------------------------------------------------------------------
        try:
            pe_vulns = inspect_pe_vulnerabilities_and_legacy_crt(
                pe,
                data.get("imports", {}),
                data.get("sections", []),
                raw_str=raw_str
            )
            data["pe_vulnerabilities"] = pe_vulns
            if pe_vulns.get("legacy_crt_apis"):
                crit_crt = any(a["severity"] == "CRITICAL" for a in pe_vulns["legacy_crt_apis"])
                findings.append(Finding(
                    category="structure",
                    severity="high" if crit_crt else "medium",
                    title=f"Dangerous Legacy C Runtime Functions ({len(pe_vulns['legacy_crt_apis'])} APIs)",
                    description=f"Binary imports memory-unsafe C runtime functions susceptible to buffer overflows: {', '.join([a['api'] for a in pe_vulns['legacy_crt_apis'][:6]])}.",
                    details={"legacy_apis": pe_vulns["legacy_crt_apis"]}
                ))
        except Exception as vuln_err:
            logger.debug(f"PE vulnerability analysis error: {vuln_err}")
            data["pe_vulnerabilities"] = {}

        # ---------------------------------------------------------------------
        # 16. Capability Correlation (MITRE ATT&CK aligned)
        # ---------------------------------------------------------------------
        try:
            capabilities = correlate_pe_capabilities(data.get("imports", {}), data.get("strings", {}), data.get("sections", []), raw_str)
            data["pe_capabilities"] = capabilities
            for cap in capabilities:
                if cap["severity"] in ["CRITICAL", "HIGH"]:
                    findings.append(Finding(
                        category="active_content",
                        severity=cap["severity"].lower(),
                        title=f"Malware Capability: {cap['name']} ({cap['mitre_attack']})",
                        description=f"{cap['description']} Supporting evidence: {', '.join(cap['evidence'][:5])}.",
                        details=cap
                    ))
        except Exception as cap_err:
            logger.debug(f"Capabilities correlation error: {cap_err}")
            data["pe_capabilities"] = []

        # ---------------------------------------------------------------------
        # 17. Executive PE Security Verdict Model
        # ---------------------------------------------------------------------
        try:
            pe_verdict = calculate_pe_verdict(data, findings, data.get("pe_capabilities", []), data.get("pe_vulnerabilities", {}))
            data["pe_verdict"] = pe_verdict
        except Exception as verd_err:
            logger.debug(f"Verdict calculation error: {verd_err}")
            data["pe_verdict"] = {
                "verdict": "Inconclusive",
                "severity": "low",
                "confidence_score": 50,
                "rationale": ["PE analysis completed with limited signals."],
                "mitre_techniques": [],
                "containment_recommendations": []
            }

        pe.close()

    def _inspect_elf(self, file_path: Path, file_bytes: bytes, findings: List[Finding], urls: Set[str], data: Dict[str, Any]) -> None:
        from elftools.elf.elffile import ELFFile
        data["format"] = "Linux Executable and Linkable Format (ELF)"
        try:
            with open(file_path, "rb") as ef:
                elf = ELFFile(ef)
                data["architecture"] = f"{elf.get_machine_arch()} ({'64-bit' if elf.elfclass == 64 else '32-bit'}, {'Little Endian' if elf.little_endian else 'Big Endian'})"
                data["subsystem"] = elf.header['e_type']

                # Mitigations inspection
                is_pie = (elf.header['e_type'] == 'ET_DYN')
                has_nx = True
                has_relro = False
                has_canary = False
                rpath_entries = []

                for seg in elf.iter_segments():
                    if seg['p_type'] == 'PT_GNU_STACK':
                        # If p_flags has execute flag PF_X (1), then NX is disabled
                        has_nx = not bool(seg['p_flags'] & 1)
                    elif seg['p_type'] == 'PT_GNU_RELRO':
                        has_relro = True

                # Sections & Entropy
                stripped = True
                for sec in elf.iter_sections():
                    sec_name = sec.name
                    if sec_name in [".symtab", ".strtab"]:
                        stripped = False
                    if sec['sh_type'] in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                        for sym in sec.iter_symbols():
                            if sym.name == "__stack_chk_fail":
                                has_canary = True
                    sec_data = sec.data()
                    sec_ent = calculate_shannon_entropy(sec_data)
                    sec_type = str(sec['sh_type'])
                    data["sections"].append({
                        "name": sec_name or "[unnamed]",
                        "type": sec_type,
                        "virtual_address": hex(sec['sh_addr']),
                        "virtual_size": sec['sh_size'],
                        "raw_offset": hex(sec['sh_offset']),
                        "raw_size": sec['sh_size'],
                        "size": sec['sh_size'],
                        "entropy": sec_ent,
                        "flags": [sec_type],
                        "is_wx": False,
                        "is_entry_point": False,
                        "is_packed": sec_ent >= 7.2
                    })

                # If section headers were stripped (e_shoff == 0), populate sections from segments
                if len(data["sections"]) == 0:
                    for s_idx, seg in enumerate(elf.iter_segments()):
                        seg_type = seg['p_type']
                        seg_flags = []
                        if seg['p_flags'] & 4:
                            seg_flags.append("R")
                        if seg['p_flags'] & 2:
                            seg_flags.append("W")
                        if seg['p_flags'] & 1:
                            seg_flags.append("X")
                        flags_str = "".join(seg_flags) or "NONE"
                        seg_bytes = seg.data() if hasattr(seg, 'data') else file_bytes[seg['p_offset']:seg['p_offset']+seg['p_filesz']]
                        seg_ent = calculate_shannon_entropy(seg_bytes)
                        data["sections"].append({
                            "name": f"SEGMENT_{s_idx}_{seg_type}",
                            "type": seg_type,
                            "virtual_address": hex(seg['p_vaddr']),
                            "virtual_size": seg['p_memsz'],
                            "raw_offset": hex(seg['p_offset']),
                            "raw_size": seg['p_filesz'],
                            "size": seg['p_filesz'],
                            "entropy": seg_ent,
                            "flags": [flags_str],
                            "is_wx": ("W" in flags_str and "X" in flags_str),
                            "is_entry_point": seg['p_vaddr'] <= elf.header['e_entry'] < seg['p_vaddr'] + seg['p_memsz'],
                            "is_packed": seg_ent >= 7.2
                        })

                data["mitigations"] = {
                    "nx": has_nx,
                    "pie": is_pie,
                    "relro": has_relro,
                    "stack_canary": has_canary,
                    "stripped": stripped
                }

                # Build elf_mitigations block for MITRE mapper and UI
                missing_mitigations = []
                if not has_nx:
                    missing_mitigations.append("No NX (Executable Stack — PT_GNU_STACK flags=RWX)")
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title="ELF Executable Stack (No NX / DEP)",
                        description=(
                            "The ELF binary has PT_GNU_STACK with execute permission (p_flags=RWX), "
                            "disabling the No-eXecute (NX) mitigation. This allows shellcode to run "
                            "directly on the stack — a classic exploit primitive."
                        )
                    ))
                if not is_pie:
                    missing_mitigations.append("No PIE (Non-Position-Independent Executable — fixed base address)")
                    findings.append(Finding(
                        category="structure",
                        severity="medium",
                        title="Non-PIE ELF (No ASLR Protection)",
                        description=(
                            "The ELF binary is a non-position-independent executable (ET_EXEC). "
                            "It loads at a fixed, predictable base address, making ROP chains, "
                            "ret2libc, and GOT overwrite attacks significantly easier."
                        )
                    ))
                if stripped:
                    missing_mitigations.append("Stripped ELF (No Symbol Table / Debug Info)")
                    findings.append(Finding(
                        category="structure",
                        severity="low",
                        title="Stripped ELF Binary (No Symbol Table)",
                        description=(
                            "The ELF binary has been stripped of its symbol table and debug sections "
                            "(.symtab, .strtab). This is a common anti-forensics technique that hinders "
                            "reverse engineering and incident response attribution."
                        )
                    ))

                data["elf_mitigations"] = {
                    "has_nx": has_nx,
                    "has_pie": is_pie,
                    "has_relro": has_relro,
                    "has_canary": has_canary,
                    "is_stripped": stripped,
                    "missing_mitigations": missing_mitigations
                }

                # --- checksec integration (slimm609/checksec v3) ---
                checksec_data = _run_checksec(file_path)
                if checksec_data:
                    data["elf_mitigations"]["checksec"] = checksec_data
                    # Merge any additional detail from checksec that pyelftools may miss
                    checks = checksec_data.get("checks", {})

                    # RELRO detail (full vs partial vs none)
                    relro_val = checks.get("relro", {}).get("value", "")
                    if "full" in relro_val.lower():
                        data["elf_mitigations"]["has_relro"] = True
                        data["elf_mitigations"]["relro_type"] = "Full RELRO"
                    elif "partial" in relro_val.lower():
                        data["elf_mitigations"]["has_relro"] = True
                        data["elf_mitigations"]["relro_type"] = "Partial RELRO"
                        findings.append(Finding(
                            category="structure", severity="medium",
                            title="ELF Partial RELRO (Writable GOT)",
                            description="Binary uses Partial RELRO only. The Global Offset Table (GOT) is not fully read-only, leaving it writable and exploitable for GOT-overwrite attacks."
                        ))
                    else:
                        data["elf_mitigations"]["relro_type"] = "No RELRO"
                        if "no relro" in relro_val.lower() or checks.get("relro", {}).get("status") == "red":
                            findings.append(Finding(
                                category="structure", severity="high",
                                title="ELF No RELRO (Writable PLT/GOT)",
                                description="Binary has no RELRO protection. The PLT and GOT are fully writable, enabling GOT-overwrite and PLT poisoning attacks."
                            ))

                    # Stack Canary (if checksec contradicts pyelftools)
                    canary_val = checks.get("canary", {}).get("value", "")
                    if "found" in canary_val.lower() and not has_canary:
                        data["elf_mitigations"]["has_canary"] = True
                    elif "no canary" in canary_val.lower() and not has_canary:
                        findings.append(Finding(
                            category="structure", severity="medium",
                            title="ELF No Stack Canary",
                            description="Binary was not compiled with stack canary protection (-fstack-protector). Stack-based buffer overflows can overwrite the return address without triggering a canary abort."
                        ))

                    # CFI (Control Flow Integrity)
                    cfi_val = checks.get("cfi", {}).get("value", "")
                    cfi_status = checks.get("cfi", {}).get("status", "")
                    data["elf_mitigations"]["has_cfi"] = cfi_status == "green"
                    if cfi_status in ("red", "yellow") and "unknown" not in cfi_val.lower():
                        findings.append(Finding(
                            category="structure", severity="low",
                            title=f"ELF No CFI (Control Flow Integrity): {cfi_val}",
                            description="Binary lacks Control Flow Integrity (CFI) instrumentation. CFI restricts the set of valid jump targets, mitigating ROP/JOP attacks."
                        ))

                    # SafeStack
                    ss_val = checks.get("safestack", {}).get("value", "")
                    ss_status = checks.get("safestack", {}).get("status", "")
                    data["elf_mitigations"]["has_safestack"] = "found" in ss_val.lower()
                    # SafeStack absence is informational only (not a finding by default)

                    # Stack Clash Protection
                    sc_val = checks.get("stack_clash", {}).get("value", "")
                    sc_status = checks.get("stack_clash", {}).get("status", "")
                    data["elf_mitigations"]["has_stack_clash_protection"] = sc_status == "green"

                    # RPATH / RUNPATH (potential DLL hijacking vectors)
                    rpath_val = checks.get("rpath", {}).get("value", "")
                    rp_status = checks.get("rpath", {}).get("status", "")
                    if rp_status == "red" and rpath_val and "no rpath" not in rpath_val.lower():
                        data["elf_mitigations"]["rpath"] = rpath_val
                        findings.append(Finding(
                            category="structure", severity="medium",
                            title=f"ELF Insecure RPATH: {rpath_val}",
                            description=f"Binary embeds a hardcoded RPATH '{rpath_val}', which can be abused for dynamic linker hijacking if the path is world-writable."
                        ))

                    runpath_val = checks.get("runpath", {}).get("value", "")
                    rn_status = checks.get("runpath", {}).get("status", "")
                    if rn_status == "red" and runpath_val and "no runpath" not in runpath_val.lower():
                        data["elf_mitigations"]["runpath"] = runpath_val
                        findings.append(Finding(
                            category="structure", severity="medium",
                            title=f"ELF Insecure RUNPATH: {runpath_val}",
                            description=f"Binary embeds a hardcoded RUNPATH '{runpath_val}', overriding LD_LIBRARY_PATH and potentially loading attacker-controlled libraries."
                        ))

                    # Sanitizers
                    san_val = checks.get("sanitizers", {}).get("value", "")
                    data["elf_mitigations"]["sanitizers"] = san_val if san_val and san_val.lower() != "none" else "None"

                    # Fortify Source level
                    fortify_val = checks.get("fortify_source", {}).get("value", "")
                    data["elf_mitigations"]["fortify_source"] = fortify_val or "Unknown"

                    # Symbols (stripped/debug)
                    sym_val = checks.get("symbols", {}).get("value", "")
                    if "no symbols" in sym_val.lower():
                        data["elf_mitigations"]["is_stripped"] = True

                compiler_desc = "Stripped binary (debug and symbol tables removed)" if stripped else "Unstripped binary (symbol table present)"
                data["compiler"] = compiler_desc
                data["compilers"] = [compiler_desc]
                data["packers"] = []
                data["detected_tools"] = []

                # Size analysis
                data["size_analysis"] = {
                    "physical_size": len(file_bytes),
                    "declared_virtual_size": len(file_bytes),
                    "headers_size": elf.header['e_ehsize'] if hasattr(elf, 'header') and 'e_ehsize' in elf.header else 64,
                    "sections_raw_total": sum(s.get("raw_size", 0) for s in data["sections"]),
                    "has_overlay": False,
                    "overlay_offset": "0x0",
                    "overlay_size": 0,
                    "overlay_entropy": 0.0
                }

                # Dynamic dependencies & symbols
                dynamic_sec = elf.get_section_by_name('.dynamic')
                if dynamic_sec:
                    for tag in dynamic_sec.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            data["imports"].setdefault("Libraries", []).append({
                                "name": tag.needed,
                                "dll": "ELF Shared Object",
                                "is_suspicious": False
                            })

                # Check symbols and populate imports
                suspicious_elf_found = []
                all_symbols = []
                for sec in elf.iter_sections():
                    if sec['sh_type'] in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                        for sym in sec.iter_symbols():
                            if not sym.name:
                                continue
                            is_susp = sym.name in SUSPICIOUS_LINUX_SYSCALLS
                            desc = SUSPICIOUS_LINUX_SYSCALLS.get(sym.name, ("medium", "Linux System Call / Libc Symbol"))[1] if is_susp else ""
                            sym_item = {
                                "name": sym.name,
                                "type": str(sym.entry.st_info.type),
                                "binding": str(sym.entry.st_info.bind),
                                "address": hex(sym.entry.st_value),
                                "size": sym.entry.st_size,
                                "is_suspicious": is_susp,
                                "description": desc
                            }
                            all_symbols.append(sym_item)
                            data["imports"].setdefault("Symbols", []).append(sym_item)
                            if is_susp:
                                sev, sdesc = SUSPICIOUS_LINUX_SYSCALLS[sym.name]
                                suspicious_elf_found.append({"syscall": sym.name, "severity": sev, "description": sdesc})

                if suspicious_elf_found:
                    findings.append(Finding(
                        category="active_content",
                        severity="high" if any(s["severity"] in ["high", "critical"] for s in suspicious_elf_found) else "medium",
                        title=f"Suspicious Linux System Calls / Symbols Detected ({len(suspicious_elf_found)} APIs)",
                        description=f"ELF imports system calls associated with memory tampering, process control, or network sockets: {', '.join(set(s['syscall'] for s in suspicious_elf_found))}.",
                        details={"symbols": suspicious_elf_found}
                    ))
                data["symbols"] = all_symbols[:150]
                data["suspicious_apis"] = suspicious_elf_found

                # If dynamic_sec not found by name, check segments for PT_DYNAMIC
                if not dynamic_sec:
                    for seg in elf.iter_segments():
                        if seg['p_type'] == 'PT_DYNAMIC':
                            try:
                                for tag in seg.iter_tags():
                                    if tag.entry.d_tag == 'DT_NEEDED':
                                        data["imports"].setdefault("Libraries", []).append({
                                            "name": tag.needed,
                                            "dll": "ELF Shared Object",
                                            "is_suspicious": False
                                        })
                            except Exception:
                                pass

                # Entry Point Disassembly via Capstone for ELF
                try:
                    import capstone
                    ep_addr = elf.header.get('e_entry', 0)
                    if ep_addr > 0:
                        ep_data = None
                        for seg in elf.iter_segments():
                            if seg['p_vaddr'] <= ep_addr < seg['p_vaddr'] + seg['p_filesz']:
                                ep_offset = seg['p_offset'] + (ep_addr - seg['p_vaddr'])
                                ep_data = file_bytes[ep_offset : ep_offset + 512]
                                break
                        if ep_data:
                            arch_name = elf.get_machine_arch()
                            arch_cs = capstone.CS_ARCH_X86
                            mode_cs = capstone.CS_MODE_64 if elf.elfclass == 64 else capstone.CS_MODE_32
                            if "ARM" in arch_name or "AArch64" in arch_name:
                                arch_cs = capstone.CS_ARCH_ARM64 if elf.elfclass == 64 else capstone.CS_ARCH_ARM
                                mode_cs = capstone.CS_MODE_ARM
                            md = capstone.Cs(arch_cs, mode_cs)
                            disasm_insts = []
                            suspicious_patterns = []
                            for i in md.disasm(ep_data, ep_addr):
                                disasm_insts.append({
                                    "address": hex(i.address),
                                    "mnemonic": i.mnemonic,
                                    "op_str": i.op_str,
                                    "bytes": i.bytes.hex()
                                })
                                line_str = f"{i.mnemonic} {i.op_str}".lower()
                                if "syscall" in i.mnemonic:
                                    suspicious_patterns.append("Direct Linux Syscall Invocation")
                                elif "ptrace" in line_str:
                                    suspicious_patterns.append("Anti-Debugging (ptrace call)")
                                elif "rdtsc" in line_str:
                                    suspicious_patterns.append("Timing Attack / Cycle Counting (RDTSC)")
                                if len(disasm_insts) >= 80:
                                    break
                            data["disassembly"] = {
                                "entry_point": hex(ep_addr),
                                "instructions": disasm_insts,
                                "suspicious_patterns": list(set(suspicious_patterns))
                            }
                            try:
                                data["decompilation"] = BinaryDecompiler.decompile_function(
                                    instructions=disasm_insts,
                                    entry_point=hex(ep_addr),
                                    function_name="main",
                                    architecture=f"ELF {arch_name} {elf.elfclass}-bit",
                                    imported_apis=data.get("imports", []),
                                    exported_symbols=data.get("exports", [])
                                )
                            except Exception as decomp_err:
                                logger.debug(f"ELF Decompilation note: {decomp_err}")

                            # Generate ELF Cross-References (XREFs)
                            try:
                                data["xrefs"] = XrefEngine.generate_xrefs(
                                    instructions=disasm_insts,
                                    entry_point=hex(ep_addr),
                                    known_strings=data.get("strings", {}).get("items", []),
                                    imported_apis=data.get("imports", []),
                                    exported_symbols=data.get("exports", [])
                                )
                            except Exception as xref_err:
                                logger.debug(f"ELF XREFs note: {xref_err}")

                            # Generate ELF Visual Call Graph Hierarchy
                            try:
                                data["call_graph"] = CallGraphEngine.generate_call_graph(
                                    instructions=disasm_insts,
                                    entry_point=hex(ep_addr),
                                    imported_apis=data.get("imports", []),
                                    exported_symbols=data.get("exports", [])
                                )
                            except Exception as cg_err:
                                logger.debug(f"ELF Call Graph note: {cg_err}")

                            if suspicious_patterns:
                                findings.append(Finding(
                                    category="active_content",
                                    severity="high",
                                    title=f"Suspicious ELF Entry Point Instructions ({len(suspicious_patterns)} patterns)",
                                    description=f"Entry point instructions indicate evasion or raw syscalls: {', '.join(set(suspicious_patterns))}.",
                                    details={"patterns": suspicious_patterns, "instructions": disasm_insts[:10]}
                                ))
                except Exception as cs_err:
                    logger.debug(f"ELF Capstone disassembly note: {cs_err}")

        except Exception as e:
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="ELF Inspection Warning",
                description=f"Could not fully parse ELF headers: {e}"
            ))

    def _inspect_macho(self, header: bytes, file_bytes: bytes, findings: List[Finding], urls: Set[str], data: Dict[str, Any]) -> None:
        data["format"] = "Apple macOS Mach-O Executable / Universal Binary"
        magic = header[:4]

        is_fat = magic in [b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA"]
        is_64 = magic in [b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"]

        if is_fat:
            data["architecture"] = "macOS Universal Fat Binary (Multi-Architecture Slices)"
            try:
                num_fat = struct.unpack(">I", header[4:8])[0] if magic == b"\xCA\xFE\xBA\xBE" else struct.unpack("<I", header[4:8])[0]
                data["subsystem"] = f"Fat Binary with {num_fat} architecture slices"
                findings.append(Finding(
                    category="structure",
                    severity="info",
                    title=f"macOS Universal Fat Binary ({num_fat} architecture slices)",
                    description="Contains multi-architecture slices capable of running natively on Intel (x86_64) and Apple Silicon (ARM64)."
                ))
            except Exception:
                data["subsystem"] = "Universal Binary"
        elif is_64:
            data["architecture"] = "macOS 64-bit Mach-O (x86_64 / arm64)"
            data["subsystem"] = "Mach-O 64-bit"
        else:
            data["architecture"] = "macOS 32-bit Mach-O"
            data["subsystem"] = "Mach-O 32-bit"

        # Check for Apple Code Signature marker (LC_CODE_SIGNATURE = 0x1d)
        if b"\x1d\x00\x00\x00" in header or b"\x00\x00\x00\x1d" in header:
            data["digital_signature"] = "SIGNED (Apple Code Signature Structure Present)"
        else:
            data["digital_signature"] = "UNSIGNED (No Apple Code Signature detected)"
            findings.append(Finding(
                category="structure",
                severity="low",
                title="Unsigned macOS Mach-O Binary",
                description="The macOS executable does not have an embedded code signature (will be blocked by Gatekeeper)."
            ))

        data["packers"] = []
        data["compilers"] = ["Apple LLVM / Clang"]
        data["detected_tools"] = []
        data["size_analysis"] = {
            "physical_size": len(file_bytes),
            "declared_virtual_size": len(file_bytes),
            "headers_size": min(len(file_bytes), 4096),
            "sections_raw_total": len(file_bytes),
            "has_overlay": False,
            "overlay_offset": "0x0",
            "overlay_size": 0,
            "overlay_entropy": 0.0
        }

    def _extract_rich_strings(self, file_bytes: bytes, urls: Set[str], findings: List[Finding], data: Dict[str, Any]) -> None:
        try:
            # 1. ASCII strings >= 4 chars
            ascii_matches = re.findall(rb'[\x20-\x7E]{4,}', file_bytes)
            # 2. UTF-16LE Unicode strings >= 4 chars
            unicode_matches = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', file_bytes)

            raw_strings = []
            for s in ascii_matches:
                try:
                    raw_strings.append(s.decode('ascii', errors='ignore'))
                except Exception:
                    pass
            for s in unicode_matches:
                try:
                    raw_strings.append(s.decode('utf-16le', errors='ignore'))
                except Exception:
                    pass

            net_strings = []
            path_strings = []
            reg_strings = []
            cmd_strings = []
            seen = set()

            for s in raw_strings:
                clean = s.strip()
                if not clean or clean in seen or len(clean) < 4:
                    continue
                seen.add(clean)

                # URLs & IPs
                extracted = extract_clean_urls(clean)
                for u in extracted:
                    if not u.startswith("http://schemas.") and not u.startswith("http://www.w3.org"):
                        urls.add(u)
                        net_strings.append(u)

                # IPs
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean)
                if ip_match and not ip_match.group(0).startswith(("127.", "0.")):
                    net_strings.append(ip_match.group(0))

                # Paths
                if re.search(r'(?i)(?:[C-Z]:\\[^\s\<\>:"/\\|?*]+|/(?:bin|etc|usr|var|tmp)/[^\s]+|\.(?:exe|dll|sys|bat|ps1|vbs|sh|py))\b', clean):
                    path_strings.append(clean)

                # Registry
                if any(clean.upper().startswith(rk) for rk in ["HKEY_", "HKLM\\", "HKCU\\", "SOFTWARE\\", "SYSTEM\\"]):
                    reg_strings.append(clean)

                # Commands & LOLBins
                if any(cmd in clean.lower() for cmd in ["powershell", "cmd.exe", "certutil", "wmic", "vssadmin", "schtasks", "netsh", "net user", "reg add", "curl ", "wget "]):
                    cmd_strings.append(clean)

            data["strings"] = {
                "total_count": len(seen),
                "network": list(set(net_strings))[:150],
                "file_paths": list(set(path_strings))[:150],
                "registry": list(set(reg_strings))[:100],
                "commands": list(set(cmd_strings))[:100],
                "all_sample": list(seen)[:600]
            }

            if net_strings:
                findings.append(Finding(
                    category="url",
                    severity="medium",
                    title=f"Embedded Network Endpoints in Binary ({len(net_strings)} URLs/IPs)",
                    description="Extracted hardcoded IP addresses or external URL endpoints directly from executable string tables.",
                    details={"endpoints": list(set(net_strings))[:15]}
                ))

            if cmd_strings:
                findings.append(Finding(
                    category="active_content",
                    severity="high",
                    title=f"Suspicious Shell & Command Strings Embedded ({len(cmd_strings)} commands)",
                    description="Executable contains embedded command-line strings invoking PowerShell, command interpreters, or administrative utilities.",
                    details={"commands": list(set(cmd_strings))[:10]}
                ))

        except Exception as e:
            logger.debug(f"Rich string extraction error: {e}")

    @staticmethod
    def dump_section(file_path: Path, section_name: str) -> Optional[bytes]:
        """Extract and dump the raw bytes of a specified PE section."""
        import pefile
        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            for sec in pe.sections:
                name = sec.Name.decode('latin-1', errors='ignore').rstrip('\x00').strip()
                if name.lower() == section_name.lower():
                    return sec.get_data()
            return None
        except Exception as e:
            logger.error(f"Error dumping section '{section_name}': {e}")
            return None

    @staticmethod
    def dump_resource(file_path: Path, resource_type: str, resource_name: str) -> Optional[bytes]:
        """Extract and dump the raw bytes of a specified PE resource by type and ID/name."""
        import pefile
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
            if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                return None
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                t_name = pefile.RESOURCE_TYPE.get(res_type.struct.Id, str(res_type.name or res_type.struct.Id))
                if t_name.lower() == resource_type.lower() or str(res_type.struct.Id) == resource_type:
                    if hasattr(res_type, "directory"):
                        for res_id in res_type.directory.entries:
                            i_name = str(res_id.name or res_id.struct.Id)
                            if i_name.lower() == resource_name.lower() or str(res_id.struct.Id) == resource_name:
                                if hasattr(res_id, "directory") and res_id.directory.entries:
                                    res_lang = res_id.directory.entries[0]
                                    rva = res_lang.data.struct.OffsetToData
                                    size = res_lang.data.struct.Size
                                    return pe.get_data(rva, size)
            return None
        except Exception as e:
            logger.error(f"Error dumping resource '{resource_type}/{resource_name}': {e}")
            return None
