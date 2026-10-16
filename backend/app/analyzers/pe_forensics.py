import math
import re
from typing import Dict, Any, List, Optional, Set, Tuple

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


def format_hex_preview(raw_bytes: bytes, max_len: int = 256) -> str:
    """Format a byte sequence into a classic hex editor ASCII/hex dump."""
    if not raw_bytes:
        return ""
    lines = []
    chunk = raw_bytes[:max_len]
    for i in range(0, len(chunk), 16):
        block = chunk[i : i + 16]
        hex_str = " ".join(f"{b:02x}" for b in block)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
        lines.append(f"{i:04x}  {hex_str:<48}  |{ascii_str}|")
    if len(raw_bytes) > max_len:
        lines.append(f"... ({len(raw_bytes) - max_len} more bytes omitted) ...")
    return "\n".join(lines)


# Catalog of commonly targeted DLL names for DLL Sideloading / Search-Order Hijacking
KNOWN_SIDELOADING_TARGET_DLLS: Dict[str, Dict[str, Any]] = {
    "version.dll": {
        "risk": "CRITICAL",
        "victims": ["Discord", "Telegram", "Spotify", "Steam", "OneDrive"],
        "description": "Widely abused Windows Version Library for proxy DLL sideloading via missing load path validation."
    },
    "dbghelp.dll": {
        "risk": "CRITICAL",
        "victims": ["Teams", "Visual Studio", "Google Chrome", "Edge"],
        "description": "Image Help / Debugging library commonly loaded from current application directory."
    },
    "cryptbase.dll": {
        "risk": "HIGH",
        "victims": ["Windows system utilities", "MMC", "Explorer"],
        "description": "Base Cryptographic API provider abused in DLL search-order hijacking."
    },
    "winhttp.dll": {
        "risk": "HIGH",
        "victims": ["Microsoft Office", "Windows Update clients", "Cloud sync tools"],
        "description": "Windows HTTP Services DLL abused to intercept or inject outbound network activity."
    },
    "uxtheme.dll": {
        "risk": "HIGH",
        "victims": ["Third-party desktop apps", "Game launchers"],
        "description": "Theme Library frequently exploited for local DLL hijacking."
    },
    "dwmapi.dll": {
        "risk": "HIGH",
        "victims": ["Electron applications", "Office", "Browsers"],
        "description": "Desktop Window Manager API commonly placed alongside legitimate host executables."
    },
    "d3d9.dll": {
        "risk": "HIGH",
        "victims": ["Gaming clients", "CAD utilities", "Media players"],
        "description": "Direct3D 9 runtime hijacked for in-game overlay injection or persistence."
    },
    "userenv.dll": {
        "risk": "HIGH",
        "victims": ["User profile services", "Installation packages"],
        "description": "User Environment DLL targeted during application setup or privilege escalation."
    },
    "wtsapi32.dll": {
        "risk": "HIGH",
        "victims": ["Remote desktop clients", "Citrix Workspace"],
        "description": "Windows Terminal Server SDK library abused to monitor active sessions."
    },
    "shcore.dll": {
        "risk": "HIGH",
        "victims": ["Modern Windows GUI applications", "Store apps"],
        "description": "Shell Core scaling and DPI library targeted in current directory sideloading."
    },
    "apphelp.dll": {
        "risk": "HIGH",
        "victims": ["Application Compatibility shims", "Taskmgr"],
        "description": "Application Compatibility library abused for persistence and bypass."
    },
    "iphlpapi.dll": {
        "risk": "HIGH",
        "victims": ["Network monitoring tools", "VPN clients"],
        "description": "IP Helper API DLL hijacked to sniff or redirect networking."
    },
    "amsi.dll": {
        "risk": "CRITICAL",
        "victims": ["PowerShell hosts", "Script engines", "WScript"],
        "description": "Antimalware Scan Interface DLL targeted for AMSI bypass via spoofed export shims."
    }
}

# Dangerous Legacy C Runtime APIs susceptible to buffer overflows or format string exploits
DANGEROUS_LEGACY_CRT_APIS: Dict[str, Dict[str, str]] = {
    "strcpy": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Unbounded Buffer Copy",
        "description": "Copies string without boundary verification, causing classic stack/heap buffer overflows.",
        "replacement": "strcpy_s / strncpy_s"
    },
    "wcscpy": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Unbounded Wide Buffer Copy",
        "description": "Wide-character copy without length check.",
        "replacement": "wcscpy_s"
    },
    "strcat": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Unbounded Buffer Concatenation",
        "description": "Appends string to destination buffer without checking remaining capacity.",
        "replacement": "strcat_s / strncat_s"
    },
    "wcscat": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Unbounded Wide Buffer Concatenation",
        "description": "Wide-character concatenation without boundary verification.",
        "replacement": "wcscat_s"
    },
    "sprintf": {
        "cwe": "CWE-134",
        "severity": "HIGH",
        "type": "Unbounded String Formatting",
        "description": "Formats string into fixed buffer without max length, vulnerable to buffer overflows.",
        "replacement": "sprintf_s / snprintf"
    },
    "wsprintfA": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Legacy Windows String Formatting",
        "description": "1024-byte limited string format function with no overflow validation.",
        "replacement": "StringCchPrintfA"
    },
    "wsprintfW": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Legacy Windows Wide String Formatting",
        "description": "1024-byte limited wide string format without bounds validation.",
        "replacement": "StringCchPrintfW"
    },
    "vsprintf": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "type": "Variadic Format Buffer Overflow",
        "description": "Writes formatted variable arguments without output size limitation.",
        "replacement": "vsnprintf_s"
    },
    "gets": {
        "cwe": "CWE-242",
        "severity": "CRITICAL",
        "type": "Inherently Dangerous Input Function",
        "description": "Reads standard input into buffer until newline with no size argument. Guaranteed overflow if input exceeds buffer.",
        "replacement": "fgets_s"
    },
    "scanf": {
        "cwe": "CWE-120",
        "severity": "MEDIUM",
        "type": "Unbounded Formatted Input",
        "description": "%s specifier in scanf writes unbounded input into buffer.",
        "replacement": "scanf_s"
    },
    "sscanf": {
        "cwe": "CWE-120",
        "severity": "MEDIUM",
        "type": "Unbounded String Parsing",
        "description": "%s specifier in sscanf parses unbounded string without boundary checking.",
        "replacement": "sscanf_s"
    }
}


def classify_pe_overlay(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect and classify trailing overlay data past declared PE sections."""
    if not raw_bytes:
        return {
            "has_overlay": False,
            "size": 0,
            "entropy": 0.0,
            "classified_type": "None",
            "hex_preview": ""
        }

    size = len(raw_bytes)
    entropy = calculate_shannon_entropy(raw_bytes)
    hex_preview = format_hex_preview(raw_bytes, max_len=256)

    classified_type = "Generic Overlay Data"
    if raw_bytes.startswith(b"MZ"):
        classified_type = "Embedded Windows PE Binary (MZ/PE Dropper)"
    elif raw_bytes.startswith(b"PK\x03\x04"):
        classified_type = "Embedded ZIP Archive"
    elif raw_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        classified_type = "Embedded 7-Zip Archive"
    elif raw_bytes.startswith(b"Rar!\x1a\x07"):
        classified_type = "Embedded RAR Archive"
    elif raw_bytes.startswith(b"\x1f\x8b"):
        classified_type = "Embedded GZIP Stream"
    elif entropy >= 7.5:
        classified_type = "Encrypted or High-Entropy Packed Payload (Shellcode/C2)"
    elif entropy >= 6.5:
        classified_type = "Compressed Asset or Binary Configuration"
    elif all(32 <= b < 127 or b in (9, 10, 13) for b in raw_bytes[:100]):
        classified_type = "Appended Plaintext / Script Overlay"

    return {
        "has_overlay": True,
        "size": size,
        "entropy": entropy,
        "classified_type": classified_type,
        "hex_preview": hex_preview
    }


def inspect_dll_forensics(pe: Any, file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Examine DLL-specific characteristics:
    - Export Table enumeration with Forwarded Exports (Proxy DLL detection)
    - TLS Callbacks (Thread Local Storage callbacks that execute prior to DllMain)
    - DLL Sideloading / Search-Order Hijacking target risk profiling
    """
    is_dll = False
    if hasattr(pe, "FILE_HEADER") and bool(pe.FILE_HEADER.Characteristics & 0x2000):
        is_dll = True
    elif filename.lower().endswith(".dll"):
        is_dll = True

    exports_list: List[Dict[str, Any]] = []
    forwarded_exports: List[Dict[str, Any]] = []

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []):
            name = exp.name.decode("latin-1", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
            forwarder = None
            if getattr(exp, "forwarder", None):
                forwarder = exp.forwarder.decode("latin-1", errors="ignore")

            item = {
                "name": name,
                "ordinal": exp.ordinal,
                "address": hex(exp.address) if exp.address else "0x0",
                "forwarder": forwarder,
                "is_forwarded": bool(forwarder)
            }
            exports_list.append(item)
            if forwarder:
                forwarded_exports.append(item)

    export_count = len(exports_list)
    forwarded_count = len(forwarded_exports)
    has_proxy_exports = forwarded_count > 0 and (forwarded_count / max(1, export_count) >= 0.2 or forwarded_count >= 2)

    # 2. TLS Callbacks Inspection
    tls_callbacks: List[Dict[str, Any]] = []
    has_tls = False
    tls_dir = None
    if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 9:
            tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]

    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        has_tls = True
        try:
            tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
            callbacks_va = getattr(tls_struct, "AddressOfCallBacks", 0)
            image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)
            is_64 = getattr(pe.OPTIONAL_HEADER, "Magic", 0) == 0x20b

            if callbacks_va and callbacks_va > image_base:
                callbacks_rva = callbacks_va - image_base
                ptr_size = 8 if is_64 else 4
                idx = 0
                while idx < 50:  # Bound to 50 callbacks max
                    try:
                        if is_64:
                            cb_va = pe.get_qword_at_rva(callbacks_rva + (idx * ptr_size))
                        else:
                            cb_va = pe.get_dword_at_rva(callbacks_rva + (idx * ptr_size))
                        if not cb_va or cb_va == 0:
                            break

                        cb_rva = cb_va - image_base
                        sec_name = "Header"
                        for sec in getattr(pe, "sections", []):
                            if sec.VirtualAddress <= cb_rva < (sec.VirtualAddress + sec.Misc_VirtualSize):
                                sec_name = sec.Name.decode("latin-1", errors="ignore").rstrip("\x00").strip()
                                break

                        tls_callbacks.append({
                            "index": idx,
                            "va": hex(cb_va),
                            "rva": hex(cb_rva),
                            "section": sec_name,
                            "description": "Pre-execution TLS callback routine (fires before entry point / DllMain)"
                        })
                        idx += 1
                    except Exception:
                        break
        except Exception:
            pass

    # 3. DLL Sideloading & Hijacking Target Detection
    clean_fn = filename.lower()
    sideloading_match = None
    for target_name, details in KNOWN_SIDELOADING_TARGET_DLLS.items():
        if clean_fn == target_name:
            sideloading_match = (target_name, details)
            break

    sideloading_risk: Dict[str, Any] = {
        "is_common_target_dll": bool(sideloading_match),
        "target_match_name": sideloading_match[0] if sideloading_match else None,
        "risk_level": sideloading_match[1]["risk"] if sideloading_match else "LOW",
        "description": sideloading_match[1]["description"] if sideloading_match else "DLL filename does not match known high-risk sideloading targets.",
        "common_host_processes": sideloading_match[1]["victims"] if sideloading_match else []
    }

    if has_proxy_exports and sideloading_match:
        sideloading_risk["risk_level"] = "CRITICAL"
        sideloading_risk["description"] += " Confirmed Proxy DLL pattern: forwards original exports while embedding customized code!"

    return {
        "is_dll": is_dll,
        "export_count": export_count,
        "forwarded_export_count": forwarded_count,
        "has_proxy_exports": has_proxy_exports,
        "forwarded_exports": forwarded_exports[:50],
        "tls_callbacks": tls_callbacks,
        "has_tls_callbacks": len(tls_callbacks) > 0,
        "sideloading_risk": sideloading_risk
    }


def inspect_dotnet_assembly(pe: Any, file_bytes: bytes) -> Dict[str, Any]:
    """
    Examine Microsoft .NET Managed Assembly characteristics:
    - CLR Header (IMAGE_COR20_HEADER) inspection
    - Runtime version targeting (v4.0.30319, v2.0, .NET Core)
    - Assembly flags (ILOnly, 32BitRequired, StrongNameSigned)
    - Suspicious managed APIs (Assembly.Load, Reflection, Process.Start, HttpClient)
    - .NET Obfuscator & protector signatures (ConfuserEx, SmartAssembly, Reactor, Costura)
    """
    is_dotnet = False
    clr_dir = None
    if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14:
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_dir.VirtualAddress > 0 and clr_dir.Size > 0:
                is_dotnet = True

    raw_str = file_bytes.decode("latin-1", errors="ignore")
    if not is_dotnet and ("_CorExeMain" in raw_str or "_CorDllMain" in raw_str or "mscoree.dll" in raw_str):
        is_dotnet = True

    if not is_dotnet:
        return {
            "is_dotnet": False,
            "runtime_version": None,
            "target_framework": None,
            "assembly_name": None,
            "flags": [],
            "entry_point_token": None,
            "is_il_only": False,
            "is_32bit_required": False,
            "is_strong_name_signed": False,
            "suspicious_features": [],
            "detected_obfuscators": []
        }

    # Extract target runtime version string
    runtime_ver = "Unknown CLR"
    match = re.search(r"v[0-9]+\.[0-9]+\.[0-9]+", raw_str)
    if match:
        runtime_ver = match.group(0)

    target_fw = None
    if ".NETFramework,Version=" in raw_str:
        fw_match = re.search(r"\.NETFramework,Version=v([0-9\.]+)", raw_str)
        if fw_match:
            target_fw = f".NET Framework {fw_match.group(1)}"
    elif ".NETCoreApp,Version=" in raw_str:
        core_match = re.search(r"\.NETCoreApp,Version=v([0-9\.]+)", raw_str)
        if core_match:
            target_fw = f".NET {core_match.group(1)} (Core)"

    # Parse CLR header flags if pefile has parsed it
    flags_list: List[str] = []
    entry_point_token = None
    is_il_only = False
    is_32bit = False
    is_signed = False

    if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR") and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR:
        try:
            struct = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct
            flags_val = getattr(struct, "Flags", 0)
            entry_point_token = hex(getattr(struct, "EntryPointToken", 0))
            if flags_val & 0x00000001:
                flags_list.append("COMIMAGE_FLAGS_ILONLY")
                is_il_only = True
            if flags_val & 0x00000002:
                flags_list.append("COMIMAGE_FLAGS_32BITREQUIRED")
                is_32bit = True
            if flags_val & 0x00000004:
                flags_list.append("COMIMAGE_FLAGS_IL_LIBRARY")
            if flags_val & 0x00000008:
                flags_list.append("COMIMAGE_FLAGS_STRONGNAMESIGNED")
                is_signed = True
            if flags_val & 0x00000010:
                flags_list.append("COMIMAGE_FLAGS_NATIVE_ENTRYPOINT")
            if flags_val & 0x00010000:
                flags_list.append("COMIMAGE_FLAGS_TRACKDEBUGDATA")
        except Exception:
            pass

    # Suspicious .NET APIs and behaviors
    suspicious_dotnet_features: List[Dict[str, Any]] = []

    dotnet_api_checks = [
        ("Dynamic Assembly Loading", "Assembly.Load", "CRITICAL", "Loads and executes in-memory assembly byte arrays (payload dropper / reflective load)"),
        ("Dynamic Assembly Loading", "Assembly.LoadFile", "HIGH", "Loads external assembly directly from file path"),
        ("Reflection Invocation", "System.Reflection", "MEDIUM", "Invokes internal methods dynamically to evade static API symbol tracing"),
        ("Reflection Invocation", "MethodInfo.Invoke", "HIGH", "Executes late-bound methods via reflection"),
        ("Process Execution", "Process.Start", "HIGH", "Spawns host processes or command lines from managed code"),
        ("Network Communications", "WebClient", "HIGH", "Downloads payloads or exfiltrates data via legacy HTTP client"),
        ("Network Communications", "HttpClient", "MEDIUM", "Outbound HTTP/HTTPS REST operations"),
        ("Native Interop (P/Invoke)", "DllImport", "HIGH", "Invokes unmanaged Win32 APIs bypassing CLR managed sandbox"),
        ("Cryptographic Operation", "CryptoStream", "MEDIUM", "Encrypts or decrypts streams in memory (ransomware or payload unpacker)"),
        ("Cryptographic Operation", "RijndaelManaged", "MEDIUM", "AES / Rijndael symmetric cipher operations"),
        ("Scripting Engine", "powershell", "HIGH", "Embedded PowerShell script runner inside managed application"),
    ]

    for cat, api, sev, desc in dotnet_api_checks:
        if api in raw_str:
            suspicious_dotnet_features.append({
                "category": cat,
                "api": api,
                "severity": sev,
                "description": desc
            })

    # Obfuscator Detection
    detected_obfuscators: List[str] = []
    if "Confuser.Core" in raw_str or "ConfusedByAttribute" in raw_str:
        detected_obfuscators.append("ConfuserEx Obfuscator")
    if "SmartAssembly.Attributes" in raw_str or "PoweredByAttribute" in raw_str:
        detected_obfuscators.append("RedGate SmartAssembly")
    if "DotNetReactor" in raw_str or "Reactor" in raw_str and "Eziriz" in raw_str:
        detected_obfuscators.append("Eziriz .NET Reactor")
    if "BabelAttribute" in raw_str:
        detected_obfuscators.append("Babel .NET Obfuscator")
    if "DotfuscatorAttribute" in raw_str:
        detected_obfuscators.append("PreEmptive Dotfuscator")
    if "Eazfuscator.NET" in raw_str:
        detected_obfuscators.append("Eazfuscator.NET")
    if "costura." in raw_str.lower() or "costura.fody" in raw_str.lower():
        detected_obfuscators.append("Costura.Fody (Embedded Assembly Bundler)")

    return {
        "is_dotnet": True,
        "runtime_version": runtime_ver,
        "target_framework": target_fw or runtime_ver,
        "assembly_name": None,
        "flags": flags_list,
        "entry_point_token": entry_point_token,
        "is_il_only": is_il_only,
        "is_32bit_required": is_32bit,
        "is_strong_name_signed": is_signed,
        "suspicious_features": suspicious_dotnet_features,
        "detected_obfuscators": detected_obfuscators
    }


def inspect_pe_vulnerabilities_and_legacy_crt(
    pe: Any,
    imports: Dict[str, List[Any]],
    sections: List[Dict[str, Any]],
    raw_str: str = ""
) -> Dict[str, Any]:
    """
    Examine exploit mitigations and potential software vulnerabilities:
    - W+X (Writable & Executable) memory sections (W^X violation)
    - Dangerous legacy C runtime functions (buffer overflows, format string bugs)
    - Missing PE exploit mitigations (ASLR, DEP, CFG, SafeSEH)
    """
    # 1. W+X sections
    wx_sections: List[str] = []
    for sec in sections:
        if sec.get("is_wx"):
            wx_sections.append(sec.get("name", "unnamed"))

    # 2. Legacy CRT functions in imports and static symbol strings
    legacy_crt_found: List[Dict[str, Any]] = []
    flat_imported_names: Set[str] = set()

    for dll, funcs in imports.items():
        for f in funcs:
            fn_name = f.get("name") if isinstance(f, dict) else str(f)
            if fn_name:
                flat_imported_names.add(fn_name)

    for api, details in DANGEROUS_LEGACY_CRT_APIS.items():
        found = False
        source = "Import Table"
        if api in flat_imported_names:
            found = True
            source = "Import Table"
        elif raw_str and (f"\x00{api}\x00" in raw_str or f" {api} " in raw_str or raw_str.startswith(f"{api}\x00")):
            found = True
            source = "Static Symbol / String"

        if found:
            legacy_crt_found.append({
                "api": api,
                "cwe": details["cwe"],
                "severity": details["severity"],
                "vulnerability_type": details["type"],
                "description": details["description"],
                "replacement": details["replacement"],
                "source": source
            })

    # 3. Mitigations posture
    dll_char = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0) if hasattr(pe, "OPTIONAL_HEADER") else 0
    missing_mitigations: List[str] = []
    if not bool(dll_char & 0x0040):
        missing_mitigations.append("ASLR (Address Space Layout Randomization) Disabled")
    if not bool(dll_char & 0x0100):
        missing_mitigations.append("DEP / NX (Data Execution Prevention) Disabled")
    if not bool(dll_char & 0x4000):
        missing_mitigations.append("Control Flow Guard (Guard CF) Disabled")
    if not bool(dll_char & 0x0400):
        missing_mitigations.append("Structured Exception Handling (SafeSEH) Not Enforced")

    risk_score = 0
    if wx_sections:
        risk_score += 40
    if len(missing_mitigations) >= 2:
        risk_score += 25
    if legacy_crt_found:
        risk_score += min(35, len(legacy_crt_found) * 10)

    return {
        "vulnerability_count": len(legacy_crt_found) + (1 if wx_sections else 0),
        "has_wx_sections": len(wx_sections) > 0,
        "wx_sections": wx_sections,
        "missing_mitigations": missing_mitigations,
        "legacy_crt_apis": legacy_crt_found,
        "risk_score": min(100, risk_score)
    }


def correlate_pe_capabilities(
    imports: Dict[str, List[Any]],
    strings: Dict[str, Any],
    sections: List[Dict[str, Any]],
    raw_str: str
) -> List[Dict[str, Any]]:
    """
    Correlate imports, strings, and structural features into capa / ATT&CK-aligned malware capabilities.
    """
    flat_apis: Set[str] = set()
    for funcs in imports.values():
        for f in funcs:
            fn = f.get("name") if isinstance(f, dict) else str(f)
            if fn:
                flat_apis.add(fn)

    capabilities: List[Dict[str, Any]] = []

    # Helper to check API membership
    def has_any_api(*api_names: str) -> List[str]:
        return [a for a in api_names if a in flat_apis]

    # Helper to check strings
    def has_any_str(*str_patterns: str) -> List[str]:
        matched = []
        for p in str_patterns:
            if p.lower() in raw_str.lower():
                matched.append(p)
        return matched

    # 1. Process Injection / Memory Hollowing
    inject_apis = has_any_api(
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "ZwMapViewOfSection", "ResumeThread"
    )
    if inject_apis:
        has_full_chain = (
            "VirtualAllocEx" in inject_apis and
            "WriteProcessMemory" in inject_apis and
            any(t in inject_apis for t in ["CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "ResumeThread"])
        )
        capabilities.append({
            "id": "CAP_PROCESS_INJECTION",
            "name": "Process Injection / Memory Hollowing",
            "tactic": "Defense Evasion & Privilege Escalation",
            "mitre_attack": "T1055",
            "severity": "CRITICAL",
            "confidence": "HIGH" if has_full_chain else "MEDIUM",
            "description": "Allocates memory and writes code into remote host processes, followed by remote thread creation.",
            "evidence": inject_apis
        })

    # 2. Dynamic Memory RWX Staging
    rwx_apis = has_any_api("VirtualProtect", "VirtualProtectEx", "VirtualAlloc")
    has_wx_sec = any(s.get("is_wx") for s in sections)
    if ("VirtualProtect" in rwx_apis or "VirtualProtectEx" in rwx_apis) or (has_wx_sec and "VirtualAlloc" in rwx_apis):
        evid = list(rwx_apis)
        if has_wx_sec:
            evid.append("Writable & Executable Section present")
        capabilities.append({
            "id": "CAP_MEMORY_PROTECTION_ALTER",
            "name": "Dynamic Memory Protection Alteration (RWX Staging)",
            "tactic": "Defense Evasion",
            "mitre_attack": "T1055.002",
            "severity": "HIGH",
            "confidence": "HIGH" if "VirtualProtectEx" in rwx_apis or has_wx_sec else "MEDIUM",
            "description": "Modifies memory page protections at runtime to stage and execute shellcode or unpacked payloads.",
            "evidence": evid
        })

    # 3. Dynamic API Resolution
    dyn_apis = has_any_api("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrGetProcedureAddress")
    if "GetProcAddress" in dyn_apis and len(dyn_apis) >= 2:
        capabilities.append({
            "id": "CAP_DYNAMIC_API_RESOLUTION",
            "name": "Dynamic API Resolution & Import Hiding",
            "tactic": "Defense Evasion",
            "mitre_attack": "T1027.007",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "description": "Resolves imported Windows API functions dynamically at runtime to conceal true intent from static analyzers.",
            "evidence": dyn_apis
        })

    # 4. Command & Process Execution
    exec_apis = has_any_api("CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "CreateProcessInternalW")
    cmd_strings = has_any_str("cmd.exe", "powershell.exe", "-ExecutionPolicy Bypass", "/c start", "wscript.exe")
    if exec_apis or (len(cmd_strings) >= 2):
        evid = list(exec_apis) + [f"String: {s}" for s in cmd_strings]
        capabilities.append({
            "id": "CAP_COMMAND_EXECUTION",
            "name": "Command & Process Spawning",
            "tactic": "Execution",
            "mitre_attack": "T1059",
            "severity": "HIGH",
            "confidence": "HIGH" if (exec_apis and cmd_strings) else "MEDIUM",
            "description": "Spawns child processes or executes system command interpreters (cmd/powershell).",
            "evidence": evid
        })

    # 5. Persistence via Registry or Startup
    reg_apis = has_any_api("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW")
    reg_strings = has_any_str("CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Winlogon\\Userinit", "System\\CurrentControlSet\\Services")
    if reg_apis and reg_strings:
        evid = list(reg_apis) + [f"Key: {k}" for k in reg_strings]
        capabilities.append({
            "id": "CAP_REGISTRY_PERSISTENCE",
            "name": "Persistence via Windows Registry Run Keys",
            "tactic": "Persistence",
            "mitre_attack": "T1547.001",
            "severity": "HIGH",
            "confidence": "HIGH",
            "description": "Creates or updates registry autorun keys to maintain system persistence across reboots.",
            "evidence": evid
        })

    # 6. Service Installation & Control
    svc_apis = has_any_api("CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "OpenSCManagerA", "OpenSCManagerW")
    if len(svc_apis) >= 2:
        capabilities.append({
            "id": "CAP_SERVICE_INSTALLATION",
            "name": "Windows Service Installation & Control",
            "tactic": "Persistence & Privilege Escalation",
            "mitre_attack": "T1543.003",
            "severity": "HIGH",
            "confidence": "HIGH",
            "description": "Communicates with Service Control Manager (SCM) to create or start system background services.",
            "evidence": svc_apis
        })

    # 7. Network Communications & C2 Beaconing
    net_apis = has_any_api(
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen", "WinHttpSendRequest",
        "WSAStartup", "socket", "connect", "send", "recv", "URLDownloadToFileA", "URLDownloadToFileW"
    )
    if net_apis:
        has_c2_download = any(a in net_apis for a in ["URLDownloadToFileA", "URLDownloadToFileW", "HttpSendRequestA", "WinHttpSendRequest"])
        capabilities.append({
            "id": "CAP_NETWORK_C2",
            "name": "Network Communication & Payload Ingress",
            "tactic": "Command and Control",
            "mitre_attack": "T1071.001",
            "severity": "HIGH" if has_c2_download else "MEDIUM",
            "confidence": "HIGH" if len(net_apis) >= 2 else "MEDIUM",
            "description": "Establishes socket connections or HTTP/HTTPS channels for remote command and control or payload staging.",
            "evidence": net_apis
        })

    # 8. Credential Theft & Memory Dumping
    cred_apis = has_any_api("MiniDumpWriteDump", "SamIConnect", "LsaEnumerateLogonSessions", "CryptUnprotectData", "GetAsyncKeyState", "SetWindowsHookExA")
    if cred_apis:
        capabilities.append({
            "id": "CAP_CREDENTIAL_ACCESS",
            "name": "Credential Access & Memory Dumping",
            "tactic": "Credential Access",
            "mitre_attack": "T1003",
            "severity": "CRITICAL" if any(a in cred_apis for a in ["MiniDumpWriteDump", "SamIConnect", "CryptUnprotectData"]) else "HIGH",
            "confidence": "HIGH",
            "description": "Interrogates LSASS / process memory or captures keystrokes to harvest passwords, tokens, or DPAPI credentials.",
            "evidence": cred_apis
        })

    # 9. Cryptography / Ransomware Indicators
    crypto_apis = has_any_api("CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW")
    ransom_strings = has_any_str("vssadmin.exe delete shadows", "wmic shadowcopy delete", "bcdedit /set", ".locked", "README_DECRYPT")
    if (crypto_apis and ransom_strings) or (len(crypto_apis) >= 2 and len(ransom_strings) >= 1):
        evid = list(crypto_apis) + [f"String: {s}" for s in ransom_strings]
        capabilities.append({
            "id": "CAP_RANSOMWARE_ENCRYPTION",
            "name": "Ransomware-like Encryption & Shadow Copy Deletion",
            "tactic": "Impact",
            "mitre_attack": "T1486",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "description": "Destroys volume shadow copies and leverages cryptographic APIs to perform mass file encryption.",
            "evidence": evid
        })

    # 10. Anti-Debugging & Sandbox Evasion
    evasion_apis = has_any_api("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA")
    evasion_strings = has_any_str("VBox", "VMware", "QEMU", "VirtualBox", "wine_get_version")
    if evasion_apis or evasion_strings:
        evid = list(evasion_apis) + [f"Artifact: {s}" for s in evasion_strings]
        capabilities.append({
            "id": "CAP_DEFENSE_EVASION",
            "name": "Anti-Debugging & Analysis Environment Fingerprinting",
            "tactic": "Defense Evasion",
            "mitre_attack": "T1497",
            "severity": "HIGH",
            "confidence": "HIGH" if (evasion_apis and evasion_strings) else "MEDIUM",
            "description": "Detects attached debuggers, virtualization hypervisors, or analysis sandboxes to halt execution.",
            "evidence": evid
        })

    return capabilities


def calculate_pe_verdict(
    data: Dict[str, Any],
    findings: List[Any],
    capabilities: List[Dict[str, Any]],
    vulns: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesize an executive security verdict based on PE static features,
    identified capabilities, exploit mitigations, and Authenticode integrity.
    """
    crit_count = sum(1 for c in capabilities if c["severity"] == "CRITICAL")
    high_count = sum(1 for c in capabilities if c["severity"] == "HIGH")
    vuln_count = vulns.get("vulnerability_count", 0)
    has_wx = vulns.get("has_wx_sections", False)
    is_packed = data.get("is_packed", False)
    auth_info = data.get("authenticode", {})
    is_signed = auth_info.get("is_signed", False)
    is_valid_sig = auth_info.get("has_valid_chain", False)

    rationale: List[str] = []
    containment: List[str] = []

    # Map techniques
    mitre_techniques: List[Dict[str, str]] = []
    for cap in capabilities:
        mitre_techniques.append({
            "id": cap["mitre_attack"],
            "name": cap["name"],
            "tactic": cap["tactic"]
        })

    # Verdict evaluation
    if crit_count > 0:
        verdict = "Malicious"
        severity = "critical"
        confidence = 95
        rationale.append(f"Identified {crit_count} CRITICAL malware capability pattern(s) including {[c['name'] for c in capabilities if c['severity'] == 'CRITICAL'][0]}.")
        if is_packed:
            rationale.append("Binary employs high-entropy packing or protective wrapper to conceal malicious code.")
        containment.extend([
            "Quarantine binary immediately on endpoint detection & response (EDR).",
            "Block cryptographic hash (SHA-256) at border firewalls and mail gateways.",
            "Investigate parent process lineage and check for memory injection in running processes.",
            "Perform network perimeter search for related C2 domain and IP indicators."
        ])
    elif high_count >= 2 or (high_count >= 1 and has_wx):
        verdict = "Suspicious"
        severity = "high"
        confidence = 85
        rationale.append(f"Identified {high_count} HIGH-risk capability patterns ({', '.join([c['name'] for c in capabilities[:2]])}).")
        if has_wx:
            rationale.append(f"Contains writable and executable section(s) violating W^X policy: {', '.join(vulns.get('wx_sections', []))}.")
        containment.extend([
            "Submit binary to isolated sandbox for behavioral monitoring of process and network events.",
            "Inspect binary in a debugger or disassembler to verify intent of high-risk capabilities.",
            "Verify code signing identity against vendor authorized baseline."
        ])
    elif vuln_count > 0 or len(vulns.get("missing_mitigations", [])) >= 3:
        verdict = "Potentially Vulnerable"
        severity = "medium"
        confidence = 75
        rationale.append(f"Discovered {len(vulns.get('legacy_crt_apis', []))} dangerous legacy CRT function(s) susceptible to buffer overflows.")
        if vulns.get("missing_mitigations"):
            rationale.append(f"Missing modern exploit mitigations: {', '.join(vulns.get('missing_mitigations', [])[:2])}.")
        containment.extend([
            "Update source code to adopt safe string functions (e.g. strcpy_s, sprintf_s).",
            "Enable ASLR (/DYNAMICBASE) and DEP (/NXCOMPAT) compiler flags.",
            "Recompile with Control Flow Guard (/guard:cf) and address sanitizer."
        ])
    elif is_signed and is_valid_sig:
        verdict = "No Known Threat Detected"
        severity = "clean"
        confidence = 80
        rationale.append(f"Binary is digitally signed by trusted publisher '{auth_info.get('signer_name', 'Verified Publisher')}' with valid certificate chain.")
        rationale.append("No weaponized capabilities, packers, or structural anomalies detected.")
        containment.append("No immediate incident containment needed. Monitor operational behavior per standard policy.")
    else:
        verdict = "No Known Threat Detected" if not findings else "Inconclusive"
        severity = "low"
        confidence = 65
        rationale.append("Standard binary structure without overt weaponized capabilities.")
        if not is_signed:
            rationale.append("Executable lacks Authenticode digital signature.")
        containment.append("Retain sample for threat intelligence baseline clustering.")

    return {
        "verdict": verdict,
        "severity": severity,
        "confidence_score": confidence,
        "rationale": rationale,
        "mitre_techniques": mitre_techniques,
        "containment_recommendations": containment
    }
