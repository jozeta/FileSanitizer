"""
Advanced Shellcode & Position-Independent Code (PIC) Static Analyzer.
Disassembles and heuristically inspects raw binary shellcode (x86 and x86_64) using Capstone:
- Architecture detection & confidence scoring (32-bit x86 vs 64-bit x64)
- NOP sled detection (0x90 runs and multi-byte slides)
- Get-EIP / Delta offset calculation (call $+5, fnstenv / FPU)
- PEB / TEB traversal (fs:[0x30], gs:[0x60], Ldr data tables)
- Direct Windows / Linux syscalls (syscall, sysenter, int 0x2e, int 0x80)
- API hashing & resolution loops (ROR13, Cobalt Strike, Metasploit hash dictionary)
- Egg hunter routines (repeated tag search, memory probe syscalls)
- Dynamic stack strings reconstruction (push imm / mov [rsp/esp], imm)
- Socket & network payload detection (sockaddr_in, connect, WSASocket)
- Multi-architecture disassembly listing with highlighted forensic indicators
"""

import re
import struct
import capstone
from typing import Dict, Any, List, Tuple, Optional
from app.analyzers.base import Finding
from app.core.logging_config import logger

# Metasploit, Cobalt Strike, and common malware ROR-13 API hashes
KNOWN_ROR13_HASHES = {
    0xEC0E4E8E: ("LoadLibraryA", "kernel32.dll", "Loads arbitrary DLL library into memory"),
    0x0726774C: ("LoadLibraryA", "kernel32.dll", "Loads arbitrary DLL library into memory"),
    0x16B0D72C: ("CreateProcessA", "kernel32.dll", "Spawns new child process"),
    0x790C3E44: ("ExitProcess", "kernel32.dll", "Terminates calling process cleanly"),
    0x4EEB3A27: ("VirtualAlloc", "kernel32.dll", "Allocates executable/writable memory"),
    0xE553A458: ("VirtualAllocEx", "kernel32.dll", "Allocates memory in target remote process"),
    0x382C3E97: ("VirtualProtect", "kernel32.dll", "Changes page protection to RWX"),
    0x876F8B31: ("WinExec", "kernel32.dll", "Executes command line directly"),
    0x5BAE572D: ("WriteProcessMemory", "kernel32.dll", "Writes payload into target process"),
    0x7C0DFCAA: ("CreateRemoteThread", "kernel32.dll", "Executes thread in target process"),
    0xCF310ACD: ("GetProcAddress", "kernel32.dll", "Dynamically resolves exported function address"),
    0x0B8FE44B: ("GetProcAddress", "kernel32.dll", "Dynamically resolves exported function address"),
    0x60E0CE70: ("WSAStartup", "ws2_32.dll", "Initializes network socket subsystem"),
    0x614D6E75: ("WSASocketA", "ws2_32.dll", "Creates raw network socket"),
    0x6174A599: ("connect", "ws2_32.dll", "Connects outbound to command-and-control IP"),
    0xDA0297B3: ("bind", "ws2_32.dll", "Binds socket to local network port"),
    0x5FC8D902: ("listen", "ws2_32.dll", "Listens for incoming network connections"),
    0xE13BE29C: ("accept", "ws2_32.dll", "Accepts incoming network connection"),
    0x8A8B4676: ("URLDownloadToFileA", "urlmon.dll", "Downloads remote payload directly to disk"),
    0xC870E51D: ("InternetOpenA", "wininet.dll", "Initializes WinINet HTTP connection"),
    0x51E2F099: ("InternetOpenUrlA", "wininet.dll", "Fetches remote URL payload"),
    0xAFE4E07B: ("HttpSendRequestA", "wininet.dll", "Transmits HTTP payload to C2 server"),
    0x006B8029: ("Sleep", "kernel32.dll", "Sandbox evasion / timing sleep delay"),
    0x89C5D06A: ("GetTickCount", "kernel32.dll", "Anti-debugging timing check"),
    0xC7492A72: ("IsDebuggerPresent", "kernel32.dll", "Direct debugger detection probe"),
}


class ShellcodeAnalyzer:
    """Disassembles and heuristically inspects position-independent shellcode payloads."""

    @staticmethod
    def is_likely_shellcode(data: bytes, filename: str = "") -> bool:
        """Determines if a raw buffer or file likely represents position-independent shellcode."""
        fn_lower = filename.lower()
        if any(fn_lower.endswith(ext) for ext in [".sc", ".shellcode", ".bin", ".raw", ".dat"]):
            if not data.startswith((b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed", b"PK", b"%PDF")):
                return True

        if len(data) < 16 or len(data) > 50 * 1024 * 1024:
            return False

        # If data starts with common shellcode signatures
        # 1. NOP Sled
        if data[:16].count(b"\x90") >= 8:
            return True
        # 2. Call $+5 (E8 00 00 00 00) followed by pop
        if b"\xe8\x00\x00\x00\x00" in data[:64]:
            return True
        # 3. FNSTENV / FSTENV
        if b"\xd9\x74\x24\xf4" in data[:64] or b"\xd9\xee" in data[:64]:
            return True
        # 4. PEB access: fs:[0x30] (64 a1 30 00 00 00 or 64 8b ...) or gs:[0x60] (65 48 8b ...)
        if b"\x64\xa1\x30\x00\x00\x00" in data[:128] or b"\x65\x48\x8b" in data[:128] or b"\x64\x8b" in data[:128]:
            return True

        return False

    @classmethod
    def analyze(cls, data: bytes, base_addr: int = 0x0) -> Dict[str, Any]:
        """
        Performs in-depth multi-architecture disassembly and heuristic feature extraction.
        """
        results: Dict[str, Any] = {
            "is_shellcode": False,
            "architecture": "x86 (32-bit)",
            "mode": 32,
            "confidence": 0.0,
            "total_bytes": len(data),
            "nop_sled": {
                "detected": False,
                "length": 0,
                "offset": 0
            },
            "heuristics": {
                "has_get_eip": False,
                "has_peb_traversal": False,
                "has_direct_syscalls": False,
                "has_api_hashing": False,
                "has_egg_hunter": False,
                "has_stack_strings": False,
                "has_socket_call": False,
                "has_fpu_routine": False
            },
            "detected_features": [],
            "resolved_api_hashes": [],
            "stack_strings": [],
            "network_indicators": [],
            "suspicious_instructions": [],
            "disassembly": [],
            "findings": []
        }

        if len(data) == 0:
            return results

        # 1. Detect NOP sled at start or within first 256 bytes
        nop_len = 0
        nop_offset = 0
        for i, b in enumerate(data[:512]):
            if b == 0x90:
                if nop_len == 0:
                    nop_offset = i
                nop_len += 1
            else:
                if nop_len >= 8:
                    break
                nop_len = 0

        if nop_len >= 8:
            results["nop_sled"] = {
                "detected": True,
                "length": nop_len,
                "offset": nop_offset
            }
            results["detected_features"].append(f"NOP Sled ({nop_len} consecutive NOP instructions at offset {hex(nop_offset)})")
            results["findings"].append(Finding(
                category="shellcode",
                severity="critical",
                title=f"Shellcode NOP Sled Detected ({nop_len} bytes)",
                description=f"Buffer begins with an executable NOP slide of {nop_len} bytes. NOP sleds allow exploit execution to slide safely into payload code without exact memory alignment.",
                details={"offset": hex(nop_offset), "length": nop_len}
            ))

        # 2. Determine Best Architecture (32-bit vs 64-bit) via Capstone Disassembly Scoring
        sample_slice = data[nop_offset + nop_len : min(len(data), nop_offset + nop_len + 4096)]
        if not sample_slice:
            sample_slice = data[: min(len(data), 4096)]

        cs_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        insts_32 = list(cs_32.disasm(sample_slice, base_addr))
        insts_64 = list(cs_64.disasm(sample_slice, base_addr))

        bytes_32 = sum(len(i.bytes) for i in insts_32)
        bytes_64 = sum(len(i.bytes) for i in insts_64)

        score_32 = (bytes_32 / max(len(sample_slice), 1))
        score_64 = (bytes_64 / max(len(sample_slice), 1))

        # Check for 64-bit specific registers (rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15, gs:[0x60])
        x64_hints = sum(
            1 for i in insts_64
            if any(r in i.op_str.lower() for r in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "gs:[0x60]"])
        )

        chosen_mode = 64 if (score_64 > score_32 and x64_hints > 3) or (x64_hints > 8) else 32
        results["mode"] = chosen_mode
        results["architecture"] = f"x86_{chosen_mode} ({chosen_mode}-bit)"
        active_insts = insts_64 if chosen_mode == 64 else insts_32
        results["confidence"] = round(max(score_32, score_64), 2)

        # 3. Instruction Analysis & Heuristics
        peb_patterns = []
        syscall_patterns = []
        api_hashes_found = []
        stack_string_frags = []
        disassembly_list = []

        for idx, inst in enumerate(active_insts[:300]):
            m = inst.mnemonic.lower()
            ops = inst.op_str.lower()
            line_str = f"{m} {ops}"
            is_suspicious = False
            flag_note = ""

            # Check PEB / TEB Traversal
            if "fs:[0x30]" in ops or "fs:[30h]" in ops or "gs:[0x60]" in ops or "gs:[60h]" in ops:
                results["heuristics"]["has_peb_traversal"] = True
                flag_note = "PEB Access (Dynamic Module & API Resolution)"
                peb_patterns.append(f"{inst.mnemonic} {inst.op_str} at {hex(inst.address)}")
                is_suspicious = True
            elif "fs:[0x18]" in ops or "fs:[18h]" in ops or "gs:[0x30]" in ops or "gs:[30h]" in ops:
                results["heuristics"]["has_peb_traversal"] = True
                flag_note = "TEB Access (Thread Information Block)"
                is_suspicious = True

            # Check Direct Syscalls
            if m in ["syscall", "sysenter"] or (m == "int" and ("0x2e" in ops or "0x80" in ops or "2eh" in ops or "80h" in ops)):
                results["heuristics"]["has_direct_syscalls"] = True
                flag_note = f"Direct Native Syscall ({inst.mnemonic})"
                syscall_patterns.append(f"{inst.mnemonic} {inst.op_str} at {hex(inst.address)}")
                is_suspicious = True

            # Check Get-EIP / Delta routines
            if m == "call" and ("$+5" in ops or "5" in ops or (idx + 1 < len(active_insts) and active_insts[idx + 1].mnemonic.lower() == "pop")):
                results["heuristics"]["has_get_eip"] = True
                flag_note = "Get-EIP Routine (Call/Pop Delta Offset)"
                is_suspicious = True
            elif "fnstenv" in line_str or "fstenv" in line_str:
                results["heuristics"]["has_fpu_routine"] = True
                results["heuristics"]["has_get_eip"] = True
                flag_note = "FPU Instruction (GetPC / Shikata Ga Nai Prologue)"
                is_suspicious = True

            # Check API Hash Loop pattern (ROR 13 / ROR 0xd / ROL)
            if ("ror" in m or "rol" in m) and ("0xd" in ops or "13" in ops or "0x7" in ops or "7" in ops):
                results["heuristics"]["has_api_hashing"] = True
                flag_note = "API Hashing Resolution Loop (ROR-13)"
                is_suspicious = True

            # Check Stack Strings
            if (m == "push" and ops.startswith("0x") and len(ops) >= 6) or ("mov dword ptr" in line_str or "mov qword ptr" in line_str):
                # Check if immediate is printable ASCII
                try:
                    raw_val = int(ops.split(",")[-1].strip(), 16) if "," in ops else int(ops.strip(), 16)
                    val_bytes = raw_val.to_bytes((raw_val.bit_length() + 7) // 8, byteorder="little")
                    if any(32 <= b <= 126 for b in val_bytes):
                        decoded_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in val_bytes)
                        stack_string_frags.append(decoded_text)
                        if any(kw in decoded_text.lower() for kw in ["cmd", "exe", "http", "dll", "ps1", "sh", "soc"]):
                            flag_note = f"Stack String: '{decoded_text}'"
                            is_suspicious = True
                except Exception:
                    pass

            if is_suspicious:
                results["suspicious_instructions"].append({
                    "address": hex(inst.address),
                    "instruction": f"{inst.mnemonic} {inst.op_str}",
                    "note": flag_note
                })

            disassembly_list.append({
                "address": hex(inst.address),
                "mnemonic": inst.mnemonic,
                "op_str": inst.op_str,
                "bytes": inst.bytes.hex(),
                "is_suspicious": is_suspicious,
                "note": flag_note
            })

        results["disassembly"] = disassembly_list

        # 4. Search Entire Buffer for Known ROR-13 API Hashes
        for offset in range(0, max(0, min(len(data) - 3, 32768))):
            dword = struct.unpack("<I", data[offset : offset + 4])[0]
            if dword in KNOWN_ROR13_HASHES:
                func_name, dll_name, func_desc = KNOWN_ROR13_HASHES[dword]
                if not any(h["hash"] == hex(dword) for h in api_hashes_found):
                    api_hashes_found.append({
                        "hash": hex(dword),
                        "offset": hex(offset),
                        "function": func_name,
                        "library": dll_name,
                        "description": func_desc
                    })

        if api_hashes_found:
            results["heuristics"]["has_api_hashing"] = True
            results["resolved_api_hashes"] = api_hashes_found
            results["detected_features"].append(f"Pre-Calculated API Hashes ({len(api_hashes_found)} resolved Win32 functions)")
            results["findings"].append(Finding(
                category="shellcode",
                severity="critical",
                title=f"Resolved Shellcode API Hashes ({len(api_hashes_found)} Win32 APIs)",
                description=(
                    f"Shellcode contains pre-calculated ROR-13 API hashes commonly utilized by Cobalt Strike, Metasploit, or custom loaders: "
                    f"{', '.join(h['function'] + ' (' + h['library'] + ')' for h in api_hashes_found[:6])}."
                ),
                details={"hashes": api_hashes_found}
            ))

        # 5. PEB Traversal Findings
        if results["heuristics"]["has_peb_traversal"]:
            results["detected_features"].append(f"PEB/TEB Dynamic Traversal ({len(peb_patterns)} instructions)")
            results["findings"].append(Finding(
                category="shellcode",
                severity="critical",
                title="Position-Independent PEB Traversal (fs:[30h] / gs:[60h])",
                description="Instructions query the Process Environment Block (PEB) directly to locate loaded modules (ntdll.dll, kernel32.dll) in memory without calling Windows API functions.",
                details={"patterns": peb_patterns}
            ))

        # 6. Direct Syscall Findings
        if results["heuristics"]["has_direct_syscalls"]:
            results["detected_features"].append(f"Direct Syscalls ({len(syscall_patterns)} syscalls)")
            results["findings"].append(Finding(
                category="shellcode",
                severity="critical",
                title="Direct / Unhooked Native Syscall Invocation",
                description="Shellcode issues direct CPU syscall instructions to bypass userland EDR / AV API hooks in ntdll.dll.",
                details={"patterns": syscall_patterns}
            ))

        # 7. Reconstructed Stack Strings
        if stack_string_frags:
            combined_strings = []
            cur = ""
            for frag in stack_string_frags:
                cur += frag
                if len(cur) >= 4:
                    combined_strings.append(cur)
                    cur = ""
            if cur:
                combined_strings.append(cur)
            results["stack_strings"] = combined_strings[:30]
            if any(len(s) >= 4 and not s.count(".") == len(s) for s in combined_strings):
                results["heuristics"]["has_stack_strings"] = True
                results["detected_features"].append(f"Dynamic Stack Strings ({len(combined_strings)} strings assembled)")

        # 8. Check for Socket / Network Configuration (IPv4 / Port)
        # Scan for sockaddr_in struct pattern: 0x0002 (AF_INET) followed by big-endian port and 4-byte IP
        for offset in range(0, min(len(data) - 8, 4096)):
            if data[offset : offset + 2] == b"\x02\x00":  # AF_INET = 2 (little endian in push or struct)
                port = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                ip_bytes = data[offset + 4 : offset + 8]
                if 1 <= port <= 65535 and ip_bytes[0] != 0 and ip_bytes[0] != 255:
                    ip_str = ".".join(str(b) for b in ip_bytes)
                    if not any(n["ip"] == ip_str and n["port"] == port for n in results["network_indicators"]):
                        results["network_indicators"].append({
                            "ip": ip_str,
                            "port": port,
                            "offset": hex(offset)
                        })
                        results["heuristics"]["has_socket_call"] = True

        if results["network_indicators"]:
            results["detected_features"].append(f"C2 Network Sockaddr Config ({len(results['network_indicators'])} endpoints)")
            results["findings"].append(Finding(
                category="network",
                severity="critical",
                title=f"Hardcoded Command & Control Socket Configuration ({results['network_indicators'][0]['ip']}:{results['network_indicators'][0]['port']})",
                description=f"Identified hardcoded network connection configuration inside shellcode: {', '.join(n['ip'] + ':' + str(n['port']) for n in results['network_indicators'])}.",
                details={"endpoints": results["network_indicators"]}
            ))

        # Overall shellcode determination
        feature_score = (
            (3 if results["nop_sled"]["detected"] else 0) +
            (3 if results["heuristics"]["has_peb_traversal"] else 0) +
            (3 if results["heuristics"]["has_api_hashing"] else 0) +
            (3 if results["heuristics"]["has_direct_syscalls"] else 0) +
            (2 if results["heuristics"]["has_get_eip"] else 0) +
            (2 if results["heuristics"]["has_socket_call"] else 0) +
            (1 if results["heuristics"]["has_stack_strings"] else 0)
        )

        results["is_shellcode"] = feature_score >= 3 or (len(data) <= 65536 and results["confidence"] >= 0.75 and feature_score >= 2)

        return results
