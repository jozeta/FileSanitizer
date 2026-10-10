"""
API Hashing & Dynamic Resolution Detection Engine for FileSanitizer.

Detects API hashing techniques commonly employed by malware loaders, droppers,
Cobalt Strike beacons, and shellcode (MITRE ATT&CK T1027.007: Dynamic API Resolution).
Reconstructs hidden Win32/Native APIs from precomputed 32-bit hash constants
(ROR13, CRC32, FNV-1a, MurmurHash3, SDBM, DJB2).
"""

import re
import zlib
from typing import Dict, Any, List, Optional, Set, Tuple


def _ror13(s: str) -> int:
    """Standard ROR13 hash (Metasploit / Cobalt Strike / Carberp convention)."""
    h = 0
    for ch in s:
        h = ((h >> 13) | ((h << (32 - 13)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + ord(ch)) & 0xFFFFFFFF
    return h


def _ror13_with_null(s: str) -> int:
    """ROR13 including trailing null terminator."""
    h = 0
    for ch in s + "\0":
        h = ((h >> 13) | ((h << (32 - 13)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + ord(ch)) & 0xFFFFFFFF
    return h


def _crc32(s: str) -> int:
    """POSIX / Win32 standard CRC32."""
    return zlib.crc32(s.encode("latin1", errors="ignore")) & 0xFFFFFFFF


def _fnv1a_32(s: str) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for b in s.encode("latin1", errors="ignore"):
        h = (h ^ b) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _sdbm(s: str) -> int:
    """SDBM hash algorithm."""
    h = 0
    for ch in s:
        h = (ord(ch) + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def _djb2(s: str) -> int:
    """DJB2 hash algorithm."""
    h = 5381
    for ch in s:
        h = (((h << 5) + h) + ord(ch)) & 0xFFFFFFFF
    return h


def _murmur3_32(key: str, seed: int = 0) -> int:
    """MurmurHash3 32-bit implementation."""
    data = bytearray(key.encode("latin1", errors="ignore"))
    length = len(data)
    nblocks = length // 4
    h1 = seed

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        idx = i * 4
        k1 = data[idx] | (data[idx + 1] << 8) | (data[idx + 2] << 16) | (data[idx + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> (32 - 15))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> (32 - 13))) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

    tail_idx = nblocks * 4
    k1 = 0
    rem = length & 3
    if rem >= 3:
        k1 ^= data[tail_idx + 2] << 16
    if rem >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if rem >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> (32 - 15))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    return h1 & 0xFFFFFFFF


# Comprehensive Win32 & Native API Catalog for API Hashing Resolution
CRITICAL_APIS: List[Dict[str, str]] = [
    # Memory Allocation & RWX Permissions (Shellcode Staging)
    {"dll": "kernel32.dll", "api": "VirtualAlloc", "category": "Memory Management", "severity": "high", "description": "Allocates virtual memory page (common for shellcode payload staging)"},
    {"dll": "kernel32.dll", "api": "VirtualAllocEx", "category": "Process Injection", "severity": "critical", "description": "Allocates memory within a remote process address space"},
    {"dll": "kernel32.dll", "api": "VirtualProtect", "category": "Memory Management", "severity": "high", "description": "Modifies memory page protection rights (e.g. PAGE_EXECUTE_READWRITE)"},
    {"dll": "kernel32.dll", "api": "VirtualProtectEx", "category": "Process Injection", "severity": "critical", "description": "Modifies memory protection in target remote process"},
    {"dll": "kernel32.dll", "api": "WriteProcessMemory", "category": "Process Injection", "severity": "critical", "description": "Writes code/payload into remote target process"},
    {"dll": "kernel32.dll", "api": "ReadProcessMemory", "category": "Credential Dumping", "severity": "high", "description": "Reads raw memory from target process (e.g. LSASS dumping)"},
    {"dll": "ntdll.dll", "api": "NtAllocateVirtualMemory", "category": "Native API", "severity": "high", "description": "Low-level system call allocating virtual memory pages"},
    {"dll": "ntdll.dll", "api": "NtProtectVirtualMemory", "category": "Native API", "severity": "high", "description": "Low-level system call modifying virtual memory protection"},
    {"dll": "ntdll.dll", "api": "NtWriteVirtualMemory", "category": "Process Injection", "severity": "critical", "description": "Low-level system call writing memory into another process"},
    {"dll": "ntdll.dll", "api": "NtMapViewOfSection", "category": "Process Hollowing", "severity": "critical", "description": "Maps a section view for process hollowing or DLL unhooking"},
    {"dll": "ntdll.dll", "api": "NtUnmapViewOfSection", "category": "Process Hollowing", "severity": "critical", "description": "Unmaps original executable code section during process hollowing"},

    # Execution & Process/Thread Injection
    {"dll": "kernel32.dll", "api": "CreateProcessA", "category": "Process Spawning", "severity": "medium", "description": "Launches child executable process"},
    {"dll": "kernel32.dll", "api": "CreateProcessW", "category": "Process Spawning", "severity": "medium", "description": "Launches child executable process (Unicode)"},
    {"dll": "kernel32.dll", "api": "CreateRemoteThread", "category": "Process Injection", "severity": "critical", "description": "Executes injected code thread in remote process (MITRE T1055)"},
    {"dll": "kernel32.dll", "api": "QueueUserAPC", "category": "Early Bird Injection", "severity": "critical", "description": "Queues asynchronous procedure call (APC injection)"},
    {"dll": "ntdll.dll", "api": "NtQueueApcThread", "category": "APC Injection", "severity": "critical", "description": "Native syscall queuing an APC thread callback"},
    {"dll": "ntdll.dll", "api": "NtCreateThreadEx", "category": "Process Injection", "severity": "critical", "description": "Undocumented native API spawning a remote thread"},
    {"dll": "kernel32.dll", "api": "SetThreadContext", "category": "Thread Hijacking", "severity": "critical", "description": "Alters register state/EIP/RIP of existing thread"},
    {"dll": "kernel32.dll", "api": "GetThreadContext", "category": "Thread Hijacking", "severity": "high", "description": "Inspects CPU register state of thread"},
    {"dll": "kernel32.dll", "api": "ResumeThread", "category": "Process Injection", "severity": "medium", "description": "Resumes suspended thread execution"},
    {"dll": "kernel32.dll", "api": "OpenProcess", "category": "Process Access", "severity": "medium", "description": "Acquires process handle with access rights"},
    {"dll": "kernel32.dll", "api": "WinExec", "category": "Execution", "severity": "high", "description": "Legacy process execution function commonly used by droppers"},

    # Dynamic Linking & Module Loading (PEB Walkers)
    {"dll": "kernel32.dll", "api": "LoadLibraryA", "category": "Dynamic Resolution", "severity": "medium", "description": "Dynamically loads an external DLL into process memory"},
    {"dll": "kernel32.dll", "api": "LoadLibraryW", "category": "Dynamic Resolution", "severity": "medium", "description": "Dynamically loads an external DLL (Unicode)"},
    {"dll": "kernel32.dll", "api": "GetProcAddress", "category": "Dynamic Resolution", "severity": "medium", "description": "Retrieves the memory address of an exported function"},
    {"dll": "kernel32.dll", "api": "GetModuleHandleA", "category": "Dynamic Resolution", "severity": "low", "description": "Retrieves module handle for loaded dynamic link library"},
    {"dll": "kernel32.dll", "api": "GetModuleHandleW", "category": "Dynamic Resolution", "severity": "low", "description": "Retrieves module handle (Unicode)"},
    {"dll": "ntdll.dll", "api": "LdrLoadDll", "category": "Native Dynamic Linking", "severity": "high", "description": "Native loader routine loading dynamic link library without Win32 hooks"},
    {"dll": "ntdll.dll", "api": "LdrGetProcedureAddress", "category": "Native Dynamic Linking", "severity": "high", "description": "Native loader routine resolving exported function pointer"},

    # Anti-Debugging & Defense Evasion
    {"dll": "kernel32.dll", "api": "IsDebuggerPresent", "category": "Anti-Debugging", "severity": "high", "description": "Checks PEB BeingDebugged flag"},
    {"dll": "kernel32.dll", "api": "CheckRemoteDebuggerPresent", "category": "Anti-Debugging", "severity": "high", "description": "Queries ProcessDebugPort of active process"},
    {"dll": "ntdll.dll", "api": "NtQueryInformationProcess", "category": "Anti-Debugging", "severity": "high", "description": "Queries process debug flags or process parameters"},
    {"dll": "ntdll.dll", "api": "NtSetInformationThread", "category": "Anti-Debugging", "severity": "high", "description": "Hides thread from debugger (ThreadHideFromDebugger 0x11)"},
    {"dll": "kernel32.dll", "api": "OutputDebugStringA", "category": "Anti-Debugging", "severity": "medium", "description": "Emits debugger string or detects debugger presence via GetLastError"},

    # Network, C2 & Droppers
    {"dll": "wininet.dll", "api": "InternetOpenA", "category": "C2 Communication", "severity": "high", "description": "Initializes WinINet HTTP/FTP session"},
    {"dll": "wininet.dll", "api": "InternetOpenUrlA", "category": "C2 Communication", "severity": "high", "description": "Opens remote HTTP URL resource for download"},
    {"dll": "wininet.dll", "api": "HttpOpenRequestA", "category": "C2 Communication", "severity": "high", "description": "Creates an HTTP request handle for C2 beaconing"},
    {"dll": "wininet.dll", "api": "HttpSendRequestA", "category": "C2 Communication", "severity": "high", "description": "Transmits HTTP payload to remote command-and-control server"},
    {"dll": "urlmon.dll", "api": "URLDownloadToFileA", "category": "Payload Downloader", "severity": "critical", "description": "Downloads remote file directly to disk"},
    {"dll": "urlmon.dll", "api": "URLDownloadToFileW", "category": "Payload Downloader", "severity": "critical", "description": "Downloads remote file directly to disk (Unicode)"},
    {"dll": "ws2_32.dll", "api": "WSAStartup", "category": "Network Socket", "severity": "medium", "description": "Initializes Windows Sockets network subsystem"},
    {"dll": "ws2_32.dll", "api": "connect", "category": "Network Socket", "severity": "high", "description": "Establishes socket connection to remote host/port"},
    {"dll": "ws2_32.dll", "api": "send", "category": "Network Socket", "severity": "high", "description": "Transmits bytes over raw TCP socket"},
    {"dll": "ws2_32.dll", "api": "recv", "category": "Network Socket", "severity": "high", "description": "Receives bytes from raw TCP socket"},

    # Persistence & Registry
    {"dll": "advapi32.dll", "api": "RegOpenKeyExA", "category": "Persistence", "severity": "medium", "description": "Opens Windows Registry hive key"},
    {"dll": "advapi32.dll", "api": "RegSetValueExA", "category": "Persistence", "severity": "high", "description": "Sets Registry value (e.g. Run/RunOnce autostart keys)"},
    {"dll": "kernel32.dll", "api": "CreateFileA", "category": "File I/O", "severity": "low", "description": "Creates or opens file or device"},
    {"dll": "kernel32.dll", "api": "WriteFile", "category": "File I/O", "severity": "low", "description": "Writes data stream to file handle"},
]


class ApiHashingDetector:
    """
    Engine that identifies and resolves API hash constants in binary disassembly or raw bytes.
    """

    # Precomputed table: hash_int -> list of matches
    _HASH_DATABASE: Dict[int, List[Dict[str, Any]]] = {}
    _INITIALIZED = False

    @classmethod
    def _init_database(cls):
        if cls._INITIALIZED:
            return

        db: Dict[int, List[Dict[str, Any]]] = {}

        def _add(h_val: int, algo: str, api_meta: Dict[str, str]):
            if h_val <= 0xFF:  # Ignore trivial low byte numbers
                return
            if h_val not in db:
                db[h_val] = []
            db[h_val].append({
                "api": api_meta["api"],
                "dll": api_meta["dll"],
                "algorithm": algo,
                "category": api_meta["category"],
                "severity": api_meta["severity"],
                "description": api_meta["description"],
                "hash_hex": f"0x{h_val:08x}"
            })

        for item in CRITICAL_APIS:
            name = item["api"]
            dll = item["dll"].replace(".dll", "").upper()

            # 1. ROR13 standard
            _add(_ror13(name), "ROR13", item)
            _add(_ror13_with_null(name), "ROR13_NULL", item)
            # ROR13 with DLL prefix (Metasploit convention: DLL!API or DLL+API)
            _add((_ror13(dll) + _ror13(name)) & 0xFFFFFFFF, "ROR13_MOD_API", item)

            # 2. CRC32
            _add(_crc32(name), "CRC32", item)
            _add(_crc32(name.lower()), "CRC32_LOWER", item)

            # 3. FNV-1a
            _add(_fnv1a_32(name), "FNV-1a", item)
            _add(_fnv1a_32(name.lower()), "FNV-1a_LOWER", item)

            # 4. MurmurHash3
            _add(_murmur3_32(name), "MurmurHash3", item)

            # 5. SDBM
            _add(_sdbm(name), "SDBM", item)

            # 6. DJB2
            _add(_djb2(name), "DJB2", item)

        cls._HASH_DATABASE = db
        cls._INITIALIZED = True

    @classmethod
    def get_known_hashes_count(cls) -> int:
        cls._init_database()
        return len(cls._HASH_DATABASE)

    @classmethod
    def resolve_hash(cls, hash_val: int) -> Optional[List[Dict[str, Any]]]:
        """Looks up a 32-bit integer in the hash database."""
        cls._init_database()
        return cls._HASH_DATABASE.get(hash_val & 0xFFFFFFFF)

    @classmethod
    def scan_instructions(
        cls, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Scans disassembly instructions for immediate values matching known API hashes.
        """
        cls._init_database()
        results: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str, str]] = set()

        # Regex for hexadecimal immediate constants: e.g. 0x91afca54, 0xec0e4e8e
        hex_regex = re.compile(r"0x([0-9a-fA-F]{5,8})\b")

        for inst in instructions:
            addr = inst.get("address", "")
            mnem = inst.get("mnemonic", "").lower()
            op_str = inst.get("op_str", "")

            # Look for hex constants in operands
            matches = hex_regex.findall(op_str)
            for m in matches:
                try:
                    val = int(m, 16)
                    matched_apis = cls.resolve_hash(val)
                    if matched_apis:
                        for entry in matched_apis:
                            key = (addr, entry["api"], entry["algorithm"])
                            if key not in seen_keys:
                                seen_keys.add(key)
                                results.append({
                                    "address": addr,
                                    "instruction": f"{mnem} {op_str}",
                                    "hash_hex": f"0x{val:08x}",
                                    "resolved_api": entry["api"],
                                    "dll": entry["dll"],
                                    "algorithm": entry["algorithm"],
                                    "category": entry["category"],
                                    "severity": entry["severity"],
                                    "description": entry["description"],
                                    "mitre_tactic": "T1027.007 (Dynamic API Resolution)",
                                    "confidence": "High (Cryptographic Hash Match)"
                                })
                except ValueError:
                    continue

        return results

    @classmethod
    def scan_raw_bytes(cls, raw_bytes: bytes, max_scan_len: int = 524288) -> List[Dict[str, Any]]:
        """
        Scans raw buffer for 4-byte little-endian integers that match API hashes.
        """
        import struct

        cls._init_database()
        results: List[Dict[str, Any]] = []
        seen_hashes = set()
        scan_len = min(len(raw_bytes), max_scan_len)

        for i in range(0, scan_len - 4, 4):
            val = struct.unpack_from("<I", raw_bytes, i)[0]
            if val in cls._HASH_DATABASE and val not in seen_hashes:
                seen_hashes.add(val)
                matches = cls._HASH_DATABASE[val]
                for entry in matches:
                    results.append({
                        "offset": f"0x{i:08x}",
                        "hash_hex": f"0x{val:08x}",
                        "resolved_api": entry["api"],
                        "dll": entry["dll"],
                        "algorithm": entry["algorithm"],
                        "category": entry["category"],
                        "severity": entry["severity"],
                        "description": entry["description"],
                        "mitre_tactic": "T1027.007 (Dynamic API Resolution)",
                        "confidence": "High (Binary Literal Match)"
                    })

        return results
