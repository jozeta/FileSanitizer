import pytest
from pathlib import Path
from typing import Dict, Any

from app.analyzers.executable_analyzer import ExecutableAnalyzer
from app.analyzers.pe_forensics import (
    calculate_shannon_entropy,
    format_hex_preview,
    classify_pe_overlay,
    inspect_dll_forensics,
    inspect_dotnet_assembly,
    inspect_pe_vulnerabilities_and_legacy_crt,
    correlate_pe_capabilities,
    calculate_pe_verdict
)


def _build_minimal_pe_bytes(
    is_dll: bool = False,
    is_64bit: bool = False,
    extra_sections: list = None,
    dll_char_flags: int = 0x8140, # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    overlay_bytes: bytes = b""
) -> bytes:
    """Helper to synthesize a structurally valid PE binary."""
    # DOS Header (64 bytes)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew = 0x80

    # DOS Stub padding up to 0x80
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos_full = (bytes(dos) + dos_stub).ljust(0x80, b"\x00")

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    machine = 0x8664 if is_64bit else 0x014C
    sections_count = 2 + (len(extra_sections) if extra_sections else 0)
    opt_size = 0xF0 if is_64bit else 0xE0
    characteristics = 0x0002 | (0x2000 if is_dll else 0)  # EXECUTABLE_IMAGE | DLL

    file_header = bytearray(20)
    file_header[0:2] = machine.to_bytes(2, "little")
    file_header[2:4] = sections_count.to_bytes(2, "little")
    file_header[4:8] = (1700000000).to_bytes(4, "little")  # Timestamp
    file_header[16:18] = opt_size.to_bytes(2, "little")
    file_header[18:20] = characteristics.to_bytes(2, "little")

    # Optional Header
    opt_header = bytearray(opt_size)
    magic = 0x020B if is_64bit else 0x010B
    opt_header[0:2] = magic.to_bytes(2, "little")
    opt_header[16:20] = (0x1000).to_bytes(4, "little")  # AddressOfEntryPoint
    opt_header[28:32] = (0x00400000).to_bytes(4, "little") if not is_64bit else (0x0000000140000000).to_bytes(8, "little") # ImageBase
    opt_header[32:36] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    opt_header[36:40] = (0x0200).to_bytes(4, "little")  # FileAlignment
    opt_header[56:60] = (0x4000).to_bytes(4, "little")  # SizeOfImage
    opt_header[60:64] = (0x0400).to_bytes(4, "little")  # SizeOfHeaders
    opt_header[68:70] = (2).to_bytes(2, "little")       # Subsystem: Windows GUI
    opt_header[70:72] = dll_char_flags.to_bytes(2, "little")  # DllCharacteristics
    opt_header[92:96] = (16).to_bytes(4, "little")      # NumberOfRvaAndSizes

    # Section 1: .text (W+X for testing or normal RX)
    sec1 = bytearray(40)
    sec1[0:8] = b".text\x00\x00\x00"
    sec1[8:12] = (0x0200).to_bytes(4, "little")  # VirtualSize
    sec1[12:16] = (0x1000).to_bytes(4, "little") # VirtualAddress
    sec1[16:20] = (0x0200).to_bytes(4, "little") # SizeOfRawData
    sec1[20:24] = (0x0400).to_bytes(4, "little") # PointerToRawData
    sec1[36:40] = (0x60000020).to_bytes(4, "little") # CODE | EXECUTE | READ

    # Section 2: .data
    sec2 = bytearray(40)
    sec2[0:8] = b".data\x00\x00\x00"
    sec2[8:12] = (0x0200).to_bytes(4, "little")  # VirtualSize
    sec2[12:16] = (0x2000).to_bytes(4, "little") # VirtualAddress
    sec2[16:20] = (0x0200).to_bytes(4, "little") # SizeOfRawData
    sec2[20:24] = (0x0600).to_bytes(4, "little") # PointerToRawData
    sec2[36:40] = (0xC0000040).to_bytes(4, "little") # INITIALIZED_DATA | READ | WRITE

    # Combine headers up to 0x400
    headers = dos_full + pe_sig + bytes(file_header) + bytes(opt_header) + bytes(sec1) + bytes(sec2)
    headers_padded = headers.ljust(0x400, b"\x00")

    # Section 1 data (512 bytes)
    sec1_data = (
        b"\x90\x90\xcc" +
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00" +
        b"strcpy\x00sprintf\x00gets\x00" +
        b"cmd.exe /c powershell.exe -ExecutionPolicy Bypass\x00"
    ).ljust(0x200, b"\x90")

    # Section 2 data (512 bytes)
    sec2_data = (
        b"Hello PE World\x00" +
        b"v4.0.30319\x00.NETFramework,Version=v4.8\x00" +
        b"Assembly.Load\x00Process.Start\x00WebClient\x00"
    ).ljust(0x200, b"\x00")

    return headers_padded + sec1_data + sec2_data + overlay_bytes


def test_shannon_entropy_and_hex_preview():
    """Verify Shannon entropy computation and hex dump formatting."""
    zero_bytes = b"\x00" * 100
    assert calculate_shannon_entropy(zero_bytes) == 0.0

    high_ent_bytes = bytes([i % 256 for i in range(1024)])
    ent = calculate_shannon_entropy(high_ent_bytes)
    assert ent >= 7.9

    preview = format_hex_preview(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00PE-HEADER-TEST", max_len=32)
    assert "0000" in preview
    assert "4d 5a" in preview.lower()
    assert "|MZ" in preview


def test_overlay_classification():
    """Verify detection and classification of trailing overlay payloads."""
    # Embedded PE Dropper overlay
    pe_overlay = b"MZ\x90\x00" + b"\x41" * 300
    ov_res = classify_pe_overlay(pe_overlay)
    assert ov_res["has_overlay"] is True
    assert "Embedded Windows PE Binary" in ov_res["classified_type"]
    assert ov_res["size"] == len(pe_overlay)
    assert len(ov_res["hex_preview"]) > 0

    # High entropy encrypted blob overlay
    high_ent = bytes([((x * 37) % 256) for x in range(1024)])
    ov_high = classify_pe_overlay(high_ent)
    assert "Encrypted or High-Entropy" in ov_high["classified_type"]


def test_dll_forensics_and_sideloading():
    """Verify DLL inspection, proxy DLL forwarders, and sideloading target detection."""
    # Test sideloading target matching
    dll_forensics = inspect_dll_forensics(None, b"", "version.dll")
    assert dll_forensics["sideloading_risk"]["is_common_target_dll"] is True
    assert dll_forensics["sideloading_risk"]["target_match_name"] == "version.dll"
    assert dll_forensics["sideloading_risk"]["risk_level"] in ["CRITICAL", "HIGH"]
    assert "Discord" in dll_forensics["sideloading_risk"]["common_host_processes"]

    # Test non-target DLL
    normal_dll = inspect_dll_forensics(None, b"", "custom_application_helper.dll")
    assert normal_dll["sideloading_risk"]["is_common_target_dll"] is False
    assert normal_dll["sideloading_risk"]["risk_level"] == "LOW"


def test_dotnet_assembly_forensics():
    """Verify .NET CLR runtime detection, P/Invoke, and obfuscator markers."""
    dotnet_bytes = (
        b"Some binary padding" +
        b"v4.0.30319\x00.NETFramework,Version=v4.7.2\x00" +
        b"Assembly.Load\x00Process.Start\x00Confuser.Core\x00" +
        b"_CorExeMain\x00mscoree.dll\x00"
    )

    dn_res = inspect_dotnet_assembly(None, dotnet_bytes)
    assert dn_res["is_dotnet"] is True
    assert "v4.0.30319" in dn_res["runtime_version"]
    assert ".NET Framework 4.7.2" in dn_res["target_framework"]
    assert "ConfuserEx Obfuscator" in dn_res["detected_obfuscators"]

    api_names = [f["api"] for f in dn_res["suspicious_features"]]
    assert "Assembly.Load" in api_names
    assert "Process.Start" in api_names


def test_pe_vulnerabilities_and_legacy_crt():
    """Verify detection of memory-unsafe CRT functions and W+X sections."""
    imports_mock = {
        "msvcrt.dll": [
            {"name": "strcpy"},
            {"name": "sprintf"},
            {"name": "gets"},
            {"name": "strlen"}
        ],
        "kernel32.dll": [
            {"name": "ExitProcess"}
        ]
    }
    sections_mock = [
        {"name": ".text", "is_wx": False},
        {"name": ".rwx", "is_wx": True}  # W+X section!
    ]

    vulns = inspect_pe_vulnerabilities_and_legacy_crt(None, imports_mock, sections_mock)
    assert vulns["has_wx_sections"] is True
    assert ".rwx" in vulns["wx_sections"]
    assert len(vulns["legacy_crt_apis"]) == 3  # strcpy, sprintf, gets

    cwe_list = [v["cwe"] for v in vulns["legacy_crt_apis"]]
    assert "CWE-120" in cwe_list
    assert "CWE-242" in cwe_list  # gets
    assert vulns["risk_score"] > 50


def test_correlate_pe_capabilities():
    """Verify ATT&CK-aligned capability correlation from imports and strings."""
    imports_mock = {
        "kernel32.dll": [
            {"name": "VirtualAllocEx"},
            {"name": "WriteProcessMemory"},
            {"name": "CreateRemoteThread"},
            {"name": "IsDebuggerPresent"},
            {"name": "GetProcAddress"}
        ],
        "wininet.dll": [
            {"name": "InternetOpenA"},
            {"name": "HttpSendRequestA"}
        ]
    }
    raw_str = "cmd.exe /c start powershell.exe -ExecutionPolicy Bypass VBoxGuest"

    caps = correlate_pe_capabilities(imports_mock, {}, [], raw_str)
    cap_ids = [c["id"] for c in caps]

    # Process Injection
    assert "CAP_PROCESS_INJECTION" in cap_ids
    inj = [c for c in caps if c["id"] == "CAP_PROCESS_INJECTION"][0]
    assert inj["severity"] == "CRITICAL"
    assert inj["mitre_attack"] == "T1055"
    assert "VirtualAllocEx" in inj["evidence"]

    # Command Execution
    assert "CAP_COMMAND_EXECUTION" in cap_ids

    # Defense Evasion / Anti-Debugging
    assert "CAP_DEFENSE_EVASION" in cap_ids

    # Network C2
    assert "CAP_NETWORK_C2" in cap_ids


def test_calculate_pe_verdict():
    """Verify synthesis of executive verdict model and containment advice."""
    caps_crit = [
        {
            "id": "CAP_PROCESS_INJECTION",
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "mitre_attack": "T1055",
            "severity": "CRITICAL"
        }
    ]
    vulns = {"vulnerability_count": 2, "has_wx_sections": True, "wx_sections": [".rwx"]}
    data_mock = {"is_packed": True, "authenticode": {"is_signed": False}}

    verdict_info = calculate_pe_verdict(data_mock, [], caps_crit, vulns)
    assert verdict_info["verdict"] == "Malicious"
    assert verdict_info["severity"] == "critical"
    assert verdict_info["confidence_score"] >= 90
    assert len(verdict_info["containment_recommendations"]) > 0
    assert any("Quarantine" in r for r in verdict_info["containment_recommendations"])


def test_full_executable_pe_pipeline(tmp_path: Path):
    """End-to-end integration test with ExecutableAnalyzer on synthesized PE binary."""
    overlay_payload = b"MZ\x90\x00AppendedDropperExecutable" + (b"\x90" * 300)
    pe_bytes = _build_minimal_pe_bytes(
        is_dll=False,
        is_64bit=False,
        overlay_bytes=overlay_payload
    )

    sample_pe = tmp_path / "threat_sample.exe"
    sample_pe.write_bytes(pe_bytes)

    analyzer = ExecutableAnalyzer()
    res = analyzer.analyze(sample_pe, "threat_sample.exe", "application/x-dosexec")
    assert res.success is True
    data = res.data

    # Verify PE checklist fields
    assert "pe_verdict" in data
    assert data["pe_verdict"]["verdict"] in ["Malicious", "Suspicious", "Potentially Vulnerable", "No Known Threat Detected", "Inconclusive"]
    assert "pe_capabilities" in data
    assert "dll_forensics" in data
    assert "dotnet_assembly" in data
    assert "pe_vulnerabilities" in data
    assert "overlay_forensics" in data
    assert data["overlay_forensics"]["has_overlay"] is True
    assert "Embedded Windows PE" in data["overlay_forensics"]["classified_type"]

    # Verify findings were emitted
    finding_titles = [f.title for f in res.findings]
    assert any("Overlay" in t for t in finding_titles)
