"""
Unit tests for Advanced Reverse Engineering & Forensic Capabilities:
- Cross-References (XREFs) System
- Interactive Function Call Graph Engine
- API Hashing & Dynamic Resolution Detection Engine
- Unified Super-Timeline with Timestomping Anomaly Detection
"""

import pytest
from datetime import datetime, timezone
from app.analyzers.api_hashing_detector import ApiHashingDetector, _ror13, _crc32, _fnv1a_32
from app.analyzers.xref_engine import XrefEngine
from app.analyzers.call_graph_engine import CallGraphEngine
from app.analyzers.forensic_timeline import ForensicTimelineBuilder


def test_api_hashing_detector_algorithms():
    """Verify hash calculation and API lookup across algorithms."""
    # Test ROR13
    va_ror13 = _ror13("VirtualAlloc")
    assert va_ror13 == 0x91afca54
    resolved = ApiHashingDetector.resolve_hash(va_ror13)
    assert resolved is not None
    assert any(r["api"] == "VirtualAlloc" and r["algorithm"] == "ROR13" for r in resolved)

    # Test CRC32
    crt_crc = _crc32("CreateRemoteThread")
    resolved_crc = ApiHashingDetector.resolve_hash(crt_crc)
    assert resolved_crc is not None
    assert any(r["api"] == "CreateRemoteThread" and r["algorithm"] == "CRC32" for r in resolved_crc)

    # Test instruction scanning
    sample_instructions = [
        {"address": "0x401010", "mnemonic": "push", "op_str": "0x91afca54", "bytes": "68 54 ca af 91"},
        {"address": "0x401015", "mnemonic": "call", "op_str": "resolve_api_stub", "bytes": "e8 40 00 00 00"},
        {"address": "0x40101a", "mnemonic": "mov", "op_str": "edx, 0x160d6838", "bytes": "ba 38 68 0d 16"},
    ]
    matches = ApiHashingDetector.scan_instructions(sample_instructions)
    assert len(matches) >= 1
    assert matches[0]["resolved_api"] == "VirtualAlloc"
    assert matches[0]["mitre_tactic"] == "T1027.007 (Dynamic API Resolution)"


def test_xref_engine_bidirectional():
    """Verify code and data cross-references are constructed correctly."""
    instructions = [
        {"address": "0x401000", "mnemonic": "sub", "op_str": "rsp, 0x28", "bytes": "48 83 ec 28"},
        {"address": "0x401004", "mnemonic": "lea", "op_str": "rdx, [0x403000]", "bytes": "48 8d 15 f5 1f 00 00"},
        {"address": "0x40100b", "mnemonic": "call", "op_str": "sub_401050", "bytes": "e8 40 00 00 00"},
        {"address": "0x401010", "mnemonic": "test", "op_str": "eax, eax", "bytes": "85 c0"},
        {"address": "0x401012", "mnemonic": "je", "op_str": "0x401030", "bytes": "74 1c"},
        {"address": "0x401030", "mnemonic": "ret", "op_str": "", "bytes": "c3"},
        # Target function
        {"address": "0x401050", "mnemonic": "push", "op_str": "rbp", "bytes": "55"},
        {"address": "0x401051", "mnemonic": "call", "op_str": "VirtualAlloc", "bytes": "ff 15 00 20 00 00"},
        {"address": "0x401057", "mnemonic": "ret", "op_str": "", "bytes": "c3"},
    ]
    known_strings = [{"offset": "0x403000", "value": "powershell.exe -enc AAAA"}]
    imported_apis = [{"name": "VirtualAlloc"}]

    xrefs = XrefEngine.generate_xrefs(
        instructions=instructions,
        entry_point="0x401000",
        known_strings=known_strings,
        imported_apis=imported_apis
    )

    assert xrefs["total_xrefs"] > 0
    assert xrefs["code_xrefs_count"] >= 2  # call sub_401050 + je 0x401030
    assert xrefs["string_xrefs_count"] >= 1  # powershell.exe

    target_map = xrefs["target_to_xrefs"]
    assert "sub_401050" in target_map or "0x401050" in target_map
    assert "virtualalloc" in target_map


def test_call_graph_engine_topology():
    """Verify directed call graph nodes, edges, risk scoring, and dynamic hashing nodes."""
    instructions = [
        {"address": "0x401000", "mnemonic": "call", "op_str": "sub_401050"},
        {"address": "0x401005", "mnemonic": "call", "op_str": "CreateRemoteThread"},
        {"address": "0x401050", "mnemonic": "push", "op_str": "rbp"},
        {"address": "0x401055", "mnemonic": "call", "op_str": "VirtualAlloc"},
    ]
    imported_apis = [{"name": "CreateRemoteThread"}, {"name": "VirtualAlloc"}]
    api_hashing_matches = [{
        "address": "0x401020",
        "resolved_api": "WriteProcessMemory",
        "algorithm": "ROR13",
        "hash_hex": "0xec0e4e8e",
        "severity": "critical"
    }]

    cg = CallGraphEngine.generate_call_graph(
        instructions=instructions,
        entry_point="0x401000",
        imported_apis=imported_apis,
        api_hashing_matches=api_hashing_matches
    )

    assert len(cg["nodes"]) >= 4
    assert len(cg["edges"]) >= 3
    node_labels = {n["label"] for n in cg["nodes"]}
    assert "entry_point" in node_labels
    assert "CreateRemoteThread" in node_labels
    assert any("WriteProcessMemory" in l for l in node_labels)
    assert cg["metrics"]["high_risk_nodes_count"] >= 2


def test_unified_super_timeline_and_timestomping():
    """Verify super-timeline merging and deep timestomping anomaly detectors."""
    class MockJob:
        def __init__(self, filename, created_at, binary_info=None, evtx_info=None, pcap_info=None):
            self.job_id = f"job_{filename}"
            self.filename = filename
            self.created_at = created_at
            self.hashes = {"sha256": "abcdef123456"}
            self.binary_info = binary_info
            self.evtx_info = evtx_info
            self.pcap_info = pcap_info
            self.metadata = None
            self.findings = []

    # 1. Job with Delphi Epoch (1992-06-19 22:22:17)
    job1 = MockJob(
        filename="delphi_dropper.exe",
        created_at="2026-03-15T12:00:00Z",
        binary_info={
            "compiler": "Borland Delphi",
            "file_header": {
                "timestamp": "1992-06-19 22:22:17",
                "time_date_stamp_raw": 0x2A25C7B9,
                "machine": "x86"
            }
        }
    )

    # 2. Job with EVTX containing log clearing (Event 1102) & Process creation (Event 4688)
    job2 = MockJob(
        filename="incident_security.evtx",
        created_at="2026-03-15T12:01:00Z",
        evtx_info={
            "events": [
                {
                    "event_id": 4688,
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "timestamp": "2026-03-15T11:45:00Z",
                    "computer": "DC01.CORP",
                    "user": "Administrator",
                    "new_process_name": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c wevtutil cl Security"
                },
                {
                    "event_id": 1102,
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "timestamp": "2026-03-15T11:45:05Z",
                    "computer": "DC01.CORP",
                    "user": "Administrator",
                    "description": "The audit log was cleared"
                }
            ]
        }
    )

    # 3. Job with Future timestamp (year 2035)
    job3 = MockJob(
        filename="future_compiled.exe",
        created_at="2026-03-15T12:02:00Z",
        binary_info={
            "file_header": {
                "timestamp": "2035-08-01 10:00:00",
                "time_date_stamp_raw": 2070000000,
                "machine": "x64"
            }
        }
    )

    res = ForensicTimelineBuilder.generate_super_timeline([job1, job2, job3])

    assert res["total_events"] >= 6
    assert res["anomalies_count"] >= 3  # Delphi epoch, EVTX log clear, Future compile time

    event_types = {e["event_type"] for e in res["events"]}
    assert "TIMESTOMPING_DELPHI_EPOCH" in event_types
    assert "EVTX_AUDIT_LOG_CLEARED" in event_types
    assert "TIMESTOMPING_FUTURE_TIMESTAMP" in event_types
    assert "EVTX_PROCESS_CREATION" in event_types

    assert res["timestomping_report"]["detected"] is True
    assert res["timestomping_report"]["risk_rating"] == "CRITICAL"
