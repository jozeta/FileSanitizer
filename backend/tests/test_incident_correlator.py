import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.job_manager import job_manager
from app.core.incident_correlator import IncidentCorrelator

client = TestClient(app)

def test_correlate_invalid_jobs():
    res = client.post("/api/jobs/correlate", json={"job_ids": ["non_existent_1", "non_existent_2"]})
    assert res.status_code == 400
    assert "No valid jobs" in res.json().get("detail", "")

def test_correlate_synthetic_jobs():
    # Create two synthetic jobs
    job1 = job_manager.create_job(b"MZtestbinary1", "sample_dropper.exe")
    job1.category = "executable"
    job1.extracted_code = "https://c2.evil-corp.cc/beacon 198.51.100.44"
    job1.hashes = {"md5": "1111", "sha256": "aaaa", "imphash": "imp123"}
    job1.binary_info = {
        "architecture": "x64",
        "imphash": "imp123",
        "file_header": {"compile_time": "2026-08-01 10:00:00 UTC"},
        "sections": [
            {"name": ".text", "virtual_address": "0x1000", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.3},
            {"name": ".data", "virtual_address": "0x2000", "virtual_size": 1024, "raw_size": 1024, "entropy": 3.1},
        ],
        "imports": {
            "KERNEL32.dll": [
                {"name": "VirtualAlloc", "is_suspicious": True},
                {"name": "ExitProcess", "is_suspicious": False}
            ]
        },
        "disassembly": {
            "instructions": [
                {"address": "0x140001000", "mnemonic": "sub", "op_str": "rsp, 0x28", "bytes": "4883ec28"},
                {"address": "0x140001004", "mnemonic": "call", "op_str": "0x140001050", "bytes": "e847000000"}
            ]
        }
    }
    job1.mitre_attack = [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"}
    ]

    job2 = job_manager.create_job(b"MZtestbinary2", "sample_payload.exe")
    job2.category = "executable"
    job2.extracted_code = "https://c2.evil-corp.cc/gate 198.51.100.44"
    job2.hashes = {"md5": "2222", "sha256": "bbbb", "imphash": "imp123"}
    job2.binary_info = {
        "architecture": "x64",
        "imphash": "imp123",
        "file_header": {"compile_time": "2026-08-01 10:05:00 UTC"},
        "sections": [
            {"name": ".text", "virtual_address": "0x1000", "virtual_size": 4200, "raw_size": 4608, "entropy": 6.4},
            {"name": ".rdata", "virtual_address": "0x3000", "virtual_size": 512, "raw_size": 512, "entropy": 4.2}
        ],
        "imports": {
            "KERNEL32.dll": [
                {"name": "VirtualAlloc", "is_suspicious": True},
                {"name": "Sleep", "is_suspicious": False}
            ]
        },
        "disassembly": {
            "instructions": [
                {"address": "0x140001000", "mnemonic": "sub", "op_str": "rsp, 0x28", "bytes": "4883ec28"},
                {"address": "0x140001004", "mnemonic": "call", "op_str": "0x140001080", "bytes": "e877000000"}
            ]
        }
    }
    job2.mitre_attack = [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"}
    ]

    # Test correlation engine directly
    corr = IncidentCorrelator.correlate_jobs([job1.job_id, job2.job_id])
    assert corr["success"] is True
    assert corr["total_jobs"] == 2

    # Check IOC overlap
    ioc = corr["ioc_comparison"]
    assert any(i["ip"] == "198.51.100.44" and i["is_shared"] for i in ioc["ips"])
    assert any(d["domain"] == "c2.evil-corp.cc" and d["is_shared"] for d in ioc["domains"])

    # Check BinDiff
    bindiff = corr["binary_diff"]
    assert bindiff["available"] is True
    assert len(bindiff["pairs"]) == 1
    pair = bindiff["pairs"][0]
    assert pair["similarity_score"] > 35.0
    assert len(pair["sections_diff"]) >= 2
    assert pair["imports_diff"]["matched_count"] >= 1
    assert any(m["api"] == "VirtualAlloc" for m in pair["imports_diff"]["matched"])
    assert pair["disassembly_diff"]["available"] is True

    # Check CFG Flow Graph Diff (zynamics BinDiff style)
    assert "flow_graph_diff" in pair
    fg = pair["flow_graph_diff"]
    assert fg["available"] is True
    assert fg["cfg_similarity"] > 0
    assert "sample_a_cfg" in fg
    assert "sample_b_cfg" in fg
    assert len(fg["sample_a_cfg"]["blocks"]) > 0
    assert len(fg["sample_b_cfg"]["blocks"]) > 0

    # Check Threat Graph
    graph = corr["campaign_graph"]
    assert graph["total_nodes"] >= 4
    assert graph["shared_nodes_count"] >= 1

    # Check Timeline Comparison
    timeline = corr["timeline_comparison"]
    assert "events" in timeline
    assert "staging_sequence" in timeline

    # Check Hash Comparison
    hashes = corr["hash_comparison"]
    assert len(hashes["files"]) == 2
    assert len(hashes["pairwise_matrix"]) == 1
    assert hashes["pairwise_matrix"][0]["imphash_match"] is True

    # Check MITRE Campaign Mapping
    mitre = corr["mitre_campaign"]
    assert mitre["total_techniques"] >= 2
    assert any(t["tactic"] == "Execution" for t in mitre["tactics"])

    # Check API endpoint
    res = client.post("/api/jobs/correlate", json={"job_ids": [job1.job_id, job2.job_id]})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["campaign_summary"]["total_files"] == 2
    assert data["campaign_summary"]["shared_ioc_count"] >= 2


def test_correlate_multi_evtx_fleet():
    # Create two synthetic EVTX jobs representing two hosts
    job_dc = job_manager.create_job(b"<Events>DC</Events>", "DC01-Security.evtx")
    job_dc.category = "evtx"
    job_dc.evtx_info = {
        "summary": {"total_events": 4},
        "timeline_events": [
            {
                "timestamp": "2026-10-04T12:00:00Z",
                "event_id": 1102,
                "computer": "CORP-DC01.target.local",
                "channel": "Security",
                "user": "Administrator",
                "severity": "critical",
                "description": "Security audit log was cleared."
            },
            {
                "timestamp": "2026-10-04T12:05:00Z",
                "event_id": 4624,
                "computer": "CORP-DC01.target.local",
                "channel": "Security",
                "user": "evil_admin",
                "severity": "info",
                "logon_type": 3,
                "details": {
                    "LogonType": "3",
                    "WorkstationName": "WKS-ATTACK-01",
                    "IpAddress": "192.168.1.50",
                    "TargetUserName": "evil_admin"
                }
            },
            {
                "timestamp": "2026-10-04T12:06:00Z",
                "event_id": 7045,
                "computer": "CORP-DC01.target.local",
                "channel": "System",
                "severity": "high",
                "details": {
                    "ServiceName": "PSEXESVC",
                    "ImagePath": "C:\\Windows\\PSEXESVC.exe"
                }
            },
            {
                "timestamp": "2026-10-04T12:10:00Z",
                "event_id": 4625,
                "computer": "CORP-DC01.target.local",
                "channel": "Security",
                "user": "victim_user",
                "severity": "medium",
                "ip": "198.51.100.99"
            }
        ]
    }

    job_wks = job_manager.create_job(b"<Events>WKS</Events>", "WKS01-Security.evtx")
    job_wks.category = "evtx"
    job_wks.evtx_info = {
        "summary": {"total_events": 2},
        "timeline_events": [
            {
                "timestamp": "2026-10-04T12:12:00Z",
                "event_id": 4625,
                "computer": "WKS-FINANCE-01.target.local",
                "channel": "Security",
                "user": "victim_user",
                "severity": "medium",
                "ip": "198.51.100.99"
            },
            {
                "timestamp": "2026-10-04T12:15:00Z",
                "event_id": 4688,
                "computer": "WKS-FINANCE-01.target.local",
                "channel": "Security",
                "user": "victim_user",
                "severity": "high",
                "details": {
                    "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                    "CommandLine": "vssadmin.exe delete shadows /all /quiet"
                }
            }
        ]
    }

    corr = IncidentCorrelator.correlate_jobs([job_dc.job_id, job_wks.job_id])
    assert corr["success"] is True

    # Check EVTX Fleet Forensics
    assert "evtx_fleet_forensics" in corr
    fleet = corr["evtx_fleet_forensics"]
    assert fleet["available"] is True
    assert fleet["total_hosts"] == 2
    assert fleet["total_logs"] == 2
    assert fleet["fleet_risk_level"] in ("HIGH", "CRITICAL")
    assert fleet["fleet_risk_score"] >= 50

    # Verify anti-forensics alert
    assert len(fleet["anti_forensics_alerts"]) >= 1
    assert fleet["anti_forensics_alerts"][0]["event_id"] == 1102

    # Verify lateral movement chain
    assert len(fleet["lateral_movement_chains"]) >= 1
    chain = fleet["lateral_movement_chains"][0]
    assert "CORP-DC01" in chain["target_host"] or "target" in chain["target_host"]
    assert chain["mitre_id"] in ("T1021.001", "T1021.002")

    # Verify password spray campaign across hosts
    spray = fleet["password_spray_analysis"]
    assert spray["total_failed_logons"] >= 2
    assert any(u["username"] == "victim_user" and u["is_spray_target"] for u in spray["user_matrix"])

    # Verify LOLBin divergence
    assert len(fleet["lolbin_divergence"]) >= 1
    assert any("vssadmin" in l["process_name"] for l in fleet["lolbin_divergence"])


def test_correlate_multi_pcap_fleet():
    # Two synthetic PCAP jobs
    pcap1 = job_manager.create_job(b"pcap_data_1", "perimeter_sensor_01.pcap")
    pcap1.category = "pcap"
    pcap1.pcap_info = {
        "packet_count": 1200,
        "duration_seconds": 45,
        "start_time": "2026-10-04T12:00:00Z",
        "end_time": "2026-10-04T12:00:45Z",
        "protocols": ["TCP", "HTTP", "DNS"],
        "conversations": [
            {
                "src_ip": "10.0.0.15",
                "dst_ip": "198.51.100.77",
                "src_port": 49152,
                "dst_port": 80,
                "packets": 50,
                "bytes": 10240,
                "protocol": "TCP"
            }
        ],
        "dns_queries": [
            {"query": "c2-beacon.darknet.org", "resolved_ip": "198.51.100.77", "timestamp": "2026-10-04T12:00:02Z"}
        ],
        "http_transactions": [
            {"method": "GET", "host": "c2-beacon.darknet.org", "uri": "/stage1", "timestamp": "2026-10-04T12:00:05Z"}
        ],
        "credentials": [
            {"username": "admin_service", "password": "Password123!", "protocol": "HTTP Basic", "timestamp": "2026-10-04T12:00:05Z"}
        ],
        "beaconing_flows": [
            {"dst_ip": "198.51.100.77", "dst_port": 80, "interval_seconds": 15.0, "jitter_percent": 2.5}
        ]
    }

    pcap2 = job_manager.create_job(b"pcap_data_2", "internal_dmz_sensor_02.pcap")
    pcap2.category = "pcap"
    pcap2.pcap_info = {
        "packet_count": 850,
        "duration_seconds": 60,
        "start_time": "2026-10-04T12:02:00Z",
        "end_time": "2026-10-04T12:03:00Z",
        "protocols": ["TCP", "SMB", "DNS"],
        "conversations": [
            # Lateral movement between private IPs over SMB (port 445)
            {
                "src_ip": "10.0.0.15",
                "dst_ip": "10.0.0.22",
                "src_port": 49800,
                "dst_port": 445,
                "packets": 320,
                "bytes": 85000,
                "protocol": "SMB"
            },
            # Common external IP bridge
            {
                "src_ip": "10.0.0.22",
                "dst_ip": "198.51.100.77",
                "src_port": 49801,
                "dst_port": 443,
                "packets": 12,
                "bytes": 2400,
                "protocol": "TCP"
            }
        ],
        "dns_queries": [
            {"query": "c2-beacon.darknet.org", "resolved_ip": "198.51.100.77", "timestamp": "2026-10-04T12:02:05Z"}
        ],
        "credentials": [
            {"username": "admin_service", "password": "Password123!", "protocol": "SMB NTLM", "timestamp": "2026-10-04T12:02:10Z"}
        ]
    }

    corr = IncidentCorrelator.correlate_jobs([pcap1.job_id, pcap2.job_id])
    assert corr["success"] is True
    pcap_fleet = corr["pcap_fleet_intelligence"]
    assert pcap_fleet["available"] is True
    assert pcap_fleet["total_captures"] == 2
    assert pcap_fleet["total_fleet_packets"] == 2050

    # Cross-capture IP bridge
    assert any(x["ip"] == "198.51.100.77" and x["capture_count"] == 2 for x in pcap_fleet["cross_capture_ips"])
    assert any(x["ip"] == "10.0.0.15" and x["capture_count"] == 2 for x in pcap_fleet["cross_capture_ips"])

    # Cross-capture domain bridge
    assert any(x["domain"] == "c2-beacon.darknet.org" and x["capture_count"] == 2 for x in pcap_fleet["cross_capture_domains"])

    # Shared credentials across captures
    assert any(c["username"] == "admin_service" and c["is_cross_capture"] for c in pcap_fleet["shared_credentials"])

    # Internal lateral movement flow detected
    assert len(pcap_fleet["lateral_network_flows"]) >= 1
    lat = pcap_fleet["lateral_network_flows"][0]
    assert lat["src_ip"] == "10.0.0.15"
    assert lat["dst_ip"] == "10.0.0.22"
    assert lat["port"] == 445


def test_cross_extension_unified_correlation():
    # Correlate 1 EVTX + 1 PCAP + 1 Binary EXE
    j_evtx = job_manager.create_job(b"<Events>EVTX</Events>", "host_security.evtx")
    j_evtx.category = "evtx"
    j_evtx.evtx_info = {
        "timeline_events": [
            {
                "timestamp": "2026-10-04T12:00:00Z",
                "event_id": 4688,
                "computer": "CORP-WKS-01",
                "user": "alice",
                "description": "powershell.exe -enc dGVzdA==",
                "ip": "10.0.0.15"
            }
        ]
    }

    j_pcap = job_manager.create_job(b"pcap_bytes", "network_dump.pcap")
    j_pcap.category = "pcap"
    j_pcap.pcap_info = {
        "packet_count": 500,
        "start_time": "2026-10-04T12:00:05Z",
        "conversations": [{"src_ip": "10.0.0.15", "dst_ip": "198.51.100.99", "dst_port": 443}],
        "dns_queries": [{"query": "beacon.apt.org", "resolved_ip": "198.51.100.99", "timestamp": "2026-10-04T12:00:05Z"}]
    }

    j_exe = job_manager.create_job(b"MZ...", "malware_payload.exe")
    j_exe.category = "executable"
    j_exe.extracted_code = "https://beacon.apt.org/connect 198.51.100.99"
    j_exe.hashes = {"sha256": "abcdef123456"}

    corr = IncidentCorrelator.correlate_jobs([j_evtx.job_id, j_pcap.job_id, j_exe.job_id])
    assert corr["success"] is True
    assert corr["total_jobs"] == 3

    # Unified timeline has events from all three sources in chronological order
    timeline = corr["timeline_comparison"]["events"]
    assert len(timeline) >= 2
    for idx in range(len(timeline) - 1):
        t1 = timeline[idx].get("timestamp") or ""
        t2 = timeline[idx + 1].get("timestamp") or ""
        assert t1 <= t2

    # Cross-artifact IOC correlation connects PCAP and EXE
    ioc = corr["ioc_comparison"]
    assert any(i["ip"] == "198.51.100.99" and i["is_shared"] for i in ioc["ips"])
    assert any(d["domain"] == "beacon.apt.org" and d["is_shared"] for d in ioc["domains"])

