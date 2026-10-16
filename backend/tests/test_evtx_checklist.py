"""
Comprehensive Unit & Integration Test Suite for Windows Event Logs (EVTX) Security Analysis Checklist.

Verifies:
1. File identification, integrity & validation (magic bytes, version, hashes, continuity & gaps)
2. Log inventory & coverage analysis (channel catalog, coverage score, limitations)
3. Sigma-compatible detection rules engine (credential dumping, LOLBins, tampering, cradles)
4. Authentication & logon analysis (logon types, status codes, spray, brute-force-to-success)
5. Kerberos forensics (Kerberoasting RC4 encryption 0x17, AS-REP Roasting 0x18)
6. Account, group & privilege changes (sensitive group SID resolution, user rights)
7. Lateral movement attack chain correlation
8. Log tampering & anti-forensics (1102, 104, 4719, 4616, Defender 5001)
9. Offline analysis tools guide (EvtxECmd, Chainsaw, Hayabusa, wevtutil, Get-WinEvent)
10. Executive EVTX Security Verdict computation, confidence calibration, MITRE mapping, and containment guidance
11. Full EvtxAnalyzer integration
"""

import struct
from pathlib import Path
import pytest

from app.analyzers.evtx_forensics import (
    audit_evtx_capture_integrity,
    audit_record_continuity_and_gaps,
    audit_log_inventory_and_coverage,
    evaluate_sigma_rules,
    analyze_authentication_forensics,
    analyze_account_and_privilege_changes,
    analyze_lateral_movement_chains,
    analyze_log_tampering_and_anti_forensics,
    get_offline_analysis_tools_guide,
    calculate_evtx_verdict,
    WELL_KNOWN_SIDS,
    AUTH_STATUS_CODES,
)
from app.analyzers.evtx_analyzer import EvtxAnalyzer


def create_dummy_evtx_header(chunk_count=2, flags=0) -> bytes:
    """Builds a valid 4096-byte EVTX header binary block."""
    hdr = bytearray(4096)
    # Magic 'ElfFile\x00'
    hdr[0:8] = b"ElfFile\x00"
    # First chunk: 0, Last chunk: chunk_count - 1, Next record ID: 100
    struct.pack_into("<QQQ", hdr, 8, 0, max(0, chunk_count - 1), 100)
    # Header size: 4096, minor: 1, major: 3, header chunk size: 4096, chunk count: chunk_count
    struct.pack_into("<IHHHH", hdr, 32, 4096, 1, 3, 4096, chunk_count)
    # Flags at offset 0x78
    struct.pack_into("<I", hdr, 0x78, flags)
    return bytes(hdr)


def test_evtx_capture_integrity_and_provenance():
    dummy_evtx = create_dummy_evtx_header(chunk_count=3, flags=0)
    res = audit_evtx_capture_integrity(dummy_evtx, "Security.evtx")

    assert res["is_valid_evtx"] is True
    assert res["is_binary_evtx"] is True
    assert res["format"] == "Classic Windows Event Log (Binary EVTX)"
    assert res["evtx_header"]["major_version"] == 3
    assert res["evtx_header"]["minor_version"] == 1
    assert res["evtx_header"]["header_chunk_count"] == 3
    assert res["file_hashes"]["sha256"] != "unknown"
    assert len(res["file_hashes"]["sha256"]) == 64
    assert res["integrity_status"] == "INTACT"


def test_record_continuity_and_gaps():
    # Construct mock records with skipped record IDs and a 20-hour timestamp gap
    records = [
        {"details": {"EventRecordID": "1001"}, "timestamp": "2026-10-01T08:00:00Z"},
        {"details": {"EventRecordID": "1002"}, "timestamp": "2026-10-01T08:15:00Z"},
        # Skipped from 1002 to 1015 (12 missing records) and 20-hour gap
        {"details": {"EventRecordID": "1015"}, "timestamp": "2026-10-02T04:15:00Z"},
        {"details": {"EventRecordID": "1016"}, "timestamp": "2026-10-02T04:30:00Z"},
    ]
    res = audit_record_continuity_and_gaps(records)
    assert res["has_continuity_anomalies"] is True
    assert len(res["record_id_gaps"]) == 1
    assert res["record_id_gaps"][0]["missing_count"] == 12
    assert res["record_id_gaps"][0]["severity"] == "high"
    assert len(res["timestamp_gaps"]) == 1
    assert res["timestamp_gaps"][0]["gap_duration_hours"] == 20.0


def test_log_inventory_and_coverage_analysis():
    parsed_files = [
        {"filename": "Security.evtx", "channels": ["Security"]},
        {"filename": "System.evtx", "channels": ["System"]},
    ]
    records = [
        {"channel": "Security", "event_id": 4624},
        {"channel": "System", "event_id": 7045},
    ]
    res = audit_log_inventory_and_coverage(parsed_files, records)
    assert "Security" in res["channels_present"]
    assert "System" in res["channels_present"]
    assert res["coverage_score"] > 0
    assert any("Sysmon is not present" in lim for lim in res["coverage_limitations"])
    assert any("PowerShell ScriptBlock logging channel absent" in lim for lim in res["coverage_limitations"])


def test_sigma_rules_evaluation():
    records = [
        {
            "event_id": 1102,
            "timestamp": "2026-10-02T10:00:00Z",
            "user": "malicious_admin",
            "computer": "DC01",
            "summary": "Security audit log cleared"
        },
        {
            "event_id": 4688,
            "timestamp": "2026-10-02T10:05:00Z",
            "user": "malicious_admin",
            "computer": "DC01",
            "process_name": "cmd.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "summary": "Shadow copy deletion"
        },
        {
            "event_id": 5001,
            "timestamp": "2026-10-02T10:06:00Z",
            "user": "SYSTEM",
            "computer": "DC01",
            "summary": "Defender Antivirus disabled"
        },
        {
            "event_id": 4728,
            "timestamp": "2026-10-02T10:10:00Z",
            "user": "malicious_admin",
            "computer": "DC01",
            "summary": "Added user to Domain Admins"
        }
    ]
    alerts = evaluate_sigma_rules(records)
    alert_ids = [a["rule_id"] for a in alerts]

    assert "SIGMA-WIN-001" in alert_ids  # Security log cleared
    assert "SIGMA-WIN-003" in alert_ids  # Shadow copy deletion
    assert "SIGMA-WIN-005" in alert_ids  # Defender disabled
    assert "SIGMA-WIN-006" in alert_ids  # Admin group add
    assert all("mitre_technique" in a for a in alerts)


def test_authentication_forensics_spray_and_brute_force_success():
    records = [
        # Password spraying from 192.168.1.50 against 4 distinct accounts
        {"event_id": 4625, "user": "alice", "ip_address": "192.168.1.50", "timestamp": "2026-10-02T11:00:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4625, "user": "bob", "ip_address": "192.168.1.50", "timestamp": "2026-10-02T11:01:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4625, "user": "charlie", "ip_address": "192.168.1.50", "timestamp": "2026-10-02T11:02:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4625, "user": "dave", "ip_address": "192.168.1.50", "timestamp": "2026-10-02T11:03:00Z", "details": {"Status": "0xC000006A"}},
        # Brute force against target account 'administrator' (3 failures) followed by success
        {"event_id": 4625, "user": "administrator", "ip_address": "192.168.1.99", "timestamp": "2026-10-02T11:10:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4625, "user": "administrator", "ip_address": "192.168.1.99", "timestamp": "2026-10-02T11:11:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4625, "user": "administrator", "ip_address": "192.168.1.99", "timestamp": "2026-10-02T11:12:00Z", "details": {"Status": "0xC000006A"}},
        {"event_id": 4624, "user": "administrator", "ip_address": "192.168.1.99", "timestamp": "2026-10-02T11:13:00Z", "logon_type": "10", "details": {"LogonType": "10"}},
    ]
    res = analyze_authentication_forensics(records)

    assert len(res["password_spray_sources"]) == 1
    assert res["password_spray_sources"][0]["source_ip"] == "192.168.1.50"
    assert res["password_spray_sources"][0]["targeted_accounts_count"] == 4

    assert len(res["brute_force_success"]) == 1
    assert res["brute_force_success"][0]["target_account"] == "administrator"
    assert res["brute_force_success"][0]["failure_count"] == 3

    # Status code resolution
    status_meanings = [s["meaning"] for s in res["status_code_audit"]]
    assert any("bad password" in m.lower() for m in status_meanings)


def test_kerberos_forensics_kerberoasting():
    records = [
        {"event_id": 4768, "user": "attacker", "timestamp": "2026-10-02T12:00:00Z"},
        # 4769 with RC4 encryption type 0x17 (Kerberoasting)
        {
            "event_id": 4769,
            "user": "attacker",
            "timestamp": "2026-10-02T12:05:00Z",
            "details": {"ServiceName": "MSSQLSvc/db01.corp:1433", "TicketEncryptionType": "0x17", "IpAddress": "192.168.1.80"}
        },
        # 4771 pre-auth failure with 0x18
        {
            "event_id": 4771,
            "user": "victim_svc",
            "timestamp": "2026-10-02T12:10:00Z",
            "details": {"Status": "0x18", "IpAddress": "192.168.1.80"}
        }
    ]
    res = analyze_authentication_forensics(records)
    kerb = res["kerberos_forensics"]

    assert kerb["tgt_requests_count"] == 1
    assert kerb["service_tickets_count"] == 1
    assert len(kerb["kerberoasting_candidates"]) == 1
    assert kerb["kerberoasting_candidates"][0]["service_name"] == "MSSQLSvc/db01.corp:1433"
    assert kerb["kerberoasting_candidates"][0]["encryption_type"] == "RC4-HMAC (0x17)"
    assert len(kerb["kerberos_preauth_failures"]) == 1


def test_account_and_privilege_management_sid_resolution():
    records = [
        {"event_id": 4720, "timestamp": "2026-10-02T13:00:00Z", "user": "admin", "details": {"TargetUserName": "backdoor_user"}},
        {"event_id": 4722, "timestamp": "2026-10-02T13:01:00Z", "user": "admin", "details": {"TargetUserName": "backdoor_user"}},
        # User added to Administrators group (S-1-5-32-544)
        {
            "event_id": 4732,
            "timestamp": "2026-10-02T13:05:00Z",
            "user": "admin",
            "details": {
                "MemberName": "backdoor_user",
                "GroupName": "Administrators",
                "TargetSid": "S-1-5-32-544"
            }
        },
        # User right assigned
        {
            "event_id": 4704,
            "timestamp": "2026-10-02T13:06:00Z",
            "user": "admin",
            "details": {"TargetUserName": "backdoor_user", "PrivilegeList": "SeDebugPrivilege"}
        }
    ]
    res = analyze_account_and_privilege_changes(records)

    assert len(res["users_created"]) == 1
    assert res["users_created"][0]["created_user"] == "backdoor_user"
    assert len(res["sensitive_group_additions"]) == 1
    assert res["sensitive_group_additions"][0]["is_sensitive_group"] is True
    assert res["sensitive_group_additions"][0]["group_sid"] == "S-1-5-32-544"
    assert len(res["user_rights_assigned"]) == 1
    assert "SeDebugPrivilege" in res["user_rights_assigned"][0]["rights"]


def test_lateral_movement_chain_correlation():
    host = "FINANCE-PC02"
    records = [
        {"event_id": 4625, "computer": host, "user": "bad_actor", "timestamp": "2026-10-02T14:00:00Z"},
        {"event_id": 4624, "computer": host, "user": "bad_actor", "logon_type": "3", "ip_address": "10.0.0.55", "timestamp": "2026-10-02T14:02:00Z"},
        {"event_id": 5145, "computer": host, "user": "bad_actor", "share_name": "\\\\*\\C$", "relative_target_name": "temp\\stage.exe", "timestamp": "2026-10-02T14:03:00Z"},
        {"event_id": 7045, "computer": host, "user": "SYSTEM", "service_name": "PSEXESVC", "timestamp": "2026-10-02T14:04:00Z"},
        {"event_id": 4688, "computer": host, "user": "SYSTEM", "process_name": "powershell.exe", "is_lolbin": True, "timestamp": "2026-10-02T14:05:00Z"}
    ]
    chains = analyze_lateral_movement_chains(records)

    assert len(chains) == 1
    chain = chains[0]
    assert chain["target_host"] == host
    assert chain["stages_count"] == 5
    assert chain["severity"] == "critical"
    assert chain["payload_dropped"] == "temp\\stage.exe"


def test_log_tampering_and_anti_forensics():
    records = [
        {"event_id": 1102, "computer": "CORP-DC", "user": "attacker", "timestamp": "2026-10-02T15:00:00Z"},
        {"event_id": 4719, "computer": "CORP-DC", "user": "attacker", "timestamp": "2026-10-02T15:02:00Z", "details": {"CategoryId": "Logon/Logoff"}},
        {"event_id": 4616, "computer": "CORP-DC", "user": "attacker", "timestamp": "2026-10-02T15:03:00Z", "details": {"PreviousTime": "15:03:00", "NewTime": "01:00:00"}},
        {"event_id": 5001, "computer": "CORP-DC", "timestamp": "2026-10-02T15:04:00Z"},
    ]
    res = analyze_log_tampering_and_anti_forensics(records)

    assert res["tampering_detected"] is True
    assert len(res["logs_cleared"]) == 1
    assert len(res["audit_policy_changes"]) == 1
    assert len(res["system_time_manipulations"]) == 1
    assert len(res["defender_tampering"]) == 1


def test_offline_analysis_tools_guide():
    guide = get_offline_analysis_tools_guide("Corporate_Security.evtx")
    assert "evtxecmd" in guide
    assert "chainsaw" in guide
    assert "hayabusa" in guide
    assert "wevtutil" in guide
    assert "Corporate_Security.evtx" in guide["evtxecmd"]["command"]
    assert "Corporate_Security.evtx" in guide["chainsaw"]["command"]
    assert "Corporate_Security.evtx" in guide["hayabusa"]["command"]


def test_executive_evtx_verdict_malicious():
    records = [{"event_id": 1102, "user": "admin"}]
    findings = []
    sigma_alerts = [{
        "rule_id": "SIGMA-WIN-001",
        "title": "Windows Security Audit Log Cleared",
        "level": "critical",
        "mitre_technique": "T1070.001",
        "match_count": 1
    }]
    coverage_audit = {"coverage_score": 60}
    auth_forensics = {"password_spray_sources": [], "brute_force_success": []}
    tampering = {"tampering_detected": True, "logs_cleared": [{"log_type": "Security Audit Log", "user": "admin", "event_id": 1102}]}
    lateral_chains = []

    verdict = calculate_evtx_verdict(
        records, findings, sigma_alerts, coverage_audit,
        auth_forensics, tampering, lateral_chains
    )

    assert verdict["verdict"] == "Malicious"
    assert verdict["severity"] == "critical"
    assert verdict["confidence_score"] >= 80
    assert "T1070.001" in verdict["mitre_attack_techniques"]
    assert len(verdict["containment_guidance"]) > 0
    assert any("isolate" in step.lower() for step in verdict["containment_guidance"])


def test_full_evtx_analyzer_integration(tmp_path):
    # Test full end-to-end analyze on an XML-exported EVTX containing multiple attack vectors
    sample_xml = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Provider Name="Microsoft-Windows-Security-Auditing" />
          <EventID>1102</EventID>
          <TimeCreated SystemTime="2026-10-02T16:00:00.000Z" />
          <EventRecordID>5001</EventRecordID>
          <Channel>Security</Channel>
          <Computer>CORP-DC01</Computer>
        </System>
        <UserData>
          <LogFileCleared>
            <SubjectUserName>evil_admin</SubjectUserName>
          </LogFileCleared>
        </UserData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Provider Name="Microsoft-Windows-Security-Auditing" />
          <EventID>4688</EventID>
          <TimeCreated SystemTime="2026-10-02T16:05:00.000Z" />
          <EventRecordID>5002</EventRecordID>
          <Channel>Security</Channel>
          <Computer>CORP-DC01</Computer>
        </System>
        <EventData>
          <Data Name="NewProcessName">C:\\Windows\\System32\\vssadmin.exe</Data>
          <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
          <Data Name="SubjectUserName">evil_admin</Data>
        </EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Provider Name="Microsoft-Windows-Security-Auditing" />
          <EventID>5145</EventID>
          <TimeCreated SystemTime="2026-10-02T16:07:00.000Z" />
          <EventRecordID>5003</EventRecordID>
          <Channel>Security</Channel>
          <Computer>CORP-DC01</Computer>
        </System>
        <EventData>
          <Data Name="ShareName">\\\\*\\C$</Data>
          <Data Name="RelativeTargetName">Windows\\Temp\\beacon.exe</Data>
          <Data Name="AccessMask">0x2</Data>
          <Data Name="AccessList">WriteData</Data>
          <Data Name="SubjectUserName">evil_admin</Data>
          <Data Name="IpAddress">10.0.0.44</Data>
        </EventData>
      </Event>
    </Events>"""

    evtx_file = tmp_path / "test_incident.evtx"
    evtx_file.write_text(sample_xml, encoding="utf-8")

    analyzer = EvtxAnalyzer()
    res = analyzer.analyze(evtx_file, "test_incident.evtx", "application/x-ms-evtx")

    assert res.success is True
    assert res.data["total_events"] == 3
    assert res.data["evtx_verdict"]["verdict"] == "Malicious"
    assert res.data["evtx_verdict"]["severity"] == "critical"
    assert res.data["evtx_verdict"]["confidence_score"] >= 80

    # Verify checklist keys exist
    assert "capture_integrity" in res.data
    assert "coverage_audit" in res.data
    assert "sigma_alerts" in res.data
    assert "auth_forensics" in res.data
    assert "account_management" in res.data
    assert "lateral_chains" in res.data
    assert "tampering_analysis" in res.data
    assert "offline_tools_guide" in res.data

    assert len(res.data["sigma_alerts"]) >= 2
    assert res.data["tampering_analysis"]["tampering_detected"] is True
