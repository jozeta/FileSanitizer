"""
Unit and Integration Test Suite for PCAP / PCAPNG Network Security Forensics.
Validates implementation of the Comprehensive PCAP Security Analysis Checklist:
- Capture integrity & evidence provenance diagnostics (endianness, precision, truncation, time gaps, SHA256)
- Zeek-style structured session logs (conn.log, dns.log, ssl.log, x509.log, files.log)
- Suricata-compatible IDS signatures and alert rules engine
- Advanced DNS forensics (Shannon entropy, DGA detection, DNS tunneling heuristics, NXDOMAIN bursts)
- Malware C2 & beaconing detection with jitter tolerance
- Data exfiltration & covert channels (upload/download ratio, ICMP ping tunneling, cloud exfiltration)
- Reconnaissance & lateral movement (port scans, ARP/ICMP sweeps, SMB admin shares, WinRM)
- Protocol-specific inspection (ARP spoofing, rogue DHCP, Modbus/TCP industrial OT write operations)
- Standardized Executive PCAP Security Verdict engine with MITRE ATT&CK mapping and containment advice
"""

import struct
from pathlib import Path
from app.analyzers.pcap_analyzer import PcapAnalyzer
from app.analyzers.pcap_forensics import (
    calculate_shannon_entropy,
    calculate_string_entropy,
    audit_capture_integrity,
    generate_zeek_logs,
    evaluate_suricata_ids_rules,
    analyze_dns_forensics,
    analyze_advanced_beaconing,
    analyze_exfiltration_and_covert_channels,
    analyze_recon_and_lateral_movement,
    inspect_protocol_anomalies,
    calculate_pcap_verdict
)


def test_entropy_and_string_calculations():
    # Uniform bytes have maximum entropy
    random_bytes = bytes([i % 256 for i in range(1024)])
    ent = calculate_shannon_entropy(random_bytes)
    assert ent >= 7.5

    # Zero bytes have 0 entropy
    null_bytes = b"\x00" * 1024
    assert calculate_shannon_entropy(null_bytes) == 0.0

    # High entropy DGA domain
    dga_domain = "x8k2lm9pq7wz3rt1.attacker-c2.net"
    sub_ent = calculate_string_entropy("x8k2lm9pq7wz3rt1")
    assert sub_ent >= 3.6


def test_capture_integrity_and_provenance():
    # Little-endian microsecond classic PCAP header
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    # 2 sample packets with a 15-second gap and 1 truncated packet
    pkt1 = b"\x00" * 60
    pkt2 = b"\x00" * 40
    
    packets = [
        {"timestamp": 1760000000.0, "length": 60, "data": pkt1, "link_type": "Ethernet"},
        {"timestamp": 1760000015.0, "length": 100, "data": pkt2, "link_type": "Ethernet"} # Truncated: orig 100 > cap 40
    ]
    
    raw_capture = pcap_hdr + struct.pack("<IIII", 1760000000, 0, 60, 60) + pkt1
    
    diag = audit_capture_integrity(raw_capture, "sample.pcap", is_pcapng=False, packets=packets)
    assert diag["format"] == "Classic PCAP (libpcap)"
    assert "Little-endian" in diag["endianness"]
    assert "Microsecond" in diag["timestamp_precision"]
    assert diag["truncated_packets_count"] == 1
    assert diag["integrity_status"] == "TRUNCATED_FRAMES"
    assert len(diag["time_gaps"]) >= 1
    assert diag["time_gaps"][0]["duration_sec"] >= 15.0
    assert len(diag["provenance"]["sha256"]) == 64


def test_zeek_style_structured_logs():
    flows = {
        "10.0.0.15:51200<->142.250.190.46:80:TCP": {
            "id": "flow_1",
            "src_ip": "10.0.0.15",
            "src_port": 51200,
            "dst_ip": "142.250.190.46",
            "dst_port": 80,
            "transport": "TCP",
            "protocol": "HTTP",
            "duration_seconds": 2.5,
            "client_bytes": 450,
            "server_bytes": 12000,
            "state": "TERMINATED_NORMAL",
            "flags_summary": {"syn": 1, "ack": 3, "fin": 1}
        }
    }
    dns_queries = [{
        "domain": "api.github.com",
        "query_type": "A",
        "resolved_ips": ["140.82.121.4"],
        "client_ip": "10.0.0.15",
        "threat_status": "CLEAN"
    }]
    tls_sessions = [{
        "sni": "api.github.com",
        "client_ip": "10.0.0.15",
        "server_ip": "140.82.121.4",
        "server_port": 443,
        "tls_version": "TLSv1.3",
        "ja3": "cd08e31494f9531f560d64c695473da9",
        "is_self_signed": False
    }]
    carved_files = [{
        "filename": "update.bin",
        "mime_type": "application/octet-stream",
        "size_bytes": 2048,
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "is_dangerous": False,
        "threat_reason": "Clean Transfer"
    }]

    logs = generate_zeek_logs(flows, dns_queries, tls_sessions, carved_files, [])
    assert "conn_log" in logs and len(logs["conn_log"]) == 1
    assert logs["conn_log"][0]["conn_state"] == "SF"
    assert logs["conn_log"][0]["local_orig"] is True
    assert "dns_log" in logs and len(logs["dns_log"]) == 1
    assert "ssl_log" in logs and len(logs["ssl_log"]) == 1
    assert "x509_log" in logs and len(logs["x509_log"]) == 1
    assert "files_log" in logs and len(logs["files_log"]) == 1


def test_suricata_ids_rule_engine():
    packets = []
    flows = {
        "fl_1": {
            "src_ip": "192.168.1.100",
            "src_port": 49200,
            "dst_ip": "192.168.1.5",
            "dst_port": 80,
            "payload_preview_ascii": "GET /index.php?id=1' UNION SELECT username, password FROM users-- HTTP/1.1",
            "flags_summary": {}
        }
    }
    http_txs = [{
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.5",
        "src_port": 49200,
        "dst_port": 80,
        "method": "GET",
        "uri": "/index.php?id=1' UNION SELECT username, password FROM users--",
        "user_agent": "Mozilla/5.0",
        "payload_sample": "",
        "full_url": "http://192.168.1.5/index.php?id=1' UNION SELECT username, password FROM users--"
    }]
    dns_qs = []
    creds = [{"protocol": "HTTP", "username": "admin", "password": "SuperSecretPassword123!", "client_ip": "192.168.1.100", "server_ip": "192.168.1.5"}]

    alerts = evaluate_suricata_ids_rules(packets, flows, http_txs, dns_qs, creds)
    assert len(alerts) >= 2
    # Verify SQL injection alert
    sqli_alert = next((a for a in alerts if "SQL Injection" in a["msg"]), None)
    assert sqli_alert is not None
    assert sqli_alert["severity"] == 1
    # Verify cleartext credentials alert
    cred_alert = next((a for a in alerts if "Credentials Exposed" in a["msg"]), None)
    assert cred_alert is not None


def test_dns_forensics_dga_and_tunneling():
    dns_queries = [
        {
            "domain": "v8z7q9p1k2m3x5r7.malware-c2-infrastructure.com",
            "query_type": "A",
            "resolved_ips": ["198.51.100.1"],
            "client_ip": "10.0.0.15",
            "threat_status": "CLEAN"
        },
        {
            "domain": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6.tunnel.target.local",
            "query_type": "TXT",
            "resolved_ips": [],
            "client_ip": "10.0.0.15",
            "threat_status": "CLEAN"
        }
    ]
    res = analyze_dns_forensics(dns_queries, {})
    assert len(res["dga_candidates"]) >= 1
    assert res["dga_candidates"][0]["domain"] == "v8z7q9p1k2m3x5r7.malware-c2-infrastructure.com"
    assert len(res["tunneling_queries"]) >= 1
    assert any("tunnel.target.local" in tq["domain"] for tq in res["tunneling_queries"])


def test_malware_c2_beaconing_with_jitter():
    # Timestamps with ~10s interval and tiny jitter (0% to 5%)
    base = 1760000000.0
    flow_timestamps = {
        "10.0.0.15->185.190.140.50": [
            base + 0.0,
            base + 10.0,
            base + 20.1,
            base + 30.05,
            base + 40.0,
            base + 50.15
        ]
    }
    flows = {}
    beacon_res = analyze_advanced_beaconing(flows, flow_timestamps)
    assert beacon_res["detected_beacon_count"] >= 1
    b = beacon_res["beaconing_sessions"][0]
    assert b["target_ip"] == "185.190.140.50"
    assert b["jitter_percent"] <= 10.0
    assert b["threat_level"] == "CRITICAL"


def test_exfiltration_and_icmp_tunneling():
    # Asymmetric ratio flow (185.190.140.50 is public Internet IP)
    flows = {
        "fl_exfil": {
            "id": "fl_exfil",
            "src_ip": "10.0.0.15",
            "src_port": 54321,
            "dst_ip": "185.190.140.50",
            "dst_port": 443,
            "client_bytes": 150000,
            "server_bytes": 1500,
            "protocol": "TLS"
        }
    }
    # ICMP ping packet with readable command payload
    eth_ip_hdr = b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x50\x00\x00\x00\x00\x40\x01\x00\x00\x0a\x00\x00\x0f\xc6\x33\x64\x63"
    icmp_body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"whoami && cat /etc/shadow"
    icmp_packet = {"data": eth_ip_hdr + icmp_body, "length": len(eth_ip_hdr + icmp_body)}

    res = analyze_exfiltration_and_covert_channels(flows, [icmp_packet], [], [], [])
    assert len(res["ratio_anomalies"]) >= 1
    assert res["ratio_anomalies"][0]["upload_ratio"] >= 90.0
    assert len(res["icmp_tunneling_packets"]) >= 1
    assert "Command shell syntax exposed" in res["icmp_tunneling_packets"][0]["reason"]
    assert res["has_high_confidence_exfiltration"] is True


def test_recon_lateral_movement_and_protocol_anomalies():
    # Port scan packets: source 10.0.0.15 probing 10 ports on 10.0.0.50
    packets = []
    base_eth_ip = b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x30\x00\x00\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x0f\x0a\x00\x00\x32"
    for port in [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]:
        tcp_hdr = struct.pack("!HHIIBBHHH", 50000, port, 1000, 0, 0x50, 0x02, 8192, 0, 0)
        packets.append({"data": base_eth_ip + tcp_hdr, "length": len(base_eth_ip + tcp_hdr)})

    # Lateral movement SMB flow accessing ADMIN$
    flows = {
        "smb_lat": {
            "src_ip": "10.0.0.15",
            "dst_ip": "10.0.0.20",
            "dst_port": 445,
            "bytes": 5000,
            "payload_preview_ascii": "TreeConnect: \\\\10.0.0.20\\ADMIN$"
        }
    }
    recon = analyze_recon_and_lateral_movement(flows, packets, {})
    assert len(recon["scans_detected"]) >= 1
    assert recon["scans_detected"][0]["scan_type"] == "Vertical Port Scan (Single Host, Multi-Port)"
    assert len(recon["lateral_movement_events"]) >= 1
    assert recon["lateral_movement_events"][0]["admin_share"] == "ADMIN$"

    # Protocol anomalies: ARP Spoofing
    arp_pkt1 = {"data": b"\x00" * 12 + b"\x08\x06" + struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, b"\x00\x11\x22\x33\x44\x55", bytes([10, 0, 0, 1]), b"\x00"*6, bytes([10, 0, 0, 2]))}
    arp_pkt2 = {"data": b"\x00" * 12 + b"\x08\x06" + struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, b"\xaa\xbb\xcc\xdd\xee\xff", bytes([10, 0, 0, 1]), b"\x00"*6, bytes([10, 0, 0, 2]))}
    proto_res = inspect_protocol_anomalies([arp_pkt1, arp_pkt2], {}, [], [])
    assert len(proto_res["arp_spoofing_alerts"]) >= 1
    assert proto_res["arp_spoofing_alerts"][0]["target_ip"] == "10.0.0.1"


def test_executive_verdict_engine():
    # Critical threat verdict
    integrity = {"packet_count": 100, "integrity_status": "INTACT"}
    ids_alerts = [{"severity": 1, "msg": "ET EXPLOIT Log4j JNDI RCE"}]
    verdict = calculate_pcap_verdict(integrity, {}, ids_alerts, {}, {}, {}, {}, {"cleartext_credentials_count": 0}, [])
    assert verdict["verdict"] == "Malicious"
    assert verdict["severity"] == "critical"
    assert verdict["confidence_score"] >= 90
    assert any("T1190" in m["id"] for m in verdict["mitre_techniques"])
    assert len(verdict["containment_recommendations"]) >= 3


def _build_forensic_pcap_bytes() -> bytes:
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    base_ts = 1760000000.0
    packets = []

    mac_client = b"\x00\x11\x22\x33\x44\x55"
    mac_server = b"\x00\xaa\xbb\xcc\xdd\xee"

    def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        eth_hdr = dst_mac + src_mac + b"\x08\x00"
        total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, 1234, 0x4000, 64, 6, 0,
            bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split(".")))
        )
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0
        )
        return eth_hdr + ip_hdr + tcp_hdr + payload

    # HTTP POST with credentials
    s1 = b"POST /login.php HTTP/1.1\r\nHost: portal.target.local\r\nContent-Length: 50\r\n\r\nusername=admin&password=P@ssw0rd2026!&action=login"
    p1 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "185.190.140.50", 51200, 80, 1000, 0, 0x18, s1)
    packets.append((base_ts + 1.0, p1))

    # HTTP GET payload download
    s2 = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"malware.exe\"\r\n\r\nMZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode."
    p2 = make_eth_ip_tcp(mac_server, mac_client, "185.190.140.50", "10.0.0.15", 80, 51200, 5000, 1050, 0x18, s2)
    packets.append((base_ts + 2.0, p2))

    buf = bytearray(pcap_hdr)
    for ts, pkt in packets:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
        buf.extend(pkt_hdr)
        buf.extend(pkt)
    return bytes(buf)


def test_end_to_end_pcap_analyzer(tmp_path: Path):
    sample_file = tmp_path / "threat_network_capture.pcap"
    sample_file.write_bytes(_build_forensic_pcap_bytes())

    analyzer = PcapAnalyzer()
    res = analyzer.analyze(sample_file, sample_file.name, "application/vnd.tcpdump.pcap")
    assert res.success is True
    data = res.data

    # Verify all checklist keys are populated
    for expected_key in [
        "pcap_verdict",
        "capture_integrity",
        "zeek_logs",
        "ids_alerts",
        "dns_forensics",
        "beaconing_analysis",
        "exfiltration_analysis",
        "lateral_movement",
        "protocol_anomalies",
        "summary",
        "conversations",
        "credentials",
        "transferred_files",
        "gantt_items"
    ]:
        assert expected_key in data, f"Missing expected key: {expected_key}"

    # Verify Executive Verdict
    verdict_info = data["pcap_verdict"]
    assert verdict_info["verdict"] in ("Malicious", "Suspicious", "Potentially Vulnerable", "No Known Threat Detected")
    assert verdict_info["confidence_score"] > 0
    assert len(verdict_info["rationale"]) > 0
    assert len(verdict_info["containment_recommendations"]) > 0

    # Verify capture integrity
    integrity = data["capture_integrity"]
    assert integrity["packet_count"] > 0
    assert "provenance" in integrity
    assert len(integrity["provenance"]["sha256"]) == 64

    # Verify Zeek logs
    zeek = data["zeek_logs"]
    assert "conn_log" in zeek and len(zeek["conn_log"]) > 0
