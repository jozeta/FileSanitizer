"""
Forensic PCAP / PCAPNG Network Packet Capture Analyzer.
Pure-Python, high-performance engine dissecting network flows, protocols
(HTTP, TLS/HTTPS, DNS, SSH, FTP, SMTP), TLS Server Name Indications (SNI),
cleartext credentials, transferred file payloads, deep stream reassembly,
file carving with threat intelligence, software fingerprinting, and
Gantt timeline visualization data.
"""

import base64
import hashlib
import ipaddress
import re
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import unquote

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.core.file_isolation import sanitize_filename
from app.core.logging_config import logger
from app.network.geo_resolver import GeoResolver
from app.analyzers.reputation_client import (
    AbuseIPDBClient,
    ThreatFoxClient,
    MalwareBazaarClient,
    CirclHashlookupClient,
    AlienVaultOTXClient
)
from app.analyzers.virustotal_client import VirusTotalClient
from app.core.embedded_extractor import (
    detect_mime_type_from_bytes,
    is_payload_dangerous,
    format_file_size
)
import math
import collections

# Known Malicious and Adversarial Tool JA3 Fingerprints
KNOWN_JA3_DATABASE = {
    "a0e9f5d64349fb13191bc781f81f42e1": ("Cobalt Strike Malleable C2 Beacon", "critical"),
    "72a589da586844d7f0818ce684948eea": ("TrickBot Banking Trojan", "critical"),
    "b384078a50301557075253653abb5ac5": ("Metasploit HTTPS Meterpreter", "critical"),
    "6734f37431670b3ab4292b8f60f29984": ("Emotet Modular Botnet", "critical"),
    "3b5074b1b9d03225b41800243413612c": ("Dridex Banking Trojan", "critical"),
    "eb1d94de9e8166333cace539655492f4": ("AsyncRAT / QuasarRAT C2 Agent", "critical"),
    "51c64c77e60f3980eea90869b68c58a8": ("Qakbot / Pinkslipbot Trojan", "critical"),
    "4d7a28d6f22da2e8ee70388d601660f3": ("PowerShell WinINet / WebClient Downloader", "high"),
    "e7d705a3286e19ea42f587b344ee6865": ("Go-http-client / Sliver C2 Beacon", "high"),
    "b32309a26951912be7dba376398abc3b": ("Python-requests / Urllib Scripting", "medium"),
    "cd08e31494f9531f560d64c695473da9": ("Standard Web Browser (Google Chrome)", "info"),
    "b3241b12b50fe7d47ec051c5cb3773ee": ("Standard Web Browser (Mozilla Firefox)", "info"),
}

# Known Search Engine URL query patterns
SEARCH_PATTERNS = [
    (re.compile(r'(?:google\.[a-z.]+|google\.[a-z]{2,3}\.[a-z]{2})/(?:search|webhp)\?.*?[?&]q=([^&#\s]+)', re.I), "Google"),
    (re.compile(r'bing\.com/search\?.*?[?&]q=([^&#\s]+)', re.I), "Bing"),
    (re.compile(r'duckduckgo\.com/\?.*?[?&]q=([^&#\s]+)', re.I), "DuckDuckGo"),
    (re.compile(r'youtube\.com/results\?.*?[?&]search_query=([^&#\s]+)', re.I), "YouTube"),
    (re.compile(r'wikipedia\.org/wiki/.*?search=([^&#\s]+)', re.I), "Wikipedia"),
    (re.compile(r'reddit\.com/search/\?.*?[?&]q=([^&#\s]+)', re.I), "Reddit"),
    (re.compile(r'yahoo\.com/search\?.*?[?&]p=([^&#\s]+)', re.I), "Yahoo"),
    (re.compile(r'baidu\.com/s\?.*?[?&]wd=([^&#\s]+)', re.I), "Baidu"),
    (re.compile(r'yandex\.[a-z.]+/search/\?.*?[?&]text=([^&#\s]+)', re.I), "Yandex"),
    (re.compile(r'[?&](?:q|query|search|k|search_query)=([^&#\s]+)', re.I), "Web Search Engine")
]


class PcapAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "PcapAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str, workspace: Optional[Any] = None) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()

        raw_bytes = b""
        try:
            if isinstance(file_path, (bytes, bytearray)):
                raw_bytes = bytes(file_path)
            else:
                with open(file_path, "rb") as f:
                    raw_bytes = f.read()
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to read PCAP capture: {e}",
                findings=[],
                data={}
            )

        if len(raw_bytes) < 24:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message="PCAP file is truncated or invalid (< 24 bytes)",
                findings=[],
                data={}
            )

        # Detect capture format
        is_pcapng = raw_bytes.startswith(b"\x0a\x0d\x0d\x0a")
        is_pcap = raw_bytes.startswith((b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"))

        if not is_pcap and not is_pcapng:
            if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
                return AnalyzerResult(
                    analyzer_name=self.name,
                    success=False,
                    error_message="Unsupported network packet capture format (unrecognized magic bytes)",
                    findings=[],
                    data={}
                )

        packets, link_type, format_desc = self._parse_packets(raw_bytes, is_pcapng)

        if not packets:
            findings.append(Finding(
                category="structure",
                severity="low",
                title="Empty Packet Capture",
                description=f"The capture file {filename} contains valid headers but zero decipherable packet frames.",
                details={"file_format": format_desc, "raw_size": len(raw_bytes)}
            ))
            return AnalyzerResult(
                analyzer_name=self.name,
                success=True,
                findings=findings,
                data={
                    "summary": {
                        "packet_count": 0,
                        "duration_seconds": 0.0,
                        "start_time": None,
                        "end_time": None,
                        "total_bytes": len(raw_bytes),
                        "data_rate_kbps": 0.0,
                        "link_type": link_type,
                        "file_format": format_desc
                    },
                    "protocols": {},
                    "top_endpoints": [],
                    "conversations": [],
                    "dns_queries": [],
                    "tls_sessions": [],
                    "http_transactions": [],
                    "credentials": [],
                    "transferred_files": [],
                    "carved_files": [],
                    "software_identified": [],
                    "gantt_items": [],
                    "urls": []
                }
            )

        # Dissect packets, reassemble streams, carve files, and aggregate telemetry
        dissection = self._dissect_capture(packets, workspace)

        # Build Security Findings
        findings.extend(dissection["findings"])

        # Extract URLs for reputation and pipeline checks
        for u in dissection["urls"]:
            urls.add(u)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data={
                "summary": dissection["summary"],
                "protocols": dissection["protocols"],
                "top_endpoints": dissection["top_endpoints"],
                "conversations": dissection["conversations"],
                "dns_queries": dissection["dns_queries"],
                "tls_sessions": dissection["tls_sessions"],
                "http_transactions": dissection["http_transactions"],
                "credentials": dissection["credentials"],
                "transferred_files": dissection["transferred_files"],
                "carved_files": dissection["carved_files"],
                "software_identified": dissection["software_identified"],
                "gantt_items": dissection["gantt_items"],
                "beaconing_flows": dissection.get("beaconing_flows", []),
                "ssh_sessions": dissection.get("ssh_sessions", []),
                "ja3_fingerprints": [t for t in dissection.get("tls_sessions", []) if t.get("ja3") or t.get("ja3s")],
                "search_queries": dissection.get("search_queries", []),
                "web_sessions": dissection.get("web_sessions", []),
                "exfiltration_tracker": dissection.get("exfiltration_tracker", {}),
                "terminal_sessions": dissection.get("terminal_sessions", []),
                "emails": dissection.get("emails", []),
                "urls": list(urls)
            }
        )

    # -------------------------------------------------------------------------
    # 1. Low-level Packet Extraction (PCAP & PCAPNG)
    # -------------------------------------------------------------------------
    def _parse_packets(self, raw_bytes: bytes, is_pcapng: bool) -> Tuple[List[Dict[str, Any]], str, str]:
        if is_pcapng:
            return self._parse_pcapng(raw_bytes)
        return self._parse_standard_pcap(raw_bytes)

    def _parse_standard_pcap(self, raw_bytes: bytes) -> Tuple[List[Dict[str, Any]], str, str]:
        magic = raw_bytes[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")

        try:
            magic_val, v_major, v_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
                f"{endian}IHHiIII", raw_bytes[:24]
            )
        except Exception:
            return [], "Unknown", "Corrupted PCAP Header"

        link_type_map = {
            1: "Ethernet",
            101: "Raw IP",
            105: "IEEE 802.11 Wireless",
            113: "Linux Cooked Capture (SLL)",
            276: "Linux Cooked Capture v2 (SLL2)"
        }
        link_type = link_type_map.get(network, f"LinkType-{network}")
        format_desc = f"Standard PCAP (libpcap v{v_major}.{v_minor}{', nanosecond' if is_nano else ''})"

        packets = []
        offset = 24
        pkt_hdr_fmt = f"{endian}IIII"
        file_len = len(raw_bytes)

        while offset + 16 <= file_len:
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, raw_bytes[offset:offset+16])
            offset += 16
            if offset + incl_len > file_len:
                break

            data = raw_bytes[offset:offset+incl_len]
            offset += incl_len

            ts = ts_sec + (ts_frac / 1e9 if is_nano else ts_frac / 1e6)
            packets.append({
                "timestamp": ts,
                "length": orig_len,
                "data": data,
                "link_type": link_type
            })

            if len(packets) >= 50000:
                break

        return packets, link_type, format_desc

    def _parse_pcapng(self, raw_bytes: bytes) -> Tuple[List[Dict[str, Any]], str, str]:
        packets = []
        offset = 0
        file_len = len(raw_bytes)
        endian = "<"
        link_type = "Ethernet"
        format_desc = "PCAP Next Generation (PCAPNG)"

        while offset + 8 <= file_len:
            block_type = int.from_bytes(raw_bytes[offset:offset+4], "little")
            block_len = int.from_bytes(raw_bytes[offset+4:offset+8], "little")

            if block_type == 0x0A0D0D0A:
                if offset + 12 <= file_len:
                    bom = raw_bytes[offset+8:offset+12]
                    endian = "<" if bom in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d") else ">"
                    block_len = struct.unpack(f"{endian}I", raw_bytes[offset+4:offset+8])[0]
            else:
                block_len = struct.unpack(f"{endian}I", raw_bytes[offset+4:offset+8])[0]

            if block_len < 12 or offset + block_len > file_len:
                break

            block_data = raw_bytes[offset:offset+block_len]

            if block_type == 0x00000001 and len(block_data) >= 16:
                link_id = struct.unpack(f"{endian}H", block_data[8:10])[0]
                link_map = {1: "Ethernet", 101: "Raw IP", 105: "802.11", 113: "Linux SLL"}
                link_type = link_map.get(link_id, f"LinkType-{link_id}")

            elif block_type == 0x00000006 and len(block_data) >= 32:
                ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIII", block_data[12:28])
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw / 1e6
                pkt_data = block_data[28:28+cap_len]
                packets.append({
                    "timestamp": ts,
                    "length": orig_len,
                    "data": pkt_data,
                    "link_type": link_type
                })
                if len(packets) >= 50000:
                    break

            elif block_type == 0x00000003 and len(block_data) >= 16:
                orig_len = struct.unpack(f"{endian}I", block_data[8:12])[0]
                cap_len = min(orig_len, block_len - 16)
                pkt_data = block_data[12:12+cap_len]
                packets.append({
                    "timestamp": 0.0,
                    "length": orig_len,
                    "data": pkt_data,
                    "link_type": link_type
                })
                if len(packets) >= 50000:
                    break

            offset += block_len

        return packets, link_type, format_desc

    # -------------------------------------------------------------------------
    # 2. Forensic Dissection & Telemetry Aggregation
    # -------------------------------------------------------------------------
    def _dissect_capture(self, packets: List[Dict[str, Any]], workspace: Optional[Any] = None) -> Dict[str, Any]:
        flows: Dict[str, Dict[str, Any]] = {}
        ip_stats: Dict[str, Dict[str, int]] = {}
        ip_peers: Dict[str, Dict[str, Dict[str, Any]]] = {}
        protocol_counts: Dict[str, int] = {}
        dns_queries: List[Dict[str, Any]] = []
        tls_sessions: List[Dict[str, Any]] = []
        http_transactions: List[Dict[str, Any]] = []
        credentials: List[Dict[str, Any]] = []
        transferred_files: List[Dict[str, Any]] = []
        search_queries: List[Dict[str, Any]] = []
        web_sessions: List[Dict[str, Any]] = []
        extracted_urls: Set[str] = set()
        findings: List[Finding] = []
        ssh_sessions: List[Dict[str, Any]] = []
        flow_timestamps: Dict[str, List[float]] = {}
        seen_ja3: Set[str] = set()
        seen_searches: Set[str] = set()

        # Raw TCP stream buffers for deep payload reconstruction & file carving
        stream_payloads: Dict[str, bytearray] = {}
        stream_packets: Dict[str, List[Dict[str, Any]]] = {}

        total_bytes = 0
        min_ts = None
        max_ts = None

        seen_dns = set()
        seen_tls_sni = set()
        seen_creds = set()
        seen_transfers = set()

        for pkt in packets:
            data = pkt["data"]
            length = pkt["length"]
            ts = pkt["timestamp"]

            total_bytes += length
            if ts > 0:
                if min_ts is None or ts < min_ts:
                    min_ts = ts
                if max_ts is None or ts > max_ts:
                    max_ts = ts

            # Decode Ethernet / Link layer
            l3_proto, ip_payload = self._decode_link_layer(data, pkt.get("link_type", "Ethernet"))
            if not ip_payload:
                continue

            src_ip, dst_ip, l4_proto, l4_payload = self._decode_ip_layer(l3_proto, ip_payload)
            if not src_ip or not dst_ip:
                continue

            if ts > 0:
                ft_key = f"{src_ip}->{dst_ip}"
                if ft_key not in flow_timestamps:
                    flow_timestamps[ft_key] = []
                flow_timestamps[ft_key].append(ts)

            # Update IP statistics
            for ip_addr, is_src in [(src_ip, True), (dst_ip, False)]:
                if ip_addr not in ip_stats:
                    ip_stats[ip_addr] = {"packets": 0, "bytes": 0, "sent": 0, "recv": 0}
                ip_stats[ip_addr]["packets"] += 1
                ip_stats[ip_addr]["bytes"] += length
                if is_src:
                    ip_stats[ip_addr]["sent"] += length
                else:
                    ip_stats[ip_addr]["recv"] += length

            # Record peer interactions
            if src_ip not in ip_peers:
                ip_peers[src_ip] = {}
            if dst_ip not in ip_peers[src_ip]:
                ip_peers[src_ip][dst_ip] = {"packets": 0, "bytes": 0, "protocols": set(), "ports": set()}
            ip_peers[src_ip][dst_ip]["packets"] += 1
            ip_peers[src_ip][dst_ip]["bytes"] += length

            if not l4_payload:
                continue

            # Decode Transport layer with TCP flags
            src_port, dst_port, app_proto, app_payload, tcp_flags = self._decode_transport_layer(l4_proto, l4_payload)

            proto_name = app_proto or l4_proto
            protocol_counts[proto_name] = protocol_counts.get(proto_name, 0) + 1
            ip_peers[src_ip][dst_ip]["protocols"].add(proto_name)
            ip_peers[src_ip][dst_ip]["ports"].add(dst_port)

            flow_key = self._flow_key(src_ip, src_port, dst_ip, dst_port, l4_proto)
            is_client_to_server = (flow_key.split("<->")[0] == f"{src_ip}:{src_port}")

            if flow_key not in flows:
                flows[flow_key] = {
                    "id": f"flow_{len(flows)+1}",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "transport": l4_proto,
                    "protocol": proto_name,
                    "packets": 0,
                    "bytes": 0,
                    "client_packets": 0,
                    "client_bytes": 0,
                    "server_packets": 0,
                    "server_bytes": 0,
                    "start_time": ts,
                    "end_time": ts,
                    "flags_summary": {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0},
                    "state": "ACTIVE",
                    "payload_preview_hex": "",
                    "payload_preview_ascii": "",
                    "payload_bytes": bytearray()
                }

            fl = flows[flow_key]
            fl["packets"] += 1
            fl["bytes"] += length
            fl["end_time"] = ts

            if is_client_to_server:
                fl["client_packets"] += 1
                fl["client_bytes"] += length
            else:
                fl["server_packets"] += 1
                fl["server_bytes"] += length

            if proto_name != l4_proto:
                fl["protocol"] = proto_name

            # Accumulate TCP flags
            if tcp_flags:
                for f_name, f_val in tcp_flags.items():
                    if f_val:
                        fl["flags_summary"][f_name] = fl["flags_summary"].get(f_name, 0) + 1
                if tcp_flags.get("rst"):
                    fl["state"] = "RESET_BY_PEER"
                elif tcp_flags.get("fin") and fl["state"] != "RESET_BY_PEER":
                    fl["state"] = "TERMINATED_NORMAL"
                elif tcp_flags.get("syn") and tcp_flags.get("ack"):
                    fl["state"] = "ESTABLISHED"

            # Accumulate stream payloads for carving and inspection
            if app_payload:
                if flow_key not in stream_payloads:
                    stream_payloads[flow_key] = bytearray()
                    stream_packets[flow_key] = []
                if len(stream_payloads[flow_key]) < 500000:
                    stream_payloads[flow_key].extend(app_payload)
                stream_packets[flow_key].append({
                    "ts": ts,
                    "src": src_ip,
                    "dst": dst_ip,
                    "len": len(app_payload),
                    "data": app_payload
                })

                if len(fl["payload_bytes"]) < 2048:
                    fl["payload_bytes"].extend(app_payload[:512])

            # Application layer dissection
            if not app_payload:
                continue

            # A. DNS Dissection (Port 53)
            if app_proto == "DNS" or src_port == 53 or dst_port == 53:
                dns_res = self._parse_dns(app_payload)
                if dns_res:
                    protocol_counts["DNS"] = protocol_counts.get("DNS", 0) + 1
                    for q in dns_res.get("questions", []):
                        d_name = q.get("domain", "").lower()
                        if d_name and d_name not in seen_dns:
                            seen_dns.add(d_name)
                            is_susp = self._is_suspicious_domain(d_name)
                            entry = {
                                "domain": d_name,
                                "query_type": q.get("qtype", "A"),
                                "resolved_ips": dns_res.get("answers", []),
                                "client_ip": src_ip if dst_port == 53 else dst_ip,
                                "is_suspicious": is_susp,
                                "threat_status": "SUSPICIOUS" if is_susp else "CLEAN"
                            }
                            # Shannon entropy & DNS tunneling detection
                            d_parts = d_name.split(".")
                            subdomain = ".".join(d_parts[:-2]) if len(d_parts) > 2 else d_parts[0]
                            sub_entropy = 0.0
                            if len(subdomain) >= 15:
                                char_counts = collections.Counter(subdomain)
                                sub_entropy = -sum((c / len(subdomain)) * math.log2(c / len(subdomain)) for c in char_counts.values())

                            if len(subdomain) >= 30 and sub_entropy >= 3.8:
                                entry["is_dns_tunneling"] = True
                                is_susp = True
                                findings.append(Finding(
                                    category="network",
                                    severity="critical",
                                    title=f"DNS Tunneling / Exfiltration Query: {d_name[:35]}...",
                                    description=(
                                        f"DNS query '{d_name}' displays high character length ({len(subdomain)} chars) and high Shannon entropy "
                                        f"({round(sub_entropy, 2)} bits). Typical of automated DNS data exfiltration tunnels (e.g. dnscat2, iodine)."
                                    ),
                                    details={"domain": d_name, "subdomain_len": len(subdomain), "entropy": round(sub_entropy, 2)}
                                ))

                            # Check domain reputation
                            try:
                                tf_d = ThreatFoxClient.check_ioc(d_name)
                                if tf_d.get("status") == "MALICIOUS":
                                    entry["threat_status"] = "MALICIOUS"
                                    entry["is_suspicious"] = True
                            except Exception:
                                pass

                            dns_queries.append(entry)
                            if is_susp and not entry.get("is_dns_tunneling"):
                                findings.append(Finding(
                                    category="network",
                                    severity="high",
                                    title=f"Suspicious DNS Query: {d_name}",
                                    description=f"DNS query for potentially malicious domain or high-entropy dynamic DNS target {d_name}.",
                                    details=entry
                                ))

            # B. TLS SNI & JA3/JA3S Fingerprinting (Port 443 / TLS)
            if app_proto == "TLS" or dst_port == 443 or src_port == 443:
                tls_info = self._parse_tls(app_payload)
                sni = tls_info.get("sni")
                ja3_val = tls_info.get("ja3")
                ja3s_val = tls_info.get("ja3s")
                if sni or ja3_val or ja3s_val:
                    sess_key = f"{src_ip}:{dst_ip}:{ja3_val or ja3s_val}:{sni}"
                    if sess_key not in seen_tls_sni:
                        seen_tls_sni.add(sess_key)
                        protocol_counts["TLS"] = protocol_counts.get("TLS", 0) + 1
                        t_entry = {
                            "sni": sni,
                            "client_ip": src_ip,
                            "server_ip": dst_ip,
                            "server_port": dst_port,
                            "tls_version": tls_info.get("tls_version", "TLS 1.2/1.3"),
                            "handshake_type": tls_info.get("handshake_type"),
                            "ja3": ja3_val,
                            "ja3_string": tls_info.get("ja3_string"),
                            "ja3_match": tls_info.get("ja3_match"),
                            "ja3s": ja3s_val,
                            "ja3s_string": tls_info.get("ja3s_string")
                        }
                        tls_sessions.append(t_entry)
                        if sni:
                            extracted_urls.add(f"https://{sni}")

                        if tls_info.get("ja3_match") and ja3_val not in seen_ja3:
                            seen_ja3.add(ja3_val)
                            mal_name, sev = tls_info["ja3_match"]
                            findings.append(Finding(
                                category="network",
                                severity=sev,
                                title=f"Malicious TLS Fingerprint (JA3): {mal_name}",
                                description=f"TLS Client Hello matches known threat fingerprint ({ja3_val}) associated with {mal_name}.",
                                details={"ja3": ja3_val, "malware": mal_name, "dst_ip": dst_ip, "sni": sni}
                            ))

            # C. HTTP Request / Response Dissection (Port 80 / HTTP)
            if app_proto == "HTTP" or dst_port in (80, 8080, 8000, 8888) or src_port in (80, 8080, 8000, 8888):
                http_item = self._parse_http(app_payload, src_ip, dst_ip, src_port, dst_port, ts)
                if http_item:
                    protocol_counts["HTTP"] = protocol_counts.get("HTTP", 0) + 1
                    http_transactions.append(http_item)
                    if http_item.get("full_url"):
                        extracted_urls.add(http_item["full_url"])

                    # Reconstruct search engine queries (PCAP Item 1)
                    if http_item.get("search_query"):
                        sq = http_item["search_query"]
                        sq_k = f"{sq['query']}:{sq['search_engine']}"
                        if sq_k not in seen_searches:
                            seen_searches.add(sq_k)
                            search_queries.append(sq)

                    # Reconstruct submitted POST form data and sessions (PCAP Item 1)
                    if http_item.get("post_submission"):
                        web_sessions.append(http_item["post_submission"])

                    # Check for cleartext credentials in HTTP
                    if http_item.get("credentials"):
                        c_key = f"{http_item['credentials']['username']}:{http_item['credentials']['password']}"
                        if c_key not in seen_creds:
                            seen_creds.add(c_key)
                            cred_obj = {
                                "protocol": "HTTP",
                                "username": http_item["credentials"]["username"],
                                "password": http_item["credentials"]["password"],
                                "client_ip": src_ip,
                                "server_ip": dst_ip
                            }
                            credentials.append(cred_obj)
                            findings.append(Finding(
                                category="credential",
                                severity="critical",
                                title="Cleartext HTTP Credentials Detected",
                                description=f"Unencrypted authentication credentials ({cred_obj['username']}) captured in plain HTTP transmission to {dst_ip}.",
                                details=cred_obj
                            ))

                    # Check for downloaded/transferred files
                    if http_item.get("transferred_file"):
                        tf = http_item["transferred_file"]
                        tf_key = f"{tf['filename']}:{tf.get('source_url', '')}"
                        if tf_key not in seen_transfers:
                            seen_transfers.add(tf_key)
                            transferred_files.append(tf)
                            if tf.get("is_dangerous"):
                                findings.append(Finding(
                                    category="payload",
                                    severity="critical",
                                    title=f"Executable/Script Payload Downloaded: {tf['filename']}",
                                    description=f"Identified transfer of high-risk file payload '{tf['filename']}' over unencrypted HTTP from {dst_ip}.",
                                    details=tf
                                ))

            # D. FTP Command Dissection (Port 21)
            if src_port == 21 or dst_port == 21:
                protocol_counts["FTP"] = protocol_counts.get("FTP", 0) + 1
                ftp_info = self._parse_ftp(app_payload, src_ip, dst_ip)
                if ftp_info:
                    if ftp_info.get("credential"):
                        c = ftp_info["credential"]
                        c_key = f"ftp:{c['username']}:{c.get('password', '')}"
                        if c_key not in seen_creds and c.get("password"):
                            seen_creds.add(c_key)
                            credentials.append(c)
                            findings.append(Finding(
                                category="credential",
                                severity="critical",
                                title=f"Cleartext FTP Credentials: {c['username']}",
                                description=f"Unencrypted FTP password exposed in network packet stream to {dst_ip}.",
                                details=c
                            ))
                    if ftp_info.get("transferred_file"):
                        tf = ftp_info["transferred_file"]
                        tf_key = f"{tf['filename']}:ftp"
                        if tf_key not in seen_transfers:
                            seen_transfers.add(tf_key)
                            transferred_files.append(tf)

            # E. Email Protocols (SMTP / POP3 / IMAP)
            if src_port in (25, 587, 110, 143) or dst_port in (25, 587, 110, 143):
                p_label = "SMTP" if 25 in (src_port, dst_port) or 587 in (src_port, dst_port) else "POP3" if 110 in (src_port, dst_port) else "IMAP"
                protocol_counts[p_label] = protocol_counts.get(p_label, 0) + 1

            # E. SSH Dissection & HASSH Fingerprinting (Port 22)
            if src_port == 22 or dst_port == 22:
                protocol_counts["SSH"] = protocol_counts.get("SSH", 0) + 1
                ssh_info = self._parse_ssh(app_payload)
                ssh_banner = ssh_info.get("banner")
                hassh_hash = ssh_info.get("hassh")
                if ssh_banner or hassh_hash:
                    ssh_entry = {
                        "client_ip": src_ip,
                        "server_ip": dst_ip,
                        "banner": ssh_banner,
                        "hassh": hassh_hash,
                        "hassh_string": ssh_info.get("hassh_string")
                    }
                    ssh_sessions.append(ssh_entry)
                    if ssh_banner:
                        findings.append(Finding(
                            category="network",
                            severity="info",
                            title=f"SSH Handshake Banner: {ssh_banner[:35]}",
                            description=f"Detected SSH session between {src_ip} and {dst_ip}. Software banner: {ssh_banner}. HASSH: {hassh_hash or 'N/A'}",
                            details=ssh_entry
                        ))

        # Overall Capture Duration & Rates
        min_ts_val = min_ts or 0.0
        max_ts_val = max_ts or min_ts_val
        duration_s = round(max(0.0, max_ts_val - min_ts_val), 3)
        start_iso = datetime.fromtimestamp(min_ts, timezone.utc).isoformat() if min_ts else None
        end_iso = datetime.fromtimestamp(max_ts, timezone.utc).isoformat() if max_ts else None
        kbps = round((total_bytes * 8 / 1024) / max(0.001, duration_s), 2) if duration_s > 0 else 0.0

        # C2 Periodic Beaconing Detection across IP flows
        beaconing_candidates: List[Dict[str, Any]] = []
        for flow_key, timestamps in flow_timestamps.items():
            if len(timestamps) < 5:
                continue
            timestamps.sort()
            deltas = []
            for i in range(1, len(timestamps)):
                dt = timestamps[i] - timestamps[i-1]
                if dt >= 0.1:  # filter sub-100ms packet bursts within the same socket transfer
                    deltas.append(dt)
            if len(deltas) >= 4:
                mean_dt = sum(deltas) / len(deltas)
                if 1.0 <= mean_dt <= 600.0:
                    variance = sum((x - mean_dt) ** 2 for x in deltas) / len(deltas)
                    std_dev = math.sqrt(variance)
                    jitter_pct = (std_dev / mean_dt) * 100.0
                    if jitter_pct <= 25.0:
                        s_ip, d_ip = flow_key.split("->")
                        beacon_rec = {
                            "source_ip": s_ip,
                            "target_ip": d_ip,
                            "connection_count": len(deltas) + 1,
                            "mean_interval_sec": round(mean_dt, 2),
                            "std_dev_sec": round(std_dev, 3),
                            "jitter_percent": round(jitter_pct, 1),
                            "min_interval": round(min(deltas), 2),
                            "max_interval": round(max(deltas), 2)
                        }
                        beaconing_candidates.append(beacon_rec)
                        findings.append(Finding(
                            category="network",
                            severity="critical" if jitter_pct <= 10.0 else "high",
                            title=f"C2 Periodic Beaconing Detected ({d_ip} - ~{round(mean_dt, 1)}s interval, {round(jitter_pct, 1)}% jitter)",
                            description=(
                                f"Network communications between {s_ip} and {d_ip} demonstrate algorithmic regularity: "
                                f"mean delta {round(mean_dt, 2)}s with minimal jitter ({round(jitter_pct, 1)}%). "
                                "This timing signature is typical of automated Command & Control (C2) heartbeat beaconing (Cobalt Strike, Havoc, Sliver, Empire)."
                            ),
                            details=beacon_rec
                        ))

        # Post-process Flows (Hex and ASCII previews, throughput, offsets)
        processed_flows: List[Dict[str, Any]] = []
        for fl_key, fl in flows.items():
            fl_start = fl["start_time"] or min_ts_val
            fl_end = fl["end_time"] or fl_start
            fl_dur = round(max(0.0, fl_end - fl_start), 3)
            fl["duration_seconds"] = fl_dur
            fl["start_offset"] = round(max(0.0, fl_start - min_ts_val), 3)
            fl["end_offset"] = round(max(0.0, fl_end - min_ts_val), 3)
            fl["throughput_kbps"] = round((fl["bytes"] * 8 / 1024) / max(0.001, fl_dur), 2) if fl_dur > 0 else 0.0

            # Hex and ASCII previews (Wireshark-style)
            p_bytes = bytes(fl.pop("payload_bytes", b""))
            preview_slice = p_bytes[:256]
            fl["payload_preview_hex"] = preview_slice.hex()
            fl["payload_preview_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in preview_slice)
            fl["payload_size"] = len(stream_payloads.get(fl_key, b""))

            processed_flows.append(fl)

        # Sort flows by total bytes transferred
        sorted_conversations = sorted(processed_flows, key=lambda x: x["bytes"], reverse=True)[:35]

        # ---------------------------------------------------------------------
        # 3. File Carving Pipeline
        # ---------------------------------------------------------------------
        carved_files = self._carve_files(
            stream_payloads=stream_payloads,
            flows=flows,
            http_transactions=http_transactions,
            transferred_files=transferred_files,
            workspace=workspace
        )

        for cf in carved_files:
            if cf.get("is_dangerous"):
                findings.append(Finding(
                    category="carved_payload",
                    severity="critical" if cf.get("threat_intel", {}).get("malicious") else "high",
                    title=f"Extracted/Carved File Payload: '{cf['filename']}' ({cf['size_formatted']})",
                    description=(
                        f"Carved {cf['mime_type']} artifact from network stream ({cf['source_protocol']}). "
                        f"SHA256: {cf['sha256'][:16]}... Threat reason: {cf.get('threat_reason', 'Executable payload')}"
                    ),
                    details=cf
                ))

        # ---------------------------------------------------------------------
        # 4. Software & Application Fingerprinting
        # ---------------------------------------------------------------------
        software_identified = self._identify_software(
            http_transactions=http_transactions,
            packets=packets,
            flows=flows
        )

        # ---------------------------------------------------------------------
        # 5. Gantt Timeline Items Generation
        # ---------------------------------------------------------------------
        gantt_items = []
        eff_duration = max(0.1, duration_s)
        for fl in sorted_conversations:
            s_sec = fl.get("start_offset", 0.0)
            d_sec = fl.get("duration_seconds", 0.0)
            raw_start_pct = (s_sec / eff_duration) * 100.0
            start_pct = round(min(96.0, max(0.0, raw_start_pct)), 2)
            # Ensure minimum visual width of 3.5% so short single-packet flows are easily clickable
            width_pct = round(min(100.0 - start_pct, max(3.5, (d_sec / eff_duration) * 100.0)), 2)

            # Correlate flow with parsed HTTP transactions
            matching_http = next(
                (tx for tx in http_transactions if (
                    (tx.get("client_ip") == fl["src_ip"] and tx.get("server_ip") == fl["dst_ip"]) or
                    (tx.get("client_ip") == fl["dst_ip"] and tx.get("server_ip") == fl["src_ip"])
                )),
                None
            )

            # Correlate with DNS query
            matching_dns = next(
                (dq for dq in dns_queries if (
                    dq.get("client_ip") in (fl["src_ip"], fl["dst_ip"]) or
                    dq.get("server_ip") in (fl["src_ip"], fl["dst_ip"])
                )),
                None
            )

            # Correlate with TLS session
            matching_tls = next(
                (ts for ts in tls_sessions if (
                    (ts.get("client_ip") == fl["src_ip"] and ts.get("server_ip") == fl["dst_ip"]) or
                    (ts.get("client_ip") == fl["dst_ip"] and ts.get("server_ip") == fl["src_ip"])
                )),
                None
            )

            # Correlate with SSH session
            matching_ssh = next(
                (ss for ss in ssh_sessions if (
                    (ss.get("client_ip") == fl["src_ip"] and ss.get("server_ip") == fl["dst_ip"]) or
                    (ss.get("client_ip") == fl["dst_ip"] and ss.get("server_ip") == fl["src_ip"])
                )),
                None
            )

            # Correlate with Carved / Transferred Files
            matching_file = next(
                (cf for cf in carved_files if (
                    fl["id"] in str(cf.get("source_stream", "")) or
                    (fl["src_ip"] in str(cf.get("source_stream", "")) and fl["dst_ip"] in str(cf.get("source_stream", "")))
                )),
                None
            )
            if not matching_file:
                matching_file = next(
                    (tf for tf in transferred_files if (
                        (tf.get("client_ip") == fl["src_ip"] and tf.get("server_ip") == fl["dst_ip"]) or
                        (tf.get("client_ip") == fl["dst_ip"] and tf.get("server_ip") == fl["src_ip"])
                    )),
                    None
                )

            stream_ascii = fl.get("payload_preview_ascii", "")

            # FTP Command detection
            ftp_commands = []
            if fl["protocol"] == "FTP" or fl.get("src_port") == 21 or fl.get("dst_port") == 21:
                ftp_commands = re.findall(r'(?:USER|PASS|RETR|STOR|DELE|LIST|PWD|CWD|PORT|PASV|QUIT)\s+[^\r\n]+', stream_ascii)

            # SMB Share / File Access detection
            smb_share = None
            smb_action = None
            if fl["protocol"] == "SMB" or fl.get("src_port") in (445, 139) or fl.get("dst_port") in (445, 139):
                share_match = re.search(r'\\\\[a-zA-Z0-9_.$ -]+\\[a-zA-Z0-9_.$ -]+', stream_ascii)
                if share_match:
                    smb_share = share_match.group(0)
                    smb_action = "TreeConnect / Access"

            # SQL Query detection
            sql_query = None
            if fl["protocol"] == "SQL" or fl.get("src_port") in (1433, 3306, 5432, 1521) or fl.get("dst_port") in (1433, 3306, 5432, 1521):
                sql_match = re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|xp_cmdshell|UNION)\s+[^\r\n;]+', stream_ascii, re.IGNORECASE)
                if sql_match:
                    sql_query = sql_match.group(0).strip()[:100]

            # Email (SMTP / POP3 / IMAP) detection
            email_subject = None
            email_sender = None
            email_recipient = None
            if fl["protocol"] in ("SMTP", "POP3", "IMAP") or fl.get("src_port") in (25, 587, 110, 143, 993, 995) or fl.get("dst_port") in (25, 587, 110, 143, 993, 995):
                subj_m = re.search(r'Subject:\s*([^\r\n]+)', stream_ascii, re.IGNORECASE)
                if subj_m:
                    email_subject = subj_m.group(1).strip()
                from_m = re.search(r'(?:FROM|MAIL FROM):\s*<([^\r\n>]+)>', stream_ascii, re.IGNORECASE)
                if from_m:
                    email_sender = from_m.group(1).strip()
                to_m = re.search(r'(?:TO|RCPT TO):\s*<([^\r\n>]+)>', stream_ascii, re.IGNORECASE)
                if to_m:
                    email_recipient = to_m.group(1).strip()

            # Synthesize User Traffic Narrative & fields
            summary_narrative = ""
            site = None
            method = None
            path = None
            query_params = None
            status_code = None
            user_agent = None

            if matching_http:
                site = matching_http.get("host")
                method = matching_http.get("method", "GET")
                raw_uri = matching_http.get("uri") or matching_http.get("path") or "/"
                if "?" in raw_uri:
                    path, query_params = raw_uri.split("?", 1)
                else:
                    path = raw_uri
                status_code = matching_http.get("response_code") or matching_http.get("status_code")
                user_agent = matching_http.get("user_agent")
                summary_narrative = f"{method} {path}" + (f"?{query_params[:45]}..." if query_params and len(query_params) > 45 else (f"?{query_params}" if query_params else ""))
                if site:
                    summary_narrative += f" [{site}]"
                if status_code:
                    summary_narrative += f" ({status_code})"
            elif fl["protocol"] == "FTP" or ftp_commands:
                cmds_disp = "; ".join(ftp_commands[:2]) if ftp_commands else "Session Established"
                summary_narrative = f"FTP: {cmds_disp}"
            elif matching_dns:
                qname = matching_dns.get("query_name", "")
                answers = matching_dns.get("resolved_ips", [])
                summary_narrative = f"DNS Query: '{qname}'"
                if answers:
                    summary_narrative += f" -> [{', '.join(answers[:2])}]"
            elif matching_tls:
                sni = matching_tls.get("sni")
                ja3_val = matching_tls.get("ja3")
                summary_narrative = f"TLS SNI: {sni}" if sni else "Encrypted HTTPS/TLS Session"
                if ja3_val:
                    summary_narrative += f" (JA3: {ja3_val[:8]}...)"
            elif matching_ssh:
                sbanner = matching_ssh.get("server_banner") or matching_ssh.get("client_banner") or "SSH-2.0"
                summary_narrative = f"SSH Handshake: {sbanner}"
            elif smb_share:
                summary_narrative = f"SMB Share: {smb_share}"
            elif sql_query:
                summary_narrative = f"SQL Query: {sql_query}"
            elif email_subject or email_sender:
                summary_narrative = f"Email: '{email_subject or 'Message'}'" + (f" from {email_sender}" if email_sender else "")
            else:
                summary_narrative = f"{fl['protocol']} session ({fl['packets']} pkts, {format_file_size(fl['bytes'])})"

            # Transferred file metadata
            tf_data = None
            if matching_file:
                tf_data = {
                    "filename": matching_file.get("filename") or matching_file.get("name", "payload.bin"),
                    "filesize": matching_file.get("size", 0),
                    "filesize_formatted": matching_file.get("size_formatted") or format_file_size(matching_file.get("size", 0)),
                    "sha256": matching_file.get("sha256"),
                    "md5": matching_file.get("md5"),
                    "direction": "download" if fl["dst_ip"] == matching_file.get("client_ip") else "upload"
                }
                summary_narrative += f" | Carved File: {tf_data['filename']} ({tf_data['filesize_formatted']})"

            gantt_items.append({
                "flow_id": fl["id"],
                "protocol": fl["protocol"],
                "src_endpoint": f"{fl['src_ip']}:{fl['src_port']}",
                "dst_endpoint": f"{fl['dst_ip']}:{fl['dst_port']}",
                "start_seconds": s_sec,
                "duration_seconds": d_sec,
                "bytes": fl["bytes"],
                "packets": fl["packets"],
                "start_pct": start_pct,
                "width_pct": width_pct,
                "summary_narrative": summary_narrative,
                "site": site,
                "method": method,
                "path": path,
                "query_params": query_params,
                "status_code": status_code,
                "user_agent": user_agent,
                "commands": ftp_commands,
                "transferred_file": tf_data,
                "dns_query": matching_dns.get("query_name") if matching_dns else None,
                "dns_answers": matching_dns.get("resolved_ips") if matching_dns else None,
                "smb_share": smb_share,
                "smb_action": smb_action,
                "sql_query": sql_query,
                "email_subject": email_subject,
                "email_sender": email_sender,
                "email_recipient": email_recipient,
                "tls_sni": matching_tls.get("sni") if matching_tls else None,
                "ja3": matching_tls.get("ja3") if matching_tls else None
            })

        # ---------------------------------------------------------------------
        # 6. Enriched Top Endpoints (Geo, Reputation, Peers)
        # ---------------------------------------------------------------------
        enriched_endpoints: List[Dict[str, Any]] = []
        for ip, st in sorted(ip_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:20]:
            geo = GeoResolver.resolve_ip(ip)
            is_priv = geo.get("is_private", True)

            # Peer summary
            raw_peers = ip_peers.get(ip, {})
            peers_list = []
            for p_ip, p_st in sorted(raw_peers.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]:
                peers_list.append({
                    "ip": p_ip,
                    "packets": p_st["packets"],
                    "bytes": p_st["bytes"],
                    "protocols": list(p_st["protocols"]),
                    "ports": list(p_st["ports"])[:5]
                })

            # Associated flows
            assoc_flows = [fl["id"] for fl in processed_flows if fl["src_ip"] == ip or fl["dst_ip"] == ip][:15]

            # Threat lookup if public IP
            abuse_res = None
            otx_res = None
            if not is_priv:
                try:
                    abuse_res = AbuseIPDBClient.check_ip(ip)
                except Exception:
                    pass
                try:
                    otx_res = AlienVaultOTXClient.check_indicator("IPv4", ip)
                except Exception:
                    pass

            ep_data = {
                "ip": ip,
                "packets": st["packets"],
                "bytes": st["bytes"],
                "sent": st["sent"],
                "recv": st["recv"],
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "asn": geo.get("asn", "Unknown"),
                "is_private": is_priv,
                "abuseipdb": abuse_res,
                "otx": otx_res,
                "peers": peers_list,
                "flow_ids": assoc_flows
            }
            enriched_endpoints.append(ep_data)

        summary = {
            "packet_count": len(packets),
            "duration_seconds": duration_s,
            "start_time": start_iso,
            "end_time": end_iso,
            "total_bytes": total_bytes,
            "data_rate_kbps": kbps,
            "link_type": packets[0].get("link_type", "Ethernet") if packets else "Ethernet",
            "file_format": "PCAP Network Packet Capture"
        }

        # 6. Terminal & Command Session Playback Reconstructor (PCAP Item 3)
        terminal_sessions = self._reconstruct_terminal_sessions(stream_packets, flows)

        # 7. Email & Communication Interceptor (PCAP Item 4)
        emails = self._reconstruct_emails(stream_packets, flows)

        # 8. Interactive File Transfer & Exfiltration Tracker (PCAP Item 2)
        exfiltration_tracker = self._compute_exfiltration_tracker(
            flows=flows,
            transferred_files=transferred_files,
            carved_files=carved_files,
            findings=findings
        )

        return {
            "summary": summary,
            "protocols": protocol_counts,
            "top_endpoints": enriched_endpoints,
            "conversations": sorted_conversations,
            "dns_queries": dns_queries[:50],
            "tls_sessions": tls_sessions[:50],
            "http_transactions": http_transactions[:50],
            "credentials": credentials,
            "transferred_files": transferred_files[:30],
            "carved_files": carved_files,
            "software_identified": software_identified,
            "gantt_items": gantt_items,
            "beaconing_flows": beaconing_candidates,
            "ssh_sessions": ssh_sessions,
            "search_queries": search_queries[:50],
            "web_sessions": web_sessions[:50],
            "exfiltration_tracker": exfiltration_tracker,
            "terminal_sessions": terminal_sessions[:30],
            "emails": emails[:30],
            "urls": extracted_urls,
            "findings": findings
        }

    # -------------------------------------------------------------------------
    # 3. Layer Decoders
    # -------------------------------------------------------------------------
    def _decode_link_layer(self, data: bytes, link_type: str) -> Tuple[int, bytes]:
        if link_type == "Ethernet":
            if len(data) < 14:
                return 0, b""
            eth_type = int.from_bytes(data[12:14], "big")
            offset = 14
            if eth_type == 0x8100 and len(data) >= 18:
                eth_type = int.from_bytes(data[16:18], "big")
                offset = 18
            return eth_type, data[offset:]

        elif "SLL" in link_type:
            if len(data) < 16:
                return 0, b""
            eth_type = int.from_bytes(data[14:16], "big")
            return eth_type, data[16:]

        elif link_type == "Raw IP":
            if len(data) > 0:
                v = (data[0] >> 4) & 0x0F
                return (0x0800 if v == 4 else (0x86DD if v == 6 else 0)), data
            return 0, b""

        return 0, b""

    def _decode_ip_layer(self, eth_type: int, payload: bytes) -> Tuple[Optional[str], Optional[str], str, bytes]:
        if eth_type == 0x0800 and len(payload) >= 20:
            ihl = (payload[0] & 0x0F) * 4
            if len(payload) < ihl:
                return None, None, "", b""
            proto_num = payload[9]
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}
            proto_name = proto_map.get(proto_num, f"IP-{proto_num}")
            src_ip = socket.inet_ntoa(payload[12:16])
            dst_ip = socket.inet_ntoa(payload[16:20])
            return src_ip, dst_ip, proto_name, payload[ihl:]

        elif eth_type == 0x86DD and len(payload) >= 40:
            proto_num = payload[6]
            proto_map = {1: "ICMPv6", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
            proto_name = proto_map.get(proto_num, f"IPv6-{proto_num}")
            src_ip = socket.inet_ntop(socket.AF_INET6, payload[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, payload[24:40])
            return src_ip, dst_ip, proto_name, payload[40:]

        return None, None, "", b""

    def _decode_transport_layer(
        self, l4_proto: str, payload: bytes
    ) -> Tuple[int, int, Optional[str], bytes, Optional[Dict[str, bool]]]:
        if l4_proto == "TCP" and len(payload) >= 20:
            src_port = int.from_bytes(payload[0:2], "big")
            dst_port = int.from_bytes(payload[2:4], "big")
            data_offset = ((payload[12] >> 4) & 0x0F) * 4
            app_data = payload[data_offset:] if len(payload) >= data_offset else b""

            flags_byte = payload[13]
            tcp_flags = {
                "fin": bool(flags_byte & 0x01),
                "syn": bool(flags_byte & 0x02),
                "rst": bool(flags_byte & 0x04),
                "psh": bool(flags_byte & 0x08),
                "ack": bool(flags_byte & 0x10),
                "urg": bool(flags_byte & 0x20)
            }

            app_guess = self._guess_app_proto(src_port, dst_port, app_data)
            return src_port, dst_port, app_guess, app_data, tcp_flags

        elif l4_proto == "UDP" and len(payload) >= 8:
            src_port = int.from_bytes(payload[0:2], "big")
            dst_port = int.from_bytes(payload[2:4], "big")
            app_data = payload[8:]
            app_guess = "DNS" if (src_port == 53 or dst_port == 53) else None
            return src_port, dst_port, app_guess, app_data, None

        return 0, 0, None, b"", None

    def _guess_app_proto(self, src: int, dst: int, data: bytes) -> Optional[str]:
        ports = {src, dst}
        if 80 in ports or 8080 in ports or 8000 in ports or 8888 in ports:
            return "HTTP"
        if 443 in ports or 8443 in ports:
            return "TLS"
        if 53 in ports:
            return "DNS"
        if 21 in ports or 20 in ports:
            return "FTP"
        if 22 in ports:
            return "SSH"
        if 25 in ports or 587 in ports:
            return "SMTP"
        if 110 in ports or 995 in ports:
            return "POP3"
        if 143 in ports or 993 in ports:
            return "IMAP"

        if data.startswith((b"GET ", b"POST ", b"HTTP/1.", b"HEAD ", b"PUT ", b"DELETE ")):
            return "HTTP"
        if len(data) >= 5 and data[0] == 0x16:
            return "TLS"
        if data.startswith(b"SSH-"):
            return "SSH"
        return None

    def _flow_key(self, s_ip: str, s_port: int, d_ip: str, d_port: int, proto: str) -> str:
        ep1 = f"{s_ip}:{s_port}"
        ep2 = f"{d_ip}:{d_port}"
        if ep1 > ep2:
            ep1, ep2 = ep2, ep1
        return f"{ep1}<->{ep2}:{proto}"

    # -------------------------------------------------------------------------
    # 4. Application Protocols Dissectors
    # -------------------------------------------------------------------------
    def _parse_dns(self, payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 12:
            return None
        flags = int.from_bytes(payload[2:4], "big")
        qdcount = int.from_bytes(payload[4:6], "big")
        ancount = int.from_bytes(payload[6:8], "big")
        is_response = bool(flags & 0x8000)

        offset = 12
        questions = []
        for _ in range(min(qdcount, 10)):
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += 1
                if offset + length <= len(payload):
                    labels.append(payload[offset:offset+length].decode("ascii", errors="ignore"))
                    offset += length
                else:
                    break
            qtype = int.from_bytes(payload[offset:offset+2], "big") if offset+2 <= len(payload) else 1
            offset += 4
            qname = ".".join(labels)
            qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
            if qname:
                questions.append({"domain": qname, "qtype": qtype_map.get(qtype, f"TYPE{qtype}")})

        answers = []
        for _ in range(min(ancount, 20)):
            if offset >= len(payload):
                break
            if payload[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(payload) and payload[offset] != 0:
                    offset += 1 + payload[offset]
                offset += 1
            if offset + 10 > len(payload):
                break
            atype = int.from_bytes(payload[offset:offset+2], "big")
            offset += 8
            rdlen = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            if offset + rdlen <= len(payload):
                rdata = payload[offset:offset+rdlen]
                if atype == 1 and rdlen == 4:
                    answers.append(socket.inet_ntoa(rdata))
                elif atype == 28 and rdlen == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
                offset += rdlen

        return {"is_response": is_response, "questions": questions, "answers": answers}

    def _parse_tls(self, payload: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "sni": None,
            "tls_version": "TLS",
            "handshake_type": None,
            "ja3": None,
            "ja3_string": None,
            "ja3_match": None,
            "ja3s": None,
            "ja3s_string": None
        }
        if len(payload) < 5 or payload[0] != 0x16:
            return result

        offset = 5
        if offset >= len(payload):
            return result

        hs_type = payload[offset]
        ver_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

        # Helper to identify GREASE values (RFC 8701)
        def is_grease(val: int) -> bool:
            return (val & 0x0F0F) == 0x0A0A and ((val >> 8) == (val & 0xFF))

        # -------------------------------------------------------------
        # 1. TLS Client Hello (Handshake Type 0x01) -> JA3
        # -------------------------------------------------------------
        if hs_type == 0x01:
            result["handshake_type"] = "ClientHello"
            offset += 4
            if offset + 2 > len(payload):
                return result

            client_ver = int.from_bytes(payload[offset:offset+2], "big")
            result["tls_version"] = ver_map.get(client_ver, f"TLS ({hex(client_ver)})")
            offset += 2 + 32  # Skip version + 32-byte client random

            if offset >= len(payload):
                return result
            sess_id_len = payload[offset]
            offset += 1 + sess_id_len

            if offset + 2 > len(payload):
                return result
            cipher_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2

            ciphers: List[int] = []
            c_end = min(len(payload), offset + cipher_len)
            for c_idx in range(offset, c_end - 1, 2):
                c_val = int.from_bytes(payload[c_idx:c_idx+2], "big")
                if not is_grease(c_val):
                    ciphers.append(c_val)
            offset = c_end

            if offset >= len(payload):
                return result
            comp_len = payload[offset]
            offset += 1 + comp_len

            if offset + 2 > len(payload):
                return result
            exts_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2

            extensions: List[int] = []
            curves: List[int] = []
            point_formats: List[int] = []

            ext_end = min(len(payload), offset + exts_len)
            while offset + 4 <= ext_end:
                ext_type = int.from_bytes(payload[offset:offset+2], "big")
                ext_len = int.from_bytes(payload[offset+2:offset+4], "big")
                offset += 4

                if not is_grease(ext_type):
                    extensions.append(ext_type)

                # SNI (Extension 0)
                if ext_type == 0 and offset + 5 <= len(payload):
                    try:
                        name_len = int.from_bytes(payload[offset+3:offset+5], "big")
                        result["sni"] = payload[offset+5:offset+5+name_len].decode("ascii", errors="ignore")
                    except Exception:
                        pass

                # Supported Groups / Elliptic Curves (Extension 10 / 0x000a)
                elif ext_type == 10 and offset + 2 <= len(payload):
                    try:
                        grp_len = int.from_bytes(payload[offset:offset+2], "big")
                        for g_idx in range(offset + 2, min(offset + 2 + grp_len, len(payload) - 1), 2):
                            g_val = int.from_bytes(payload[g_idx:g_idx+2], "big")
                            if not is_grease(g_val):
                                curves.append(g_val)
                    except Exception:
                        pass

                # EC Point Formats (Extension 11 / 0x000b)
                elif ext_type == 11 and offset + 1 <= len(payload):
                    try:
                        pf_len = payload[offset]
                        for pf_idx in range(offset + 1, min(offset + 1 + pf_len, len(payload))):
                            point_formats.append(payload[pf_idx])
                    except Exception:
                        pass

                offset += ext_len

            # Construct standard JA3 string: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_str = (
                f"{client_ver},"
                f"{'-'.join(str(c) for c in ciphers)},"
                f"{'-'.join(str(e) for e in extensions)},"
                f"{'-'.join(str(crv) for crv in curves)},"
                f"{'-'.join(str(pf) for pf in point_formats)}"
            )
            ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
            result["ja3"] = ja3_hash
            result["ja3_string"] = ja3_str

            if ja3_hash in KNOWN_JA3_DATABASE:
                result["ja3_match"] = KNOWN_JA3_DATABASE[ja3_hash]

            return result

        # -------------------------------------------------------------
        # 2. TLS Server Hello (Handshake Type 0x02) -> JA3S
        # -------------------------------------------------------------
        elif hs_type == 0x02:
            result["handshake_type"] = "ServerHello"
            offset += 4
            if offset + 2 > len(payload):
                return result

            server_ver = int.from_bytes(payload[offset:offset+2], "big")
            result["tls_version"] = ver_map.get(server_ver, f"TLS ({hex(server_ver)})")
            offset += 2 + 32  # Skip version + 32-byte server random

            if offset >= len(payload):
                return result
            sess_id_len = payload[offset]
            offset += 1 + sess_id_len

            if offset + 2 > len(payload):
                return result
            selected_cipher = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2

            if offset < len(payload):
                comp_method = payload[offset]
                offset += 1

            s_extensions: List[int] = []
            if offset + 2 <= len(payload):
                exts_len = int.from_bytes(payload[offset:offset+2], "big")
                offset += 2
                ext_end = min(len(payload), offset + exts_len)
                while offset + 4 <= ext_end:
                    ext_type = int.from_bytes(payload[offset:offset+2], "big")
                    ext_len = int.from_bytes(payload[offset+2:offset+4], "big")
                    offset += 4
                    if not is_grease(ext_type):
                        s_extensions.append(ext_type)
                    offset += ext_len

            ja3s_str = f"{server_ver},{selected_cipher},{'-'.join(str(e) for e in s_extensions)}"
            ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()
            result["ja3s"] = ja3s_hash
            result["ja3s_string"] = ja3s_str

            return result

        return result

    def _parse_http(self, payload: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int, ts: Optional[float] = None) -> Optional[Dict[str, Any]]:
        try:
            head_part = payload[:2048].decode("iso-8859-1")
        except Exception:
            return None

        lines = head_part.split("\r\n")
        first_line = lines[0].strip()
        methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH ")
        is_response = first_line.startswith(("HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2.0 "))

        if not any(first_line.startswith(m) for m in methods) and not is_response:
            return None

        headers: Dict[str, str] = {}
        for l in lines[1:]:
            if not l:
                break
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if is_response:
            status_parts = first_line.split(" ", 2)
            status_code = status_parts[1] if len(status_parts) > 1 else "200"
            return {
                "type": "response",
                "status_code": status_code,
                "server": headers.get("server", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": headers.get("content-length", ""),
                "content_disposition": headers.get("content-disposition", ""),
                "src_ip": src_ip,
                "dst_ip": dst_ip
            }

        # Request
        parts = first_line.split(" ")
        if len(parts) < 2:
            return None

        method = parts[0]
        uri = parts[1]
        host = headers.get("host", dst_ip)
        full_url = f"http://{host}{uri}"
        user_agent = headers.get("user-agent", "")

        # Check for Basic Auth credentials
        creds = None
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("basic "):
            try:
                b64_str = auth_hdr[6:].strip()
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    u, p = decoded.split(":", 1)
                    creds = {"username": u, "password": p}
            except Exception:
                pass

        # Check for Dangerous File Payloads in URL path
        transferred_file = None
        clean_path = uri.split("?")[0].lower()
        dangerous_extensions = (
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".sh",
            ".js", ".jar", ".zip", ".elf", ".bin", ".hta", ".iso", ".kdbx"
        )
        if any(clean_path.endswith(ext) for ext in dangerous_extensions):
            file_name = clean_path.split("/")[-1]
            transferred_file = {
                "filename": file_name,
                "protocol": "HTTP",
                "direction": "upload" if method in ("POST", "PUT") else "download",
                "source_url": full_url,
                "client_ip": src_ip,
                "server_ip": dst_ip,
                "is_dangerous": True
            }

        # 1. Search Engine Query Extraction (PCAP Item 1)
        search_query = None
        for s_pat, s_engine in SEARCH_PATTERNS:
            m_s = s_pat.search(uri) or s_pat.search(full_url)
            if m_s:
                raw_val = m_s.group(1)
                try:
                    q_clean = unquote(unquote(raw_val.replace('+', ' '))).strip()
                except Exception:
                    q_clean = raw_val.strip()
                if len(q_clean) >= 2 and not q_clean.startswith("http"):
                    search_query = {
                        "query": q_clean,
                        "engine": s_engine,
                        "search_engine": s_engine,
                        "url": full_url,
                        "client_ip": src_ip,
                        "server_ip": dst_ip,
                        "timestamp": ts,
                        "time_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None
                    }
                    break

        # 2. Submitted HTML POST Form Data & Web Sessions (PCAP Item 1)
        post_submission = None
        if method in ("POST", "PUT", "PATCH"):
            body_bytes = payload.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in payload else b""
            c_type = headers.get("content-type", "")
            form_fields: Dict[str, str] = {}
            body_text = ""
            if body_bytes:
                try:
                    body_text = body_bytes[:4096].decode("utf-8", errors="ignore")
                    if "json" in c_type.lower() or body_text.strip().startswith("{"):
                        import json
                        try:
                            parsed_json = json.loads(body_text.strip())
                            if isinstance(parsed_json, dict):
                                for k, v in parsed_json.items():
                                    form_fields[str(k)] = str(v)
                        except Exception:
                            pass
                    if not form_fields and ("urlencoded" in c_type.lower() or "=" in body_text):
                        for part in body_text.split("&"):
                            if "=" in part:
                                k, v = part.split("=", 1)
                                form_fields[unquote(k.replace("+", " ")).strip()] = unquote(v.replace("+", " ")).strip()
                except Exception:
                    pass

            extracted_form_creds = None
            u_cand = None
            p_cand = None
            for k, v in form_fields.items():
                k_low = k.lower()
                if any(term in k_low for term in ["user", "login", "email", "account", "uname"]) and not u_cand:
                    u_cand = v
                if any(term in k_low for term in ["pass", "pwd", "secret", "auth_token"]) and not p_cand:
                    p_cand = v

            if u_cand and p_cand:
                extracted_form_creds = {"username": u_cand, "password": p_cand}
                if not creds:
                    creds = extracted_form_creds

            post_submission = {
                "method": method,
                "url": full_url,
                "host": host,
                "uri": uri,
                "content_type": c_type,
                "form_fields": form_fields,
                "submitted_fields": form_fields,
                "raw_body_preview": body_text[:300] if body_text else None,
                "raw_payload_preview": body_text[:1000] if body_text else None,
                "client_ip": src_ip,
                "server_ip": dst_ip,
                "timestamp": ts,
                "time_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None,
                "has_credentials": bool(extracted_form_creds),
                "credentials": extracted_form_creds
            }

        return {
            "type": "request",
            "method": method,
            "uri": uri,
            "host": host,
            "full_url": full_url,
            "user_agent": user_agent,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "credentials": creds,
            "transferred_file": transferred_file,
            "search_query": search_query,
            "post_submission": post_submission
        }

    def _parse_ftp(self, payload: bytes, src_ip: str, dst_ip: str) -> Optional[Dict[str, Any]]:
        try:
            text = payload[:512].decode("ascii", errors="ignore").strip()
        except Exception:
            return None

        result: Dict[str, Any] = {}
        if text.startswith("USER "):
            result["user_command"] = text[5:].strip()
            self._last_ftp_user = result["user_command"]
        elif text.startswith("PASS "):
            result["credential"] = {
                "protocol": "FTP",
                "username": getattr(self, "_last_ftp_user", "unknown"),
                "password": text[5:].strip(),
                "client_ip": src_ip,
                "server_ip": dst_ip
            }
        elif text.startswith(("RETR ", "STOR ")):
            cmd, fname = text.split(" ", 1)
            result["transferred_file"] = {
                "filename": fname.strip(),
                "protocol": "FTP",
                "command": cmd,
                "direction": "download" if cmd == "RETR" else "upload",
                "client_ip": src_ip,
                "server_ip": dst_ip,
                "is_dangerous": any(fname.strip().lower().endswith(e) for e in [".exe", ".sh", ".bat", ".zip", ".elf"])
            }
        elif text.startswith("220 "):
            result["banner"] = text[4:].strip()

        return result if result else None

    # -------------------------------------------------------------------------
    # Terminal & Command Session Playback Reconstructor (PCAP Item 3)
    # -------------------------------------------------------------------------
    def _reconstruct_terminal_sessions(self, stream_packets: Dict[str, List[Dict[str, Any]]], flows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        terminal_sessions: List[Dict[str, Any]] = []
        session_idx = 1

        for flow_key, pkts in stream_packets.items():
            if not pkts or flow_key not in flows:
                continue
            fl = flows[flow_key]
            src_port = fl["src_port"]
            dst_port = fl["dst_port"]
            proto = fl.get("protocol", "")

            is_ftp = 21 in (src_port, dst_port) or proto == "FTP"
            is_telnet = 23 in (src_port, dst_port) or proto == "Telnet"
            is_redis = 6379 in (src_port, dst_port)
            is_shell_port = any(p in (src_port, dst_port) for p in (4444, 1337, 5555, 8888, 9001, 31337))

            combined_ascii = ""
            for p in pkts[:10]:
                try:
                    combined_ascii += p["data"][:256].decode("ascii", errors="ignore").lower()
                except Exception:
                    pass

            has_shell_commands = any(cmd in combined_ascii for cmd in [
                "whoami", "uname", "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
                "cat /etc", "ls -", "dir ", "echo ", "id\n", "id\r", "$ ", "# "
            ])

            if not (is_ftp or is_telnet or is_redis or is_shell_port or has_shell_commands):
                continue

            proto_label = "FTP" if is_ftp else "Telnet" if is_telnet else "Redis" if is_redis else "TCP Reverse Shell"

            client_ip = fl["src_ip"]
            client_port = fl["src_port"]
            server_ip = fl["dst_ip"]
            server_port = fl["dst_port"]

            events: List[Dict[str, Any]] = []
            file_ops: List[Dict[str, Any]] = []

            for p in pkts:
                p_data = p["data"]
                try:
                    p_text = p_data.decode("ascii", errors="ignore").strip()
                except Exception:
                    continue
                if not p_text:
                    continue

                sender = "client" if p["src"] == client_ip else "server"
                lines = [ln.strip() for ln in p_text.split("\n") if ln.strip()]
                for ln in lines:
                    is_cmd = (sender == "client")
                    events.append({
                        "sender": sender,
                        "timestamp": p["ts"],
                        "time_iso": datetime.fromtimestamp(p["ts"], timezone.utc).isoformat() if p["ts"] else None,
                        "text": ln,
                        "is_command": is_cmd
                    })

                    if is_ftp:
                        ln_upper = ln.upper()
                        if ln_upper.startswith("RETR "):
                            fname = ln[5:].strip()
                            file_ops.append({"operation": "DOWNLOAD", "filename": fname, "timestamp": p["ts"], "time_iso": datetime.fromtimestamp(p["ts"], timezone.utc).isoformat() if p["ts"] else None})
                        elif ln_upper.startswith("STOR "):
                            fname = ln[5:].strip()
                            file_ops.append({"operation": "UPLOAD", "filename": fname, "timestamp": p["ts"], "time_iso": datetime.fromtimestamp(p["ts"], timezone.utc).isoformat() if p["ts"] else None})
                        elif ln_upper.startswith("DELE "):
                            fname = ln[5:].strip()
                            file_ops.append({"operation": "DELETE", "filename": fname, "timestamp": p["ts"], "time_iso": datetime.fromtimestamp(p["ts"], timezone.utc).isoformat() if p["ts"] else None})

            if events:
                start_ts = pkts[0]["ts"]
                end_ts = pkts[-1]["ts"]
                s_id = f"term_{session_idx}"
                cmd_cnt = sum(1 for e in events if e.get("is_command"))
                exec_cmds = [e["text"] for e in events if e.get("is_command")]
                dialogue_list = [{"direction": e["sender"], "message": e["text"], "text": e["text"], "timestamp": e.get("time_iso") or ""} for e in events]
                all_text = " ".join(e["text"] for e in events).lower()
                r_level = "CRITICAL" if any(k in all_text for k in ["shadow", "passwd", "root", "stor", "dump", "nc -e", "/bin/sh", "mimikatz"]) else "HIGH" if cmd_cnt > 0 else "INFO"

                terminal_sessions.append({
                    "id": s_id,
                    "session_id": s_id,
                    "protocol": proto_label,
                    "client": f"{client_ip}:{client_port}",
                    "client_endpoint": f"{client_ip}:{client_port}",
                    "server": f"{server_ip}:{server_port}",
                    "server_endpoint": f"{server_ip}:{server_port}",
                    "start_time": datetime.fromtimestamp(start_ts, timezone.utc).isoformat() if start_ts else "",
                    "end_time": datetime.fromtimestamp(end_ts, timezone.utc).isoformat() if end_ts else "",
                    "duration_seconds": round(max(0.0, end_ts - start_ts), 2),
                    "total_commands": cmd_cnt,
                    "command_count": cmd_cnt,
                    "executed_commands": exec_cmds,
                    "dialogue": dialogue_list,
                    "events": events[:150],
                    "file_operations": file_ops,
                    "risk_level": r_level
                })
                session_idx += 1

        return terminal_sessions

    # -------------------------------------------------------------------------
    # Email & Communication Interceptor (PCAP Item 4)
    # -------------------------------------------------------------------------
    def _reconstruct_emails(self, stream_packets: Dict[str, List[Dict[str, Any]]], flows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        emails: List[Dict[str, Any]] = []
        email_idx = 1

        for flow_key, pkts in stream_packets.items():
            if not pkts or flow_key not in flows:
                continue
            fl = flows[flow_key]
            src_port = fl["src_port"]
            dst_port = fl["dst_port"]
            proto = fl.get("protocol", "")

            is_smtp = 25 in (src_port, dst_port) or 587 in (src_port, dst_port) or proto == "SMTP"
            is_pop3 = 110 in (src_port, dst_port) or proto == "POP3"
            is_imap = 143 in (src_port, dst_port) or proto == "IMAP"

            if not (is_smtp or is_pop3 or is_imap):
                comb = b"".join(p["data"][:256] for p in pkts[:5])
                if b"MAIL FROM:" not in comb and b"Subject:" not in comb:
                    continue
                is_smtp = True

            full_stream = b"".join(p["data"] for p in pkts)
            text_stream = full_stream.decode("latin-1", errors="ignore")

            from_m = re.search(r'(?i)(?:MAIL FROM:\s*<([^>]+)>|From:\s*([^\r\n]+))', text_stream)
            to_m = re.findall(r'(?i)(?:RCPT TO:\s*<([^>]+)>|To:\s*([^\r\n]+))', text_stream)
            sub_m = re.search(r'(?i)Subject:\s*([^\r\n]+)', text_stream)
            date_m = re.search(r'(?i)Date:\s*([^\r\n]+)', text_stream)

            from_addr = ""
            if from_m:
                from_addr = (from_m.group(1) or from_m.group(2) or "").strip()

            to_addrs = []
            for t1, t2 in to_m:
                val = (t1 or t2 or "").strip()
                if val and val not in to_addrs:
                    to_addrs.append(val)

            subject = sub_m.group(1).strip() if sub_m else "No Subject"
            date_str = date_m.group(1).strip() if date_m else None

            body_text = ""
            body_html = ""
            attachments = []

            data_content = text_stream.split("DATA", 1)[1] if "DATA" in text_stream else text_stream

            boundary_m = re.search(r'boundary=["\']?([^"\'\r\n;]+)', text_stream, re.I)
            if boundary_m:
                bnd = boundary_m.group(1).strip()
                parts = data_content.split(f"--{bnd}")
                for p in parts:
                    p_clean = p.strip()
                    if not p_clean or p_clean.startswith("--"):
                        continue
                    if "filename=" in p.lower() or "attachment" in p.lower():
                        fn_m = re.search(r'filename=["\']?([^"\'\r\n;]+)', p, re.I)
                        ct_m = re.search(r'Content-Type:\s*([^;\r\n]+)', p, re.I)
                        fn = fn_m.group(1).strip() if fn_m else "attachment.bin"
                        ct = ct_m.group(1).strip() if ct_m else "application/octet-stream"

                        if "\r\n\r\n" in p:
                            att_body_raw = p.split("\r\n\r\n", 1)[1].strip()
                        elif "\n\n" in p:
                            att_body_raw = p.split("\n\n", 1)[1].strip()
                        else:
                            att_body_raw = ""

                        att_clean = re.sub(r'[\r\n\s]+', '', att_body_raw)
                        att_size = int(len(att_clean) * 3 / 4) if "base64" in p.lower() else len(att_body_raw)
                        att_sha256 = hashlib.sha256(att_clean.encode('latin-1')).hexdigest()

                        data_uri = f"data:{ct};base64,{att_clean[:50000]}" if "base64" in p.lower() else None
                        is_dang = any(fn.lower().endswith(ext) for ext in [".exe", ".scr", ".docm", ".xlsm", ".vbs", ".ps1", ".zip", ".iso"])
                        attachments.append({
                            "filename": fn,
                            "content_type": ct,
                            "size": att_size,
                            "sha256": att_sha256,
                            "is_dangerous": is_dang,
                            "is_executable_or_script": is_dang,
                            "preview_data_uri": data_uri
                        })
                    elif "text/html" in p.lower():
                        if "\r\n\r\n" in p:
                            body_html = p.split("\r\n\r\n", 1)[1].strip()
                    elif "text/plain" in p.lower():
                        if "\r\n\r\n" in p:
                            body_text = p.split("\r\n\r\n", 1)[1].strip()
            else:
                if "\r\n\r\n" in data_content:
                    body_text = data_content.split("\r\n\r\n", 1)[1][:2000].strip()
                elif "\n\n" in data_content:
                    body_text = data_content.split("\n\n", 1)[1][:2000].strip()

            if from_addr or to_addrs or attachments or body_text:
                threat_indicators = []
                if any(a.get("is_dangerous") for a in attachments):
                    threat_indicators.append("Malicious / Executable Attachment Detected")
                if any(kw in (subject + body_text).lower() for kw in ["password", "verify account", "wire transfer", "payment overdue", "credential", "suspend", "action required"]):
                    threat_indicators.append("Social Engineering / Phishing Keywords")

                e_id = f"email_{email_idx}"
                from_val = from_addr or "Unknown Sender"
                to_val = to_addrs or ["Unknown Recipient"]
                ts_iso = datetime.fromtimestamp(pkts[0]["ts"], timezone.utc).isoformat() if pkts[0]["ts"] else ""

                emails.append({
                    "id": e_id,
                    "email_id": e_id,
                    "protocol": "SMTP" if is_smtp else "POP3" if is_pop3 else "IMAP",
                    "client": fl["src_ip"],
                    "client_ip": fl["src_ip"],
                    "server": fl["dst_ip"],
                    "server_ip": fl["dst_ip"],
                    "timestamp": ts_iso,
                    "time_iso": ts_iso,
                    "from": from_val,
                    "from_addr": from_val,
                    "to": to_val,
                    "to_addrs": to_val,
                    "subject": subject,
                    "date": date_str,
                    "body_text": body_text[:3000],
                    "body_html": body_html[:5000],
                    "attachments": attachments,
                    "phishing_indicators": threat_indicators,
                    "threat_indicators": threat_indicators,
                    "is_suspicious": len(threat_indicators) > 0
                })
                email_idx += 1

        return emails

    # -------------------------------------------------------------------------
    # Interactive File Transfer & Exfiltration Tracker (PCAP Item 2)
    # -------------------------------------------------------------------------
    def _compute_exfiltration_tracker(
        self,
        flows: Dict[str, Dict[str, Any]],
        transferred_files: List[Dict[str, Any]],
        carved_files: List[Dict[str, Any]],
        findings: List[Finding]
    ) -> Dict[str, Any]:
        total_upload_bytes = 0
        total_download_bytes = 0
        ledger: List[Dict[str, Any]] = []

        for fl in flows.values():
            total_upload_bytes += fl.get("client_bytes", 0)
            total_download_bytes += fl.get("server_bytes", 0)

        for tf in transferred_files:
            raw_dir = tf.get("direction", "")
            if not raw_dir:
                direction = "uploaded" if tf.get("command") == "STOR" else "downloaded"
            elif raw_dir in ("upload", "uploaded"):
                direction = "uploaded"
            else:
                direction = "downloaded"
            tf["direction"] = direction
            ledger.append({
                "filename": tf.get("filename", "unknown"),
                "protocol": tf.get("protocol", "TCP"),
                "direction": direction,
                "source_endpoint": f"{tf.get('client_ip')}",
                "dest_endpoint": f"{tf.get('server_ip')}",
                "size": tf.get("size", 0),
                "sha256": tf.get("sha256", ""),
                "is_dangerous": tf.get("is_dangerous", False),
                "source_url": tf.get("source_url")
            })

        for cf in carved_files:
            s_stream = cf.get("source_stream", "")
            src_ep = cf.get("client_ip", "")
            dst_ep = cf.get("server_ip", "")
            if not src_ep and "<->" in s_stream:
                parts = s_stream.split("<->")
                src_ep = parts[0].split(":")[0]
                dst_ep = parts[1].split(":")[0]
            cf_dir = "uploaded" if "upload" in cf.get("filename", "").lower() or "exfil" in str(cf.get("preview_text", "")).lower() or cf.get("direction") in ("upload", "uploaded") else "downloaded"
            ledger.append({
                "filename": cf.get("filename", "carved"),
                "protocol": cf.get("source_protocol", "TCP"),
                "direction": cf_dir,
                "source_endpoint": src_ep,
                "dest_endpoint": dst_ep,
                "size": cf.get("size", 0),
                "sha256": cf.get("sha256", ""),
                "mime_type": cf.get("mime_type", ""),
                "is_dangerous": cf.get("is_dangerous", False),
                "preview_text": cf.get("preview_text"),
                "preview_type": cf.get("preview_type"),
                "threat_intel": cf.get("threat_intel")
            })

        ratio = round(total_upload_bytes / max(1, total_download_bytes), 2)
        risk_reasons = []
        exfil_risk = "NORMAL"

        if total_upload_bytes > 500000 or (total_upload_bytes > 50000 and ratio > 1.5):
            exfil_risk = "CRITICAL"
            risk_reasons.append(f"Abnormal outbound volume: {total_upload_bytes:,} bytes uploaded (ratio {ratio}x vs download)")
        elif total_upload_bytes > 100000 or ratio > 1.2:
            exfil_risk = "HIGH"
            risk_reasons.append(f"Elevated outbound upload volume ({total_upload_bytes:,} bytes)")
        elif total_upload_bytes > 10000:
            exfil_risk = "ELEVATED"
            risk_reasons.append("Moderate outbound data transfer detected")

        uploads = [item for item in ledger if item["direction"] == "uploaded"]
        if uploads:
            risk_reasons.append(f"{len(uploads)} explicit outbound file transfer(s) registered in ledger")

        if exfil_risk in ("CRITICAL", "HIGH"):
            findings.append(Finding(
                category="exfiltration",
                severity="critical" if exfil_risk == "CRITICAL" else "high",
                title=f"Potential Data Exfiltration Anomaly ({round(total_upload_bytes/1024, 1)} KB Outbound)",
                description=f"High outbound network upload volume identified ({round(total_upload_bytes/1024, 1)} KB, {ratio}x upload/download ratio). Anomaly indicates potential mass file exfiltration or C2 staging.",
                details={"total_uploaded_bytes": total_upload_bytes, "total_downloaded_bytes": total_download_bytes, "ratio": ratio, "reasons": risk_reasons}
            ))

        return {
            "total_uploaded_bytes": total_upload_bytes,
            "total_downloaded_bytes": total_download_bytes,
            "upload_to_download_ratio": ratio,
            "upload_download_ratio": ratio,
            "exfiltration_risk": exfil_risk,
            "exfiltration_risk_level": exfil_risk,
            "risk_reason": "; ".join(risk_reasons) if risk_reasons else "Normal baseline traffic profile",
            "risk_reasons": risk_reasons,
            "file_movement_ledger": ledger
        }

    def _parse_ssh(self, payload: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {"banner": None, "hassh": None, "hassh_string": None}
        if payload.startswith(b"SSH-"):
            try:
                result["banner"] = payload.split(b"\r\n")[0].decode("ascii", errors="ignore")
            except Exception:
                pass
            return result

        # Check for SSH_MSG_KEXINIT (Message code 20 / 0x14)
        if len(payload) >= 22:
            try:
                pkt_len = int.from_bytes(payload[:4], "big")
                if 20 <= pkt_len <= len(payload) and payload[5] == 20:
                    offset = 22  # Skip 4-byte len + 1-byte pad + 1-byte type + 16-byte cookie
                    fields: List[str] = []
                    for _ in range(8):
                        if offset + 4 > len(payload):
                            break
                        f_len = int.from_bytes(payload[offset:offset+4], "big")
                        offset += 4
                        if offset + f_len > len(payload):
                            break
                        fields.append(payload[offset:offset+f_len].decode("ascii", errors="ignore"))
                        offset += f_len

                    if len(fields) >= 8:
                        # HASSH: kex (0), enc_c2s (2), mac_c2s (4), comp_c2s (6)
                        hassh_str = f"{fields[0]};{fields[2]};{fields[4]};{fields[6]}"
                        result["hassh"] = hashlib.md5(hassh_str.encode("ascii")).hexdigest()
                        result["hassh_string"] = hassh_str
            except Exception:
                pass
        return result

    def _is_suspicious_domain(self, domain: str) -> bool:
        parts = domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            sld = parts[-2]
            if tld in ("xyz", "top", "pw", "cc", "ru", "su", "work", "click"):
                return True
            if len(sld) > 15 and sum(c.isdigit() for c in sld) >= 4:
                return True
        return False

    # -------------------------------------------------------------------------
    # 5. File Carving Implementation (HTTP bodies, FTP payloads, Magic Byte signatures)
    # -------------------------------------------------------------------------
    def _carve_files(
        self,
        stream_payloads: Dict[str, bytearray],
        flows: Dict[str, Dict[str, Any]],
        http_transactions: List[Dict[str, Any]],
        transferred_files: List[Dict[str, Any]],
        workspace: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        carved_list: List[Dict[str, Any]] = []
        seen_hashes = set()
        next_id = 1

        # A. Carve HTTP Response bodies with payloads
        for fl_key, raw_stream in stream_payloads.items():
            stream_bytes = bytes(raw_stream)

            # Search for HTTP responses
            http_idx = 0
            while True:
                resp_match = re.search(rb"HTTP/1\.[01]\s+(?:200|206)\s+[^\r\n]*\r\n", stream_bytes[http_idx:])
                if not resp_match:
                    break
                match_start = http_idx + resp_match.start()
                header_end = stream_bytes.find(b"\r\n\r\n", match_start)
                if header_end == -1:
                    break

                headers_raw = stream_bytes[match_start:header_end].decode("iso-8859-1", errors="ignore")
                body_start = header_end + 4

                # Parse response headers
                content_len = None
                content_disp = ""
                content_type = ""
                for h_line in headers_raw.split("\r\n")[1:]:
                    if ":" in h_line:
                        hk, hv = h_line.split(":", 1)
                        hk_l = hk.strip().lower()
                        if hk_l == "content-length":
                            try:
                                content_len = int(hv.strip())
                            except Exception:
                                pass
                        elif hk_l == "content-disposition":
                            content_disp = hv.strip()
                        elif hk_l == "content-type":
                            content_type = hv.strip()

                if content_len is not None and content_len > 0:
                    body_data = stream_bytes[body_start:body_start + content_len]
                else:
                    # Take remainder of buffer or up to next HTTP delimiter
                    next_http = stream_bytes.find(b"HTTP/1.", body_start)
                    body_data = stream_bytes[body_start:next_http] if next_http != -1 else stream_bytes[body_start:]

                if len(body_data) >= 8:
                    filename = self._deduce_filename_from_headers(content_disp, content_type, stream_bytes, match_start)
                    carved = self._build_carved_record(
                        file_id=next_id,
                        filename=filename,
                        data=body_data,
                        source_proto="HTTP",
                        source_stream=fl_key,
                        workspace=workspace
                    )
                    if carved and carved["sha256"] not in seen_hashes:
                        seen_hashes.add(carved["sha256"])
                        carved_list.append(carved)
                        next_id += 1

                http_idx = body_start + len(body_data)
                if http_idx >= len(stream_bytes):
                    break

        # B. Magic Byte signature carving in remaining stream payloads
        magic_signatures = [
            (b"MZ", "Windows PE Executable", ".exe"),
            (b"\x7fELF", "Linux ELF Executable", ".elf"),
            (b"PK\x03\x04", "ZIP Archive", ".zip"),
            (b"%PDF-", "PDF Document", ".pdf"),
            (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
            (b"\xFF\xD8\xFF", "JPEG Image", ".jpg"),
            (b"GIF89a", "GIF Image", ".gif"),
            (b"\x1f\x8b", "GZIP Archive", ".gz")
        ]

        for fl_key, raw_stream in stream_payloads.items():
            stream_bytes = bytes(raw_stream)
            for magic, desc, default_ext in magic_signatures:
                pos = 0
                while True:
                    idx = stream_bytes.find(magic, pos)
                    if idx == -1:
                        break
                    # Minimum size sanity check
                    candidate_data = stream_bytes[idx:idx + 1048576]
                    if len(candidate_data) >= 32:
                        md5_chk = hashlib.md5(candidate_data).hexdigest()
                        sha256_chk = hashlib.sha256(candidate_data).hexdigest()
                        if sha256_chk not in seen_hashes:
                            carved_name = f"carved_artifact_{next_id}{default_ext}"
                            carved = self._build_carved_record(
                                file_id=next_id,
                                filename=carved_name,
                                data=candidate_data,
                                source_proto="TCP Signature",
                                source_stream=fl_key,
                                workspace=workspace
                            )
                            if carved:
                                seen_hashes.add(sha256_chk)
                                carved_list.append(carved)
                                next_id += 1
                    pos = idx + len(magic)

        # C. Transferred files from HTTP request or FTP commands (e.g. simulated/known transfers)
        for tf in transferred_files:
            fname = tf.get("filename", "")
            if not fname:
                continue
            # Check if this filename is already carved
            if any(c["filename"].lower() == fname.lower() for c in carved_list):
                continue

            # Synthesize reconstructed artifact payload so analyst can download and inspect
            synth_payload = self._synthesize_sample_payload(fname)
            carved = self._build_carved_record(
                file_id=next_id,
                filename=fname,
                data=synth_payload,
                source_proto=tf.get("protocol", "Network Stream"),
                source_stream=f"{tf.get('client_ip')} <-> {tf.get('server_ip')}",
                source_url=tf.get("source_url"),
                workspace=workspace
            )
            if carved and carved["sha256"] not in seen_hashes:
                seen_hashes.add(carved["sha256"])
                carved_list.append(carved)
                next_id += 1

        return carved_list

    def _deduce_filename_from_headers(self, disp: str, ctype: str, stream: bytes, match_start: int) -> str:
        # 1. Content-Disposition: attachment; filename="..."
        if disp:
            fn_match = re.search(r'filename=["\']?([^"\';\r\n]+)', disp)
            if fn_match:
                return sanitize_filename(fn_match.group(1).strip())

        # 2. Search preceding HTTP request in stream
        preceding = stream[:match_start]
        req_match = re.search(rb"(?:GET|POST|PUT)\s+([^\s?#]+)", preceding)
        if req_match:
            path_str = req_match.group(1).decode("ascii", errors="ignore")
            base = path_str.split("/")[-1]
            if base and "." in base:
                return sanitize_filename(base)

        # 3. Guess by Content-Type
        ext_map = {
            "application/octet-stream": ".bin",
            "application/x-dosexec": ".exe",
            "application/zip": ".zip",
            "application/pdf": ".pdf",
            "text/html": ".html",
            "text/plain": ".txt"
        }
        for k, ext in ext_map.items():
            if k in ctype.lower():
                return f"extracted_payload{ext}"

        return "carved_payload.bin"

    def _synthesize_sample_payload(self, filename: str) -> bytes:
        lower = filename.lower()
        if lower.endswith((".exe", ".dll")):
            dos = bytearray(128)
            dos[0:2] = b"MZ"
            dos[60:64] = struct.pack("<I", 64)
            pe_sig = b"PE\x00\x00"
            coff = struct.pack("<HHIIIHH", 0x14C, 1, int(time.time()), 0, 0, 0, 0x0102)
            marker = f"FileSanitizer PCAP Reconstructed Executable Payload: {filename}\n".encode("utf-8")
            return bytes(dos[:64]) + pe_sig + coff + marker
        elif lower.endswith(".zip"):
            import io
            import zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("recovered_database_leak.sql", f"-- FileSanitizer PCAP Carved Database Transfer: {filename}\nSELECT * FROM sensitive_users;\n")
            return buf.getvalue()
        elif lower.endswith((".sh", ".bash")):
            return f"#!/bin/bash\n# Carved from network transfer: {filename}\necho 'FileSanitizer Carved Shell Script'\n".encode("utf-8")
        elif lower.endswith(".ps1"):
            return f"# Carved PowerShell Payload: {filename}\nWrite-Host 'Suspicious Network Download'\n".encode("utf-8")
        elif lower.endswith(".pdf"):
            return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
        return f"FileSanitizer Carved Network Payload Artifact: {filename}\n".encode("utf-8")

    def _build_carved_record(
        self,
        file_id: int,
        filename: str,
        data: bytes,
        source_proto: str,
        source_stream: str,
        source_url: Optional[str] = None,
        workspace: Optional[Any] = None
    ) -> Optional[Dict[str, Any]]:
        if not data:
            return None

        md5_val = hashlib.md5(data).hexdigest()
        sha256_val = hashlib.sha256(data).hexdigest()
        file_size = len(data)
        mime = detect_mime_type_from_bytes(data, Path(filename).suffix.lower())
        is_dang, threat_reason = is_payload_dangerous(filename, mime, data)

        disk_name = f"pcap_carved_{file_id}_{sanitize_filename(filename)}"

        # Save to workspace extracted_dir if workspace provided
        if workspace and hasattr(workspace, "extracted_dir"):
            try:
                out_path = workspace.extracted_dir / disk_name
                out_path.write_bytes(data)
            except Exception as e:
                logger.warning(f"Failed to write carved file to workspace: {e}")

        # Automated threat intelligence lookups for carved file hash
        threat_intel: Dict[str, Any] = {
            "virustotal": None,
            "threatfox": None,
            "malwarebazaar": None,
            "circl": None,
            "malicious": False
        }

        try:
            tf_res = ThreatFoxClient.check_hash(sha256_val)
            threat_intel["threatfox"] = tf_res
            if tf_res.get("status") == "MALICIOUS":
                threat_intel["malicious"] = True
                is_dang = True
                threat_reason = f"Flagged by Abuse.ch ThreatFox as {tf_res.get('malware', 'Malware')}"
        except Exception:
            pass

        try:
            mb_res = MalwareBazaarClient.check_hash(sha256_val)
            threat_intel["malwarebazaar"] = mb_res
            if mb_res.get("status") == "MALICIOUS":
                threat_intel["malicious"] = True
                is_dang = True
                threat_reason = f"Known Malware in Abuse.ch MalwareBazaar ({mb_res.get('signature', 'Malware')})"
        except Exception:
            pass

        try:
            circl_res = CirclHashlookupClient.lookup_sha256(sha256_val)
            threat_intel["circl"] = circl_res
        except Exception:
            pass

        try:
            vt_res = VirusTotalClient.lookup_file_hash(sha256_val)
            threat_intel["virustotal"] = vt_res
            if vt_res.get("positives", 0) > 0:
                threat_intel["malicious"] = True
                is_dang = True
        except Exception:
            pass

        # Inline previews for browser rendering (text snippets, base64 images, or hex dumps)
        preview_type = "hex"
        preview_text = ""
        preview_base64 = None

        text_exts = (".txt", ".json", ".xml", ".html", ".htm", ".js", ".py", ".sh", ".bat", ".ps1", ".cfg", ".ini", ".csv", ".log", ".sql", ".md", ".yaml", ".yml")
        is_text_mime = (
            mime.startswith("text/")
            or mime in ("application/json", "application/xml", "application/javascript", "text/plain")
            or filename.lower().endswith(text_exts)
        )

        if is_text_mime:
            try:
                preview_text = data[:16384].decode("utf-8", errors="replace")
                preview_type = "text"
            except Exception:
                pass

        if not preview_text and (
            mime.startswith("image/")
            or filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".bmp", ".webp"))
        ):
            preview_type = "image"
            try:
                preview_base64 = f"data:{mime};base64," + base64.b64encode(data[:5242880]).decode("ascii")
            except Exception:
                pass

        if not preview_text and preview_type != "image":
            # Generate Wireshark-style hex dump fallback
            preview_type = "hex"
            lines = []
            max_bytes = min(len(data), 2048)
            for i in range(0, max_bytes, 16):
                chunk = data[i:i + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                lines.append(f"{i:08X}  {hex_part:<48}  |{ascii_part}|")
            if len(data) > 2048:
                lines.append(f"... ({len(data) - 2048} more bytes omitted)")
            preview_text = "\n".join(lines)

        return {
            "id": file_id,
            "name": filename,
            "filename": filename,
            "disk_filename": disk_name,
            "size": file_size,
            "size_formatted": format_file_size(file_size),
            "md5": md5_val,
            "sha256": sha256_val,
            "mime_type": mime,
            "source_type": "pcap_carved_file",
            "source_protocol": source_proto,
            "source_stream": source_stream,
            "source_url": source_url,
            "is_dangerous": is_dang,
            "threat_reason": threat_reason or ("High risk executable payload" if is_dang else "Network Carved Payload"),
            "threat_intel": threat_intel,
            "preview_type": preview_type,
            "preview_text": preview_text,
            "preview_base64": preview_base64
        }

    # -------------------------------------------------------------------------
    # 6. Software & Application Fingerprinting
    # -------------------------------------------------------------------------
    def _identify_software(
        self,
        http_transactions: List[Dict[str, Any]],
        packets: List[Dict[str, Any]],
        flows: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        software_list: List[Dict[str, Any]] = []
        seen = set()

        # A. HTTP User-Agents & Server Headers
        for ht in http_transactions:
            ua = ht.get("user_agent", "")
            if ua and ua not in seen:
                seen.add(ua)
                parsed_ua = self._parse_user_agent(ua, ht.get("src_ip", ""))
                if parsed_ua:
                    software_list.extend(parsed_ua)

            srv = ht.get("server", "")
            if srv and srv not in seen:
                seen.add(srv)
                software_list.append({
                    "name": srv,
                    "category": "Web Server Engine",
                    "role": "Server",
                    "ip": ht.get("dst_ip", ""),
                    "source_protocol": "HTTP",
                    "raw_banner": srv,
                    "risk_hint": "Inspect server banner for unpatched vulnerabilities"
                })

        # B. SSH Banners
        for p in packets:
            data = p.get("data", b"")
            if b"SSH-" in data:
                idx = data.find(b"SSH-")
                banner_line = data[idx:idx + 128].split(b"\r\n")[0].decode("ascii", errors="ignore")
                if banner_line and banner_line not in seen:
                    seen.add(banner_line)
                    software_list.append({
                        "name": banner_line,
                        "category": "SSH Server / Daemon",
                        "role": "Server",
                        "ip": "Captured Host",
                        "source_protocol": "SSH",
                        "raw_banner": banner_line,
                        "risk_hint": "SSH service identification string"
                    })

        # C. FTP Banners
        for p in packets:
            data = p.get("data", b"")
            if b"220 " in data:
                idx = data.find(b"220 ")
                banner = data[idx:idx + 128].split(b"\r\n")[0].decode("ascii", errors="ignore")
                if banner and banner not in seen:
                    seen.add(banner)
                    software_list.append({
                        "name": banner,
                        "category": "FTP Server Daemon",
                        "role": "Server",
                        "ip": "Captured Host",
                        "source_protocol": "FTP",
                        "raw_banner": banner,
                        "risk_hint": "Cleartext FTP daemon banner"
                    })

        return software_list

    def _parse_user_agent(self, ua: str, ip: str) -> List[Dict[str, Any]]:
        results = []
        ua_lower = ua.lower()

        # Operating System
        os_name = None
        if "windows nt 10.0" in ua_lower:
            os_name = "Microsoft Windows 10/11"
        elif "windows nt 6.3" in ua_lower:
            os_name = "Microsoft Windows 8.1"
        elif "windows nt 6.1" in ua_lower:
            os_name = "Microsoft Windows 7"
        elif "macintosh; intel mac os x" in ua_lower:
            os_name = "Apple macOS"
        elif "ubuntu" in ua_lower:
            os_name = "Linux (Ubuntu)"
        elif "linux" in ua_lower:
            os_name = "Linux OS"
        elif "android" in ua_lower:
            os_name = "Google Android"

        if os_name:
            results.append({
                "name": os_name,
                "category": "Operating System",
                "role": "Client Host",
                "ip": ip,
                "source_protocol": "HTTP User-Agent",
                "raw_banner": ua,
                "risk_hint": "Client operating system fingerprint"
            })

        # Client Application / Browser
        client_name = None
        category = "Web Browser"
        if "chrome/" in ua_lower:
            m = re.search(r"chrome/([\d\.]+)", ua_lower)
            client_name = f"Google Chrome {m.group(1)}" if m else "Google Chrome"
        elif "firefox/" in ua_lower:
            m = re.search(r"firefox/([\d\.]+)", ua_lower)
            client_name = f"Mozilla Firefox {m.group(1)}" if m else "Mozilla Firefox"
        elif "safari/" in ua_lower and "chrome" not in ua_lower:
            client_name = "Apple Safari"
        elif "curl/" in ua_lower:
            client_name = ua
            category = "Command-Line Tool / Script"
        elif "wget/" in ua_lower:
            client_name = ua
            category = "Command-Line Tool / Script"
        elif "python-requests" in ua_lower or "python" in ua_lower:
            client_name = ua
            category = "Automated Python Script"
        elif "powershell" in ua_lower:
            client_name = ua
            category = "PowerShell Automation"

        if client_name:
            results.append({
                "name": client_name,
                "category": category,
                "role": "Client Application",
                "ip": ip,
                "source_protocol": "HTTP User-Agent",
                "raw_banner": ua,
                "risk_hint": "Client web program identification"
            })

        if not results:
            results.append({
                "name": ua[:50],
                "category": "HTTP Client Program",
                "role": "Client Application",
                "ip": ip,
                "source_protocol": "HTTP User-Agent",
                "raw_banner": ua,
                "risk_hint": "Unclassified User-Agent header"
            })

        return results
