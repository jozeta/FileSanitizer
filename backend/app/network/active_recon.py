"""
Controlled Service Banner & Port Discovery using Nmap (Strictly Opt-In).
Performs SYN stealth and service-version scanning with strict timeouts,
rate limits, and pre-scan anti-SSRF verification.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


# Default target port specification requested for active reconnaissance
DEFAULT_NMAP_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
    "1433,1521,2049,2375,3306,3389,5432,5900,5985,5986,6379,"
    "8080,8443,9200,11211,27017"
)

# Standard fallback probe definitions when Nmap binary is unavailable
STANDARD_PROBE_PORTS = [
    {"port": 21, "service": "FTP", "probe": b""},
    {"port": 22, "service": "SSH", "probe": b""},
    {"port": 23, "service": "Telnet", "probe": b""},
    {"port": 25, "service": "SMTP", "probe": b"EHLO filesanitizer.local\r\n"},
    {"port": 53, "service": "DNS", "probe": b""},
    {"port": 80, "service": "HTTP", "probe": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"},
    {"port": 110, "service": "POP3", "probe": b""},
    {"port": 111, "service": "RPCBind", "probe": b""},
    {"port": 135, "service": "MSRPC", "probe": b""},
    {"port": 139, "service": "NetBIOS-SSN", "probe": b""},
    {"port": 143, "service": "IMAP", "probe": b""},
    {"port": 443, "service": "HTTPS", "probe": b""},
    {"port": 445, "service": "SMB", "probe": b""},
    {"port": 993, "service": "IMAPS", "probe": b""},
    {"port": 995, "service": "POP3S", "probe": b""},
    {"port": 1433, "service": "MS-SQL", "probe": b""},
    {"port": 1521, "service": "Oracle-TNS", "probe": b""},
    {"port": 2049, "service": "NFS", "probe": b""},
    {"port": 2375, "service": "Docker-API", "probe": b""},
    {"port": 3306, "service": "MySQL", "probe": b""},
    {"port": 3389, "service": "RDP", "probe": b""},
    {"port": 5432, "service": "PostgreSQL", "probe": b""},
    {"port": 5900, "service": "VNC", "probe": b""},
    {"port": 5985, "service": "WinRM-HTTP", "probe": b""},
    {"port": 5986, "service": "WinRM-HTTPS", "probe": b""},
    {"port": 6379, "service": "Redis", "probe": b""},
    {"port": 8080, "service": "HTTP-Alt", "probe": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"},
    {"port": 8443, "service": "HTTPS-Alt", "probe": b""},
    {"port": 9200, "service": "Elasticsearch", "probe": b""},
    {"port": 11211, "service": "Memcached", "probe": b""},
    {"port": 27017, "service": "MongoDB", "probe": b""}
]


class ActiveServiceScanner:
    """
    Executes controlled, authorized service and port reconnaissance using Nmap.
    Employs SYN stealth scanning (-sS -sV --version-light -T3 --open --reason -oA)
    with graceful unprivileged connect fallback (-sT) and in-memory socket probe fallback.
    """

    @classmethod
    def scan_services(
        cls,
        target_host: str,
        authorized: bool = False,
        ports: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scans standard ports on target_host only when authorized=True.
        Enforces SSRF boundary guards prior to dispatching any network probes.
        """
        clean_host = target_host.strip().lower().rstrip(".")

        result: Dict[str, Any] = {
            "target": clean_host,
            "authorized": authorized,
            "executed": False,
            "scanner": "nmap",
            "scan_command": None,
            "open_ports_count": 0,
            "services": [],
            "raw_nmap": None,
            "message": "Active port reconnaissance requires explicit operator authorization."
        }

        if not authorized:
            return result

        # Anti-SSRF check before scanning
        is_safe, ssrf_reason, resolved_ips = validate_url_for_ssrf(f"http://{clean_host}")
        if not is_safe:
            result["message"] = f"Active scan prohibited: {ssrf_reason}"
            return result

        target_ip = resolved_ips[0] if resolved_ips else clean_host
        scan_ports = ports or DEFAULT_NMAP_PORTS

        # Attempt Nmap execution
        nmap_path = shutil.which("nmap")
        if nmap_path:
            try:
                services, raw_nmap, executed_cmd = cls._execute_nmap_scan(
                    target=clean_host,
                    target_ip=target_ip,
                    ports=scan_ports
                )
                result["executed"] = True
                result["scanner"] = "nmap"
                result["scan_command"] = executed_cmd
                result["services"] = services
                result["open_ports_count"] = len(services)
                result["raw_nmap"] = raw_nmap
                result["message"] = (
                    f"Nmap active reconnaissance completed: "
                    f"{len(services)} open service{'s' if len(services) != 1 else ''} identified."
                )
                return result
            except Exception as e:
                logger.warning(
                    f"[ActiveServiceScanner] Nmap scan execution failed ({e}); "
                    "falling back to socket probe.",
                    exc_info=True
                )

        # Fallback to Python socket banner grabber if Nmap is absent or failed
        logger.info(f"[ActiveServiceScanner] Using socket probe fallback for {clean_host}")
        services = cls._fallback_socket_scan(clean_host=clean_host, target_ip=target_ip)
        result["executed"] = True
        result["scanner"] = "socket_probe"
        result["scan_command"] = f"socket_connect({target_ip}, 31 ports)"
        result["services"] = services
        result["open_ports_count"] = len(services)
        result["message"] = (
            f"Active socket reconnaissance completed: "
            f"{len(services)} open service{'s' if len(services) != 1 else ''} identified."
        )
        return result

    @classmethod
    def _execute_nmap_scan(
        cls,
        target: str,
        target_ip: str,
        ports: str
    ) -> Tuple[List[Dict[str, Any]], str, str]:
        """
        Executes Nmap with -sS (or fallback to -sT) and parses XML/normal output.
        """
        scan_id = uuid.uuid4().hex[:8]
        tmp_dir = Path(tempfile.gettempdir()) / f"nmap_{scan_id}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        try:
            tmp_dir.chmod(0o777)
        except Exception:
            pass
        out_prefix = tmp_dir / "nmap-service-scan"

        # Determine target string to pass to Nmap
        # Using target ensures SNI/vhost inspection works if hostname, target_ip if direct IP
        scan_target = target if target else target_ip

        # Command attempt 1: sudo nmap -sS -sV --version-light -T3 --open -p <ports> --reason -oA <out> <target>
        # We also pass -Pn to avoid false drops when ICMP echo is firewalled
        syn_cmd = [
            "sudo", "nmap",
            "-sS",
            "-sV",
            "--version-light",
            "-T3",
            "--open",
            "-Pn",
            "-p", ports,
            "--reason",
            "-oA", str(out_prefix),
            scan_target
        ]

        connect_cmd = [
            "nmap",
            "-sT",
            "-sV",
            "--version-light",
            "-T3",
            "--open",
            "-Pn",
            "-p", ports,
            "--reason",
            "-oA", str(out_prefix),
            scan_target
        ]

        executed_cmd_str = " ".join(syn_cmd)
        raw_nmap = ""
        services: List[Dict[str, Any]] = []

        try:
            logger.info(f"[ActiveServiceScanner] Running SYN scan: {executed_cmd_str}")
            proc = subprocess.run(
                syn_cmd,
                capture_output=True,
                text=True,
                timeout=90
            )

            # Check if SYN scan succeeded
            xml_file = tmp_dir / "nmap-service-scan.xml"
            if proc.returncode == 0 and xml_file.exists():
                raw_nmap = (tmp_dir / "nmap-service-scan.nmap").read_text(errors="replace") if (tmp_dir / "nmap-service-scan.nmap").exists() else proc.stdout
                services = cls._parse_nmap_xml(xml_file.read_text(errors="replace"))
                return services, raw_nmap, executed_cmd_str
            else:
                logger.warning(
                    f"[ActiveServiceScanner] SYN scan exited with {proc.returncode}. Stderr: {proc.stderr[:200]}. "
                    "Attempting fallback TCP connect scan (-sT)..."
                )
        except Exception as syn_err:
            logger.warning(f"[ActiveServiceScanner] SYN scan attempt encountered error: {syn_err}. Trying -sT...")

        # Fallback to connect scan -sT
        executed_cmd_str = " ".join(connect_cmd)
        logger.info(f"[ActiveServiceScanner] Running connect scan: {executed_cmd_str}")
        proc_conn = subprocess.run(
            connect_cmd,
            capture_output=True,
            text=True,
            timeout=90,
            check=True
        )

        xml_file = tmp_dir / "nmap-service-scan.xml"
        if xml_file.exists():
            raw_nmap = (tmp_dir / "nmap-service-scan.nmap").read_text(errors="replace") if (tmp_dir / "nmap-service-scan.nmap").exists() else proc_conn.stdout
            services = cls._parse_nmap_xml(xml_file.read_text(errors="replace"))
        else:
            raw_nmap = proc_conn.stdout

        # Clean up temporary scan files
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        return services, raw_nmap, executed_cmd_str

    @classmethod
    def _parse_nmap_xml(cls, xml_content: str) -> List[Dict[str, Any]]:
        """
        Parses Nmap XML output (-oX or -oA .xml) into structured service objects.
        """
        services: List[Dict[str, Any]] = []
        if not xml_content or not xml_content.strip():
            return services

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as pe:
            logger.warning(f"[ActiveServiceScanner] Failed to parse Nmap XML: {pe}")
            return services

        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                try:
                    port_id = int(port_el.get("portid", 0))
                except ValueError:
                    continue

                proto = (port_el.get("protocol") or "tcp").upper()
                state_el = port_el.find("state")
                state = state_el.get("state", "open") if state_el is not None else "open"
                reason = state_el.get("reason", "syn-ack") if state_el is not None else "syn-ack"

                # Filter strictly for open ports
                if state != "open":
                    continue

                service_el = port_el.find("service")
                service_name = "unknown"
                product = None
                version = None
                extrainfo = None
                tunnel = None
                cpe_list: List[str] = []

                if service_el is not None:
                    service_name = service_el.get("name", "unknown")
                    product = service_el.get("product")
                    version = service_el.get("version")
                    extrainfo = service_el.get("extrainfo")
                    tunnel = service_el.get("tunnel")
                    for cpe_el in service_el.findall("cpe"):
                        if cpe_el.text:
                            cpe_list.append(cpe_el.text)

                # Normalize service name when SSL/TLS tunnel is active
                display_service = service_name
                if tunnel == "ssl":
                    if service_name == "http":
                        display_service = "https"
                    elif not service_name.endswith("s"):
                        display_service = f"{service_name}s"

                # Construct rich banner string from product and version metadata
                banner_parts = []
                if product:
                    banner_parts.append(product)
                if version:
                    banner_parts.append(version)
                if extrainfo:
                    banner_parts.append(f"({extrainfo})")

                banner_str = " ".join(banner_parts).strip() if banner_parts else None

                services.append({
                    "port": port_id,
                    "protocol": proto,
                    "service": display_service,
                    "state": state,
                    "reason": reason,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel,
                    "cpe": cpe_list,
                    "banner": banner_str or f"{display_service} service"
                })

        # Sort ascending by port number
        services.sort(key=lambda s: s["port"])
        return services

    @classmethod
    def _fallback_socket_scan(cls, clean_host: str, target_ip: str) -> List[Dict[str, Any]]:
        """
        Pure Python fallback TCP socket probe when Nmap is unavailable.
        """
        import concurrent.futures

        open_services: List[Dict[str, Any]] = []

        def _probe_port(spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            port = spec["port"]
            service_name = spec["service"]
            raw_probe = spec.get("probe", b"")
            if b"{host}" in raw_probe:
                raw_probe = raw_probe.replace(b"{host}", clean_host.encode())

            try:
                with socket.create_connection((target_ip, port), timeout=0.8) as sock:
                    sock.settimeout(0.8)
                    banner = ""
                    if raw_probe:
                        try:
                            sock.sendall(raw_probe)
                        except Exception:
                            pass

                    try:
                        resp = sock.recv(512)
                        if resp:
                            banner = resp.decode("utf-8", errors="ignore").strip()
                            banner = banner.split("\r\n")[0].split("\n")[0][:120]
                    except Exception:
                        pass

                    return {
                        "port": port,
                        "protocol": "TCP",
                        "service": service_name,
                        "state": "open",
                        "reason": "conn-ack",
                        "product": None,
                        "version": None,
                        "extrainfo": None,
                        "tunnel": "ssl" if "HTTPS" in service_name or port in (443, 8443, 993, 995) else None,
                        "cpe": [],
                        "banner": banner if banner else f"{service_name} service"
                    }
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_probe_port, spec) for spec in STANDARD_PROBE_PORTS]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    open_services.append(res)

        open_services.sort(key=lambda x: x["port"])
        return open_services
