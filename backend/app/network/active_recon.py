"""
Controlled Service Banner & Port Discovery (Strictly Opt-In).
Performs bounded TCP handshakes and banner grabbing on standard ports with strict timeouts,
rate limits, and pre-scan anti-SSRF verification.
"""

import socket
import concurrent.futures
from typing import Dict, Any, List, Optional
from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


# Standard well-known service ports to check in active reconnaissance
STANDARD_PROBE_PORTS = [
    {"port": 21, "service": "FTP", "probe": b""},
    {"port": 22, "service": "SSH", "probe": b""},
    {"port": 25, "service": "SMTP", "probe": b"EHLO filesanitizer.local\r\n"},
    {"port": 53, "service": "DNS", "probe": b""},
    {"port": 80, "service": "HTTP", "probe": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"},
    {"port": 110, "service": "POP3", "probe": b""},
    {"port": 143, "service": "IMAP", "probe": b""},
    {"port": 443, "service": "HTTPS", "probe": b""},
    {"port": 465, "service": "SMTPS", "probe": b""},
    {"port": 587, "service": "Submission", "probe": b"EHLO filesanitizer.local\r\n"},
    {"port": 853, "service": "DNS-over-TLS", "probe": b""},
    {"port": 993, "service": "IMAPS", "probe": b""},
    {"port": 995, "service": "POP3S", "probe": b""},
    {"port": 3389, "service": "RDP", "probe": b""},
    {"port": 8080, "service": "HTTP-Proxy / Alt-HTTP", "probe": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"},
    {"port": 8443, "service": "Alt-HTTPS", "probe": b""}
]


class ActiveServiceScanner:
    """
    Executes controlled, authorized TCP port checks and banner grabs.
    """

    @classmethod
    def scan_services(cls, target_host: str, authorized: bool = False) -> Dict[str, Any]:
        """
        Scans standard ports on target_host only when authorized=True.
        """
        clean_host = target_host.strip().lower().rstrip(".")

        result: Dict[str, Any] = {
            "target": clean_host,
            "authorized": authorized,
            "executed": False,
            "open_ports_count": 0,
            "services": [],
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
        result["executed"] = True
        result["message"] = "Active reconnaissance completed."

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
                            # Clean up multi-line banner
                            banner = banner.split("\r\n")[0].split("\n")[0][:120]
                    except Exception:
                        pass

                    return {
                        "port": port,
                        "protocol": "TCP",
                        "service": service_name,
                        "state": "open",
                        "banner": banner if banner else None
                    }
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(_probe_port, spec) for spec in STANDARD_PROBE_PORTS]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    open_services.append(res)

        # Sort by port number
        open_services.sort(key=lambda x: x["port"])
        result["services"] = open_services
        result["open_ports_count"] = len(open_services)

        return result
