import socket
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from app.config import settings
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger

class ClamAVScanner(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "ClamAVScanner"

    def _connect(self) -> Optional[socket.socket]:
        """Establish TCP connection to ClamAV daemon."""
        if not settings.CLAMAV_ENABLED:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(settings.CLAMAV_TIMEOUT)
            s.connect((settings.CLAMAV_HOST, settings.CLAMAV_PORT))
            return s
        except Exception as e:
            logger.debug(f"Unable to connect to ClamAV daemon at {settings.CLAMAV_HOST}:{settings.CLAMAV_PORT}: {e}")
            return None

    def get_version(self) -> Tuple[str, str]:
        """Query ClamAV daemon version and signature database date."""
        sock = self._connect()
        if not sock:
            return "Unavailable", "Unavailable"
        try:
            sock.sendall(b"zVERSION\0")
            response = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response += chunk
            text = response.decode('utf-8', errors='ignore').strip()
            # Format typically: ClamAV 1.0.0/26000/Fri Sep 24 ...
            parts = text.split("/")
            engine = parts[0] if len(parts) > 0 else text
            db_date = parts[2] if len(parts) > 2 else "Current"
            return engine, db_date
        except Exception:
            return "Unknown", "Unknown"
        finally:
            sock.close()

    def scan_file_stream(self, file_path: Path) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Stream file to ClamAV daemon using INSTREAM protocol.
        Returns: (status, threat_name, error_message)
        status: CLEAN, MALICIOUS, ERROR, UNAVAILABLE
        """
        if not settings.CLAMAV_ENABLED:
            return "UNAVAILABLE", None, "ClamAV scanner is disabled in configuration."

        sock = self._connect()
        if not sock:
            return "UNAVAILABLE", None, f"ClamAV daemon at {settings.CLAMAV_HOST}:{settings.CLAMAV_PORT} is not reachable."

        try:
            # Send INSTREAM command with null delimiter
            sock.sendall(b"zINSTREAM\0")

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    # Send chunk size as 4-byte network-order integer followed by chunk
                    sock.sendall(struct.pack("!I", len(chunk)) + chunk)

            # Send 0-length chunk to indicate EOF
            sock.sendall(struct.pack("!I", 0))

            # Read response
            response = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            resp_str = response.decode("utf-8", errors="ignore").strip()
            # Typical responses:
            # "stream: OK"
            # "stream: Eicar-Test-Signature FOUND"
            # "stream: ... ERROR"
            if "FOUND" in resp_str:
                # Extract threat name
                threat = resp_str.replace("stream:", "").replace("FOUND", "").strip()
                return "MALICIOUS", threat, None
            elif "OK" in resp_str:
                return "CLEAN", None, None
            elif "ERROR" in resp_str:
                return "ERROR", None, resp_str
            else:
                return "ERROR", None, f"Unexpected response: {resp_str}"

        except Exception as e:
            logger.error(f"Error communicating with ClamAV: {e}")
            return "ERROR", None, str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        timestamp = datetime.utcnow().isoformat() + "Z"
        engine_version, db_info = self.get_version()
        status, threat_name, err = self.scan_file_stream(file_path)

        findings = []
        if status == "MALICIOUS":
            findings.append(Finding(
                category="malware",
                severity="critical",
                title=f"Malware Detected: {threat_name or 'Unknown Threat'}",
                description=(
                    f"ClamAV detected malicious content ({threat_name}). "
                    "By security policy, downloading or sanitizing files with active malware detections is restricted."
                ),
                details={
                    "scanner": "ClamAV",
                    "threat": threat_name,
                    "engine": engine_version,
                    "db": db_info,
                    "timestamp": timestamp
                }
            ))
        elif status == "ERROR":
            findings.append(Finding(
                category="malware",
                severity="medium",
                title="Antivirus Scanner Error",
                description=f"ClamAV encountered an error scanning this file: {err}",
                details={"error": err}
            ))
        elif status == "UNAVAILABLE":
            findings.append(Finding(
                category="malware",
                severity="info",
                title="Antivirus Scanner Unavailable",
                description=(
                    f"ClamAV scanning was not performed: {err}. "
                    "Ensure ClamAV container is running if real-time AV scanning is required."
                ),
                details={"reason": err}
            ))

        return AnalyzerResult(
            analyzer_name=self.name,
            success=(status != "ERROR"),
            error_message=err or "",
            findings=findings,
            data={
                "scanner": "ClamAV",
                "status": status,
                "engine_version": engine_version,
                "signature_db": db_info,
                "threat_name": threat_name,
                "scan_timestamp": timestamp
            }
        )
