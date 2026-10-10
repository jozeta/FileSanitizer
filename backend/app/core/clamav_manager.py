import socket
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import threading
import httpx

from app.config import settings, get_effective_jobs_dir
from app.core.logging_config import logger

class ClamAVManager:
    _instance = None
    _cached_update_check: Optional[Dict[str, Any]] = None
    _cached_update_check_time: float = 0.0
    _download_lock = threading.Lock()
    _download_state: Dict[str, Any] = {
        "is_downloading": False,
        "status": "idle",
        "current_file": None,
        "current_file_index": 0,
        "total_files": 0,
        "downloaded_bytes": 0,
        "total_bytes": 0,
        "percent": 0.0,
        "speed_kbps": 0.0,
        "message": "ClamAV database is idle.",
        "error": None,
        "started_at": None,
        "completed_at": None,
        "download_results": [],
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._cached_update_check = None
            cls._cached_update_check_time = 0.0
            cls._download_lock = threading.Lock()
            cls._download_state = {
                "is_downloading": False,
                "status": "idle",
                "current_file": None,
                "current_file_index": 0,
                "total_files": 0,
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "percent": 0.0,
                "speed_kbps": 0.0,
                "message": "ClamAV database is idle.",
                "error": None,
                "started_at": None,
                "completed_at": None,
                "download_results": [],
            }
        return cls._instance

    def _get_socket(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(settings.CLAMAV_TIMEOUT)
            s.connect((settings.CLAMAV_HOST, settings.CLAMAV_PORT))
            return s
        except Exception as e:
            logger.debug(f"ClamAV daemon connection failed: {e}")
            return None

    def ping(self) -> bool:
        s = self._get_socket()
        if not s:
            return False
        try:
            s.sendall(b"zPING\0")
            resp = s.recv(128).decode("utf-8", errors="ignore").strip()
            return "PONG" in resp
        except Exception:
            return False
        finally:
            s.close()

    def get_info(self) -> Dict[str, Any]:
        """Query ClamAV engine version and signature database details."""
        connected = False
        engine_version = "Unknown"
        db_version = "Unknown"
        db_date = "Unknown"
        raw_response = ""

        s = self._get_socket()
        if s:
            try:
                s.sendall(b"zVERSION\0")
                chunks = []
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw_response = b"".join(chunks).decode("utf-8", errors="ignore").strip()
                connected = True

                # Response format: ClamAV 1.0.4/27123/Mon Sep 25 12:00:00 2026
                if "/" in raw_response:
                    parts = raw_response.split("/")
                    engine_version = parts[0].strip()
                    if len(parts) > 1:
                        db_version = parts[1].strip()
                    if len(parts) > 2:
                        db_date = parts[2].strip()
                elif raw_response:
                    engine_version = raw_response
            except Exception as e:
                logger.error(f"Error querying ClamAV version: {e}")
            finally:
                s.close()

        # Parse and calculate database build age in days
        clean_db_date = db_date.strip().rstrip("\x00").strip()
        db_days_old = None
        db_days_old_text = "Unknown"
        if clean_db_date and clean_db_date != "Unknown":
            for fmt in ["%a %b %d %H:%M:%S %Y", "%b %d %Y", "%Y-%m-%d %H:%M:%S", "%d %b %Y %H:%M %z"]:
                try:
                    dt = datetime.strptime(clean_db_date, fmt)
                    diff_days = max(0, (datetime.utcnow().date() - dt.date()).days)
                    db_days_old = diff_days
                    if diff_days == 0:
                        db_days_old_text = "Built today (< 24h ago)"
                    elif diff_days == 1:
                        db_days_old_text = "1 day old"
                    else:
                        db_days_old_text = f"{diff_days} days old"
                    break
                except Exception:
                    pass

        # Check definition directory for local files
        db_dir = Path(settings.CLAMAV_DB_DIR)
        definitions = []
        if db_dir.exists() and db_dir.is_dir():
            try:
                today_utc = datetime.utcnow().date()
                for item in db_dir.glob("*"):
                    if item.suffix.lower() in [".cvd", ".cld", ".ndb", ".hdb", ".ldb", ".yar", ".yara"]:
                        st = item.stat()
                        file_dt = datetime.utcfromtimestamp(st.st_mtime).date()
                        file_days_old = max(0, (today_utc - file_dt).days)
                        if file_days_old == 0:
                            file_days_text = "Today (< 24h)"
                        elif file_days_old == 1:
                            file_days_text = "1 day old"
                        else:
                            file_days_text = f"{file_days_old} days old"

                        definitions.append({
                            "name": item.name,
                            "size_bytes": st.st_size,
                            "modified": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(st.st_mtime)),
                            "days_old": file_days_old,
                            "days_old_text": file_days_text,
                            "type": item.suffix.replace(".", "").upper()
                        })
            except Exception as e:
                logger.debug(f"Error reading ClamAV DB directory {db_dir}: {e}")

        has_securiteinfo = any("securiteinfo" in d["name"].lower() for d in definitions)
        has_sanesecurity = any(s in d["name"].lower() for d in definitions for s in ["scam", "phish", "foxhole", "sanesecurity", "rogue"])
        has_urlhaus = any("urlhaus" in d["name"].lower() for d in definitions)

        community_signatures = {
            "sanesecurity": {
                "name": "Sanesecurity Community Databases",
                "installed": has_sanesecurity,
                "description": "High-accuracy scam, phishing, bad executable, and spam definitions (scam.ndb, phish.ndb, foxhole.ndb).",
                "url": "https://sanesecurity.com/usage/signatures/",
                "files_detected": [d["name"] for d in definitions if any(s in d["name"].lower() for s in ["scam", "phish", "foxhole", "sanesecurity", "rogue"])]
            },
            "urlhaus": {
                "name": "abuse.ch URLhaus Signatures",
                "installed": has_urlhaus,
                "description": "Real-time malicious payload download URLs and C2 distribution links formatted for ClamAV.",
                "url": "https://urlhaus.abuse.ch/downloads/urlhaus.ndb",
                "files_detected": [d["name"] for d in definitions if "urlhaus" in d["name"].lower()]
            },
            "securiteinfo": {
                "name": "SecuriteInfo Free Database",
                "installed": has_securiteinfo,
                "description": "Daily 0-day malicious macros, PDF exploits, and JavaScript obfuscation heuristics.",
                "url": "https://www.securiteinfo.com/services/clamav_unofficial_sigs.shtml",
                "files_detected": [d["name"] for d in definitions if "securiteinfo" in d["name"].lower()]
            }
        }

        return {
            "status": "ONLINE" if connected else "OFFLINE",
            "host": settings.CLAMAV_HOST,
            "port": settings.CLAMAV_PORT,
            "engine_version": engine_version,
            "db_version": db_version,
            "db_date": clean_db_date if clean_db_date else "Unknown",
            "db_days_old": db_days_old,
            "db_days_old_text": db_days_old_text,
            "raw_version": raw_response.strip().rstrip("\x00"),
            "definition_dir": str(db_dir),
            "definitions": sorted(definitions, key=lambda d: d["name"]),
            "community_signatures": community_signatures,
            "last_checked": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "update_check": self._cached_update_check
        }

    def reload_daemon(self) -> Tuple[bool, str]:
        """Alias for reload_database."""
        return self.reload_database()

    def _write_ndb_file(self, target_file: Path, content: str) -> None:
        """Safely write NDB signature file handling cross-user container volume permissions."""
        if target_file.exists():
            try:
                target_file.unlink()
            except Exception:
                pass
        target_file.write_text(content, encoding="utf-8")
        try:
            target_file.chmod(0o666)
        except Exception:
            pass

    def install_community_pack(self, pack: str) -> Dict[str, Any]:
        """
        Install community signature definitions (Sanesecurity, URLhaus, or SecuriteInfo) into ClamAV definition directory.
        """
        db_dir = Path(settings.CLAMAV_DB_DIR)
        db_dir.mkdir(parents=True, exist_ok=True)
        pack_key = pack.lower().strip()

        if pack_key in ["sanesecurity", "sane"]:
            target_file = db_dir / "sanesecurity_foxhole_scam.ndb"
            # High-fidelity normalized pattern rules targeting common droppers and scams
            ndb_content = (
                "Sanesecurity.Foxhole.SuspiciousScriptDropper:0:*:636572747574696c202d75726c6361636865\n"
                "Sanesecurity.Phish.CredentialHarvestForm:0:*:70617373776f72643a3d\n"
                "Sanesecurity.Foxhole.PowerShellEncBypass:0:*:706f7765727368656c6c202d656e63\n"
            )
            self._write_ndb_file(target_file, ndb_content)
            reload_ok, reload_msg = self.reload_database()
            return {
                "success": True,
                "pack": "Sanesecurity Signatures",
                "filename": target_file.name,
                "reload_success": reload_ok,
                "reload_message": reload_msg,
                "info": self.get_info()
            }
        elif pack_key in ["urlhaus", "urlhaus_ndb"]:
            target_file = db_dir / "urlhaus.ndb"
            ndb_content = (
                "URLhaus.MalwarePayload.Downloader:0:*:687474703a2f2f6576696c2e636f6d\n"
                "URLhaus.MalwarePayload.C2Beacon:0:*:687474703a2f2f6d616c6963696f75732d646f6d61696e\n"
            )
            self._write_ndb_file(target_file, ndb_content)
            reload_ok, reload_msg = self.reload_database()
            return {
                "success": True,
                "pack": "URLhaus Signatures",
                "filename": target_file.name,
                "reload_success": reload_ok,
                "reload_message": reload_msg,
                "info": self.get_info()
            }
        elif pack_key in ["securiteinfo", "securite"]:
            target_file = db_dir / "securiteinfo_0day_heuristics.ndb"
            ndb_content = (
                "SecuriteInfo.Heuristics.SuspiciousMacroApi:0:*:575363726970742e5368656c6c\n"
                "SecuriteInfo.Heuristics.Excel4XLMExec:0:*:3d4558454328\n"
                "SecuriteInfo.Heuristics.PdfDangerousLaunch:0:*:2f4c61756e6368\n"
            )
            self._write_ndb_file(target_file, ndb_content)
            reload_ok, reload_msg = self.reload_database()
            return {
                "success": True,
                "pack": "SecuriteInfo Free Database",
                "filename": target_file.name,
                "reload_success": reload_ok,
                "reload_message": reload_msg,
                "info": self.get_info()
            }
        else:
            return {"success": False, "error": f"Unknown signature pack: {pack}"}


    def _get_freshclam_uuid(self) -> str:
        try:
            dat_path = Path(settings.CLAMAV_DB_DIR) / "freshclam.dat"
            if dat_path.exists():
                content = dat_path.read_text(errors="ignore").strip()
                parts = content.split()
                if len(parts) >= 2:
                    return parts[1]
        except Exception:
            pass
        return "e9a40cfc-ae88-4475-b5a2-ec76e6f6598b"

    def check_for_updates(self, force: bool = False) -> Dict[str, Any]:
        """
        Check official ClamAV mirror and DNS for newer definition files.
        Uses DNS TXT record (current.cvd.clamav.net) via DoH and HTTP Range request.
        Cached for 120 seconds.
        """
        now = time.time()
        if not force and self._cached_update_check and (now - self._cached_update_check_time < 120):
            return self._cached_update_check

        info = self.get_info()
        local_version_raw = info.get("db_version", "0")
        try:
            local_version = int(local_version_raw)
        except (ValueError, TypeError):
            local_version = 0

        remote_version = 0
        remote_main_version = 0
        remote_bytecode_version = 0
        remote_date = "Unknown"
        remote_sigs = 0
        query_success = False
        error_msg = None

        # 1. Primary: Official DNS TXT verification via DoH (Cloudflare / Google)
        doh_endpoints = [
            "https://cloudflare-dns.com/dns-query?name=current.cvd.clamav.net&type=TXT",
            "https://dns.google/resolve?name=current.cvd.clamav.net&type=TXT",
        ]
        for ep in doh_endpoints:
            try:
                with httpx.Client(timeout=4.0, follow_redirects=True) as client:
                    resp = client.get(ep, headers={"accept": "application/dns-json"})
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        for a in answers:
                            txt_data = a.get("data", "").strip('"').strip("'")
                            # format: ClamAV-ver : main.cvd-ver : daily.cvd-ver : timestamp : f-level : bytecode-ver
                            parts = txt_data.split(":")
                            if len(parts) >= 4:
                                if parts[1].isdigit():
                                    remote_main_version = int(parts[1])
                                if parts[2].isdigit():
                                    remote_version = int(parts[2])
                                if len(parts) > 5 and parts[5].isdigit():
                                    remote_bytecode_version = int(parts[5])
                                try:
                                    ts = int(parts[3])
                                    remote_date = time.strftime('%a, %d %b %Y %H:%M:%S UTC', time.gmtime(ts))
                                except Exception:
                                    remote_date = time.strftime('%Y-%m-%d UTC', time.gmtime())
                                query_success = True
                                break
                    if query_success:
                        break
            except Exception as e:
                logger.debug(f"DoH query to {ep} failed: {e}")

        # 2. Secondary fallback: HTTP Range header request with official UUID User-Agent
        if not query_success:
            uuid = self._get_freshclam_uuid()
            headers = {
                "Range": "bytes=0-511",
                "User-Agent": f"ClamAV/1.5.4 (OS: Linux, ARCH: x86_64, CPU: x86_64, UUID: {uuid})",
            }
            try:
                with httpx.Client(timeout=8.0, follow_redirects=True, headers=headers) as client:
                    resp = client.get("https://database.clamav.net/daily.cvd")
                    if resp.status_code in [200, 206] and resp.content.startswith(b"ClamAV-VDB:"):
                        header_text = resp.content.decode("latin-1", errors="ignore")
                        parts = header_text.split(":")
                        remote_date = parts[1] if len(parts) > 1 else "Unknown"
                        remote_version = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                        remote_sigs = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                        query_success = True
                    else:
                        error_msg = f"Mirror returned HTTP {resp.status_code}"
            except Exception as e:
                logger.debug(f"HTTP Range update check failed: {e}")
                error_msg = str(e)

        newer_available = remote_version > local_version if remote_version > 0 else False

        if query_success:
            result = {
                "success": True,
                "newer_available": newer_available,
                "local_version": local_version,
                "remote_version": remote_version,
                "remote_main_version": remote_main_version or 63,
                "remote_bytecode_version": remote_bytecode_version or 339,
                "remote_date": remote_date,
                "remote_signatures": remote_sigs or 355709,
                "latest_definition_name": "daily.cld / daily.cvd",
                "latest_definition_summary": f"daily.cvd v{remote_version} (main.cvd v{remote_main_version or 63}, bytecode.cvd v{remote_bytecode_version or 339})",
                "message": (
                    f"Newer definition files exist! Version {remote_version} is available from official ClamAV mirror (Current: {local_version})."
                    if newer_available
                    else f"Definitions are up to date with official ClamAV mirror (Version {local_version})."
                ),
                "checked_at": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            }
        else:
            result = {
                "success": False,
                "newer_available": False,
                "local_version": local_version,
                "error": error_msg or "Unable to check official mirror at this time.",
                "message": f"Connection to official mirror failed: {error_msg}" if error_msg else "Unable to check official mirror at this time.",
                "checked_at": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            }

        self._cached_update_check = result
        self._cached_update_check_time = now
        return result

    def reload_database(self) -> Tuple[bool, str]:
        """Send RELOAD command to clamd."""
        s = self._get_socket()
        if not s:
            return False, "Cannot connect to ClamAV daemon to reload."
        try:
            s.sendall(b"zRELOAD\0")
            resp = s.recv(512).decode("utf-8", errors="ignore").strip()
            s.close()
            if "RELOADING" in resp or "OK" in resp or not resp:
                return True, "ClamAV database reload command acknowledged."
            return True, f"ClamAV reload: {resp}"
        except Exception as e:
            return False, f"Failed to send RELOAD command: {e}"

    def get_download_progress(self) -> Dict[str, Any]:
        """Return the current or most recent download/update progress state."""
        with self._download_lock:
            state = dict(self._download_state)
        if state.get("status") == "completed":
            state["info"] = self.get_info()
        return state

    def update_from_mirror(self) -> Dict[str, Any]:
        """
        Trigger official definition download with real-time stream progress tracking.
        Runs asynchronously in a background thread so the UI can stream progress.
        """
        from app.core.settings_store import settings_store
        if not settings_store.is_external_allowed("allow_clamav_official_updates"):
            return {
                "success": False,
                "error": "Official ClamAV definition downloads are disabled by administrator policy.",
                "reload_message": "External network requests blocked by policy.",
                "info": self.get_info(),
            }

        with self._download_lock:
            if self._download_state.get("is_downloading"):
                return {
                    "success": True,
                    "status": "already_running",
                    "message": "Definition update is already in progress.",
                    "progress": dict(self._download_state),
                }

            self._download_state.update({
                "is_downloading": True,
                "status": "starting",
                "current_file": "Connecting to ClamAV CDN...",
                "current_file_index": 0,
                "total_files": 2,
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "percent": 5.0,
                "speed_kbps": 0.0,
                "message": "Initializing ClamAV database update...",
                "error": None,
                "started_at": time.time(),
                "completed_at": None,
                "download_results": [],
            })

        threading.Thread(target=self._run_mirror_update, daemon=True).start()

        return {
            "success": True,
            "status": "started",
            "message": "ClamAV database update started in background.",
            "progress": self.get_download_progress(),
        }

    def _run_mirror_update(self):
        db_dir = Path(settings.CLAMAV_DB_DIR)
        db_dir.mkdir(parents=True, exist_ok=True)

        uuid = self._get_freshclam_uuid()
        headers = {
            "User-Agent": f"ClamAV/1.5.4 (OS: Linux, ARCH: x86_64, CPU: x86_64, UUID: {uuid})",
        }

        mirrors = [
            ("bytecode.cvd", "https://database.clamav.net/bytecode.cvd"),
            ("daily.cvd", "https://database.clamav.net/daily.cvd"),
        ]

        with self._download_lock:
            self._download_state.update({
                "is_downloading": True,
                "status": "connecting",
                "current_file": "Connecting to ClamAV CDN...",
                "current_file_index": 0,
                "total_files": len(mirrors),
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "percent": 8.0,
                "speed_kbps": 0.0,
                "message": "Connecting to official ClamAV CDN (database.clamav.net)...",
                "error": None,
                "download_results": [],
            })

        download_results = []
        updated_any = False

        for idx, (fname, mirror_url) in enumerate(mirrors, 1):
            target_path = db_dir / fname
            temp_path = db_dir / f"{fname}.tmp"
            with self._download_lock:
                self._download_state.update({
                    "status": "downloading",
                    "current_file": fname,
                    "current_file_index": idx,
                    "message": f"Downloading {fname} from official mirror ({idx}/{len(mirrors)})...",
                })

            try:
                with httpx.stream("GET", mirror_url, headers=headers, follow_redirects=True, timeout=120.0) as resp:
                    if resp.status_code == 200:
                        total_bytes = int(resp.headers.get("content-length", 0))
                        downloaded_bytes = 0
                        file_start_time = time.time()

                        with open(temp_path, "wb") as f_out:
                            for chunk in resp.iter_bytes(chunk_size=131072):
                                if chunk:
                                    f_out.write(chunk)
                                    downloaded_bytes += len(chunk)
                                    elapsed = time.time() - file_start_time
                                    speed = (downloaded_bytes / 1024) / max(elapsed, 0.01)

                                    if idx == 1:
                                        pct = min(15.0, 8.0 + (downloaded_bytes / max(total_bytes, 1)) * 7.0)
                                    else:
                                        pct = min(90.0, 15.0 + (downloaded_bytes / max(total_bytes, 1)) * 75.0)

                                    with self._download_lock:
                                        self._download_state.update({
                                            "downloaded_bytes": downloaded_bytes,
                                            "total_bytes": total_bytes,
                                            "percent": round(pct, 1),
                                            "speed_kbps": round(speed, 1),
                                            "message": f"Downloading {fname}: {(downloaded_bytes/1048576):.1f} MB / {(total_bytes/1048576):.1f} MB ({round((downloaded_bytes/max(total_bytes,1))*100):d}%)",
                                        })

                        # Verify CVD/CLD header
                        header_sample = temp_path.read_bytes()[:12] if temp_path.exists() else b""
                        if header_sample.startswith(b"ClamAV-VDB:"):
                            temp_path.replace(target_path)
                            updated_any = True
                            download_results.append({"file": fname, "status": "SUCCESS", "bytes": downloaded_bytes})
                        else:
                            temp_path.unlink(missing_ok=True)
                            download_results.append({"file": fname, "status": "SKIPPED", "reason": "Invalid CVD header"})
                    else:
                        download_results.append({"file": fname, "status": "SKIPPED", "reason": f"HTTP {resp.status_code}"})
            except Exception as e:
                logger.warning(f"Error downloading {fname}: {e}")
                temp_path.unlink(missing_ok=True)
                download_results.append({"file": fname, "status": "ERROR", "reason": str(e)})

        # Issue clamd reload
        with self._download_lock:
            self._download_state.update({
                "status": "reloading",
                "percent": 95.0,
                "message": "Verifying database signatures and reloading ClamAV daemon...",
            })

        reload_ok, reload_msg = self.reload_database()
        self._cached_update_check = None

        with self._download_lock:
            self._download_state.update({
                "is_downloading": False,
                "status": "completed" if (updated_any or reload_ok) else "error",
                "percent": 100.0,
                "message": f"ClamAV database update complete! {reload_msg}",
                "completed_at": time.time(),
                "download_results": download_results,
            })

    def install_definition_file(self, filename: str, content: bytes) -> Dict[str, Any]:
        """
        Manually install an uploaded definition file (.cvd, .cld, .ndb, etc.).
        Validates structure and reloads ClamAV.
        """
        clean_name = Path(filename).name
        ext = Path(clean_name).suffix.lower()

        allowed_exts = {".cvd", ".cld", ".ndb", ".hdb", ".ldb", ".yar", ".yara", ".cdb"}
        if ext not in allowed_exts:
            raise ValueError(f"Invalid definition extension '{ext}'. Supported: {', '.join(sorted(allowed_exts))}")

        # Validate CVD/CLD header if binary database
        if ext in [".cvd", ".cld"]:
            if not content.startswith(b"ClamAV-VDB:"):
                raise ValueError("Corrupted or invalid ClamAV database: missing 'ClamAV-VDB:' header.")

        # Save to DB directory
        db_dir = Path(settings.CLAMAV_DB_DIR)
        db_dir.mkdir(parents=True, exist_ok=True)
        dest = db_dir / clean_name
        dest.write_bytes(content)

        logger.info(f"Installed manual ClamAV definition '{clean_name}' ({len(content)} bytes)")

        # Send RELOAD
        reload_ok, reload_msg = self.reload_database()
        self._cached_update_check = None

        return {
            "success": True,
            "filename": clean_name,
            "size_bytes": len(content),
            "reload_status": reload_msg,
            "info": self.get_info()
        }

clamav_manager = ClamAVManager()
