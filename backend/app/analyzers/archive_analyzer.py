import os
import tarfile
import zipfile
import gzip
import hashlib
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.config import settings
from app.core.logging_config import logger

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".pif", ".cpl", ".hta",
    ".msi", ".msp", ".jar", ".com", ".gadget", ".sh", ".bash", ".elf"
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".bz2", ".xz", ".rar"}

COMMON_MALWARE_PASSWORDS = [
    "infected", "virus", "password", "123456", "malware", "clean",
    "sample", "test", "admin", "1234", "rules", "danger", "secret"
]

class ArchiveAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "ArchiveAnalyzer"

    @staticmethod
    def _is_rar_file(file_path: Path) -> bool:
        try:
            with open(file_path, "rb") as f:
                sig = f.read(7)
                if sig.startswith(b"Rar!\x1a\x07"):
                    return True
        except Exception:
            pass
        try:
            import rarfile
            return rarfile.is_rarfile(str(file_path))
        except Exception:
            pass
        return str(file_path).lower().endswith(".rar")

    def analyze(self, file_path: Path, filename: str, mime_type: str, provided_password: Optional[str] = None) -> AnalyzerResult:
        file_path = Path(file_path)
        findings: List[Finding] = []
        data: Dict[str, Any] = {
            "total_files": 0,
            "total_uncompressed_size": 0,
            "compressed_size": file_path.stat().st_size,
            "compression_ratio": 1.0,
            "is_encrypted": False,
            "is_unlocked": False,
            "unlock_password": None,
            "has_path_traversal": False,
            "traversal_files": [],
            "has_executables": False,
            "executable_files": [],
            "nested_archives": [],
            "is_zip_bomb": False,
            "file_list": [],
            "extracted_files": [],
            "text_corpus": "",
            "extracted_iocs": {"ips": [], "domains": [], "users": [], "hosts": [], "credentials": []}
        }

        # Check for Archive Polyglots (preceding bytes before archive header)
        try:
            with open(file_path, "rb") as af:
                header_bytes = af.read(1024)
            if header_bytes.startswith(b"GIF89a") and (b"PK\x03\x04" in header_bytes or b"Rar!" in header_bytes):
                findings.append(Finding(
                    category="evasion",
                    severity="critical",
                    title="GIF/Archive Polyglot Container Detected",
                    description="File starts with a valid GIF image header but embeds a functional ZIP/RAR archive payload.",
                    details={"mitre_technique": "T1036"}
                ))
            elif header_bytes.startswith(b"\xff\xd8\xff") and (b"PK\x03\x04" in header_bytes or b"Rar!" in header_bytes):
                findings.append(Finding(
                    category="evasion",
                    severity="critical",
                    title="JPEG/Archive Polyglot Container Detected",
                    description="File starts with a valid JPEG header but embeds a functional ZIP/RAR archive payload.",
                    details={"mitre_technique": "T1036"}
                ))
            elif header_bytes.startswith(b"%PDF-") and (b"PK\x03\x04" in header_bytes or b"Rar!" in header_bytes):
                findings.append(Finding(
                    category="evasion",
                    severity="critical",
                    title="PDF/Archive Polyglot Container Detected",
                    description="File starts with a valid PDF header but embeds a functional ZIP/RAR archive payload.",
                    details={"mitre_technique": "T1036"}
                ))
        except Exception:
            pass

        # Check for ZIP archive
        if zipfile.is_zipfile(file_path):
            self._inspect_zip(file_path, data, findings, provided_password=provided_password)
        elif self._is_rar_file(file_path):
            self._inspect_rar(file_path, data, findings, provided_password=provided_password)
        elif tarfile.is_tarfile(file_path):
            self._inspect_tar(file_path, data, findings)
        elif mime_type == "application/gzip" or filename.lower().endswith(".gz"):
            self._inspect_gzip(file_path, data, findings)
        else:
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Unsupported or Corrupted Archive",
                description="Archive format could not be verified by safe container inspection."
            ))

        self._record_findings(data, findings)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )

    def _inspect_zip(self, file_path: Path, data: Dict[str, Any], findings: List[Finding], provided_password: Optional[str] = None) -> None:
        zf = None
        try:
            try:
                import pyzipper
                zf = pyzipper.AESZipFile(file_path, 'r')
            except Exception:
                zf = zipfile.ZipFile(file_path, 'r')

            infos = zf.infolist()
            data["total_files"] = len(infos)

            # Check max files limit
            if data["total_files"] > settings.MAX_ARCHIVE_FILES:
                data["is_zip_bomb"] = True
                findings.append(Finding(
                    category="archive",
                    severity="critical",
                    title="Archive File Count Exceeded (Zip Bomb Warning)",
                    description=f"Archive contains {data['total_files']} files, exceeding the safety threshold ({settings.MAX_ARCHIVE_FILES}).",
                    details={"file_count": data["total_files"]}
                ))

            uncompressed_total = 0
            for info in infos:
                filename = info.filename
                uncompressed_total += info.file_size

                dt_str = None
                if hasattr(info, "date_time") and info.date_time:
                    try:
                        dt = info.date_time
                        dt_str = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}T{dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}Z"
                    except Exception:
                        pass

                data["file_list"].append({
                    "filename": filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "date_time": dt_str,
                    "created_date": dt_str,
                    "modified_date": dt_str,
                    "is_encrypted": bool(info.flag_bits & 0x1)
                })

                # Check encryption / password
                if info.flag_bits & 0x1:
                    data["is_encrypted"] = True

                # Check Path Traversal
                if self._is_path_traversal(filename):
                    data["has_path_traversal"] = True
                    data["traversal_files"].append(filename)

                # Check Executables / Dangerous scripts
                ext = Path(filename).suffix.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    data["has_executables"] = True
                    data["executable_files"].append(filename)

                # Check Nested Archives
                if ext in ARCHIVE_EXTENSIONS:
                    data["nested_archives"].append(filename)

            data["total_uncompressed_size"] = uncompressed_total
            comp_size = max(data["compressed_size"], 1)
            data["compression_ratio"] = round(uncompressed_total / comp_size, 2)

            # Check encryption / password with auto-unlocking pipeline
            if data["is_encrypted"]:
                from app.core.settings_store import settings_store
                candidates = []
                if provided_password:
                    candidates.append(provided_password)
                for cp in settings_store.get_archive_passwords():
                    if cp not in candidates:
                        candidates.append(cp)
                for mp in COMMON_MALWARE_PASSWORDS:
                    if mp not in candidates:
                        candidates.append(mp)

                enc_info = next((i for i in infos if (i.flag_bits & 0x1) and i.file_size > 0), None)
                if enc_info:
                    for cand in candidates:
                        try:
                            pwd_bytes = cand.encode('utf-8') if isinstance(cand, str) else cand
                            with zf.open(enc_info.filename, pwd=pwd_bytes) as test_f:
                                test_f.read(16)
                                data["is_unlocked"] = True
                                data["unlock_password"] = cand
                                data["auto_unlocked"] = bool(not provided_password or cand != provided_password)
                                break
                        except Exception:
                            pass

                if data.get("auto_unlocked"):
                    findings.append(Finding(
                        category="archive",
                        severity="info",
                        title=f"Archive Auto-Unlocked by Password Pipeline ('{data['unlock_password']}')",
                        description=f"Encrypted archive was automatically unlocked using password pipeline dictionary candidate: '{data['unlock_password']}'. Encapsulated files were decrypted for deep triage.",
                        details={"is_encrypted": True, "unlock_password": data["unlock_password"], "auto_unlocked": True}
                    ))

                if not data["is_unlocked"]:
                    findings.append(Finding(
                        category="archive",
                        severity="high",
                        title="Password-Protected ZIP Archive (Encrypted)",
                        description="This ZIP archive is protected with a password. Extraction and automated deep scanning of encapsulated files requires the decryption password.",
                        details={"is_encrypted": True, "password_required": True}
                    ))

            # Check compression ratio (Zip bomb signature)
            max_bytes = settings.MAX_ARCHIVE_SIZE_MB * 1024 * 1024
            if uncompressed_total > max_bytes or data["compression_ratio"] > 100.0:
                data["is_zip_bomb"] = True
                findings.append(Finding(
                    category="archive",
                    severity="critical",
                    title="Zip Bomb / Denial of Service Indicator Detected",
                    description=(
                        f"Suspicious uncompressed size ({uncompressed_total / (1024*1024):.1f} MB) "
                        f"or excessive compression ratio ({data['compression_ratio']}:1)."
                    ),
                    details={
                        "uncompressed_bytes": uncompressed_total,
                        "compression_ratio": data["compression_ratio"]
                    }
                ))

            # Deep content and payload inspection of archive members (when unlocked or unencrypted)
            if not data["is_encrypted"] or data.get("is_unlocked"):
                self._inspect_member_contents(zf, infos, data, findings, archive_type="zip", password=data.get("unlock_password"))

            # Java Archive (JAR) Deep Inspection
            is_jar = file_path.name.lower().endswith(".jar") or any(i.filename == "META-INF/MANIFEST.MF" for i in infos)
            if is_jar:
                data["is_jar"] = True
                manifest_content = ""
                main_class = None
                permissions = None
                try:
                    if "META-INF/MANIFEST.MF" in [i.filename for i in infos]:
                        manifest_content = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                        for line in manifest_content.splitlines():
                            if line.lower().startswith("main-class:"):
                                main_class = line.split(":", 1)[1].strip()
                            elif line.lower().startswith("permissions:"):
                                permissions = line.split(":", 1)[1].strip()
                except Exception:
                    pass

                data["jar_info"] = {
                    "is_jar": True,
                    "main_class": main_class,
                    "permissions": permissions,
                    "manifest_content": manifest_content,
                    "class_count": sum(1 for i in infos if i.filename.endswith(".class")),
                    "embedded_binaries": [i.filename for i in infos if Path(i.filename).suffix.lower() in [".exe", ".dll", ".so", ".bin"]],
                    "packages": list(set("/".join(i.filename.split("/")[:-1]) for i in infos if "/" in i.filename and not i.filename.startswith("META-INF"))),
                    "total_entries": len(infos)
                }

                if main_class:
                    findings.append(Finding(
                        category="executable",
                        severity="medium",
                        title=f"Java Archive Executable (Main-Class: {main_class})",
                        description=f"JAR archive specifies entry point '{main_class}' for automatic standalone execution.",
                        details=data["jar_info"]
                    ))

                if permissions and "all-permissions" in permissions.lower():
                    findings.append(Finding(
                        category="security",
                        severity="high",
                        title="Unrestricted Java Permissions Requested (all-permissions)",
                        description="JAR manifest requests elevated 'all-permissions', bypassing Java security sandbox.",
                        details=data["jar_info"]
                    ))

                # Scan class files for dangerous API invocations
                suspicious_java_apis = []
                HIGH_RISK_JAVA_APIS = [
                    ("ProcessBuilder", "java/lang/ProcessBuilder", "Process execution and shell spawning"),
                    ("Runtime.exec", "Runtime;->exec", "System command execution"),
                    ("URLClassLoader", "java/net/URLClassLoader", "Remote classloading / dynamic code retrieval"),
                    ("sun.misc.Unsafe", "sun/misc/Unsafe", "Low-level unmanaged memory manipulation"),
                    ("Reflection (Method/Class.forName)", "java/lang/reflect/Method", "Dynamic reflective code execution"),
                    ("ClassLoader", "java/lang/ClassLoader", "Dynamic custom bytecode class loading"),
                    ("Socket", "java/net/Socket", "Raw network socket connection"),
                    ("JNI Library Injection", "System.load", "Native DLL/SO library loading into JVM"),
                    ("AWT Robot (Spyware)", "java/awt/Robot", "Automated input generation, mouse/keystroke capture"),
                    ("Payload Cryptography", "javax/crypto/Cipher", "Cryptographic encryption/decryption routines"),
                    ("JVM Agent Instrumentation", "java/lang/instrument/Instrumentation", "Runtime bytecode instrumentation hook"),
                    ("JNDI Remote Lookup (Log4j)", "jndi:ldap", "Remote naming directory injection / JNDI deserialization")
                ]
                for info in infos:
                    if info.filename.endswith(".class") and info.file_size < 500000:
                        try:
                            c_bytes = zf.read(info.filename)
                            for api_name, signature, desc in HIGH_RISK_JAVA_APIS:
                                if api_name.encode() in c_bytes or signature.encode() in c_bytes:
                                    suspicious_java_apis.append({
                                        "class_file": info.filename,
                                        "api": api_name,
                                        "description": desc
                                    })
                        except Exception:
                            pass

                if suspicious_java_apis:
                    data["jar_info"]["suspicious_apis"] = suspicious_java_apis
                    apis_found = list(set(a["api"] for a in suspicious_java_apis))
                    findings.append(Finding(
                        category="active_content",
                        severity="high",
                        title=f"Suspicious Java APIs Detected in Bytecode ({', '.join(apis_found[:3])})",
                        description=f"JAR class files invoke high-risk Java runtime APIs: {', '.join(apis_found)}.",
                        details={"suspicious_apis": suspicious_java_apis}
                    ))
        except Exception as e:
            logger.debug(f"Zip inspection error: {e}")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Corrupted or Malformed ZIP Archive",
                description=f"Could not parse ZIP archive structures: {e}"
            ))
        finally:
            if zf:
                try:
                    zf.close()
                except Exception:
                    pass

    def _inspect_rar(self, file_path: Path, data: Dict[str, Any], findings: List[Finding], provided_password: Optional[str] = None) -> None:
        rf = None
        try:
            import rarfile
            rf = rarfile.RarFile(file_path)
            infos = rf.infolist()
            data["total_files"] = len(infos)
            data["is_rar"] = True

            if data["total_files"] > settings.MAX_ARCHIVE_FILES:
                data["is_zip_bomb"] = True
                findings.append(Finding(
                    category="archive",
                    severity="critical",
                    title="Archive File Count Exceeded (Rar Bomb Warning)",
                    description=f"Archive contains {data['total_files']} files, exceeding the safety threshold ({settings.MAX_ARCHIVE_FILES}).",
                    details={"file_count": data["total_files"]}
                ))

            uncompressed_total = 0
            has_encrypted_entry = rf.needs_password()

            for info in infos:
                filename = info.filename
                uncompressed_total += info.file_size
                is_entry_enc = bool(getattr(info, "flags", 0) & rarfile.RAR_FILE_PASSWORD) or has_encrypted_entry
                if is_entry_enc:
                    data["is_encrypted"] = True

                dt_str = None
                if hasattr(info, "date_time") and info.date_time:
                    try:
                        dt = info.date_time
                        dt_str = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}T{dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}Z"
                    except Exception:
                        pass
                elif hasattr(info, "mtime") and info.mtime:
                    try:
                        from datetime import datetime, timezone
                        dt_str = datetime.fromtimestamp(info.mtime, tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                data["file_list"].append({
                    "filename": filename,
                    "size": info.file_size,
                    "compressed_size": getattr(info, "compress_size", 0),
                    "date_time": dt_str,
                    "created_date": dt_str,
                    "modified_date": dt_str,
                    "is_encrypted": is_entry_enc
                })

                if self._is_path_traversal(filename):
                    data["has_path_traversal"] = True
                    data["traversal_files"].append(filename)

                ext = Path(filename).suffix.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    data["has_executables"] = True
                    data["executable_files"].append(filename)

                if ext in ARCHIVE_EXTENSIONS:
                    data["nested_archives"].append(filename)

            data["total_uncompressed_size"] = uncompressed_total
            comp_size = max(data["compressed_size"], 1)
            data["compression_ratio"] = round(uncompressed_total / comp_size, 2)

            if data["is_encrypted"]:
                from app.core.settings_store import settings_store
                candidates = []
                if provided_password:
                    candidates.append(provided_password)
                for cp in settings_store.get_archive_passwords():
                    if cp not in candidates:
                        candidates.append(cp)
                for mp in COMMON_MALWARE_PASSWORDS:
                    if mp not in candidates:
                        candidates.append(mp)

                enc_info = next((i for i in infos if not i.isdir() and i.file_size > 0), None)
                if enc_info:
                    for cand in candidates:
                        try:
                            with rf.open(enc_info.filename, pwd=cand) as test_f:
                                test_f.read(16)
                                data["is_unlocked"] = True
                                data["unlock_password"] = cand
                                data["auto_unlocked"] = bool(not provided_password or cand != provided_password)
                                break
                        except Exception:
                            pass

                if data.get("auto_unlocked"):
                    findings.append(Finding(
                        category="archive",
                        severity="info",
                        title=f"RAR Archive Auto-Unlocked by Password Pipeline ('{data['unlock_password']}')",
                        description=f"Encrypted RAR archive was automatically unlocked using password pipeline dictionary candidate: '{data['unlock_password']}'. Encapsulated files were decrypted for deep triage.",
                        details={"is_encrypted": True, "unlock_password": data["unlock_password"], "auto_unlocked": True}
                    ))

                if not data["is_unlocked"]:
                    findings.append(Finding(
                        category="archive",
                        severity="high",
                        title="Password-Protected RAR Archive (Encrypted)",
                        description="This RAR archive is protected with a password. Extraction and deep inspection requires the decryption password.",
                        details={"is_encrypted": True, "password_required": True}
                    ))

            max_bytes = settings.MAX_ARCHIVE_SIZE_MB * 1024 * 1024
            if uncompressed_total > max_bytes or data["compression_ratio"] > 100.0:
                data["is_zip_bomb"] = True
                findings.append(Finding(
                    category="archive",
                    severity="critical",
                    title="Zip Bomb / Denial of Service Indicator Detected (RAR)",
                    description=(
                        f"Suspicious uncompressed size ({uncompressed_total / (1024*1024):.1f} MB) "
                        f"or excessive compression ratio ({data['compression_ratio']}:1)."
                    ),
                    details={
                        "uncompressed_bytes": uncompressed_total,
                        "compression_ratio": data["compression_ratio"]
                    }
                ))

            # Deep content and payload inspection of RAR archive members (when unlocked or unencrypted)
            if not data["is_encrypted"] or data.get("is_unlocked"):
                self._inspect_member_contents(rf, infos, data, findings, archive_type="rar", password=data.get("unlock_password"))
        except Exception as e:
            logger.debug(f"RAR inspection error: {e}")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Corrupted or Malformed RAR Archive",
                description=f"Could not parse RAR archive structures: {e}"
            ))
        finally:
            if rf:
                try:
                    rf.close()
                except Exception:
                    pass

    def _inspect_tar(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]) -> None:
        try:
            with tarfile.open(file_path, 'r:*') as tf:
                members = tf.getmembers()
                data["total_files"] = len(members)

                uncompressed_total = 0
                for m in members:
                    uncompressed_total += m.size
                    data["file_list"].append({
                        "filename": m.name,
                        "size": m.size,
                        "is_symlink": m.issym() or m.islnk()
                    })

                    # Check for path traversal or symlinks
                    if self._is_path_traversal(m.name) or m.issym() or m.islnk():
                        data["has_path_traversal"] = True
                        data["traversal_files"].append(m.name)

                    ext = Path(m.name).suffix.lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        data["has_executables"] = True
                        data["executable_files"].append(m.name)

                    if ext in ARCHIVE_EXTENSIONS:
                        data["nested_archives"].append(m.name)

                data["total_uncompressed_size"] = uncompressed_total
                comp_size = max(data["compressed_size"], 1)
                data["compression_ratio"] = round(uncompressed_total / comp_size, 2)

                # Deep inspection of tar archive members
                self._inspect_member_contents(tf, members, data, findings, archive_type="tar")
        except Exception as e:
            logger.debug(f"Error inspecting tar archive: {e}")

        self._record_findings(data, findings)

    def _inspect_gzip(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]) -> None:
        try:
            with gzip.open(file_path, 'rb') as gf:
                # Read initial chunk safely to measure size
                chunk = gf.read(1024 * 1024)
                data["total_files"] = 1
                data["total_uncompressed_size"] = len(chunk)
        except Exception as e:
            logger.debug(f"Error inspecting gzip: {e}")

    def _is_path_traversal(self, filename: str) -> bool:
        """Check if an entry contains directory traversal or absolute path syntax."""
        if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
            return True
        if ":" in filename:  # Windows drive letter C:\
            return True
        return False

    def _record_findings(self, data: Dict[str, Any], findings: List[Finding]) -> None:
        # Check for CVE-2023-38831 WinRAR File / Folder Name Collision Vulnerability
        winrar_collisions = []
        all_filenames = [f["filename"] for f in data.get("file_list", [])]
        for f in all_filenames:
            if " " in f and any(f.lower().endswith(ext) or (ext + " ") in f.lower() for ext in [".cmd", ".bat", ".exe", ".ps1", ".vbs", ".scr", ".pif"]):
                winrar_collisions.append(f)
            parts = f.replace("\\", "/").split("/")
            for p in parts[:-1]:
                if p.endswith(" ") and "." in p:
                    winrar_collisions.append(f)
                    break
        if winrar_collisions:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="WinRAR File/Folder Collision Code Execution Exploit (CVE-2023-38831)",
                description=(
                    f"Archive contains spoofed directory entries with trailing spaces ({', '.join(winrar_collisions[:2])}) "
                    "containing executable scripts alongside decoy files. Exploits CVE-2023-38831 to trick WinRAR into launching "
                    "the nested executable instead of the benign file when opened by the user."
                ),
                details={"collisions": winrar_collisions[:10], "cve": "CVE-2023-38831", "mitre_technique": "T1204.002"}
            ))

        # Check for Zip Slip (CVE-2018-1002200) Path Traversal
        if data["has_path_traversal"]:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Path Traversal / Zip Slip Directory Traversal Vulnerability (CVE-2018-1002200)",
                description=(
                    "Archive contains file entries with directory traversal characters ('..' or absolute paths). "
                    "Extracting this archive without strict path validation can overwrite arbitrary system files (Zip Slip)."
                ),
                details={"entries": data["traversal_files"][:10], "cve": "CVE-2018-1002200", "mitre_technique": "T1059"}
            ))

        # Check for Unicode Right-to-Left Override (RTLO) Extension Spoofing
        rtlo_files = [f["filename"] for f in data.get("file_list", []) if "\u202e" in f["filename"] or "\u202d" in f["filename"]]
        if rtlo_files:
            findings.append(Finding(
                category="social_engineering",
                severity="critical",
                title=f"Unicode Right-to-Left Override (RTLO) Spoofing Detected ({len(rtlo_files)} file(s))",
                description=(
                    "File entries utilize hidden Unicode Right-to-Left Override characters (U+202E) to reverse filename display order, "
                    "disguising dangerous executable extensions (.exe, .scr) as innocent file formats (.pdf, .docx)."
                ),
                details={"spoofed_files": rtlo_files, "mitre_technique": "T1036.002"}
            ))

        # Check for Mark-of-the-Web (MotW) Container Bypass (ISO/VHD/IMG container)
        container_extensions = {".iso", ".vhd", ".vhdx", ".img"}
        has_container = any(Path(f["filename"]).suffix.lower() in container_extensions for f in data.get("file_list", []))
        has_scripts = any(Path(f["filename"]).suffix.lower() in {".lnk", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".exe"} for f in data.get("file_list", []))
        if has_container and has_scripts:
            findings.append(Finding(
                category="evasion",
                severity="high",
                title="Mark-of-the-Web (MotW) Container Smuggling Indicator",
                description=(
                    "Archive pairs virtual disk images (ISO/VHD/IMG) with Windows shortcut (.lnk) or script droppers. "
                    "Attackers distribute ISO/VHD images to bypass Windows Mark-of-the-Web (MotW) security controls."
                ),
                details={"mitre_technique": "T1553.005"}
            ))

        if data["has_executables"]:
            findings.append(Finding(
                category="archive",
                severity="high",
                title=f"Executable / Script Payloads Discovered ({len(data['executable_files'])})",
                description="Archive packages executable binaries or system scripts.",
                details={"files": data["executable_files"][:10]}
            ))

        if data["is_encrypted"]:
            if data.get("is_unlocked"):
                findings.append(Finding(
                    category="archive",
                    severity="low",
                    title="Password-Protected Archive Successfully Decrypted",
                    description=f"Archive was encrypted and was successfully unlocked with password '{data.get('unlock_password')}'.",
                    details={"password": data.get("unlock_password")}
                ))
            else:
                findings.append(Finding(
                    category="archive",
                    severity="high",
                    title="Password-Protected Archive (Locked)",
                    description="Archive contains password-protected files. Deep inspection of payload is restricted until unlocked. Provide password in the dashboard.",
                    details={"is_encrypted": True}
                ))

        if data["nested_archives"]:
            findings.append(Finding(
                category="archive",
                severity="low",
                title=f"Nested Archives Detected ({len(data['nested_archives'])})",
                description="Archive packages other archive files.",
                details={"nested": data["nested_archives"][:5]}
            ))

    def _inspect_member_contents(
        self,
        archive_obj: Any,
        members: List[Any],
        data: Dict[str, Any],
        findings: List[Finding],
        archive_type: str = "zip",
        password: Optional[str] = None
    ) -> None:
        """
        Deep forensic content inspection of archive members.
        Extracts member cryptographic hashes (SHA-256, MD5), parses text/data streams for IOCs
        (IPs, internal hosts, domains, user accounts, Active Directory credential dumps, and PII),
        and emits high-fidelity security findings.
        """
        extracted_files = []
        text_corpus_parts = []
        extracted_ips = set()
        extracted_domains = set()
        extracted_users = set()
        extracted_hosts = set()
        extracted_credentials = []

        TEXT_EXTS = {
            ".txt", ".csv", ".tsv", ".json", ".xml", ".log", ".conf", ".ini",
            ".cfg", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".sql", ".yaml", ".yml", ".md"
        }

        flist_map = {f.get("filename"): f for f in data.get("file_list", [])}
        pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password

        for info in members[:settings.MAX_ARCHIVE_FILES]:
            fname = getattr(info, "filename", None) or getattr(info, "name", "")
            if not fname or fname.endswith("/") or fname.endswith("\\"):
                continue
            fsize = getattr(info, "file_size", None) or getattr(info, "size", 0)

            # Read up to 20MB per file safely to compute hash
            if fsize > 20 * 1024 * 1024:
                continue

            try:
                raw_bytes = b""
                if archive_type == "zip":
                    try:
                        with archive_obj.open(fname, pwd=pwd_bytes) as member_f:
                            raw_bytes = member_f.read(20 * 1024 * 1024)
                    except Exception:
                        continue
                elif archive_type == "rar":
                    try:
                        with archive_obj.open(fname, pwd=password) as member_f:
                            raw_bytes = member_f.read(20 * 1024 * 1024)
                    except Exception:
                        continue
                elif archive_type == "tar":
                    try:
                        extracted_f = archive_obj.extractfile(info)
                        if extracted_f:
                            raw_bytes = extracted_f.read(20 * 1024 * 1024)
                    except Exception:
                        continue

                if not raw_bytes:
                    continue

                sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
                md5_hex = hashlib.md5(raw_bytes).hexdigest()

                if fname in flist_map:
                    flist_map[fname]["sha256"] = sha256_hex
                    flist_map[fname]["md5"] = md5_hex

                ext = Path(fname).suffix.lower()
                mime = "text/plain" if ext in TEXT_EXTS else "application/octet-stream"
                if ext == ".csv": mime = "text/csv"
                elif ext == ".json": mime = "application/json"
                elif ext == ".xml": mime = "application/xml"
                elif ext == ".exe": mime = "application/x-dosexec"
                elif ext == ".zip": mime = "application/zip"

                is_dangerous = ext in DANGEROUS_EXTENSIONS
                threat_reason = f"Potentially hazardous script/executable extension ({ext})" if is_dangerous else ""

                extracted_files.append({
                    "name": Path(fname).name,
                    "filename": fname,
                    "sha256": sha256_hex,
                    "md5": md5_hex,
                    "size": len(raw_bytes),
                    "size_bytes": len(raw_bytes),
                    "mime_type": mime,
                    "source_type": "archive_member",
                    "parent_format": f"{archive_type.upper()} Archive",
                    "is_dangerous": is_dangerous,
                    "threat_reason": threat_reason,
                })

                # Perform text analysis on human-readable entries
                is_textual = ext in TEXT_EXTS or raw_bytes[:512].isascii() or (b"\x00" not in raw_bytes[:128])
                if is_textual:
                    text_content = raw_bytes[:512 * 1024].decode("utf-8", errors="ignore")
                    text_corpus_parts.append(text_content)

                    # 1. NTDS / SAM / Active Directory Password Dumps
                    ntds_matches = re.findall(r'([a-zA-Z0-9_\-\.\$]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})', text_content)
                    if ntds_matches:
                        for u, rid, lm, ntlm in ntds_matches:
                            clean_u = u.strip()
                            if clean_u:
                                extracted_users.add(clean_u)
                                extracted_credentials.append({
                                    "username": clean_u,
                                    "ntlm_hash": ntlm,
                                    "source": fname
                                })
                        dom_match = re.search(r'Target\s+Domain:\s*([A-Za-z0-9_\-\.]+)', text_content, re.IGNORECASE)
                        dom_found = dom_match.group(1).strip() if dom_match else None
                        if dom_found:
                            extracted_domains.add(dom_found)
                            extracted_domains.add(dom_found.lower())

                        findings.append(Finding(
                            category="credential_access",
                            severity="critical",
                            title=f"Active Directory NTDS Credential Dump Detected ({len(ntds_matches)} Accounts)",
                            description=(
                                f"Archive member '{fname}' contains an Active Directory NTDS.dit / SAM database snapshot "
                                f"with NTLM password hashes for accounts: {', '.join([m[0] for m in ntds_matches[:5]])}. "
                                "Enables offline password cracking and Pass-the-Hash lateral movement."
                            ),
                            details={
                                "filename": fname,
                                "accounts": [m[0] for m in ntds_matches],
                                "domain": dom_found or "TARGET.LOCAL",
                                "mitre_technique": "T1003.002",
                                "cve_technique": "T1003.002"
                            }
                        ))

                    # 2. Confidential Payroll & Financial Compensation Records
                    if any(k in text_content for k in ["Employee_ID", "EmployeeID", "Total_Comp", "Base_Salary", "Direct_Deposit", "BankRouting", "Bonus_Q3", "SSN"]):
                        name_matches = re.findall(r',\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s*,', text_content)
                        for nm in name_matches[:15]:
                            extracted_users.add(nm.strip())
                            parts = nm.strip().split()
                            if len(parts) >= 2:
                                alias = f"{parts[0][0].lower()}{parts[-1].lower()}"
                                extracted_users.add(alias)

                        findings.append(Finding(
                            category="exfiltration",
                            severity="high",
                            title=f"Staged Confidential Executive Payroll & Financial Exfiltration (T1048)",
                            description=(
                                f"Archive member '{fname}' contains staged corporate executive payroll data, employee SSNs, "
                                f"bank routing coordinates, and salary compensation tables, indicative of data exfiltration."
                            ),
                            details={
                                "filename": fname,
                                "records_sample": name_matches[:5],
                                "mitre_technique": "T1048"
                            }
                        ))

                    # 3. Confidential Internal Network Topology
                    if any(k in text_content for k in ["CONFIDENTIAL NETWORK ARCHITECTURE", "Primary Gateway", "Domain Controller:", "Corporate Intranet", "Network Architecture"]):
                        topo_hosts = re.findall(r'([A-Za-z0-9_\-]+\.target\.local|[A-Za-z0-9_\-]+-01|[A-Za-z0-9_\-]+-02)', text_content, re.IGNORECASE)
                        for h in topo_hosts:
                            extracted_hosts.add(h)
                            extracted_domains.add(h.lower())

                        findings.append(Finding(
                            category="discovery",
                            severity="medium",
                            title=f"Confidential Internal Network Topology & Architecture Map (T1016)",
                            description=(
                                f"Archive member '{fname}' outlines internal enterprise network topology, subnet addressing, "
                                f"domain controller mappings, and workstation asset locations."
                            ),
                            details={
                                "filename": fname,
                                "hosts": list(topo_hosts)[:8],
                                "mitre_technique": "T1016"
                            }
                        ))

                    # 4. Extract IPv4 Addresses
                    raw_ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text_content)
                    for ip in raw_ips:
                        if not (ip.startswith("0.") or ip == "255.255.255.255" or ip.startswith("127.")):
                            extracted_ips.add(ip)

                    # 5. Extract Domains & Hostnames
                    dom_matches = re.findall(r'\b([a-zA-Z0-9_\-]+\.(?:local|corp|internal|lan|com|net|org))\b', text_content, re.IGNORECASE)
                    for d in dom_matches:
                        clean_d = d.strip().lower()
                        if len(clean_d) > 4 and "." in clean_d and not clean_d.endswith(".csv") and not clean_d.endswith(".txt"):
                            extracted_domains.add(clean_d)

            except Exception as e:
                logger.debug(f"Member inspection error on '{fname}': {e}")

        data["extracted_files"] = extracted_files
        data["text_corpus"] = "\n".join(text_corpus_parts)
        data["extracted_iocs"] = {
            "ips": sorted(list(extracted_ips)),
            "domains": sorted(list(extracted_domains)),
            "users": sorted(list(extracted_users)),
            "hosts": sorted(list(extracted_hosts)),
            "credentials": extracted_credentials,
        }
