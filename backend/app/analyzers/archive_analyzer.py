import os
import tarfile
import zipfile
import gzip
from pathlib import Path
from typing import Dict, Any, List, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.config import settings
from app.core.logging_config import logger

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".pif", ".cpl", ".hta",
    ".msi", ".msp", ".jar", ".com", ".gadget", ".sh", ".bash", ".elf"
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".bz2", ".xz"}

class ArchiveAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "ArchiveAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        data: Dict[str, Any] = {
            "total_files": 0,
            "total_uncompressed_size": 0,
            "compressed_size": file_path.stat().st_size,
            "compression_ratio": 1.0,
            "is_encrypted": False,
            "has_path_traversal": False,
            "traversal_files": [],
            "has_executables": False,
            "executable_files": [],
            "nested_archives": [],
            "is_zip_bomb": False,
            "file_list": []
        }

        # Check for ZIP archive
        if zipfile.is_zipfile(file_path):
            self._inspect_zip(file_path, data, findings)
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

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )

    def _inspect_zip(self, file_path: Path, data: Dict[str, Any], findings: List[Finding]) -> None:
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
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
                    data["file_list"].append({
                        "filename": filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size
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

        except Exception as e:
            logger.debug(f"Error inspecting zip archive: {e}")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="ZIP Inspection Anomaly",
                description=f"Parser encountered error while reading archive central directory: {e}"
            ))

        self._record_findings(data, findings)

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
        if data["has_path_traversal"]:
            findings.append(Finding(
                category="archive",
                severity="critical",
                title="Path Traversal Vulnerability Detected in Archive",
                description=(
                    "Archive contains file entries with directory traversal characters ('..' or absolute paths). "
                    "Extracting this archive could overwrite arbitrary system files."
                ),
                details={"entries": data["traversal_files"][:10]}
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
            findings.append(Finding(
                category="archive",
                severity="medium",
                title="Password-Protected Archive Detected",
                description="One or more archive entries are encrypted, preventing complete security inspection."
            ))

        if data["nested_archives"]:
            findings.append(Finding(
                category="archive",
                severity="low",
                title=f"Nested Archives Detected ({len(data['nested_archives'])})",
                description="Archive packages other archive files.",
                details={"nested": data["nested_archives"][:5]}
            ))
