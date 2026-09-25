import os
import re
import uuid
import unicodedata
from pathlib import Path
from typing import Optional, Tuple
from app.config import settings
from app.core.logging_config import logger

# Regex for safe display filenames: alphanumeric, hyphens, underscores, dots, spaces
SAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9_\-\. ]+')

def sanitize_filename(filename: str, max_length: int = 120) -> str:
    """
    Sanitize an uploaded filename for safe storage and presentation:
    - Strips path components and directory traversal sequences (../, ..\\)
    - Strips null bytes and control characters
    - Normalizes unicode characters (NFKC)
    - Replaces unsafe characters with underscores
    - Preserves file extension if valid
    - Truncates base name safely if too long
    """
    if not filename:
        return "unnamed_file"

    # Strip null bytes and control chars
    clean = filename.replace("\x00", "").strip()

    # Get pure basename (handles both UNIX and Windows directory separators)
    clean = clean.split("/")[-1].split("\\")[-1]

    # Normalize unicode to avoid visual spoofing or decomposition issues
    clean = unicodedata.normalize("NFKC", clean)

    # Separate extension
    parts = clean.rsplit(".", 1)
    if len(parts) == 2:
        base, ext = parts[0], parts[1]
        # Sanitize extension: only letters, digits, max 10 chars
        ext_clean = re.sub(r'[^a-zA-Z0-9]', '', ext)[:10]
    else:
        base, ext_clean = parts[0], ""

    # Sanitize base
    base_clean = SAFE_FILENAME_RE.sub('_', base).strip()
    if not base_clean:
        base_clean = "uploaded_file"

    # Limit base length
    base_clean = base_clean[:max_length]

    if ext_clean:
        return f"{base_clean}.{ext_clean}"
    return base_clean

class JobWorkspace:
    """
    Isolated per-job directory manager.
    Guarantees all file operations occur within a dedicated, random workspace.
    """
    def __init__(self, job_id: Optional[str] = None):
        self.job_id = job_id or uuid.uuid4().hex
        self.base_dir = Path(settings.JOBS_DIR).resolve() / self.job_id
        self.original_dir = self.base_dir / "original"
        self.extracted_dir = self.base_dir / "extracted"
        self.analysis_dir = self.base_dir / "analysis"
        self.sanitized_dir = self.base_dir / "sanitized"
        self.screenshots_dir = self.base_dir / "screenshots"

    def create(self) -> "JobWorkspace":
        """Create the directory structure with secure permissions."""
        for d in [self.base_dir, self.original_dir, self.extracted_dir, 
                  self.analysis_dir, self.sanitized_dir, self.screenshots_dir]:
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self

    def original_file_path(self, safe_name: str) -> Path:
        """
        Store original file under a standardized internal name to prevent path injection.
        """
        ext = safe_name.rsplit(".", 1)[-1] if "." in safe_name else ""
        internal_name = f"input_file.{ext}" if ext else "input_file"
        target = (self.original_dir / internal_name).resolve()
        self.assert_within_workspace(target)
        return target

    def sanitized_file_path(self, safe_name: str, target_ext: Optional[str] = None) -> Path:
        """
        Path for the sanitized output file.
        """
        if target_ext:
            ext = target_ext.lstrip(".")
        else:
            ext = safe_name.rsplit(".", 1)[-1] if "." in safe_name else ""
        internal_name = f"sanitized_file.{ext}" if ext else "sanitized_file"
        target = (self.sanitized_dir / internal_name).resolve()
        self.assert_within_workspace(target)
        return target

    def assert_within_workspace(self, path: Path) -> None:
        """
        Security check: Prevent path traversal attacks by validating resolved path.
        """
        resolved = path.resolve()
        if not str(resolved).startswith(str(self.base_dir.resolve())):
            raise ValueError(f"Path traversal detected! Path {resolved} is outside workspace {self.base_dir}")

    def cleanup(self) -> None:
        """Securely remove the workspace and all its contents."""
        import shutil
        if self.base_dir.exists():
            try:
                shutil.rmtree(self.base_dir)
                logger.info(f"Workspace {self.job_id} cleaned up successfully.")
            except Exception as e:
                logger.error(f"Error cleaning up workspace {self.job_id}: {e}")
