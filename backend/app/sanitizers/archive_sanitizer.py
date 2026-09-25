import os
import zipfile
from pathlib import Path
from typing import List
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".pif", ".cpl", ".hta",
    ".msi", ".msp", ".jar", ".com", ".gadget", ".sh", ".bash", ".elf"
}

class ArchiveSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "ArchiveSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        removed_items: List[str] = []
        warnings: List[str] = []

        if not zipfile.is_zipfile(input_path):
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="zip",
                warnings=["Only ZIP archives are supported for automated member sanitization."]
            )

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_zip = output_path.with_suffix(".tmp.zip")

            with zipfile.ZipFile(input_path, 'r') as zin:
                with zipfile.ZipFile(temp_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                    for info in zin.infolist():
                        name = info.filename

                        # 1. Skip path traversal entries
                        if ".." in name or name.startswith("/") or name.startswith("\\"):
                            removed_items.append(f"Purged path traversal archive entry: {name}")
                            continue

                        # 2. Skip dangerous executables and scripts
                        ext = Path(name).suffix.lower()
                        if ext in DANGEROUS_EXTENSIONS:
                            removed_items.append(f"Excluded dangerous executable/script payload: {name}")
                            continue

                        # Write verified safe member
                        content = zin.read(name)
                        zout.writestr(info, content)

            if temp_zip.exists():
                temp_zip.replace(output_path)

            base_name = original_filename.rsplit(".", 1)[0]
            clean_filename = f"{base_name}_sanitized.zip"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension="zip",
                removed_items=removed_items,
                warnings=warnings
            )

        except Exception as e:
            logger.error(f"Archive sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="zip",
                warnings=[f"Archive sanitization error: {e}"]
            )
