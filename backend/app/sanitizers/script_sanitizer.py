"""
Script Sanitizer.
Disarms dangerous execution hooks, defangs URLs and IPs,
strips auto-execution commands, and exports to safe non-executable formats (disarmed script or PDF).
"""

import re
from pathlib import Path
from typing import Dict, Any, List
import fitz  # PyMuPDF
from app.sanitizers.base import BaseSanitizer, SanitizationResult, SanitizationOptions

class ScriptSanitizer(BaseSanitizer):
    """Sanitizes script files (ps1, vbs, vba, sh, js, php, cmd)."""

    @property
    def name(self) -> str:
        return "ScriptSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str = ""
    ) -> SanitizationResult:
        modified_items: List[str] = []
        warnings: List[str] = []
        orig_name = original_filename or input_path.name
        base_name = orig_name.rsplit(".", 1)[0]
        ext = orig_name.rsplit(".", 1)[-1].lower() if "." in orig_name else "txt"

        try:
            content_bytes = input_path.read_bytes()
            text = content_bytes.decode("utf-8", errors="ignore")
        except Exception as e:
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=f"{base_name}_sanitized.{ext}",
                target_extension=ext,
                removed_items=[],
                warnings=[f"Failed to read script file: {e}"]
            )

        # 1. Defang URLs
        def defang_url(m):
            u = m.group(0)
            u = u.replace("http://", "hxxp://").replace("https://", "hxxps://")
            parts = u.split("/", 3)
            if len(parts) >= 3:
                parts[2] = parts[2].replace(".", "[.]")
                return "/".join(parts)
            return u.replace(".", "[.]")

        new_text, url_count = re.subn(r"https?://[a-zA-Z0-9\.\-_~:/?#\[\]@!$&'()*+,;=%]+", defang_url, text)
        if url_count > 0:
            modified_items.append(f"Defanged {url_count} hyperlink(s) and URL(s)")

        # 2. Disarm execution hooks
        disarm_replacements = [
            (r"(?i)\b(invoke-expression|iex)\b", "# [DISARMED_IEX] <blocked>", "PowerShell dynamic execution"),
            (r"(?i)\bdownloadstring\b", "disarmed_downloadstring", "WebClient download cradle"),
            (r"(?i)createobject\s*\(\s*[\"\']wscript\.shell[\"\']\s*\)", "' [DISARMED_WSCRIPT_SHELL] createobject(wscript.shell)", "VBScript Shell creation"),
            (r"(?i)\|\s*(ba)?sh\b", "# [DISARMED_PIPE_SH]", "Unix shell piping execution"),
            (r"(?i)\b(eval|assert)\s*\(", "/* [DISARMED_EVAL] */ false && (", "Dynamic code evaluation"),
            (r"(?i)\b(system|shell_exec|passthru)\s*\(", "/* [DISARMED_SYSTEM] */ false && (", "Shell command execution"),
            (r"(?i)certutil(\.exe)?\s+(-urlcache|-split)", "rem [DISARMED_CERTUTIL] certutil", "Certutil file transfer"),
        ]

        for pat, repl, label in disarm_replacements:
            new_text, count = re.subn(pat, repl, new_text)
            if count > 0:
                modified_items.append(f"Disarmed {count} occurrence(s) of {label}")

        # Add top banner
        banner = (
            "######################################################################\n"
            "# [SANITIZED BY FILESANITIZER]                                       #\n"
            "# Security Notice: Dangerous execution hooks and URLs disarmed.      #\n"
            "######################################################################\n\n"
        )
        if not new_text.startswith(banner):
            new_text = banner + new_text
            modified_items.append("Appended FileSanitizer security disclosure banner")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Check output format: convert to PDF
        if options.convert_to_pdf or str(output_path).lower().endswith(".pdf"):
            target_pdf_path = output_path.with_suffix(".pdf")
            doc = fitz.open()
            font_size = 8
            line_height = 11
            margin_left = 40
            margin_top = 50
            margin_bottom = 40
            page_height = 842  # A4
            page_width = 595
            max_lines_per_page = int((page_height - margin_top - margin_bottom) / line_height)

            script_lines = new_text.splitlines()
            total_pages = max(1, (len(script_lines) + max_lines_per_page - 1) // max_lines_per_page)

            for p_idx in range(total_pages):
                page = doc.new_page(width=page_width, height=page_height)
                # Header
                page.insert_text((margin_left, 30), f"FileSanitizer — Sanitized Script Review: {orig_name} (Page {p_idx+1}/{total_pages})", fontsize=8, color=(0.4, 0.4, 0.4))
                # Watermark
                page.insert_text((page_width - 160, 30), "DISARMED / READ-ONLY", fontsize=8, color=(0.8, 0.2, 0.2))

                start_l = p_idx * max_lines_per_page
                chunk = script_lines[start_l:start_l + max_lines_per_page]

                y = margin_top
                for l_num, line_str in enumerate(chunk, start=start_l + 1):
                    # Line number
                    page.insert_text((margin_left, y), f"{l_num:4d} | ", fontsize=font_size, color=(0.6, 0.6, 0.6))
                    # Code line (truncated to fit width)
                    truncated_line = line_str[:105]
                    page.insert_text((margin_left + 35, y), truncated_line, fontsize=font_size, color=(0.1, 0.1, 0.1))
                    y += line_height

            doc.save(str(target_pdf_path))
            doc.close()
            modified_items.append("Converted sanitized script into read-only vector PDF review document")
            return SanitizationResult(
                success=True,
                output_path=target_pdf_path,
                sanitized_filename=f"{base_name}_sanitized.pdf",
                target_extension="pdf",
                removed_items=modified_items,
                warnings=warnings
            )

        # Write disarmed script file
        output_path.write_text(new_text, encoding="utf-8")
        # Ensure execute permission is cleared
        try:
            output_path.chmod(0o644)
            modified_items.append("Enforced non-executable file permissions (0o644)")
        except Exception:
            pass

        clean_filename = f"{base_name}_sanitized.{ext}"
        return SanitizationResult(
            success=True,
            output_path=output_path,
            sanitized_filename=clean_filename,
            target_extension=ext,
            removed_items=modified_items,
            warnings=warnings
        )
