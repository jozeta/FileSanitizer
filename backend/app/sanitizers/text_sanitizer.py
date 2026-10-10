import re
from pathlib import Path
from typing import List
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

class TextSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "TextSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        removed_items: List[str] = []
        warnings: List[str] = []

        try:
            raw_bytes = input_path.read_bytes()

            # Remove BOM
            if raw_bytes.startswith(b"\xef\xbb\xbf"):
                raw_bytes = raw_bytes[3:]
                removed_items.append("Stripped UTF-8 Byte Order Mark (BOM)")

            text = raw_bytes.decode("utf-8", errors="replace")

            # Neutralize CSV formula injection if CSV
            is_csv = original_filename.lower().endswith(".csv")
            if is_csv:
                lines = text.splitlines(keepends=True)
                sanitized_lines = []
                injections_neutralized = 0
                for line in lines:
                    # If line starts with =, +, -, @, prepend with single quote
                    if line and line[0] in ("=", "+", "-", "@", "\t"):
                        sanitized_lines.append("'" + line)
                        injections_neutralized += 1
                    else:
                        sanitized_lines.append(line)

                if injections_neutralized > 0:
                    text = "".join(sanitized_lines)
                    removed_items.append(f"Neutralized {injections_neutralized} spreadsheet formula injection cell(s)")

            # Strip control characters (except newline, tab, carriage return)
            clean_text = "".join(ch for ch in text if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127))
            if len(clean_text) < len(text):
                removed_items.append("Stripped unprintable binary control characters")

            output_path.parent.mkdir(parents=True, exist_ok=True)
            base_name = original_filename.rsplit(".", 1)[0]

            if options.convert_to_pdf or output_path.suffix.lower() == ".pdf":
                import fitz
                pdf_path = output_path.with_suffix(".pdf")
                doc = fitz.open()
                page = doc.new_page(width=595, height=842)
                page.insert_text((50, 50), f"FileSanitizer Text Document: {base_name}", fontsize=14, fontname="helv")
                page.draw_line((50, 60), (545, 60), color=(0.8, 0.8, 0.8), width=1)
                y = 80
                for line in clean_text.splitlines()[:200]:
                    if y > 800:
                        page = doc.new_page(width=595, height=842)
                        y = 50
                    page.insert_text((50, y), line[:85], fontsize=10, fontname="courier")
                    y += 14
                doc.save(str(pdf_path), garbage=4, deflate=True)
                doc.close()
                return SanitizationResult(
                    success=True,
                    output_path=pdf_path,
                    sanitized_filename=f"{base_name}_sanitized.pdf",
                    target_extension="pdf",
                    removed_items=removed_items + ["Converted text document into clean PDF document"],
                    warnings=warnings
                )

            if options.convert_to_png or output_path.suffix.lower() == ".png":
                import fitz
                png_path = output_path.with_suffix(".png")
                doc = fitz.open()
                page = doc.new_page(width=595, height=842)
                page.insert_text((50, 50), f"FileSanitizer Text Document: {base_name}", fontsize=14, fontname="helv")
                page.draw_line((50, 60), (545, 60), color=(0.8, 0.8, 0.8), width=1)
                y = 80
                for line in clean_text.splitlines()[:50]:
                    page.insert_text((50, y), line[:85], fontsize=10, fontname="courier")
                    y += 14
                pix = page.get_pixmap(dpi=150)
                pix.save(str(png_path))
                doc.close()
                return SanitizationResult(
                    success=True,
                    output_path=png_path,
                    sanitized_filename=f"{base_name}_sanitized.png",
                    target_extension="png",
                    removed_items=removed_items + ["Converted text document into clean PNG image"],
                    warnings=warnings
                )

            output_path.write_text(clean_text, encoding="utf-8")
            ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "txt"
            clean_filename = f"{base_name}_sanitized.{ext}"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension=ext,
                removed_items=removed_items,
                warnings=warnings
            )

        except Exception as e:
            logger.error(f"Text sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="txt",
                warnings=[f"Text sanitization error: {e}"]
            )
