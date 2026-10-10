import io
import zipfile
from pathlib import Path
from typing import Optional
from PIL import Image, ImageDraw, ImageFont
import fitz

from app.core.logging_config import logger

class ThumbnailGenerator:
    """
    Generates safe preview thumbnails for all supported file formats:
    - Images: downsampled thumbnail via Pillow
    - PDFs: safe first-page rendering via PyMuPDF (no script execution)
    - Office documents: safe rendered text snapshot card
    - HTML / SVG / Text / Archive: safe rendered document preview canvas
    """

    @classmethod
    def generate_thumbnail(cls, file_path: Path, category: str, output_path: Path) -> bool:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if output_path.exists() and output_path.stat().st_size > 0:
                return True

            if category == "image":
                return cls._generate_image_thumbnail(file_path, output_path)
            elif category == "pdf":
                return cls._generate_pdf_thumbnail(file_path, output_path)
            elif category == "office":
                return cls._generate_office_thumbnail(file_path, output_path)
            elif category in ["text", "html", "svg"]:
                return cls._generate_text_thumbnail(file_path, category, output_path)
            elif category == "archive":
                return cls._generate_archive_thumbnail(file_path, output_path)
            elif category == "domain":
                return cls._generate_domain_thumbnail(file_path, output_path)
            else:
                return cls._generate_generic_thumbnail(file_path, category, output_path)
        except Exception as e:
            logger.error(f"Failed to generate thumbnail for {file_path.name}: {e}")
            return cls._generate_generic_thumbnail(file_path, category, output_path)

    @classmethod
    def _generate_image_thumbnail(cls, file_path: Path, output_path: Path) -> bool:
        try:
            with Image.open(file_path) as img:
                # Convert RGBA or CMYK to RGB
                thumb = img.copy()
                if thumb.mode in ["RGBA", "LA", "P"]:
                    # Create white background for transparency
                    bg = Image.new("RGB", thumb.size, (255, 255, 255))
                    if thumb.mode == "P":
                        thumb = thumb.convert("RGBA")
                    bg.paste(thumb, mask=thumb.split()[-1] if len(thumb.split()) == 4 else None)
                    thumb = bg
                elif thumb.mode != "RGB":
                    thumb = thumb.convert("RGB")

                thumb.thumbnail((450, 320), Image.Resampling.LANCZOS)
                thumb.save(output_path, format="PNG")
                return True
        except Exception as e:
            logger.debug(f"Pillow image thumbnail error: {e}")
            return False

    @classmethod
    def _generate_pdf_thumbnail(cls, file_path: Path, output_path: Path) -> bool:
        try:
            doc = fitz.open(file_path)
            if doc.page_count == 0:
                doc.close()
                return False
            page = doc[0]
            # Render at 100 dpi for sharp safe thumbnail
            pix = page.get_pixmap(dpi=100)
            pix.save(str(output_path))
            doc.close()
            return True
        except Exception as e:
            logger.debug(f"PyMuPDF thumbnail error: {e}")
            return False

    @classmethod
    def _generate_office_thumbnail(cls, file_path: Path, output_path: Path) -> bool:
        """Create a safe rendered page snapshot of the Office document."""
        sample_text = []
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    if "word/document.xml" in zf.namelist():
                        import re
                        xml_str = zf.read("word/document.xml").decode('utf-8', errors='ignore')
                        texts = re.findall(r'<w:t[^>]*>(.*?)</w:t>', xml_str)
                        sample_text = texts[:12]
        except Exception:
            pass

        return cls._draw_document_canvas(
            title=f"Office Document: {file_path.name}",
            badge="DOCX / DOCM",
            lines=sample_text or ["Document text extracted safely without active macros."],
            output_path=output_path,
            accent_color=(37, 99, 235)
        )

    @classmethod
    def _generate_text_thumbnail(cls, file_path: Path, category: str, output_path: Path) -> bool:
        lines = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(12):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line.rstrip())
        except Exception:
            lines = ["Plain text document"]

        return cls._draw_document_canvas(
            title=f"{category.upper()} File: {file_path.name}",
            badge=category.upper(),
            lines=lines,
            output_path=output_path,
            accent_color=(15, 118, 110)
        )

    @classmethod
    def _generate_archive_thumbnail(cls, file_path: Path, output_path: Path) -> bool:
        members = []
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    members = [f"📁 {name}" for name in zf.namelist()[:10]]
        except Exception:
            members = ["Archive archive members"]

        return cls._draw_document_canvas(
            title=f"Archive: {file_path.name}",
            badge="ARCHIVE",
            lines=members or ["Compressed container archive"],
            output_path=output_path,
            accent_color=(194, 65, 12)
        )

    @classmethod
    def _generate_domain_thumbnail(cls, file_path: Path, output_path: Path) -> bool:
        target = file_path.name
        return cls._draw_document_canvas(
            title=f"Target: {target}",
            badge="DOMAIN / NETWORK INTEL",
            lines=[
                f"Infrastructure Target: {target}",
                "Deep DNS, WHOIS/RDAP, Reverse PTR",
                "Homograph & Visual Punycode Analysis",
                "Co-Hosted Domains & Threat Telemetry"
            ],
            output_path=output_path,
            accent_color=(37, 99, 235)
        )

    @classmethod
    def _generate_generic_thumbnail(cls, file_path: Path, category: str, output_path: Path) -> bool:
        return cls._draw_document_canvas(
            title=file_path.name,
            badge=category.upper(),
            lines=[f"Format: {category.upper()}", f"Size: {file_path.stat().st_size:,} bytes", "Safe file inspection snapshot"],
            output_path=output_path,
            accent_color=(71, 85, 105)
        )

    @classmethod
    def _draw_document_canvas(cls, title: str, badge: str, lines: list, output_path: Path, accent_color: tuple) -> bool:
        w, h = 480, 320
        img = Image.new("RGB", (w, h), color=(248, 250, 252))
        draw = ImageDraw.Draw(img)

        # White page sheet with shadow
        draw.rectangle([(16, 16), (w - 16, h - 16)], fill=(255, 255, 255), outline=(226, 232, 240), width=2)
        # Top banner bar
        draw.rectangle([(16, 16), (w - 16, 52)], fill=accent_color)
        draw.text((28, 26), badge, fill=(255, 255, 255))

        # Title
        draw.text((28, 65), title[:45], fill=(15, 23, 42))

        # Divider
        draw.line([(28, 90), (w - 28, 90)], fill=(226, 232, 240), width=1)

        # Content lines
        y = 105
        for l in lines[:7]:
            cleaned = str(l).strip()[:52]
            if cleaned:
                draw.text((28, y), cleaned, fill=(71, 85, 105))
                y += 24

        # Watermark/badge
        draw.text((28, h - 35), "🛡️ Safe Sandboxed Preview · FileSanitizer", fill=(148, 163, 184))

        img.save(output_path, format="PNG")
        return True
