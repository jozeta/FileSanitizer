import io
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from PIL import Image
import fitz

from app.core.logging_config import logger
from app.analyzers.base import extract_clean_urls

# Check pytesseract availability
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

class OCRAnalyzer:
    """
    Extracts text from images, images embedded in PDFs, and images embedded in Office documents (DOCX/DOCM).
    Extracts text via Tesseract OCR engine and indexes URLs and suspicious content found within image pixels.
    """

    @classmethod
    def is_tesseract_available(cls) -> bool:
        if not PYTESSERACT_AVAILABLE:
            return False
        return shutil.which("tesseract") is not None

    @classmethod
    def scan_pil_image(cls, img: Image.Image) -> str:
        """Run OCR on a Pillow Image instance."""
        if not cls.is_tesseract_available():
            return ""
        try:
            # Convert to RGB if needed
            if img.mode not in ["RGB", "L"]:
                img = img.convert("RGB")
            text = pytesseract.image_to_string(img, timeout=5)
            return text.strip()
        except Exception as e:
            logger.debug(f"Pytesseract error on image: {e}")
            return ""

    @classmethod
    def scan_file(cls, file_path: Path, category: str) -> Dict[str, Any]:
        """
        Extract and run OCR across standalone images or embedded images inside PDF/Office files.
        """
        result: Dict[str, Any] = {
            "ocr_enabled": cls.is_tesseract_available(),
            "images_scanned": 0,
            "extracted_text": "",
            "urls": [],
            "image_details": []
        }

        if not cls.is_tesseract_available():
            return result

        extracted_text_chunks: List[str] = []
        urls_found: Set[str] = set()

        try:
            # 1. Standalone Images
            if category == "image":
                try:
                    with Image.open(file_path) as img:
                        text = cls.scan_pil_image(img)
                        if text:
                            extracted_text_chunks.append(text)
                            urls_found.update(extract_clean_urls(text))
                            result["image_details"].append({
                                "source": "standalone_image",
                                "dimensions": list(img.size),
                                "text": text
                            })
                            result["images_scanned"] += 1
                except Exception as e:
                    logger.debug(f"Failed to load image for OCR: {e}")

            # 2. PDF Documents with Embedded Images
            elif category == "pdf":
                try:
                    doc = fitz.open(file_path)
                    for page_idx, page in enumerate(doc):
                        page_images = page.get_images()
                        for img_info in page_images[:10]:  # limit to first 10 images per page
                            xref = img_info[0]
                            try:
                                img_dict = doc.extract_image(xref)
                                if img_dict and "image" in img_dict:
                                    img_bytes = img_dict["image"]
                                    with Image.open(io.BytesIO(img_bytes)) as pil_img:
                                        text = cls.scan_pil_image(pil_img)
                                        if text:
                                            extracted_text_chunks.append(text)
                                            urls_found.update(extract_clean_urls(text))
                                            result["image_details"].append({
                                                "source": f"pdf_page_{page_idx + 1}_xref_{xref}",
                                                "dimensions": [img_dict.get("width", 0), img_dict.get("height", 0)],
                                                "text": text
                                            })
                                        result["images_scanned"] += 1
                            except Exception as e:
                                logger.debug(f"Error extracting image xref {xref} for OCR: {e}")
                    doc.close()
                except Exception as e:
                    logger.debug(f"Failed to scan PDF images for OCR: {e}")

            # 3. Office Documents with Embedded Media (word/media/)
            elif category == "office":
                try:
                    if zipfile.is_zipfile(file_path):
                        with zipfile.ZipFile(file_path, 'r') as zf:
                            for name in zf.namelist():
                                lower = name.lower()
                                if any(lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".webp"]):
                                    try:
                                        img_bytes = zf.read(name)
                                        with Image.open(io.BytesIO(img_bytes)) as pil_img:
                                            text = cls.scan_pil_image(pil_img)
                                            if text:
                                                extracted_text_chunks.append(text)
                                                urls_found.update(extract_clean_urls(text))
                                                result["image_details"].append({
                                                    "source": name,
                                                    "dimensions": list(pil_img.size),
                                                    "text": text
                                                })
                                            result["images_scanned"] += 1
                                    except Exception as e:
                                        logger.debug(f"Error scanning office image {name}: {e}")
                except Exception as e:
                    logger.debug(f"Failed to scan office embedded images for OCR: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in OCR analyzer: {e}")

        result["extracted_text"] = "\n\n".join(extracted_text_chunks)
        result["urls"] = list(urls_found)
        return result
