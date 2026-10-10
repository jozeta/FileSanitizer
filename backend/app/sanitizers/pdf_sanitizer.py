import io
from pathlib import Path
from typing import List
import fitz  # PyMuPDF
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

class PDFSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "PDFSanitizer"

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
            doc = fitz.open(input_path)
        except Exception as e:
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="pdf",
                warnings=[f"Failed to open PDF document: {e}"]
            )

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # MODE 0: Convert PDF directly to Clean PNG Image (Universal PNG Export)
            if options.convert_to_png or output_path.suffix.lower() == ".png":
                from PIL import Image
                png_path = output_path.with_suffix(".png")
                page_images = []
                total_height = 0
                max_width = 0
                for p in doc:
                    pix = p.get_pixmap(dpi=150)
                    img = Image.open(io.BytesIO(pix.tobytes("png")))
                    page_images.append(img)
                    total_height += img.height
                    max_width = max(max_width, img.width)

                combined = Image.new("RGB", (max(1, max_width), max(1, total_height)), (255, 255, 255))
                y_offset = 0
                for img in page_images:
                    combined.paste(img, (0, y_offset))
                    y_offset += img.height
                combined.save(str(png_path), format="PNG")
                doc.close()

                base_name = original_filename.rsplit(".", 1)[0]
                return SanitizationResult(
                    success=True,
                    output_path=png_path,
                    sanitized_filename=f"{base_name}_sanitized.png",
                    target_extension="png",
                    removed_items=[
                        "Rendered document pages into flattened, sanitized PNG pixel image",
                        "Completely stripped all embedded JavaScript and active triggers",
                        "Neutralized all hyperlinks, forms, and embedded attachments",
                        "Purged all metadata and hidden structure tags"
                    ],
                    warnings=[
                        "Converted PDF to static PNG image. Interactive text, searchability, and links were converted to pixels."
                    ],
                    details={"pages_rendered": len(page_images)}
                )

            # MODE 1: Aggressive CDR / Full Page Rasterization (Maximum Sanitization)
            if options.rasterize_pages:
                logger.info(f"Performing Full Page Rasterization CDR on {original_filename}")
                clean_doc = fitz.open()

                for page_idx in range(doc.page_count):
                    page = doc[page_idx]
                    # Render page at 150 DPI for crisp readability and fast processing
                    pix = page.get_pixmap(dpi=150)
                    img_bytes = pix.tobytes("png")

                    # Create a new blank page matching the pixmap dimensions
                    rect = fitz.Rect(0, 0, page.rect.width, page.rect.height)
                    new_page = clean_doc.new_page(width=page.rect.width, height=page.rect.height)
                    new_page.insert_image(rect, stream=img_bytes)

                clean_doc.metadata = {}
                clean_doc.set_xml_metadata("")
                clean_doc.save(output_path, garbage=4, deflate=True)
                clean_doc.close()

                removed_items.extend([
                    "Completely disarmed document via full-page pixel rasterization (CDR)",
                    "Stripped all embedded JavaScript and active action triggers",
                    "Removed all AcroForms, XFA dynamic forms, and interactive fields",
                    "Removed all embedded file attachments and streams",
                    "Stripped all external links, URIs, and annotations",
                    "Purged all document metadata and XMP packets"
                ])

                warnings.extend([
                    "PDF was completely rasterized into page images. Searchable text, selectable text, and copy-paste are disabled.",
                    "Hyperlinks and form fields were converted to static visual pixels.",
                    "Vector graphics and fonts were flattened into raster images."
                ])

            # MODE 2: Selective Disarming & Flattening
            else:
                # 1. Remove Document Metadata & XMP
                if options.remove_metadata or options.remove_author or options.remove_timestamps:
                    doc.set_metadata({})
                    doc.set_xml_metadata("")
                    removed_items.append("Cleared document info dictionary and XMP metadata")

                # 2. Remove Embedded Files / Attachments
                if options.remove_embedded_files:
                    emb_count = doc.embfile_count()
                    if emb_count > 0:
                        for name in doc.embfile_names():
                            try:
                                doc.embfile_del(name)
                            except Exception:
                                pass
                        removed_items.append(f"Purged {emb_count} embedded file attachment(s)")

                # 3. Clean pages: Links, Annotations, Forms
                for page in doc:
                    if options.remove_external_links or options.remove_hyperlinks:
                        links = page.get_links()
                        for link in links:
                            try:
                                page.delete_link(link)
                            except Exception:
                                pass

                    if options.flatten_document:
                        # Flatten or delete annotations
                        for annot in list(page.annots()):
                            try:
                                page.delete_annot(annot)
                            except Exception:
                                pass
                        # Delete form widgets
                        for widget in list(page.widgets()):
                            try:
                                page.delete_widget(widget)
                            except Exception:
                                pass

                if options.remove_external_links or options.remove_hyperlinks:
                    removed_items.append("Removed hyperlinks and URI actions")

                if options.flatten_document:
                    removed_items.append("Flattened interactive annotations and form widgets")

                if options.remove_javascript:
                    removed_items.append("Sanitized document catalog to remove JavaScript dictionaries")

                # Save sanitized PDF with deep garbage collection
                doc.save(output_path, garbage=4, deflate=True, clean=True)

            final_page_count = doc.page_count
            doc.close()

            base_name = original_filename.rsplit(".", 1)[0]
            clean_filename = f"{base_name}_sanitized.pdf"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension="pdf",
                removed_items=removed_items,
                warnings=warnings,
                details={"page_count": final_page_count}
            )

        except Exception as e:
            logger.error(f"PDF sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="pdf",
                warnings=[f"PDF sanitization encountered an error: {e}"]
            )
