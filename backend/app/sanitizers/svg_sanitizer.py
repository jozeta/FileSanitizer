from pathlib import Path
from typing import List
import fitz  # PyMuPDF supports SVG opening and rendering
import defusedxml.minidom as safe_minidom
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onmouseout", "onmouseenter",
    "onfocus", "onblur", "onchange", "onsubmit", "onreset", "onkeydown",
    "onkeypress", "onkeyup", "onanimationstart", "onanimationend"
]

class SVGSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "SVGSanitizer"

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
            svg_bytes = input_path.read_bytes()

            # SAFEST OPTION: Rasterize SVG -> PNG
            if options.rasterize_pages or options.convert_to_png or options.profile == "maximum":
                logger.info(f"Rasterizing SVG {original_filename} to PNG (Maximum CDR)")
                png_path = output_path.with_suffix(".png")
                png_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    # Open SVG in PyMuPDF vector engine and render to high-res PNG pixmap
                    svg_doc = fitz.open(stream=svg_bytes, filetype="svg")
                    page = svg_doc[0]
                    pix = page.get_pixmap(dpi=150)
                    pix.save(str(png_path))
                    svg_doc.close()

                    removed_items.extend([
                        "Rasterized vector SVG into static PNG image (Maximum CDR)",
                        "Destroyed all scripts, DOM events, and executable elements",
                        "Neutralized all external reference vulnerabilities"
                    ])
                    warnings.append("SVG was permanently rasterized to PNG. Scalable vector XML data was replaced with pixel data.")

                    clean_filename = f"{original_filename.rsplit('.', 1)[0]}_sanitized.png"
                    return SanitizationResult(
                        success=True,
                        output_path=png_path,
                        sanitized_filename=clean_filename,
                        target_extension="png",
                        removed_items=removed_items,
                        warnings=warnings
                    )
                except Exception as e:
                    logger.debug(f"PyMuPDF SVG rasterization fallback to XML cleaning: {e}")

            # STRUCTURAL DISARMING: Clean SVG XML
            dom = safe_minidom.parseString(svg_bytes)

            # 1. Remove all <script> tags
            scripts = list(dom.getElementsByTagName("script"))
            for s in scripts:
                s.parentNode.removeChild(s)
            if scripts:
                removed_items.append(f"Removed {len(scripts)} executable <script> element(s)")

            # 2. Iterate elements and remove event handlers & dangerous hrefs
            removed_events = 0
            removed_ext = 0
            for elem in dom.getElementsByTagName("*"):
                for attr in EVENT_HANDLERS:
                    if elem.hasAttribute(attr):
                        elem.removeAttribute(attr)
                        removed_events += 1

                for href_attr in ["href", "xlink:href"]:
                    if elem.hasAttribute(href_attr):
                        val = elem.getAttribute(href_attr).strip().lower()
                        if val.startswith("javascript:") or val.startswith("data:text/html"):
                            elem.removeAttribute(href_attr)
                            removed_items.append(f"Purged 'javascript:' payload from {elem.tagName}")
                        elif (val.startswith("http://") or val.startswith("https://")) and options.strip_external_resources:
                            elem.removeAttribute(href_attr)
                            removed_ext += 1

            if removed_events > 0:
                removed_items.append(f"Stripped {removed_events} inline DOM event handler(s)")
            if removed_ext > 0:
                removed_items.append(f"Stripped {removed_ext} external resource link(s)")

            output_path.parent.mkdir(parents=True, exist_ok=True)
            clean_xml = dom.toxml(encoding="utf-8")
            output_path.write_bytes(clean_xml)

            base_name = original_filename.rsplit(".", 1)[0]
            clean_filename = f"{base_name}_sanitized.svg"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension="svg",
                removed_items=removed_items,
                warnings=warnings
            )

        except Exception as e:
            logger.error(f"SVG sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="svg",
                warnings=[f"SVG sanitization error: {e}"]
            )
