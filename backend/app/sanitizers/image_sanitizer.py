from pathlib import Path
from typing import List
from PIL import Image
from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

class ImageSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "ImageSanitizer"

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
            with Image.open(input_path) as img:
                orig_format = (img.format or "PNG").upper()

                # Determine target extension and format
                if options.convert_to_pdf or output_path.suffix.lower() == ".pdf":
                    target_format = "PDF"
                    target_ext = "pdf"
                    removed_items.append("Converted image to sanitized standalone PDF document")
                elif options.convert_to_jpg:
                    target_format = "JPEG"
                    target_ext = "jpg"
                    if orig_format != "JPEG":
                        removed_items.append(f"Converted image format from {orig_format} to JPEG")
                elif options.convert_to_png:
                    target_format = "PNG"
                    target_ext = "png"
                    if orig_format != "PNG":
                        removed_items.append(f"Converted image format from {orig_format} to PNG")
                else:
                    target_format = orig_format
                    target_ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "png"

                # Check if flattening is required (or converting RGBA to JPEG/PDF)
                is_rgba = img.mode in ("RGBA", "LA", "P")
                flatten = options.flatten_image or (target_format in ("JPEG", "PDF") and is_rgba)

                if flatten:
                    # Create white background canvas and composite
                    background = Image.new("RGB", img.size, (255, 255, 255))
                    if img.mode == "RGBA":
                        background.paste(img, mask=img.split()[3])  # 3 is the alpha channel
                    elif img.mode == "LA":
                        background.paste(img, mask=img.split()[1])
                    else:
                        background.paste(img.convert("RGBA"))
                    clean_img = background
                    removed_items.append("Flattened transparency and alpha channels onto solid white background")
                    warnings.append("Transparency was permanently removed due to flattening/JPEG conversion.")
                else:
                    # Copy image data without metadata or info dictionaries
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(list(img.getdata()))

                # Track removed metadata items
                if options.remove_metadata or options.remove_gps:
                    removed_items.append("Stripped EXIF metadata headers")
                    removed_items.append("Removed GPS location coordinates")
                if options.remove_author:
                    removed_items.append("Removed Artist/Copyright author tags")
                if options.remove_timestamps:
                    removed_items.append("Stripped creation and digitization timestamps")
                if options.remove_comments:
                    removed_items.append("Stripped text comments and XMP/IPTC packets")

                if options.reencode_image:
                    removed_items.append("Re-encoded raw pixel data into a new image structure")
                    warnings.append("Re-encoding pixel data may result in minor lossy compression artifacts if using JPEG.")

                # Ensure output directory exists
                output_path.parent.mkdir(parents=True, exist_ok=True)

                # Save clean image WITHOUT EXIF or info metadata
                save_kwargs = {}
                if target_format == "JPEG":
                    save_kwargs["quality"] = 92
                    save_kwargs["optimize"] = True
                elif target_format == "PNG":
                    save_kwargs["optimize"] = True
                elif target_format == "PDF":
                    if clean_img.mode != "RGB":
                        clean_img = clean_img.convert("RGB")

                clean_img.save(output_path, format=target_format, **save_kwargs)

            base_name = original_filename.rsplit(".", 1)[0]
            clean_filename = f"{base_name}_sanitized.{target_ext}"

            return SanitizationResult(
                success=True,
                output_path=output_path,
                sanitized_filename=clean_filename,
                target_extension=target_ext,
                removed_items=removed_items,
                warnings=warnings,
                details={"target_format": target_format}
            )

        except Exception as e:
            logger.error(f"Image sanitization failed: {e}")
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=original_filename,
                target_extension="img",
                removed_items=[],
                warnings=[f"Sanitization failed: {e}"],
                details={"error": str(e)}
            )
