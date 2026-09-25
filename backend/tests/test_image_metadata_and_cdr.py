import pytest
from PIL import Image, ExifTags
from app.analyzers.image_analyzer import ImageAnalyzer
from app.sanitizers.image_sanitizer import ImageSanitizer
from app.sanitizers.base import SanitizationOptions

def test_image_metadata_analysis_and_stripping(temp_dir):
    img_path = temp_dir / "camera_photo.jpg"

    # Create image with EXIF and comment
    img = Image.new("RGB", (120, 120), color=(100, 150, 200))
    exif = img.getexif()
    exif[0x010F] = "Canon"  # Make
    exif[0x0110] = "Canon EOS R5"  # Model
    exif[0x0132] = "2026:01:15 10:30:00"  # DateTime
    img.save(img_path, format="JPEG", exif=exif)

    analyzer = ImageAnalyzer()
    res = analyzer.analyze(img_path, img_path.name, "image/jpeg")

    assert res.data["has_exif"] is True
    assert res.data["camera_info"].get("Make") == "Canon"
    assert res.data["camera_info"].get("Model") == "Canon EOS R5"

    # Sanitize image
    clean_path = temp_dir / "clean_photo.jpg"
    sanitizer = ImageSanitizer()
    opts = SanitizationOptions(
        profile="privacy",
        remove_metadata=True,
        reencode_image=True
    )

    clean_res = sanitizer.sanitize(img_path, clean_path, opts, img_path.name)
    assert clean_res.success is True
    assert clean_path.exists()

    # Re-analyze clean image
    clean_res_analysis = analyzer.analyze(clean_path, clean_path.name, "image/jpeg")
    assert clean_res_analysis.data["has_exif"] is False
    assert len(clean_res_analysis.data["camera_info"]) == 0

def test_image_flattening_and_conversion(temp_dir):
    # Create RGBA transparent image
    rgba_path = temp_dir / "transparent.png"
    img = Image.new("RGBA", (50, 50), color=(0, 255, 0, 100))
    img.save(rgba_path, format="PNG")

    clean_path = temp_dir / "flattened.jpg"
    sanitizer = ImageSanitizer()
    opts = SanitizationOptions(
        profile="maximum",
        flatten_image=True,
        convert_to_jpg=True
    )

    res = sanitizer.sanitize(rgba_path, clean_path, opts, rgba_path.name)
    assert res.success is True
    assert clean_path.exists()

    with Image.open(clean_path) as clean_img:
        assert clean_img.mode == "RGB"
        assert clean_img.format == "JPEG"
