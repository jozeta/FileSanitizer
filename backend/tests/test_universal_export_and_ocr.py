import pytest
from pathlib import Path
from PIL import Image

from app.sanitizers.base import SanitizationOptions
from app.sanitizers.pdf_sanitizer import PDFSanitizer
from app.sanitizers.image_sanitizer import ImageSanitizer
from app.sanitizers.office_sanitizer import OfficeSanitizer
from app.sanitizers.text_sanitizer import TextSanitizer
from app.sanitizers.svg_sanitizer import SVGSanitizer
from app.analyzers.watchlist_analyzer import WatchlistAnalyzer
from app.core.thumbnail_generator import ThumbnailGenerator
from app.core.settings_store import settings_store

def test_image_convert_to_pdf(tmp_path):
    img_path = tmp_path / "test.png"
    img = Image.new("RGB", (100, 100), color=(255, 0, 0))
    img.save(img_path, format="PNG")

    out_path = tmp_path / "out.pdf"
    options = SanitizationOptions(convert_to_pdf=True)
    res = ImageSanitizer().sanitize(img_path, out_path, options, "test.png")

    assert res.success is True
    assert res.target_extension == "pdf"
    assert out_path.exists()
    assert out_path.stat().st_size > 0

def test_pdf_convert_to_png(tmp_path):
    pdf_source = Path("test-files/clean_document.pdf")
    if not pdf_source.exists():
        pytest.skip("Test file not found")

    out_path = tmp_path / "out.png"
    options = SanitizationOptions(convert_to_png=True)
    res = PDFSanitizer().sanitize(pdf_source, out_path, options, "clean_document.pdf")

    assert res.success is True
    assert res.target_extension == "png"
    assert out_path.exists()
    assert out_path.stat().st_size > 0

def test_office_convert_to_pdf_and_png(tmp_path):
    docm_source = Path("test-files/office_vba_macro_template_injection.docm")
    if not docm_source.exists():
        pytest.skip("Test file not found")

    # PDF
    out_pdf = tmp_path / "out.pdf"
    opt_pdf = SanitizationOptions(convert_to_pdf=True)
    res_pdf = OfficeSanitizer().sanitize(docm_source, out_pdf, opt_pdf, docm_source.name)
    assert res_pdf.success is True
    assert res_pdf.target_extension == "pdf"
    assert out_pdf.exists()

    # PNG
    out_png = tmp_path / "out.png"
    opt_png = SanitizationOptions(convert_to_png=True)
    res_png = OfficeSanitizer().sanitize(docm_source, out_png, opt_png, docm_source.name)
    assert res_png.success is True
    assert res_png.target_extension == "png"
    assert out_png.exists()

def test_text_convert_to_pdf_and_png(tmp_path):
    txt_path = tmp_path / "sample.txt"
    txt_path.write_text("Hello security analysis!\nSafe plain text.\n", encoding="utf-8")

    out_pdf = tmp_path / "sample.pdf"
    res_pdf = TextSanitizer().sanitize(txt_path, out_pdf, SanitizationOptions(convert_to_pdf=True), "sample.txt")
    assert res_pdf.success is True
    assert res_pdf.target_extension == "pdf"
    assert out_pdf.exists()

    out_png = tmp_path / "sample.png"
    res_png = TextSanitizer().sanitize(txt_path, out_png, SanitizationOptions(convert_to_png=True), "sample.txt")
    assert res_png.success is True
    assert res_png.target_extension == "png"
    assert out_png.exists()

def test_thumbnail_generator(tmp_path):
    # Image thumbnail
    img_path = tmp_path / "sample.jpg"
    img = Image.new("RGB", (200, 200), (0, 128, 255))
    img.save(img_path, format="JPEG")
    thumb_img = tmp_path / "thumb_img.png"
    assert ThumbnailGenerator.generate_thumbnail(img_path, "image", thumb_img) is True
    assert thumb_img.exists()

    # Office thumbnail
    doc_path = Path("test-files/clean_office_document.docx")
    if doc_path.exists():
        thumb_doc = tmp_path / "thumb_doc.png"
        assert ThumbnailGenerator.generate_thumbnail(doc_path, "office", thumb_doc) is True
        assert thumb_doc.exists()

def test_watchlist_detection():
    # Add a custom rule
    rule = settings_store.add_warning_rule(
        pattern="CONFIDENTIAL_PROJECT_X",
        is_regex=False,
        severity="critical",
        description="Leak detection test"
    )

    findings = WatchlistAnalyzer.scan_text("This memo contains CONFIDENTIAL_PROJECT_X details for executive review.")
    assert len(findings) >= 1
    assert any(f.category == "warninglist" and f.severity == "critical" for f in findings)

    # Cleanup
    settings_store.delete_warning_rule(rule["id"])
