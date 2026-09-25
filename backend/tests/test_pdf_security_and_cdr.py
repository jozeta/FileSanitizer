import pytest
import fitz
from app.analyzers.pdf_analyzer import PDFAnalyzer
from app.sanitizers.pdf_sanitizer import PDFSanitizer
from app.sanitizers.base import SanitizationOptions

def test_pdf_javascript_and_url_detection(temp_dir):
    pdf_path = temp_dir / "suspicious.pdf"
    doc = fitz.open()
    page = doc.new_page(width=400, height=400)
    page.insert_text((50, 50), "Link to https://malicious-phish.xyz/login")

    # Add embedded JavaScript to document catalog
    doc.set_xml_metadata("<x:xmpmeta>Confidential Information</x:xmpmeta>")
    doc.save(str(pdf_path))
    doc.close()

    # Inject raw JavaScript trigger in PDF stream
    content = pdf_path.read_bytes()
    injected = content + b"\n/JavaScript << /JS (app.alert('XSS Exploit');) >>\n"
    pdf_path.write_bytes(injected)

    analyzer = PDFAnalyzer()
    res = analyzer.analyze(pdf_path, pdf_path.name, "application/pdf")

    assert res.data["has_javascript"] is True
    assert any("https://malicious-phish.xyz" in u for u in res.data["urls"])
    js_findings = [f for f in res.findings if f.category == "javascript"]
    assert len(js_findings) > 0

def test_pdf_selective_sanitization(sample_pdf, temp_dir):
    clean_pdf = temp_dir / "clean_selective.pdf"
    sanitizer = PDFSanitizer()
    opts = SanitizationOptions(
        profile="privacy",
        remove_metadata=True,
        remove_external_links=True,
        rasterize_pages=False
    )

    res = sanitizer.sanitize(sample_pdf, clean_pdf, opts, sample_pdf.name)
    assert res.success is True
    assert clean_pdf.exists()

    # Re-verify that metadata was cleared
    clean_doc = fitz.open(clean_pdf)
    assert clean_doc.metadata.get("author") in [None, ""]
    assert clean_doc.metadata.get("title") in [None, ""]
    clean_doc.close()

def test_pdf_maximum_rasterization_cdr(sample_pdf, temp_dir):
    clean_pdf = temp_dir / "clean_rasterized.pdf"
    sanitizer = PDFSanitizer()
    opts = SanitizationOptions(
        profile="maximum",
        rasterize_pages=True
    )

    res = sanitizer.sanitize(sample_pdf, clean_pdf, opts, sample_pdf.name)
    assert res.success is True
    assert clean_pdf.exists()

    # Verify that rasterized document opens and has correct page count
    clean_doc = fitz.open(clean_pdf)
    assert clean_doc.page_count == 1
    # Searchable text should be gone (rasterized to pixels)
    assert "Hello FileSanitizer" not in clean_doc[0].get_text()
    clean_doc.close()
