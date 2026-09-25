import pytest
from pathlib import Path
from app.analyzers.identification import IdentificationAnalyzer, calculate_hashes, detect_file_type

def test_hash_calculation(temp_dir):
    test_file = temp_dir / "hash_test.txt"
    test_file.write_bytes(b"FileSanitizer Security Test Content")

    hashes = calculate_hashes(test_file)
    assert "md5" in hashes
    assert "sha1" in hashes
    assert "sha256" in hashes
    assert len(hashes["sha256"]) == 64
    assert len(hashes["md5"]) == 32

def test_pdf_identification(sample_pdf):
    mime, cat, desc = detect_file_type(sample_pdf, sample_pdf.name)
    assert mime == "application/pdf"
    assert cat == "pdf"

def test_image_identification(sample_image):
    mime, cat, desc = detect_file_type(sample_image, sample_image.name)
    assert mime == "image/png"
    assert cat == "image"

def test_mime_spoofing_detection(temp_dir):
    """
    Test security check: A Windows PE executable disguised with a .pdf extension
    must trigger a MIME mismatch finding.
    """
    fake_pdf = temp_dir / "invoice.pdf"
    # Write MZ header (executable)
    fake_pdf.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100)

    analyzer = IdentificationAnalyzer()
    res = analyzer.analyze(fake_pdf, fake_pdf.name, "")

    assert res.data["detected_mime"] == "application/x-dosexec"
    assert res.data["is_mismatch"] is True
    # Verify high severity finding was raised
    mismatch_findings = [f for f in res.findings if "Mismatch" in f.title or "Executable" in f.title]
    assert len(mismatch_findings) > 0
