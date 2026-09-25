import pytest
import zipfile
from app.analyzers.archive_analyzer import ArchiveAnalyzer
from app.sanitizers.archive_sanitizer import ArchiveSanitizer
from app.sanitizers.base import SanitizationOptions

def test_archive_path_traversal_detection(temp_dir):
    zip_path = temp_dir / "traversal_attack.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("safe_doc.txt", "Normal content")

    analyzer = ArchiveAnalyzer()
    res = analyzer.analyze(zip_path, zip_path.name, "application/zip")

    assert res.data["has_path_traversal"] is True
    assert "../../etc/passwd" in res.data["traversal_files"]
    traversal_findings = [f for f in res.findings if "Path Traversal" in f.title]
    assert len(traversal_findings) > 0

def test_archive_executable_filtering_sanitizer(temp_dir):
    zip_path = temp_dir / "mixed_archive.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("clean_notes.txt", "Hello Notes")
        zf.writestr("malware_payload.exe", b"MZ\x90\x00Binary")
        zf.writestr("script.bat", "@echo off\npowershell evil")

    clean_zip = temp_dir / "sanitized_archive.zip"
    sanitizer = ArchiveSanitizer()
    opts = SanitizationOptions(profile="security")

    res = sanitizer.sanitize(zip_path, clean_zip, opts, zip_path.name)
    assert res.success is True
    assert clean_zip.exists()

    # Verify that .exe and .bat were excluded
    with zipfile.ZipFile(clean_zip, 'r') as zout:
        names = zout.namelist()
        assert "clean_notes.txt" in names
        assert "malware_payload.exe" not in names
        assert "script.bat" not in names
