import struct
import tempfile
from pathlib import Path
import pytest
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.analyzers.identification import detect_file_type, categorize_mime


def test_mraptor_macro_heuristics():
    """Verify MacroRaptor AWX heuristic scanning and finding generation."""
    analyzer = OfficeAnalyzer()
    
    # Create an RTF or document containing VBA with AutoOpen + CreateObject + Write
    # We can test VBA directly through OfficeAnalyzer with a mocked macro module or VBA parser
    # Let's test on OpenXML document with vbaProject
    import zipfile
    with tempfile.NamedTemporaryFile(suffix=".docm", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        vba_code = b"""
Sub AutoOpen()
    Dim s As Object
    Set s = CreateObject("WScript.Shell")
    s.Run "powershell.exe -enc AAAA"
End Sub
"""
        with zipfile.ZipFile(tmp_path, "w") as zf:
            zf.writestr("[Content_Types].xml", '<Types><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
            zf.writestr("_rels/.rels", '<Relationships/>')
            zf.writestr("word/vbaProject.bin", vba_code)

        res = analyzer.analyze(tmp_path, tmp_path.name, "application/vnd.ms-word.document.macroEnabled.main+xml")
        assert res.success is True
        assert res.data["has_macros"] is True
        assert res.data["mraptor"] is not None
        assert res.data["mraptor"]["suspicious"] is True
        assert "A" in res.data["mraptor"]["flags"]
        assert "X" in res.data["mraptor"]["flags"]
        assert res.data["mraptor"]["autoexec"] is True
        assert res.data["mraptor"]["execute"] is True

        mraptor_findings = [f for f in res.findings if "MacroRaptor" in f.title]
        assert len(mraptor_findings) > 0
    finally:
        tmp_path.unlink(missing_ok=True)


def test_rtf_rtfobj_extraction_and_payload_carving():
    """Verify oletools.rtfobj extracts objects, detects Equation Editor CLSID, and carves embedded binary payloads."""
    analyzer = OfficeAnalyzer()

    # Craft an RTF with Equation Editor CLSID and an embedded Package object containing an executable payload
    eq_clsid = b"0002CE02-0000-0000-C000-000000000046"
    # Construct an RTF with an object
    rtf_content = (
        rb"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard "
        rb"Exploit Document with Equation Editor "
        rb"{\object\objemb{\*\objclass Equation.3}{\*\objdata 0105000002000000" + eq_clsid.hex().encode('ascii') + rb"}} "
        rb"}"
    )

    with tempfile.NamedTemporaryFile(suffix=".rtf", delete=False) as tmp:
        tmp.write(rtf_content)
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        res = analyzer.analyze(tmp_path, tmp_path.name, "application/rtf")
        assert res.success is True
        assert res.data["rtf_exploits"]["is_rtf"] is True
        assert res.data["rtf_exploits"]["has_exploits"] is True
        assert any("Equation Editor" in exp for exp in res.data["rtf_exploits"]["details"])
        assert len(res.data["rtf_objects"]) > 0
    finally:
        tmp_path.unlink(missing_ok=True)


def test_rtf_dde_msodde_extraction():
    """Verify DDE command extraction via msodde."""
    analyzer = OfficeAnalyzer()

    rtf_dde = rb'{\rtf1\ansi{\field{\*\fldinst {DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"}}{\fldrslt}}}'
    with tempfile.NamedTemporaryFile(suffix=".rtf", delete=False) as tmp:
        tmp.write(rtf_dde)
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        res = analyzer.analyze(tmp_path, tmp_path.name, "application/rtf")
        assert res.success is True
        assert len(res.data["dde_injections"]) > 0
        assert any("cmd.exe" in dde for dde in res.data["dde_injections"])
        dde_findings = [f for f in res.findings if "Dynamic Data Exchange" in f.title or "DDE" in f.title]
        assert len(dde_findings) > 0
    finally:
        tmp_path.unlink(missing_ok=True)


def test_onenote_identification_and_payload_carving():
    """Verify OneNote file identification and embedded FileDataStoreObject attachment carving."""
    # 1. Identification check
    one_header = b"\xE4\x52\x5C\x7B\x82\xD8\xA5\x4D\xAF\x68\xD7\x0C\x7D\x33\xF8\xF4"
    with tempfile.NamedTemporaryFile(suffix=".one", delete=False) as tmp:
        # Build OneNote file with FileDataStoreObject containing a batch payload
        file_store_guid = b"\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC"
        footer_guid = b"\x43\x42\xE4\x71\x13\x73\x6A\x4B\xB6\x6A\x8A\x46\x4C\xE9\xD8\x08"
        payload = b"@echo off\r\npowershell.exe -ExecutionPolicy Bypass -Command calc.exe\r\n"
        cb_len = len(payload)

        # OneNote content
        one_content = one_header + b"\x00" * 64
        one_content += b"invoice_dropper.bat\x00\x00"
        one_content += file_store_guid + struct.pack("<Q", cb_len) + b"\x00" * 12 + payload + footer_guid
        tmp.write(one_content)
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        mime, cat, desc = detect_file_type(tmp_path, tmp_path.name)
        assert mime == "application/onenote"
        assert cat == "office"

        # 2. OfficeAnalyzer OneNote carving check
        analyzer = OfficeAnalyzer()
        res = analyzer.analyze(tmp_path, tmp_path.name, mime)
        assert res.success is True
        assert res.data["onenote_analysis"] is not None
        assert res.data["onenote_analysis"]["is_onenote"] is True
        assert len(res.data["onenote_analysis"]["embedded_attachments"]) > 0

        att = res.data["onenote_analysis"]["embedded_attachments"][0]
        assert att["suspicious"] is True
        assert "Batch" in att["file_type"] or "bat" in att["filename"].lower()

        one_findings = [f for f in res.findings if "OneNote" in f.title]
        assert len(one_findings) > 0
        assert any("Weaponized" in f.title or "Dropper" in f.title for f in one_findings)
    finally:
        tmp_path.unlink(missing_ok=True)


def test_oleid_indicators_collection():
    """Verify OleID indicators are populated in OfficeAnalyzer data."""
    analyzer = OfficeAnalyzer()
    # Test on a minimal document
    with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as tmp:
        tmp.write(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 512)
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        res = analyzer.analyze(tmp_path, tmp_path.name, "application/msword")
        assert res.success is True
        assert "oleid_indicators" in res.data
        assert isinstance(res.data["oleid_indicators"], list)
    finally:
        tmp_path.unlink(missing_ok=True)
