import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import email
from email.message import EmailMessage

from app.main import app
from app.core.job_manager import job_manager
from app.analyzers.email_analyzer import EmailAnalyzer
from app.analyzers.executable_analyzer import ExecutableAnalyzer

client = TestClient(app)

def test_email_triage_advanced_features(tmp_path: Path):
    """Test full email disassembly: visual preview, transit hops, auth, attachment download & analyze."""
    # 1. Create realistic test EML with headers, HTML body, tracking beacon, and attachment
    eml = EmailMessage()
    eml["From"] = '"Microsoft Support" <support.security@phish-attacker.com>'
    eml["To"] = "victim@target-corp.com"
    eml["Reply-To"] = "attacker-inbox@stealer-mail.com"
    eml["Subject"] = "Urgent: Verify Your Account Immediately"
    eml["Date"] = "Mon, 25 Sep 2026 10:00:00 +0000"
    eml["Received-SPF"] = "Fail (mail.phish-attacker.com: domain does not designate 185.220.101.5 as permitted sender)"
    eml["Authentication-Results"] = "mail.target-corp.com; spf=fail smtp.mailfrom=phish-attacker.com; dkim=fail header.d=phish-attacker.com; dmarc=fail (p=reject)"
    
    # Received transit hops
    eml.add_header("Received", "from mail-origin.phish-attacker.com ([185.220.101.5]) by relay1.cloud-mta.com with ESMTP id ABC1234; Mon, 25 Sep 2026 10:00:05 +0000")
    eml.add_header("Received", "from relay1.cloud-mta.com ([198.51.100.22]) by mx.target-corp.com with ESMTPS id DEF5678; Mon, 25 Sep 2026 10:00:10 +0000")

    # Body with deceptive anchor link, tracking pixel, and script tag (to verify stripping)
    html_content = """
    <html>
      <body>
        <script>alert('malicious script execution');</script>
        <p>Dear Customer, your password has expired.</p>
        <p><a href="http://credential-theft.ru/login">https://account.microsoft.com/security</a></p>
        <img src="http://telemetry.evil.com/pixel.gif" width="1" height="1" style="display:none;" />
      </body>
    </html>
    """
    eml.set_content("Dear Customer, your password has expired. Please verify at https://account.microsoft.com/security")
    eml.add_alternative(html_content, subtype="html")

    # Add dangerous attachment
    eml.add_attachment(b"MZ\x90\x00DummyExecutableBytesForTesting12345678", maintype="application", subtype="octet-stream", filename="urgent_invoice.exe")

    eml_bytes = eml.as_bytes()
    eml_file = tmp_path / "phishing_test.eml"
    eml_file.write_bytes(eml_bytes)

    # 2. Analyze via EmailAnalyzer
    analyzer = EmailAnalyzer()
    res = analyzer.analyze(eml_file, "phishing_test.eml", "message/rfc822", workspace_dir=tmp_path)
    assert res.success is True
    data = res.data

    # Check safe preview HTML generated
    assert "<script" not in data["body_html_sanitized"]
    assert "https://account.microsoft.com/security" in data["body_html_sanitized"]
    assert ' href="#"' in data["body_html_sanitized"]
    assert ' href="http://' not in data["body_html_sanitized"]
    assert data["has_html"] is True
    assert len(data["body_plain"]) > 0

    # Check raw email stream & header blocks
    assert "raw_email" in data and len(data["raw_email"]) > 0
    assert "support.security@phish-attacker.com" in data["raw_email"]
    assert "Urgent: Verify Your Account Immediately" in data["raw_email"]
    assert "raw_headers" in data and len(data["raw_headers"]) > 0
    assert "all_headers" in data and len(data["all_headers"]) >= 5

    # Check sender analysis & spoofing
    assert data["sender_analysis"]["is_mismatched_reply_to"] is True
    assert data["sender_analysis"]["from_domain"] == "phish-attacker.com"
    assert data["sender_analysis"]["reply_to_domain"] == "stealer-mail.com"

    # Check deceptive link detection
    assert len(data["deceptive_links"]) >= 1
    assert data["deceptive_links"][0]["claimed_destination"] == "account.microsoft.com"
    assert "credential-theft.ru" in data["deceptive_links"][0]["destination_host"]

    # Check authentication parsing
    assert data["authentication"]["spf"]["status"] == "FAIL"
    assert data["authentication"]["dkim"]["status"] == "FAIL"
    assert data["authentication"]["dmarc"]["status"] == "FAIL"
    assert data["authentication"]["overall_trust"] == "UNTRUSTED / SPOOFED"

    # Check transit MTA hops
    assert len(data["transit_hops"]) == 2
    assert data["transit_hops"][0]["hop_number"] == 1
    assert data["transit_hops"][0]["ip"] == "185.220.101.5"
    assert data["transit_hops"][1]["hop_number"] == 2
    assert data["transit_hops"][1]["ip"] == "198.51.100.22"

    # Check attachments and reputation structure
    assert len(data["attachments"]) == 1
    att = data["attachments"][0]
    assert att["filename"] == "urgent_invoice.exe"
    assert att["is_dangerous"] is True
    assert "reputation" in att
    assert "threatfox" in att["reputation"]
    assert "circl" in att["reputation"]
    assert "virustotal" in att["reputation"]

    # 3. Create job via API and test attachment download & analyze endpoints
    job = job_manager.create_job(eml_bytes, "phishing_sample.eml")
    job_manager.execute_analysis_pipeline(job.job_id)

    # API: get job analysis
    res_api = client.get(f"/api/jobs/{job.job_id}/analysis")
    assert res_api.status_code == 200
    job_data = res_api.json()
    assert "email_info" in job_data
    assert job_data["email_info"] is not None

    # API: download attachment
    dl_res = client.get(f"/api/jobs/{job.job_id}/email/attachments/0/download")
    assert dl_res.status_code == 200
    assert dl_res.content.startswith(b"MZ")

    # API: analyze attachment as new job
    post_res = client.post(f"/api/jobs/{job.job_id}/email/attachments/0/analyze")
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["success"] is True
    new_job_id = post_data["job_id"]
    assert new_job_id != job.job_id

    # Verify newly created attachment job
    new_job = job_manager.get_job(new_job_id)
    assert new_job is not None
    assert new_job.filename == "urgent_invoice.exe"


def test_executable_pe_analyzer_and_dump_endpoints(tmp_path: Path):
    """Test PE binary static disassembly, headers, sections, suspicious APIs, and dump endpoints."""
    # Build minimal valid PE32 binary
    pe_header_offset = 0x80
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    dos_header[0x3C:0x40] = pe_header_offset.to_bytes(4, "little")

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    # Machine: i386 (0x014c), NumberOfSections: 2, TimeDateStamp: 0x60000000, Characteristics: 0x0102 (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    file_header = (
        (0x014c).to_bytes(2, "little") +
        (2).to_bytes(2, "little") +
        (0x60000000).to_bytes(4, "little") +
        (0).to_bytes(4, "little") +
        (0).to_bytes(4, "little") +
        (0x00E0).to_bytes(2, "little") + # SizeOfOptionalHeader = 224
        (0x0102).to_bytes(2, "little")
    )

    # Optional Header (224 bytes)
    opt_header = bytearray(224)
    opt_header[0:2] = (0x010B).to_bytes(2, "little") # PE32
    opt_header[2:4] = b"\x0E\x00" # Linker 14.0
    opt_header[16:20] = (0x1000).to_bytes(4, "little") # AddressOfEntryPoint
    opt_header[28:32] = (0x00400000).to_bytes(4, "little") # ImageBase
    opt_header[32:36] = (0x1000).to_bytes(4, "little") # SectionAlignment
    opt_header[36:40] = (0x0200).to_bytes(4, "little") # FileAlignment
    opt_header[56:60] = (0x3000).to_bytes(4, "little") # SizeOfImage
    opt_header[60:64] = (0x0400).to_bytes(4, "little") # SizeOfHeaders
    opt_header[68:70] = (3).to_bytes(2, "little") # Subsystem: Windows CUI (Console)
    opt_header[70:72] = (0x8140).to_bytes(2, "little") # DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    opt_header[92:96] = (16).to_bytes(4, "little") # NumberOfRvaAndSizes

    # Section Headers (40 bytes each)
    # Section 1: .text (Code)
    sec1 = bytearray(40)
    sec1[0:8] = b".text\x00\x00\x00"
    sec1[8:12] = (0x0200).to_bytes(4, "little") # VirtualSize
    sec1[12:16] = (0x1000).to_bytes(4, "little") # VirtualAddress
    sec1[16:20] = (0x0200).to_bytes(4, "little") # SizeOfRawData
    sec1[20:24] = (0x0400).to_bytes(4, "little") # PointerToRawData
    sec1[36:40] = (0x60000020).to_bytes(4, "little") # Characteristics: CODE | EXECUTE | READ

    # Section 2: .data
    sec2 = bytearray(40)
    sec2[0:8] = b".data\x00\x00\x00"
    sec2[8:12] = (0x0200).to_bytes(4, "little") # VirtualSize
    sec2[12:16] = (0x2000).to_bytes(4, "little") # VirtualAddress
    sec2[16:20] = (0x0200).to_bytes(4, "little") # SizeOfRawData
    sec2[20:24] = (0x0600).to_bytes(4, "little") # PointerToRawData
    sec2[36:40] = (0xC0000040).to_bytes(4, "little") # Characteristics: INITIALIZED_DATA | READ | WRITE

    # Combine headers up to 0x400
    headers_data = dos_header + pe_sig + file_header + opt_header + sec1 + sec2
    headers_padded = headers_data.ljust(0x400, b"\x00")

    # Raw Section 1 data (at 0x400, 512 bytes): embed suspicious strings and bytecode
    sec1_data = (
        b"\x90\x90\xcc" +
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00" +
        b"http://malware-c2-test.com/payload.exe\x00" +
        b"powershell.exe -ExecutionPolicy Bypass\x00"
    ).ljust(0x200, b"\x90")

    # Raw Section 2 data (at 0x600, 512 bytes)
    sec2_data = b"Hello from PE .data section!\x00".ljust(0x200, b"\x00")

    # Full PE binary bytes
    full_pe_bytes = bytes(headers_padded + sec1_data + sec2_data)

    # 1. Analyze with ExecutableAnalyzer directly
    pe_file = tmp_path / "sample_pe.exe"
    pe_file.write_bytes(full_pe_bytes)

    analyzer = ExecutableAnalyzer()
    res = analyzer.analyze(pe_file, "sample_pe.exe", "application/x-dosexec")
    assert res.success is True
    data = res.data

    # Verify DOS & PE header extraction
    assert "PE" in data["format"]
    assert "32-bit" in data["architecture"]
    assert "dos_header" in data
    assert "MZ" in data["dos_header"]["e_magic"]
    assert "file_header" in data
    assert data["file_header"]["number_of_sections"] == 2
    assert "optional_header" in data
    assert data["optional_header"]["magic"] == "PE32 (32-bit)"
    assert data["optional_header"]["address_of_entry_point"] == "0x1000"

    # Verify sections extraction
    assert len(data["sections"]) == 2
    sec_names = [s["name"] for s in data["sections"]]
    assert ".text" in sec_names
    assert ".data" in sec_names

    # Verify string extraction (URLs, commands)
    assert "http://malware-c2-test.com/payload.exe" in data["urls"]
    assert any("powershell" in s.lower() for s in data["strings"]["commands"])

    # 2. Test Section Dumping helper
    text_sec_dump = ExecutableAnalyzer.dump_section(pe_file, ".text")
    assert text_sec_dump is not None
    assert len(text_sec_dump) == 0x200
    assert b"VirtualAllocEx" in text_sec_dump

    data_sec_dump = ExecutableAnalyzer.dump_section(pe_file, ".data")
    assert data_sec_dump is not None
    assert b"Hello from PE" in data_sec_dump

    # 3. Create Job and test API endpoints
    job = job_manager.create_job(full_pe_bytes, "test_binary.exe")
    job_manager.execute_analysis_pipeline(job.job_id)

    # API: get analysis including binary_info
    analysis_res = client.get(f"/api/jobs/{job.job_id}/analysis")
    assert analysis_res.status_code == 200
    job_data = analysis_res.json()
    assert "binary_info" in job_data
    assert job_data["binary_info"] is not None
    assert "PE" in job_data["binary_info"]["format"]
    assert "decompilation" in job_data["binary_info"]
    decomp = job_data["binary_info"]["decompilation"]
    if decomp:
        assert "function_name" in decomp
        assert "code" in decomp
        assert "confidence" in decomp

    # API: dump section endpoint
    dump_res = client.get(f"/api/jobs/{job.job_id}/binary/dump-section?name=.text")
    assert dump_res.status_code == 200
    assert len(dump_res.content) == 0x200
    assert b"VirtualAllocEx" in dump_res.content

    # API: 404 on nonexistent section
    bad_dump = client.get(f"/api/jobs/{job.job_id}/binary/dump-section?name=.nonexistent")
    assert bad_dump.status_code == 404
