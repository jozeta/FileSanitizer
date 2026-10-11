import io
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.job_manager import job_manager
from app.core.file_isolation import JobWorkspace
from app.core.embedded_extractor import (
    UniversalEmbeddedExtractor,
    detect_mime_type_from_bytes,
    is_payload_dangerous,
    format_file_size,
    calculate_hashes,
)
from app.analyzers.reputation_client import (
    HybridAnalysisClient,
    MXToolboxClient,
    RdapClient,
    IPinfoClient,
)
from app.core.settings_store import create_admin_token

client = TestClient(app)

def test_embedded_extractor_helper_sniffing():
    # PE Header sniffing
    pe_bytes = b"MZ\x90\x00" + b"\x00" * 100
    assert detect_mime_type_from_bytes(pe_bytes) == "application/x-dosexec"
    is_dang, reason = is_payload_dangerous("payload.exe", "application/x-dosexec", pe_bytes)
    assert is_dang is True
    assert "executable" in reason.lower()

    # ELF sniffing
    elf_bytes = b"\x7fELF" + b"\x00" * 100
    assert detect_mime_type_from_bytes(elf_bytes) == "application/x-elf"
    is_dang_elf, _ = is_payload_dangerous("dropper", "application/x-elf", elf_bytes)
    assert is_dang_elf is True

    # PDF sniffing
    pdf_bytes = b"%PDF-1.4\n"
    assert detect_mime_type_from_bytes(pdf_bytes) == "application/pdf"

    # Office OpenXML sniffing
    docx_bytes = b"PK\x03\x04" + b"\x00" * 50
    assert "openxml" in detect_mime_type_from_bytes(docx_bytes, ".docx")

    # Hashes & Formatted size
    md5, sha256 = calculate_hashes(b"hello world")
    assert len(md5) == 32
    assert len(sha256) == 64
    assert format_file_size(1024) == "1.0 KB"
    assert format_file_size(500) == "500 B"

def test_embedded_extractor_on_office_doc():
    sample_docx = Path("test-files/clean_office_document.docx")
    if sample_docx.exists():
        ws = JobWorkspace().create()
        try:
            items = UniversalEmbeddedExtractor.extract_all(
                file_path=sample_docx,
                filename="clean_office_document.docx",
                mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                category="office",
                ws=ws
            )
            assert isinstance(items, list)
        finally:
            ws.cleanup()

def test_embedded_extractor_on_pdf():
    # Test extraction on ultimate_detection.pdf which contains embedded stager_payload.exe
    sample_pdf = Path("ultimate_files/ultimate_detection.pdf")
    if not sample_pdf.exists():
        sample_pdf = Path("backend/ultimate_files/ultimate_detection.pdf")
    if not sample_pdf.exists():
        sample_pdf = Path("test-files/ultimate_files/ultimate_detection.pdf")

    if sample_pdf.exists():
        ws = JobWorkspace().create()
        try:
            items = UniversalEmbeddedExtractor.extract_all(
                file_path=sample_pdf,
                filename="ultimate_detection.pdf",
                mime_type="application/pdf",
                category="pdf",
                ws=ws
            )
            assert isinstance(items, list)
            assert len(items) >= 1
            item = items[0]
            assert "name" in item
            assert item["name"] == "stager_payload.exe"
            assert item["is_dangerous"] is True
            assert (ws.extracted_dir / item["disk_filename"]).exists()
        finally:
            ws.cleanup()

def test_rdap_client_structure_and_verification():
    # Test service availability check
    valid, msg = RdapClient.verify_service()
    assert isinstance(valid, bool)
    assert isinstance(msg, str)

    # Test domain lookup parsing
    res = RdapClient.check_domain("google.com")
    assert res.get("configured") is True
    assert res.get("domain") == "google.com"
    assert "age_days" in res
    assert "registrar" in res

def test_ipinfo_client_verification_and_parsing():
    valid, msg = IPinfoClient.verify_key("")
    assert isinstance(valid, bool)
    assert isinstance(msg, str)

    res = IPinfoClient.check_ip("8.8.8.8")
    assert res.get("configured") is True
    assert res.get("ip") == "8.8.8.8"
    assert "privacy" in res

def test_embedded_files_api_endpoints():
    # Create a job with synthetic embedded files
    dummy_bytes = b"%PDF-1.5\n%DUMMY CONTENT"
    job = job_manager.create_job(dummy_bytes, "test_doc_with_embedded.pdf")
    ws = job_manager.get_workspace(job.job_id)

    # Save a fake embedded file into ws.extracted_dir
    disk_name = "test_emb_payload.bin"
    embedded_path = ws.extracted_dir / disk_name
    embedded_path.write_bytes(b"MZ\x90\x00SUSPICIOUS_PAYLOAD_TEST")

    job.embedded_files = [
        {
            "id": 0,
            "name": "calc.exe",
            "source_type": "pdf_attachment",
            "parent_format": "PDF Document",
            "origin_stream": "/EmbeddedFiles index 0",
            "size": 28,
            "size_formatted": "28 B",
            "mime_type": "application/x-dosexec",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "is_dangerous": True,
            "threat_reason": "Embedded Windows PE Binary executable (MZ header detected)",
            "disk_filename": disk_name
        }
    ]

    # 1. Test GET /api/jobs/{job_id}/embedded-files
    res_list = client.get(f"/api/jobs/{job.job_id}/embedded-files")
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert data_list["total"] == 1
    assert data_list["files"][0]["name"] == "calc.exe"

    # 2. Test GET /api/jobs/{job_id}/analysis contains embedded_files
    res_analysis = client.get(f"/api/jobs/{job.job_id}/analysis")
    assert res_analysis.status_code == 200
    assert len(res_analysis.json().get("embedded_files", [])) == 1

    # 3. Test GET /api/jobs/{job_id}/embedded-files/{file_id}/download
    res_dl = client.get(f"/api/jobs/{job.job_id}/embedded-files/0/download")
    assert res_dl.status_code == 200
    assert res_dl.content.startswith(b"MZ")

    # 4. Test POST /api/jobs/{job_id}/embedded-files/{file_id}/analyze (spawns new job)
    res_an = client.post(f"/api/jobs/{job.job_id}/embedded-files/0/analyze")
    assert res_an.status_code == 200
    child_job_data = res_an.json()
    assert child_job_data["success"] is True
    assert child_job_data["filename"] == "calc.exe"
    assert "job_id" in child_job_data

    # Cleanup test workspace
    job_manager.delete_job(job.job_id)
    job_manager.delete_job(child_job_data["job_id"])

def test_settings_verify_key_new_services():
    admin_token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # RDAP test
    resp_rdap = client.post("/api/settings/verify-key", json={"service": "rdap"}, headers=headers)
    assert resp_rdap.status_code == 200
    data_rdap = resp_rdap.json()
    assert data_rdap["service"] == "rdap"

    # IPinfo test
    resp_ipinfo = client.post("/api/settings/verify-key", json={"service": "ipinfo"}, headers=headers)
    assert resp_ipinfo.status_code == 200
    assert resp_ipinfo.json()["service"] == "ipinfo"

    # Hybrid Analysis test with invalid/test key
    resp_ha = client.post("/api/settings/verify-key", json={"service": "hybridanalysis", "key": "test_invalid_ha_key"}, headers=headers)
    assert resp_ha.status_code == 200
    ha_data = resp_ha.json()
    assert ha_data["service"] == "hybrid_analysis"
    assert ha_data["valid"] is False
    assert "301" not in ha_data["message"]
    assert "Moved Permanently" not in ha_data["message"]
