import io
import email
from email.message import EmailMessage
from pathlib import Path
import pytest
import fitz
import zipfile
from fastapi.testclient import TestClient

from app.main import app
from app.core.job_manager import job_manager
from app.core.settings_store import create_admin_token
from app.core.forensic_report import ForensicReportGenerator
from app.analyzers.email_analyzer import EmailAnalyzer
from app.sanitizers.email_sanitizer import EmailSanitizer
from app.sanitizers.base import SanitizationOptions
from app.analyzers.reputation_client import AbuseIPDBClient, AlienVaultOTXClient

client = TestClient(app)

def test_password_protected_pdf_unlock(tmp_path):
    # 1. Create a password-protected PDF with password "secret123"
    pdf_path = tmp_path / "protected.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 100), "Confidential company data.")
    doc.save(
        str(pdf_path),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="admin123",
        user_pw="secret123"
    )
    doc.close()

    # 2. Upload file without password
    pdf_bytes = pdf_path.read_bytes()
    job = job_manager.create_job(pdf_bytes, "protected.pdf")
    job_manager.execute_analysis_pipeline(job.job_id)

    # File should be detected as encrypted and locked
    assert job.is_password_protected is True
    assert job.is_unlocked is False
    assert any("Password-Protected / Encrypted PDF (Locked)" in f.title for f in job.findings)

    # 3. Test unlocking via POST /api/jobs/{job_id}/unlock
    res_wrong = client.post(f"/api/jobs/{job.job_id}/unlock", json={"password": "wrong_password"})
    assert res_wrong.status_code == 200
    assert res_wrong.json()["is_unlocked"] is False

    res_correct = client.post(f"/api/jobs/{job.job_id}/unlock", json={"password": "secret123"})
    assert res_correct.status_code == 200
    assert res_correct.json()["is_unlocked"] is True

    # Check updated job state
    unlocked_job = job_manager.get_job(job.job_id)
    assert unlocked_job.is_unlocked is True
    assert any("Password-Protected Document Successfully Decrypted" in f.title for f in unlocked_job.findings)


def test_password_protected_dictionary_pdf(tmp_path):
    # PDF with common malware password "infected" should auto-unlock!
    pdf_path = tmp_path / "malware_sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 100), "Malware payload.")
    doc.save(
        str(pdf_path),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="admin",
        user_pw="infected"
    )
    doc.close()

    job = job_manager.create_job(pdf_path.read_bytes(), "malware_sample.pdf")
    job_manager.execute_analysis_pipeline(job.job_id)

    assert job.is_password_protected is True
    assert job.is_unlocked is True
    assert job.unlock_password == "infected"


def test_email_disassembly_and_sanitization(tmp_path):
    # 1. Build a synthetic .eml file with tracking pixel, spoofing, and attachment
    eml_path = tmp_path / "phishing.eml"
    msg = EmailMessage()
    msg["From"] = '"Security Team <security@bank.com>" <attacker@phishing-domain.xyz>'
    msg["To"] = "victim@target-corp.se"
    msg["Subject"] = "Urgent: Verify Your Credentials Immediately"
    msg["Date"] = "Fri, 25 Sep 2026 14:00:00 +0000"
    msg["Reply-To"] = "collect@dropzone-receiver.ru"

    html_content = """<html>
    <body>
        <p>Dear user, please click here: <a href="http://malicious-credential-harvest.com/login">Verify Account</a></p>
        <img src="https://tracker.analytics.com/beacon/pixel.gif" width="1" height="1" alt="" />
        <script>alert('pwned');</script>
    </body>
    </html>"""
    msg.set_content("Please click the verification link in HTML.")
    msg.add_alternative(html_content, subtype='html')

    # Add dangerous executable attachment
    msg.add_attachment(b"MZfakeexecutablepayload", maintype="application", subtype="octet-stream", filename="invoice.exe")

    eml_path.write_bytes(msg.as_bytes())

    # 2. Analyze with EmailAnalyzer
    analyzer = EmailAnalyzer()
    res = analyzer.analyze(eml_path, "phishing.eml", "message/rfc822", workspace_dir=tmp_path)
    assert res.success is True
    data = res.data

    # Verify extracted properties
    assert data["subject"] == "Urgent: Verify Your Credentials Immediately"
    assert data["tracking_pixel_count"] >= 1
    assert data["attachment_count"] == 1
    assert data["attachments"][0]["filename"] == "invoice.exe"
    assert data["attachments"][0]["is_dangerous"] is True
    assert "http://malicious-credential-harvest.com/login" in data["urls"]

    # Verify findings
    finding_titles = [f.title for f in res.findings]
    assert any("Dangerous Executable Attachment in Email" in t for t in finding_titles)
    assert any("Tracking Pixel" in t for t in finding_titles)
    assert any("Display Name Spoofing" in t for t in finding_titles)
    assert any("Mismatched From / Reply-To" in t for t in finding_titles)

    # 3. Sanitize with EmailSanitizer
    clean_eml_path = tmp_path / "sanitized_phishing.eml"
    sanitizer = EmailSanitizer()
    san_res = sanitizer.sanitize(eml_path, clean_eml_path, SanitizationOptions())
    assert san_res.success is True
    assert san_res.details["tracking_pixels_stripped"] >= 1
    assert san_res.details["attachments_quarantined"] >= 1

    # Verify sanitized email content
    clean_bytes = clean_eml_path.read_bytes()
    clean_msg = email.message_from_bytes(clean_bytes, policy=email.policy.default)
    assert clean_msg["X-Sanitized-By"] == "FileSanitizer Enterprise CDR"
    clean_html = clean_msg.get_body(preferencelist=('html',)).get_content()
    assert "pixel.gif" not in clean_html
    assert "<script>" not in clean_html


def test_abuseipdb_and_alienvault_clients():
    # Test verify_key with invalid key returns proper error without crashing
    valid_abuse, msg_abuse = AbuseIPDBClient.verify_key("")
    assert valid_abuse is False

    valid_otx, msg_otx = AlienVaultOTXClient.verify_key("")
    assert valid_otx is False

    # Test API settings verify endpoint for abuseipdb and alienvault
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    res_abuse = client.post("/api/settings/verify-api-key", json={"service": "abuseipdb", "api_key": "invalid_fake_key_123"}, headers=headers)
    assert res_abuse.status_code == 200
    assert "valid" in res_abuse.json()

    res_otx = client.post("/api/settings/verify-api-key", json={"service": "alienvault_otx", "api_key": "invalid_fake_key_456"}, headers=headers)
    assert res_otx.status_code == 200
    assert "valid" in res_otx.json()


def test_forensic_report_generation(sample_image):
    # 1. Create and process job
    job = job_manager.create_job(Path(sample_image).read_bytes(), "forensic_test.png")
    job_manager.execute_analysis_pipeline(job.job_id)

    # 2. Test JSON report endpoint
    res_json = client.get(f"/api/jobs/{job.job_id}/report?format=json")
    assert res_json.status_code == 200
    report_data = res_json.json()
    assert report_data["file_profile"]["stored_filename"] == "forensic_test.png"
    assert "threat_assessment" in report_data
    assert "cryptographic_hashes" in report_data["file_profile"]
    assert "antivirus_clamav" in report_data
    assert "yara_heuristic_engine" in report_data

    # 3. Test HTML printable report endpoint
    res_html = client.get(f"/api/jobs/{job.job_id}/report?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers.get("content-type", "")
    html_text = res_html.text
    assert "<!DOCTYPE html>" in html_text
    assert "Cybersecurity Forensic Dossier" in html_text
    assert "forensic_test.png" in html_text
    assert "Cryptographic Fingerprints" in html_text
