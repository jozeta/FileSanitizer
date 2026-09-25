import pytest
import io
from fastapi.testclient import TestClient
from app.main import app
from app.core.job_manager import job_manager

client = TestClient(app)

def test_full_pipeline_image_upload_sanitize_download(sample_image):
    # 1. Upload file
    with open(sample_image, "rb") as f:
        resp = client.post(
            "/api/files",
            files={"files": ("test_upload.png", f, "image/png")}
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["uploaded"] == 1
    job_id = data["jobs"][0]["job_id"]

    # 2. Synchronous pipeline run for reliable test
    job_manager.execute_analysis_pipeline(job_id)

    # 3. Fetch analysis
    analysis_resp = client.get(f"/api/jobs/{job_id}/analysis")
    assert analysis_resp.status_code == 200
    analysis_data = analysis_resp.json()
    assert analysis_data["category"] == "image"
    assert "sha256" in analysis_data["hashes"]

    # 4. Trigger Sanitization
    sanitize_resp = client.post(
        f"/api/jobs/{job_id}/sanitize",
        json={"profile": "privacy"}
    )
    assert sanitize_resp.status_code == 200

    # Ensure sanitization pipeline completed
    job = job_manager.get_job(job_id)
    if job.state != "COMPLETED":
        job_manager.execute_sanitization_pipeline(job_id, job.sanitization_options)

    # 5. Fetch Post-Sanitization Validation Result
    result_resp = client.get(f"/api/jobs/{job_id}/result")
    assert result_resp.status_code == 200
    result_data = result_resp.json()
    assert result_data["is_ready"] is True
    assert "validation" in result_data
    assert "original" in result_data["validation"]
    assert "sanitized" in result_data["validation"]

    # 6. Download Clean File
    download_resp = client.get(f"/api/jobs/{job_id}/download")
    assert download_resp.status_code == 200
    assert len(download_resp.content) > 0

    # 7. Download Audit Report
    report_resp = client.get(f"/api/jobs/{job_id}/report")
    assert report_resp.status_code == 200
    assert "FileSanitizer Security & CDR Audit Report" in report_resp.json()["report_type"]

    # 8. Clean up
    delete_resp = client.delete(f"/api/jobs/{job_id}")
    assert delete_resp.status_code == 200
