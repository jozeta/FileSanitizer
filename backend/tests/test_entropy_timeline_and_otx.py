import os
import io
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.core.job_manager import JobManager, JobModel
from app.analyzers.entropy_analyzer import EntropyAnalyzer
from app.analyzers.forensic_timeline import ForensicTimelineBuilder
from app.analyzers.reputation_client import AlienVaultOTXClient
from app.analyzers.metadata_extractor import StructuredMetadata, MetadataField


def test_entropy_analyzer_plaintext_vs_random():
    # Plaintext text should have moderate entropy
    text = b"This is a standard English paragraph with normal words and punctuation." * 20
    text_ent = EntropyAnalyzer.calculate_shannon_entropy(text)
    assert 3.0 <= text_ent <= 5.5

    # Completely random or high-entropy data should have entropy near 7.8 - 8.0
    random_bytes = os.urandom(8192)
    rand_ent = EntropyAnalyzer.calculate_shannon_entropy(random_bytes)
    assert rand_ent > 7.5

    profile = EntropyAnalyzer.calculate_sliding_window_entropy(random_bytes, num_points=16)
    assert len(profile) == 16
    assert all(p["entropy"] > 7.0 for p in profile)

    chi = EntropyAnalyzer.calculate_chi_square(random_bytes)
    assert "chi_square" in chi
    assert "interpretation" in chi

    mc = EntropyAnalyzer.calculate_monte_carlo_pi(random_bytes)
    assert "pi_estimate" in mc
    assert mc["pi_estimate"] > 0


def test_entropy_analyzer_embedded_high_entropy_detection():
    # File with 4KB zero/plaintext padding + 2KB packed random payload
    padding = b"A" * 4096
    packed = os.urandom(2048)
    combined = padding + packed

    analysis = EntropyAnalyzer.analyze_bytes(combined)
    assert analysis["overall_entropy"] < 7.3  # Overall diluted by padding
    assert analysis["has_embedded_high_entropy_payload"] is True
    assert analysis["high_entropy_blocks_count"] > 0
    assert analysis["verdict"] == "SUSPICIOUS_HIGH_ENTROPY"


def test_forensic_timeline_chronological_ordering_and_timestomping():
    jm = JobManager()
    file_bytes = b"Sample document payload"
    job = jm.create_job(file_bytes=file_bytes, raw_filename="forensic_evidence.docx")

    # Inverted timestamps: created 2026-10-01, modified earlier at 2026-09-01 (timestomping indicator)
    t_created = "2026-10-01T12:00:00Z"
    t_modified = "2026-09-01T12:00:00Z"

    meta = StructuredMetadata(
        general=[MetadataField(name="File Name", value="forensic_evidence.docx", category="file")],
        document=[
            MetadataField(name="Creation Date", value=t_created, category="document"),
            MetadataField(name="Mod Date", value=t_modified, category="document")
        ],
        location=[],
        camera=[],
        embedded=[]
    )
    job.metadata = meta

    job.email_info = {
        "subject": "Urgent Invoice",
        "headers": {
            "date": "Wed, 15 Sep 2026 10:00:00 +0000",
            "from": "accounting@company.com"
        },
        "transit_hops": [
            {
                "timestamp": "2026-09-15T10:01:00Z",
                "from": "mail.company.com",
                "by": "mx.gateway.com",
                "with": "ESMTPS",
                "delay_seconds": 60
            }
        ]
    }

    events = ForensicTimelineBuilder.generate_timeline(job)
    assert len(events) >= 4

    # Verify chronological ascending order
    epochs = [e["epoch"] for e in events]
    assert epochs == sorted(epochs)

    # Verify timestomping anomaly detected
    anomaly_events = [e for e in events if e.get("is_anomaly")]
    assert len(anomaly_events) >= 1
    assert "timestomp" in anomaly_events[0]["title"].lower()

    # Verify CSV export
    csv_out = ForensicTimelineBuilder.export_csv(events)
    assert "Timestamp (UTC)" in csv_out
    assert "TIMESTOMPING" in csv_out


def test_api_entropy_and_timeline_endpoints():
    client = TestClient(app)

    # Create and analyze a small test file
    content = b"PDF-1.4\n%test content\n" + bytes([i % 256 for i in range(512)])
    response = client.post(
        "/api/files",
        files=[("files", ("incident_sample.pdf", io.BytesIO(content), "application/pdf"))]
    )
    assert response.status_code == 200
    data = response.json()
    job_id = data["jobs"][0]["job_id"]

    # Test Entropy endpoint
    ent_resp = client.get(f"/api/jobs/{job_id}/entropy")
    assert ent_resp.status_code == 200
    ent_data = ent_resp.json()
    assert "overall_entropy" in ent_data
    assert "profile" in ent_data

    # Test Timeline endpoint
    tl_resp = client.get(f"/api/jobs/{job_id}/timeline")
    assert tl_resp.status_code == 200
    tl_data = tl_resp.json()
    assert "events" in tl_data
    assert tl_data["total_events"] > 0

    # Test Timeline CSV Export
    csv_resp = client.get(f"/api/jobs/{job_id}/timeline/export?format=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "Timestamp (UTC)" in csv_resp.text

    # Test Timeline JSON Export
    json_resp = client.get(f"/api/jobs/{job_id}/timeline/export?format=json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    parsed_json = json_resp.json()
    assert parsed_json["job_id"] == job_id
    assert "events" in parsed_json
