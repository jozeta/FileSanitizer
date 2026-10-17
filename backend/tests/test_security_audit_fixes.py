import pytest
import os
import re
import socket
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.core.settings_store import settings_store, create_admin_token, verify_admin_token
from app.analyzers.identification import detect_file_type
from app.analyzers.ip_domain_forensics import _execute_cli_tool, _is_safe_indicator
from app.network.tls_inspector import TLSInspector
from app.analyzers.reputation_client import HybridAnalysisClient

client = TestClient(app)

def test_fs_sec_001_command_injection_rejected():
    """Verify that malicious targets with shell metacharacters are rejected immediately."""
    malicious_targets = [
        "example.com; id; #",
        "$(whoami).evil.com",
        "`cat /etc/passwd`",
        "example.com\nrm -rf /",
        "test.com && touch /tmp/pwned",
        "target.com | bash"
    ]
    tool_info = {
        "name": "dig",
        "tool": "dig (DNS Resolution)",
        "category": "DNS",
        "purpose": "Query records",
        "description": "DNS query",
        "command": "dig target A"
    }
    for target in malicious_targets:
        assert _is_safe_indicator(target) is False
        res = _execute_cli_tool(tool_info, target, is_ip=False, primary_ip=None)
        assert res["executed"] is False
        assert res["exit_code"] == 1
        assert "rejected" in res["status"].lower()


def test_fs_sec_001_no_shell_true_in_ip_domain_forensics():
    """Verify statically that shell=True is completely eliminated from ip_domain_forensics.py."""
    code_path = Path(__file__).resolve().parent.parent / "app" / "analyzers" / "ip_domain_forensics.py"
    content = code_path.read_text(encoding="utf-8")
    assert "shell=True" not in content, "Found shell=True in ip_domain_forensics.py - must be eliminated"


def test_fs_sec_002_admin_forged_token_rejected_in_prod(monkeypatch):
    """Verify that tokens forged with known public defaults are rejected in production."""
    import jwt, time
    insecure_public_default = "filesanitizer-jwt-secret-key-32byte-minimum-secure-2026"

    # Mint token offline using the public default string
    forged_token = jwt.encode({
        "sub": "admin",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }, insecure_public_default, algorithm="HS256")

    # In production with a validated secret, the forged token must fail decoding
    with patch.object(settings, "ADMIN_SECRET_KEY", "a-different-secure-random-key-64bytes-long-super-secret"):
        decoded = verify_admin_token(forged_token)
        assert decoded is None


def test_fs_sec_003_unauthenticated_file_listing_401():
    """Verify that GET /api/files strictly requires admin authentication (prevents global enumeration)."""
    # 1. Unauthenticated request must return 401
    res_unauth = client.get("/api/files")
    assert res_unauth.status_code == 401
    assert "Admin authentication required" in res_unauth.json().get("detail", "")

    # 2. Authenticated admin request succeeds
    admin_token = create_admin_token("admin")
    res_auth = client.get("/api/files", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_auth.status_code == 200
    assert isinstance(res_auth.json(), list)


def test_fs_sec_004_cors_untrusted_origin_rejected():
    """Verify that untrusted foreign origins do not receive reflected Access-Control-Allow-Origin."""
    evil_origin = "https://malicious-attacker-site.com"
    res = client.options("/api/files", headers={
        "Origin": evil_origin,
        "Access-Control-Request-Method": "GET"
    })
    # Untrusted origin should NOT have Access-Control-Allow-Origin matching evil origin
    acao = res.headers.get("access-control-allow-origin")
    assert acao != evil_origin


def test_fs_sec_005_tls_inspector_ssrf_blocked():
    """Verify that TLS inspection rejects internal, loopback, and metadata IP ranges."""
    blocked_hosts = [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.50",
        "localhost"
    ]
    for host in blocked_hosts:
        is_safe, ip = TLSInspector._is_safe_host(host, 443)
        assert is_safe is False, f"Host {host} should be blocked by SSRF check"
        handshake = TLSInspector._perform_tls_handshake(host, 443)
        assert handshake is None


def test_fs_det_001_email_with_html_not_misclassified(tmp_path: Path):
    """Verify that an email starting with <html> or inline <svg> is classified as email, not html/svg."""
    # Email with leading HTML in first 512 bytes
    email_content = (
        b"From: billing@trusted.com\r\n"
        b"To: user@target.org\r\n"
        b"Subject: Invoice Notification\r\n"
        b"\r\n"
        b"<html><body><svg width='10' height='10'></svg><p>Please find attached invoice.</p></body></html>"
    )
    test_eml = tmp_path / "invoice_alert.eml"
    test_eml.write_bytes(email_content)

    detected_mime, category, desc = detect_file_type(test_eml, "invoice_alert.eml")
    assert category == "email", f"Expected 'email', got '{category}'"
    assert detected_mime == "message/rfc822"


def test_fs_det_002_hybrid_analysis_tags_filtered():
    """Verify that freeform tags are excluded from mitre_attck and placed in tags."""
    ha = HybridAnalysisClient()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "verdict": "malicious",
        "threat_score": 95,
        "vx_family": "AgentTesla",
        "environment_description": "Windows 10",
        "multiscan_result": 45,
        "mitre_attcks": [
            {"attck_id": "T1059.001"},
            "T1566",
            "invalid_non_attck_tag",
            "viruscheck"
        ],
        "tags": [
            "eicar",
            "scan",
            "trojan"
        ]
    }

    with patch("httpx.Client.get", return_value=mock_response), \
         patch.object(settings_store, "get_api_key", return_value="fake_ha_key"):
        res = ha.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res is not None
        assert "T1059.001" in res["mitre_attck"]
        assert "T1566" in res["mitre_attck"]
        # Free-form tags MUST NOT be in mitre_attck
        assert "invalid_non_attck_tag" not in res["mitre_attck"]
        assert "viruscheck" not in res["mitre_attck"]
        assert "eicar" not in res["mitre_attck"]
        # They should be in tags
        assert "eicar" in res["tags"]
        assert "scan" in res["tags"]
