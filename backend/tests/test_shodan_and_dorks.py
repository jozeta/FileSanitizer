"""
Unit tests for Shodan Threat Intelligence API Integration and
Automated Google Dorks & Sensitive Artifact Scanner.
"""

from unittest.mock import patch, MagicMock
import pytest
from app.network.shodan_client import ShodanClient
from app.network.dork_scanner import DorkArtifactScanner
from app.analyzers.domain_analyzer import DomainAnalyzer


def test_shodan_generate_web_links():
    res_ip = ShodanClient.lookup_ip("1.1.1.1")
    assert res_ip["target"] == "1.1.1.1"
    assert res_ip["is_ip"] is True
    assert res_ip["web_link"] == "https://www.shodan.io/host/1.1.1.1"

    res_dom = ShodanClient.lookup_domain("acme.corp")
    assert res_dom["target"] == "acme.corp"
    assert res_dom["is_ip"] is False
    assert "acme.corp" in res_dom["web_link"]


def test_shodan_verify_key_mock():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "plan": "oss",
        "query_credits": 100,
        "scan_credits": 50
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        valid, msg = ShodanClient.verify_key("test_valid_key")
        assert valid is True
        assert "OSS" in msg
        assert "100" in msg


def test_shodan_lookup_ip_mocked_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ports": [22, 80, 443],
        "hostnames": ["mail.victim.com"],
        "os": "Linux 5.4",
        "isp": "Cloudflare, Inc.",
        "org": "Cloudflare",
        "asn": "AS13335",
        "vulns": ["CVE-2021-41773", "CVE-2021-42013"],
        "tags": ["cloud", "vpn"],
        "data": [
            {"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.49", "data": "HTTP/1.1 200 OK"}
        ]
    }

    with patch.object(ShodanClient, "get_api_key", return_value="mock_key"):
        with patch("httpx.Client.get", return_value=mock_resp):
            res = ShodanClient.lookup_ip("198.51.100.25")
            assert res["configured"] is True
            assert res["queried"] is True
            assert res["ports"] == [22, 80, 443]
            assert "CVE-2021-41773" in res["vulns"]
            assert len(res["services"]) == 1
            assert res["services"][0]["product"] == "Apache httpd"


def test_dork_presets_generation():
    presets = DorkArtifactScanner.generate_dork_presets("target-corp.com")
    assert len(presets) >= 6
    preset_ids = [p["id"] for p in presets]
    assert "dork_documents" in preset_ids
    assert "dork_secrets" in preset_ids
    assert "dork_backups" in preset_ids
    assert "dork_logs" in preset_ids

    doc_preset = next(p for p in presets if p["id"] == "dork_documents")
    assert "site:target-corp.com" in doc_preset["query"]
    assert "filetype:pdf" in doc_preset["query"]
    assert "google.com/search" in doc_preset["google_url"]


def test_dork_scanner_artifact_classification():
    ext_pdf, sev_pdf, label_pdf = DorkArtifactScanner._classify_extension(".pdf", "https://corp.com/annual_report.pdf", "Financial Report 2026")
    assert ext_pdf == "document"
    assert sev_pdf == "low"

    ext_conf, sev_conf, label_conf = DorkArtifactScanner._classify_extension(".pdf", "https://corp.com/exec_salary.pdf", "strictly confidential salary sheet")
    assert ext_conf == "document"
    assert sev_conf == "high"

    ext_env, sev_env, label_env = DorkArtifactScanner._classify_extension(".env", "https://corp.com/.env", "DB_PASSWORD=secret")
    assert ext_env == "secret"
    assert sev_env == "critical"

    ext_sql, sev_sql, label_sql = DorkArtifactScanner._classify_extension(".sql", "https://corp.com/backup_2026.sql", "mysqldump table")
    assert ext_sql == "database"
    assert sev_sql == "critical"


def test_dork_scanner_mocked_results():
    mock_artifacts = [
        {
            "url": "https://corp.com/docs/budget_confidential.pdf",
            "filename": "budget_confidential.pdf",
            "extension": ".pdf",
            "title": "Confidential Budget 2026",
            "category": "document",
            "category_label": "Confidential / Internal Document",
            "severity": "high",
            "source": "Search Dork Engine",
            "snippet": "internal use only confidential board meeting"
        },
        {
            "url": "https://corp.com/.env",
            "filename": ".env",
            "extension": ".env",
            "title": "Exposed .env Configuration",
            "category": "secret",
            "category_label": "Credentials & Configuration Secret",
            "severity": "critical",
            "source": "Direct Path Exposure Audit",
            "snippet": "APP_KEY=base64:xyz DB_PASSWORD=admin"
        }
    ]

    with patch.object(DorkArtifactScanner, "_probe_common_sensitive_paths", side_effect=lambda t, arts, s: arts.extend(mock_artifacts)):
        with patch.object(DorkArtifactScanner, "_extract_from_sitemaps_and_robots"):
            with patch.object(DorkArtifactScanner, "_query_search_dorks"):
                res = DorkArtifactScanner.scan("corp.com")
                assert res["total_artifacts_found"] == 2
                assert res["category_counts"]["documents"] == 1
                assert res["category_counts"]["secrets"] == 1
                assert res["severity_counts"]["critical"] == 1
                assert res["severity_counts"]["high"] == 1
                assert len(res["artifacts"]) == 2


def test_domain_analyzer_includes_shodan_and_dorks():
    with patch.object(ShodanClient, "lookup", return_value={"configured": False, "queried": False, "target": "example.com", "web_link": "https://www.shodan.io/host/example.com"}):
        with patch.object(DorkArtifactScanner, "scan", return_value={"scanned": True, "target": "example.com", "total_artifacts_found": 0, "artifacts": [], "dork_presets": []}):
            res = DomainAnalyzer.analyze("example.com")
            assert "shodan" in res
            assert "dork_findings" in res
            assert res["shodan"]["target"] == "example.com"
            assert res["dork_findings"]["scanned"] is True
