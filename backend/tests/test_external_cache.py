import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.core.settings_store import settings_store
from app.core.external_cache import external_api_cache, format_age_human
from app.network.shodan_client import ShodanClient
from app.network.threat_intelligence import ThreatIntelligenceAggregator
from app.core.job_manager import job_manager


client = TestClient(app)


def test_format_age_human():
    assert format_age_human(10) == "just now"
    assert format_age_human(120) == "2 minutes ago"
    assert format_age_human(3600) == "1 hour ago"
    assert format_age_human(7200) == "2 hours ago"
    assert format_age_human(86400) == "1 day ago"
    assert format_age_human(172800) == "2 days ago"


def test_external_cache_set_get_and_force_refresh():
    service = "test_svc"
    key = "example.com"
    data = {"status": "ok", "open_ports": [80, 443]}

    # Ensure clean slate
    external_api_cache.clear(service)

    # Initially not in cache
    res, info = external_api_cache.get(service, key)
    assert res is None
    assert info is None

    # Set in cache
    set_info = external_api_cache.set(service, key, data)
    assert set_info["cached"] is False
    assert set_info["age_human"] == "just now"

    # Get from cache (hit)
    cached_data, get_info = external_api_cache.get(service, key)
    assert cached_data is not None
    assert cached_data["status"] == "ok"
    assert cached_data["open_ports"] == [80, 443]
    assert get_info["cached"] is True
    assert cached_data["_cache_info"]["cached"] is True

    # Force refresh bypasses cache
    refreshed, ref_info = external_api_cache.get(service, key, force_refresh=True)
    assert refreshed is None
    assert ref_info is None

    # Cleanup
    external_api_cache.clear(service)


def test_external_cache_policy_always_fetch():
    service = "test_always_fetch"
    key = "target.net"
    data = {"result": 42}

    external_api_cache.set(service, key, data)

    # Normal mode -> Hit
    settings_store.set_cache_settings({"mode": "use_cache", "max_age_value": 24, "max_age_unit": "hours"})
    res, _ = external_api_cache.get(service, key)
    assert res is not None

    # Always fetch mode -> Miss
    settings_store.set_cache_settings({"mode": "always_fetch", "max_age_value": 24, "max_age_unit": "hours"})
    res2, _ = external_api_cache.get(service, key)
    assert res2 is None

    # Reset policy
    settings_store.set_cache_settings({"mode": "use_cache", "max_age_value": 24, "max_age_unit": "hours"})
    external_api_cache.clear(service)


def test_shodan_lookup_domain_multi_host_and_cloud():
    mock_search_resp = {
        "total": 2,
        "matches": [
            {
                "ip_str": "20.160.166.193",
                "port": 443,
                "transport": "tcp",
                "hostnames": ["www3.folksam.se"],
                "domains": ["folksam.se"],
                "asn": "AS8075",
                "org": "Microsoft Corporation",
                "isp": "Microsoft Corporation",
                "cloud": {"provider": "Azure", "region": "westeurope", "service": "AzureCloud"},
                "location": {"city": "Amsterdam", "country_name": "Netherlands", "country_code": "NL"},
                "data": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nSet-Cookie: JSESSIONID=123",
                "http": {"title": "Folksam AB", "dom_hash": -12345},
                "ssl": {"cert": {"subject": {"CN": "www3.folksam.se"}}},
                "vulns": ["CVE-2023-1234"]
            },
            {
                "ip_str": "193.183.162.44",
                "port": 80,
                "transport": "tcp",
                "hostnames": ["folksam.se"],
                "domains": ["folksam.se"],
                "asn": "AS42649",
                "org": "Folksam Omsesidig Sakforsakring",
                "isp": "bbn Baffin Bay Networks AB",
                "cloud": None,
                "location": {"city": "Stockholm", "country_name": "Sweden", "country_code": "SE"},
                "data": "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.folksam.se/",
                "http": {"title": "Redirect"},
                "ssl": None,
                "vulns": []
            }
        ]
    }

    mock_dns_resp = {
        "subdomains": ["api", "www3", "cloudservices"],
        "data": [
            {"subdomain": "api", "type": "A", "value": "193.183.162.228"}
        ]
    }

    with patch.object(ShodanClient, "get_api_key", return_value="dummy_key"):
        with patch("httpx.Client.get") as mock_get:
            def side_effect(url, **kwargs):
                resp = MagicMock()
                resp.status_code = 200
                if "/dns/domain/" in url:
                    resp.json.return_value = mock_dns_resp
                elif "/shodan/host/search" in url:
                    resp.json.return_value = mock_search_resp
                else:
                    resp.json.return_value = {}
                return resp

            mock_get.side_effect = side_effect

            res = ShodanClient.lookup_domain("folksam.se", force_refresh=True)

            assert res["configured"] is True
            assert res["queried"] is True
            assert res["total_hosts"] == 2
            assert "Azure (westeurope)" in res["cloud_providers"]
            assert 443 in res["ports"]
            assert 80 in res["ports"]
            assert "CVE-2023-1234" in res["vulns"]
            assert len(res["hosts"]) == 2
            assert res["hosts"][0]["ip"] == "20.160.166.193"
            assert res["hosts"][0]["cloud"]["provider"] == "Azure"
            assert "api.folksam.se" in res["subdomains"]
            assert res["_cache_info"]["cached"] is False


def test_refresh_job_intelligence_endpoint():
    # Create a domain job
    job = job_manager.create_job(b"<html>Folksam Target</html>", "folksam.se")
    job.category = "domain"
    job.domain_info = {
        "target": "folksam.se",
        "is_ip": False,
        "shodan": {"queried": False, "configured": True}
    }
    job_manager._save_job_to_disk(job)

    mock_shodan_result = {
        "configured": True,
        "queried": True,
        "target": "folksam.se",
        "total_hosts": 1,
        "ports": [443],
        "vulns": [],
        "hosts": [{"ip": "20.160.166.193", "port": 443, "hostnames": ["www3.folksam.se"]}],
        "_cache_info": {"cached": False, "age_human": "just now"}
    }

    with patch.object(ShodanClient, "lookup", return_value=mock_shodan_result):
        resp = client.post(
            f"/api/jobs/{job.job_id}/refresh-intelligence",
            json={"service": "shodan", "force_refresh": True}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "shodan" in data["updated_services"]
        assert data["domain_info"]["shodan"]["total_hosts"] == 1
        assert data["domain_info"]["shodan"]["hosts"][0]["ip"] == "20.160.166.193"
