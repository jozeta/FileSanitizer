import pytest
import socket
import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.network.input_normalizer import UniversalInputNormalizer, InputType, NormalizedIndicator
from app.network.advanced_dns import AdvancedDNSInspector
from app.network.tls_inspector import TLSInspector
from app.network.web_fingerprinter import WebFingerprinter, murmurhash3_32
from app.network.threat_intelligence import ThreatIntelligenceAggregator
from app.network.scoring_engine import MultiDimensionalRiskEngine
from app.network.active_recon import ActiveServiceScanner
from app.core.entity_graph_builder import EntityGraphBuilder


# ============================================================================
# 1. INPUT NORMALIZER & SSRF FORTRESS TESTS
# ============================================================================

def test_input_normalizer_fqdn_and_punycode():
    # Normal domain
    res = UniversalInputNormalizer.normalize("Example.COM.")
    assert res.normalized_value == "example.com"
    assert res.indicator_type == InputType.DOMAIN
    assert res.is_safe_destination

    # Punycode / IDNA
    res_idna = UniversalInputNormalizer.normalize("münchen.de")
    assert res_idna.indicator_type == InputType.DOMAIN
    homo = res_idna.details.get("homoglyph_analysis", {})
    assert "xn--" in homo.get("punycode", "")

    # Cyrillic homoglyph confusable (e.g. Cyrillic 'а' \u0430 replacing Latin 'a')
    confusable = "p\u0430ypal.com"
    res_conf = UniversalInputNormalizer.normalize(confusable)
    assert res_conf.indicator_type == InputType.DOMAIN
    conf_analysis = res_conf.details.get("homoglyph_analysis", {})
    assert conf_analysis.get("is_confusable") is True
    assert len(conf_analysis.get("spoofed_chars", {})) > 0


def test_input_normalizer_urls():
    url = "https://admin:pass@sub.example.co.uk:8443/login?redirect=true&token=secret_123#dashboard"
    res = UniversalInputNormalizer.normalize(url)
    assert res.indicator_type == InputType.URL
    assert res.details.get("canonical_hostname") == "sub.example.co.uk"
    assert res.details.get("port") == 8443
    assert res.details.get("has_credentials") is True
    assert res.details.get("root_domain") == "example.co.uk"
    assert res.details.get("query") == "redirect=true&token=secret_123"


def test_input_normalizer_ssrf_fortress():
    # Private IPv4 addresses
    assert not UniversalInputNormalizer.normalize("127.0.0.1").is_safe_destination
    assert not UniversalInputNormalizer.normalize("10.10.10.10").is_safe_destination
    assert not UniversalInputNormalizer.normalize("172.16.5.1").is_safe_destination
    assert not UniversalInputNormalizer.normalize("192.168.1.1").is_safe_destination
    assert not UniversalInputNormalizer.normalize("169.254.169.254").is_safe_destination  # AWS IMDS

    # Loopback & IPv6
    assert not UniversalInputNormalizer.normalize("localhost").is_safe_destination
    assert not UniversalInputNormalizer.normalize("http://[::1]/admin").is_safe_destination
    assert not UniversalInputNormalizer.normalize("http://127.0.0.1:8080/metrics").is_safe_destination

    # Public IP should be safe
    pub = UniversalInputNormalizer.normalize("8.8.8.8")
    assert pub.is_safe_destination
    assert pub.indicator_type == InputType.IPV4


def test_input_normalizer_hashes_asns_and_ips():
    # SHA-256 cert fingerprint
    fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    res_fp = UniversalInputNormalizer.normalize(fp)
    assert res_fp.indicator_type == InputType.CERT_FINGERPRINT
    assert res_fp.details.get("algo") == "SHA-256"

    # ASN
    res_asn = UniversalInputNormalizer.normalize("AS15169")
    assert res_asn.indicator_type == InputType.ASN
    assert res_asn.normalized_value == "AS15169"
    assert res_asn.details.get("asn_number") == 15169

    # Public IPv6
    res_ipv6 = UniversalInputNormalizer.normalize("2001:4860:4860::8888")
    assert res_ipv6.indicator_type == InputType.IPV6
    assert res_ipv6.is_safe_destination


# ============================================================================
# 2. ADVANCED DNS & DANGLING CNAME TAKEOVER TESTS
# ============================================================================

def test_dangling_cname_takeover_detection():
    mock_result = {
        "records": {"cname": ["my-bucket.s3.amazonaws.com"]},
        "heuristics": {"dangling_cnames": []},
        "anomalies": []
    }
    # Simulate unresolving CNAME target
    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        AdvancedDNSInspector._analyze_takeover_risks("assets.example.com", mock_result)

    assert len(mock_result["heuristics"]["dangling_cnames"]) == 1
    takeover = mock_result["heuristics"]["dangling_cnames"][0]
    assert takeover["provider"] == "Amazon S3"
    assert takeover["status"] == "UNRESOLVING_CNAME_TARGET"
    assert any(a["type"] == "SUBDOMAIN_TAKEOVER_RISK" for a in mock_result["anomalies"])


def test_advanced_dns_low_ttl_and_fast_flux():
    mock_result = {
        "records": {
            "a": ["1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"],
            "txt": ["v=spf1 +all"]
        },
        "ttls": {"a": 25},
        "heuristics": {"dangling_cnames": []},
        "anomalies": []
    }
    AdvancedDNSInspector._check_ttl_and_flux(mock_result)
    assert mock_result["heuristics"].get("fast_flux_suspect") is True
    assert any(a["type"] == "FAST_FLUX_INDICATOR" for a in mock_result["anomalies"])

    # Analyze SPF +all
    AdvancedDNSInspector._analyze_txt_spf(mock_result)
    assert mock_result["heuristics"].get("suspicious_spf") is True
    assert any(a["type"] == "PERMISSIVE_SPF" for a in mock_result["anomalies"])


# ============================================================================
# 3. TLS INSPECTOR TESTS
# ============================================================================

def test_tls_inspector_mock_handshake():
    mock_cert_info = {
        "subject": {"common_name": "vault.example.com", "organization": "Example Corp"},
        "issuer": {"common_name": "DigiCert Global Root G2", "organization": "DigiCert Inc"},
        "sans": ["vault.example.com", "api.example.com"],
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "days_remaining": 120,
        "is_expired": False,
        "is_self_signed": False,
        "sha256_fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
    }

    with patch.object(TLSInspector, "_perform_tls_handshake", return_value=mock_cert_info):
        with patch.object(TLSInspector, "_query_crt_sh", return_value={"total_certificates": 2, "logged_subdomains": ["api.example.com"]}):
            tls_data = TLSInspector.inspect("vault.example.com", 443, query_ct_logs=True)
            assert tls_data["has_tls"] is True
            assert tls_data["live_cert"]["subject"]["common_name"] == "vault.example.com"
            assert "api.example.com" in tls_data["live_cert"]["sans"]
            assert tls_data["ct_logs"]["total_certificates"] == 2


# ============================================================================
# 4. WEB FINGERPRINTER & SHODAN FAVICON TESTS
# ============================================================================

def test_web_fingerprinter_shodan_favicon_hash():
    # Pure Python MurmurHash3_x86_32 standard verification
    test_str = b"test"
    h = murmurhash3_32(test_str, 0)
    assert isinstance(h, int)

    # Test favicon hash generation
    dummy_favicon_bytes = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    shodan_hash = WebFingerprinter.compute_shodan_favicon_hash(dummy_favicon_bytes)
    assert shodan_hash is not None
    assert isinstance(shodan_hash, int)


def test_web_fingerprinter_security_header_grades():
    result_a = {"security_headers": {}, "findings": []}
    headers_a = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()"
    }
    WebFingerprinter._evaluate_security_headers(headers_a, result_a)
    assert result_a["security_headers"]["grade"] in ["A+", "A"]
    assert result_a["security_headers"]["score"] >= 80

    # Grade F: Missing security headers
    result_f = {"security_headers": {}, "findings": []}
    headers_f = {"server": "apache"}
    WebFingerprinter._evaluate_security_headers(headers_f, result_f)
    assert result_f["security_headers"]["grade"] == "F"
    assert len(result_f["security_headers"]["recommendations"]) >= 4
    assert any("Poor Web Security Header Compliance" in f["title"] for f in result_f["findings"])


def test_web_fingerprinter_dom_analysis_and_forms():
    html = b"""
    <!DOCTYPE html>
    <html>
      <head>
        <title>Corporate Login Portal</title>
        <script src="https://cdn.thirdparty.com/app.js"></script>
      </head>
      <body>
        <iframe src="https://embed.partner.org/frame"></iframe>
        <form action="/auth/login" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
        </form>
      </body>
    </html>
    """
    result = {"dom_analysis": {}, "findings": []}
    WebFingerprinter._analyze_html_dom(html, "https://portal.company.com", result)
    assert result["dom_analysis"]["title"] == "Corporate Login Portal"
    assert "cdn.thirdparty.com" in result["dom_analysis"]["external_scripts"]
    assert "embed.partner.org" in result["dom_analysis"]["external_iframes"]
    assert result["dom_analysis"]["has_login_form"] is True
    assert any("Interactive Login" in f["title"] for f in result["findings"])


# ============================================================================
# 5. THREAT INTELLIGENCE & ASN PROFILING TESTS
# ============================================================================

def test_threat_intelligence_asn_profiling():
    # Cloud Hyperscaler (e.g. AWS)
    aws_net = {"asn": "AS16509", "as_org": "Amazon.com, Inc.", "isp": "Amazon Data Services", "country": "US"}
    aws_prof = ThreatIntelligenceAggregator.profile_asn("3.5.140.2", aws_net)
    assert aws_prof["is_cloud_provider"] is True
    assert "Cloud Hyperscaler" in aws_prof["classification"]

    # Bulletproof / High-Risk Suspect
    bp_net = {"asn": "AS99999", "as_org": "FlokiNET Autonomous System", "isp": "FlokiNET", "country": "IS"}
    bp_prof = ThreatIntelligenceAggregator.profile_asn("185.165.169.1", bp_net)
    assert bp_prof["is_bulletproof_suspect"] is True
    assert bp_prof["risk_level"] == "high"

    # Residential ISP
    res_net = {"asn": "AS7922", "as_org": "Comcast Cable Communications, LLC", "isp": "Comcast Broadband", "country": "US"}
    res_prof = ThreatIntelligenceAggregator.profile_asn("73.1.2.3", res_net)
    assert "Residential" in res_prof["classification"]


# ============================================================================
# 6. MULTI-DIMENSIONAL SCORING ENGINE TESTS
# ============================================================================

def test_multi_dimensional_scoring_engine():
    # 1. Clean Corporate Asset
    clean_scores = MultiDimensionalRiskEngine.evaluate(
        target="clean.example.com",
        is_ip=False,
        normalizer_details={"homoglyph_analysis": {"is_confusable": False}},
        dns_data={"heuristics": {"fast_flux_suspect": False, "suspicious_spf": False, "dangling_cnames": []}},
        whois_data={"domain_age_days": 1500},
        tls_data={"live_cert": {"is_expired": False, "is_self_signed": False, "days_remaining": 200}},
        web_data={"security_headers": {"grade": "A+", "score": 95}, "dom_analysis": {"has_login_form": False}},
        cti_data={"verdict": "clean", "malicious_votes": 0, "feeds": {}},
        asn_profile={"is_bulletproof_suspect": False, "is_cloud_provider": True},
        active_scan=None
    )
    assert clean_scores["maliciousness"]["score"] == 0
    assert clean_scores["maliciousness"]["level"] == "clean"
    assert clean_scores["infrastructure_risk"]["score"] < 40
    assert clean_scores["overall_risk"]["level"] in ["clean", "low"]

    # 2. High-Risk Asset with Multiple Red Flags
    bad_scores = MultiDimensionalRiskEngine.evaluate(
        target="pаypal-verify.xyz",
        is_ip=False,
        normalizer_details={"homoglyph_analysis": {"is_confusable": True, "spoofed_chars": {"а": "a"}}},
        dns_data={"heuristics": {"fast_flux_suspect": True, "suspicious_spf": True, "dangling_cnames": [{"provider": "AWS"}]}},
        whois_data={"domain_age_days": 5},  # Newly registered domain
        tls_data={"live_cert": {"is_expired": True, "is_self_signed": True, "days_remaining": -10}},
        web_data={"security_headers": {"grade": "F", "score": 10}, "dom_analysis": {"has_login_form": True}},
        cti_data={"verdict": "malicious", "malicious_votes": 4, "feeds": {"urlhaus": {"verdict": "malicious"}}},
        asn_profile={"is_bulletproof_suspect": True, "is_cloud_provider": False},
        active_scan={"executed": True, "open_ports_count": 3}
    )
    assert bad_scores["maliciousness"]["score"] >= 75
    assert bad_scores["maliciousness"]["level"] in ["high", "critical"]
    assert bad_scores["infrastructure_risk"]["score"] >= 60
    assert bad_scores["exposure"]["score"] >= 40
    assert bad_scores["overall_risk"]["level"] in ["high", "critical"]


# ============================================================================
# 7. ACTIVE RECON SERVICE SCANNER TESTS
# ============================================================================

def test_active_recon_service_scanner_mocked():
    # Without authorization, scanner MUST refuse
    refused = ActiveServiceScanner.scan_services("93.184.216.34", authorized=False)
    assert refused["executed"] is False
    assert "explicit operator authorization" in refused["message"]

    # With authorization and mocked open socket
    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"

        # Mock SSRF validation to allow the public IP
        with patch("app.network.active_recon.validate_url_for_ssrf", return_value=(True, None, ["93.184.216.34"])):
            recon = ActiveServiceScanner.scan_services("93.184.216.34", authorized=True)
            assert recon["executed"] is True
            assert recon["open_ports_count"] > 0
            open_port_numbers = [s["port"] for s in recon["services"]]
            assert 22 in open_port_numbers


# ============================================================================
# 8. ENTITY GRAPH BUILDER TYPED INFRASTRUCTURE EDGES TESTS
# ============================================================================

def test_entity_graph_typed_infrastructure_edges():
    mock_job = MagicMock()
    mock_job.job_id = "test-job-intel"
    mock_job.filename = "nexus-threat.org"
    mock_job.original_filename = "nexus-threat.org"
    mock_job.risk = MagicMock()
    mock_job.risk.level = "HIGH"
    mock_job.hashes = {"sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}
    mock_job.category = "domain"
    mock_job.findings = []
    mock_job.anti_analysis = None
    mock_job.extracted_files = []
    mock_job.embedded_files = []
    mock_job.yara_matches = []

    mock_job.domain_info = {
        "target": "nexus-threat.org",
        "is_ip": False,
        "resolved_ips": ["198.51.100.42"],
        "dns_records": {
            "nameservers": ["ns1.bulletproof-dns.net"]
        },
        "whois": {
            "nameservers": ["ns1.bulletproof-dns.net"]
        },
        "tls_profile": {
            "live_cert": {
                "sha256_fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "issuer": {"common_name": "Let's Encrypt Authority X3"},
                "sans": ["nexus-threat.org", "api.nexus-threat.org"]
            }
        },
        "web_fingerprint": {
            "favicon": {
                "murmur_hash": -123456789,
                "shodan_query": "http.favicon.hash:-123456789"
            }
        },
        "attack_surface": {
            "subdomains": [
                {"subdomain": "api.nexus-threat.org", "resolves": True, "ips": ["198.51.100.43"]}
            ]
        }
    }

    graph = EntityGraphBuilder.build(mock_job)
    edges = graph.get("edges", [])
    edge_types = {e.get("label") for e in edges}

    assert "USES_NAMESERVER" in edge_types
    assert "CERT_INCLUDES_SAN" in edge_types
    assert "SHARES_FAVICON_HASH" in edge_types
    assert "SUBDOMAIN_OF" in edge_types


# ============================================================================
# 9. API INTEGRATION TESTS: IOC INVESTIGATION & ACTIVE RECON
# ============================================================================

def test_api_investigate_ioc_and_deduplication():
    client = TestClient(app)

    # 1. Investigate remote asset
    resp1 = client.post("/api/files/investigate-ioc", json={"ioc": "example.org", "ioc_type": "domain"})
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "job_id" in data1
    assert data1["target"] == "example.org"
    job_id = data1["job_id"]

    # 2. Investigating same asset again should deduplicate within workspace
    resp2 = client.post("/api/files/investigate-ioc", json={"ioc": "example.org", "ioc_type": "domain"})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["already_analyzed"] is True
    assert data2["job_id"] == job_id


def test_api_active_recon_endpoint():
    client = TestClient(app)

    # Create an investigation job
    resp = client.post("/api/files/investigate-ioc", json={"ioc": "1.1.1.1", "ioc_type": "ip"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    # Trigger active recon
    with patch("app.network.active_recon.ActiveServiceScanner.scan_services") as mock_scan, \
         patch("app.network.active_security_prober.ActiveSecurityProber.probe_all") as mock_probes:
        mock_scan.return_value = {
            "target": "1.1.1.1",
            "authorized": True,
            "executed": True,
            "open_ports_count": 1,
            "services": [{"port": 53, "service": "DNS", "protocol": "TCP", "banner": "Cloudflare DNS"}],
            "message": "Active reconnaissance completed."
        }
        mock_probes.return_value = {
            "target": "1.1.1.1",
            "authorized": True,
            "executed": True,
            "sensitive_files": {"tested": 9, "exposed": []},
            "waf_detection": {"detected": False},
            "cors_and_methods": {"tested": True, "dangerous_methods": [], "cors_misconfigured": False},
            "tls_cryptography": {"tested": True},
            "api_endpoints": {"tested": 10, "discovered": []},
            "smtp_relay_starttls": {"tested": False},
            "risk_flags": []
        }
        scan_resp = client.post(f"/api/jobs/{job_id}/active-recon", json={"authorized": True})
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["success"] is True
        assert scan_data["active_recon"]["open_ports_count"] == 1
        assert "risk_scores" in scan_data
        assert "active_security_probes" in scan_data


# ============================================================================
# 10. ADVANCED THREAT INTELLIGENCE & INFRASTRUCTURE RECON TESTS
# ============================================================================

def test_email_security_auditor_dmarc_and_spoofability():
    from app.network.email_security import EmailSecurityAuditor
    
    # Test DMARC parsing logic directly
    dmarc_dict = {
        "present": True,
        "policy": "none",
        "is_enforced": False,
        "aggregate_reports": []
    }
    EmailSecurityAuditor._parse_dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com", dmarc_dict)
    assert dmarc_dict["policy"] == "reject"
    assert dmarc_dict["is_enforced"] is True
    assert "dmarc@example.com" in dmarc_dict["aggregate_reports"]

    # Test spoofability evaluation
    res = {
        "domain": "secure-corp.com",
        "dmarc": dmarc_dict,
        "dkim": {"selectors_found": [{"selector": "google"}]},
        "bimi": {"present": True},
        "spoofability": {}
    }
    EmailSecurityAuditor._evaluate_spoofability(res)
    assert res["spoofability"]["status"] == "SECURED"
    assert res["spoofability"]["risk_score"] < 20


def test_web_archive_dormant_revival():
    from app.network.web_archive import WebArchiveInspector
    
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # CDX rows: headers + rows
        mock_resp.json.return_value = [
            ["timestamp", "original", "mimetype", "statuscode", "digest", "length"],
            ["20150101120000", "old-domain.com", "text/html", "200", "DIGEST1", "1234"],
            ["20150601120000", "old-domain.com", "text/html", "200", "DIGEST2", "1234"],
            ["20251010120000", "old-domain.com", "text/html", "200", "DIGEST3", "1234"]
        ]
        mock_get.return_value = mock_resp

        res = WebArchiveInspector.inspect("old-domain.com")
        assert res["archived"] is True
        assert res["snapshot_count"] == 3
        assert res["dormant_revival_detected"] is True
        assert any(rf["id"] == "DORMANT_DOMAIN_REVIVAL" for rf in res["risk_flags"])


def test_bgp_routing_and_rpki():
    from app.network.bgp_routing import BgpRoutingInspector

    with patch("httpx.Client.get") as mock_get:
        def side_effect(url, params=None):
            resp = MagicMock()
            resp.status_code = 200
            if "rpki-validation" in url:
                resp.json.return_value = {"data": {"status": "valid"}}
            elif "prefix-overview" in url:
                resp.json.return_value = {"data": {"resource": "1.1.1.0/24", "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}]}}
            else:
                resp.json.return_value = {"data": {"visibility": {"v4": {"ratio": 0.99}}}}
            return resp

        mock_get.side_effect = side_effect
        res = BgpRoutingInspector.inspect("1.1.1.1", "AS13335")
        assert res["is_anycast"] is True
        assert "Cloudflare" in res["anycast_provider"]
        assert res["rpki_status"] == "valid"
        assert res["is_rpki_valid"] is True


def test_passive_dns_client():
    from app.network.passive_dns import PassiveDnsClient

    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "passive_dns": [
                {"hostname": "sub.target.com", "address": "198.51.100.1", "record_type": "A", "first": "2023-01-01", "last": "2024-01-01"},
                {"hostname": "target.com", "address": "198.51.100.2", "record_type": "A", "first": "2022-01-01", "last": "2024-01-01"}
            ]
        }
        mock_get.return_value = mock_resp

        res = PassiveDnsClient.query_pdns("target.com")
        assert res["total_records"] == 2
        assert "sub.target.com" in res["discovered_domains"]
        assert "198.51.100.1" in res["discovered_ips"]


def test_leak_exposure_searcher():
    from app.network.leak_search import LeakExposureSearcher

    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {"id": "paste_xyz123", "time": "2024-05-01", "tags": ["db_dump", "credentials"]}
            ]
        }
        mock_get.return_value = mock_resp

        res = LeakExposureSearcher.search_leaks("compromised-corp.com")
        assert res["has_leaks"] is True
        assert res["leak_count"] == 1
        assert res["severity"] == "MEDIUM"


def test_active_security_prober_opt_in():
    from app.network.active_security_prober import ActiveSecurityProber

    # When authorized=False, should NOT execute
    unauth = ActiveSecurityProber.probe_all("example.com", authorized=False)
    assert unauth["executed"] is False
    assert "explicit operator authorization" in unauth["message"]

    # When authorized=True with mocked SSRF validation & mock HTTP
    with patch("app.network.active_security_prober.validate_url_for_ssrf", return_value=(True, "", ["93.184.216.34"])):
        with patch("httpx.Client.get") as mock_get, patch("httpx.Client.options") as mock_opt:
            def mock_get_impl(url, headers=None):
                resp = MagicMock()
                if "/.git/HEAD" in url:
                    resp.status_code = 200
                    resp.text = "ref: refs/heads/master\n"
                    resp.content = b"ref: refs/heads/master\n"
                elif "evil-attacker.com" in (headers or {}).get("Origin", ""):
                    resp.status_code = 200
                    resp.headers = {
                        "access-control-allow-origin": "https://evil-attacker.com",
                        "access-control-allow-credentials": "true"
                    }
                else:
                    resp.status_code = 404
                    resp.text = "Not found"
                    resp.content = b"Not found"
                    resp.headers = {}
                return resp

            mock_get.side_effect = mock_get_impl

            opt_resp = MagicMock()
            opt_resp.headers = {"allow": "GET, POST, OPTIONS, DELETE"}
            mock_opt.return_value = opt_resp

            auth = ActiveSecurityProber.probe_all("example.com", authorized=True)
            assert auth["executed"] is True
            # Should have flagged exposed git
            exposed = auth["sensitive_files"]["exposed"]
            assert any(e["path"] == "/.git/HEAD" for e in exposed)
            # Dangerous HTTP methods and CORS credentials misconfiguration
            assert "DELETE" in auth["cors_and_methods"]["dangerous_methods"]
            assert auth["cors_and_methods"]["cors_misconfigured"] is True


def test_restored_domain_relation_discovery_with_pdns():
    from app.analyzers.domain_relations import DomainRelationDiscovery
    from app.network.passive_dns import PassiveDnsClient

    # Test that DomainRelationDiscovery ingests pdns_domains and adds them as relations
    with patch("app.core.settings_store.settings_store.is_external_allowed", return_value=True):
        rel = DomainRelationDiscovery.discover(
            target="target-brand.com",
            is_ip=False,
            resolved_ips=["93.184.216.34"],
            dns_data={"a": ["93.184.216.34"], "txt": ["v=spf1 include:partner-auth.com ~all"]},
            whois_data={"registrant_org": "Target Brand International"},
            net_info={"asn": "AS15133", "as_org": "EdgeCast Inc", "cidrs": ["93.184.216.0/24"]},
            co_hosted_primary=["co-located-host.com"],
            primary_ip="93.184.216.34",
            budget_s=1.0,
            pdns_domains=["historic-portal.target-brand.org", "legacy-api.net"]
        )

        assert "related_domains" in rel
        related = rel["related_domains"]
        related_names = [r["domain"] for r in related]
        assert "partner-auth.com" in related_names  # from SPF
        assert "co-located-host.com" in related_names  # from same IP
        assert "legacy-api.net" in related_names  # from Passive DNS!


# ============================================================================
# 8. TESTS FOR EXTENDED FEATURES (FEATURES 1, 2, 3, 4, 5, 6, 7, 9)
# ============================================================================

def test_passive_web_exposure_inspector():
    from app.network.web_exposure import WebExposureInspector
    with patch("httpx.Client.get") as mock_get, \
         patch("app.network.web_exposure.validate_url_for_ssrf", return_value=(True, "", "93.184.216.34")):
        def mock_get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "robots.txt" in url:
                resp.status_code = 200
                resp.headers = {"content-type": "text/plain"}
                resp.text = "User-agent: *\nDisallow: /admin\nDisallow: /staging-api\nSitemap: https://target.com/sitemap.xml"
            elif "sitemap.xml" in url:
                resp.status_code = 200
                resp.headers = {"content-type": "application/xml"}
                resp.content = b'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://target.com/home</loc></url><url><loc>https://target.com/secret-docs</loc></url></urlset>'
            elif "security.txt" in url:
                resp.status_code = 200
                resp.headers = {"content-type": "text/plain"}
                resp.text = "Contact: mailto:security@target.com\nExpires: 2027-01-01T00:00:00.000Z"
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = ""
                resp.content = b""
            return resp

        mock_get.side_effect = mock_get_side_effect
        exp = WebExposureInspector.inspect("target.com")
        assert exp["robots_txt"]["present"] is True
        assert "/admin" in exp["robots_txt"]["disallow_paths"]
        assert len(exp["robots_txt"]["sensitive_paths_flagged"]) >= 1
        assert exp["sitemap_xml"]["present"] is True
        assert exp["well_known"]["security_txt"]["present"] is True
        assert "mailto:security@target.com" in exp["well_known"]["security_txt"]["contacts"]


def test_vulnerability_intel_cisa_kev():
    from app.network.vulnerability_intel import VulnerabilityCorrelator
    # Test with Apache 2.4.49 (Known CISA KEV CVE-2021-41773)
    mock_fingerprint = {
        "server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1e",
        "headers": {"server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1e"},
        "technologies": ["Apache HTTP Server"]
    }
    intel = VulnerabilityCorrelator.correlate(web_fingerprint=mock_fingerprint)
    assert intel["tested"] is True
    assert intel["total_vulnerabilities"] >= 2  # Apache CVE-2021-41773 and OpenSSL Heartbleed
    assert intel["cisa_kev_count"] >= 2
    assert intel["has_critical_kev"] is True
    cves = [f["cve"] for f in intel["findings"]]
    assert "CVE-2021-41773" in cves
    assert "CVE-2014-0160" in cves


def test_reverse_infrastructure_pivoter():
    from app.network.reverse_infrastructure import ReverseInfrastructurePivoter
    with patch("httpx.Client.get") as mock_get:
        def mock_get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "findshareddns" in url:
                resp.status_code = 200
                resp.text = "sibling-corp.com\naffiliate-brand.org\npartner-portal.net"
            elif "findsharedmx" in url:
                resp.status_code = 200
                resp.text = "mail-sibling.com"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        mock_get.side_effect = mock_get_side_effect
        rev = ReverseInfrastructurePivoter.pivot(
            target_domain="primary-corp.com",
            nameservers=["ns1.private-dns-server.com"],
            mx_hosts=["mx1.private-mail-server.com"]
        )
        assert rev["tested"] is True
        assert "sibling-corp.com" in rev["discovered_siblings"]
        assert "mail-sibling.com" in rev["discovered_siblings"]
        assert rev["total_siblings_discovered"] >= 3


def test_batch_ioc_enrichment_api():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.job_manager import job_manager

    # Create dummy job
    test_job = job_manager.create_job(b"dummy_pcap_data", "ioc_test_capture.pcap")
    client = TestClient(app)

    with patch("socket.getaddrinfo") as mock_gai, \
         patch("app.analyzers.domain_analyzer.DomainAnalyzer.query_reverse_ip_and_asn") as mock_rev:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))
        ]
        mock_rev.return_value = (["example.com"], {"asn": "AS15133", "org": "Edgecast Inc", "country": "US"})

        resp = client.post(
            f"/api/jobs/{test_job.job_id}/enrich-iocs",
            json={"iocs": ["93.184.216.34", "example.com"]}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == test_job.job_id
        assert len(data["enriched"]) == 2
        ip_entry = next(e for e in data["enriched"] if e["indicator"] == "93.184.216.34")
        assert ip_entry["is_ip"] is True
        assert ip_entry["asn"] == "AS15133"
        dom_entry = next(e for e in data["enriched"] if e["indicator"] == "example.com")
        assert dom_entry["is_ip"] is False
        assert "93.184.216.34" in dom_entry["resolved_ips"]


def test_forward_confirmed_reverse_dns_fcrdns():
    from app.network.advanced_dns import AdvancedDNSInspector
    with patch.object(AdvancedDNSInspector, "_resolve_ptr", return_value=["mail.validhost.org"]), \
         patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 0))]):
        res_valid = AdvancedDNSInspector.verify_fcrdns("1.2.3.4")
        assert res_valid["is_fcrdns_valid"] is True
        assert res_valid["status"] == "VALID"

    with patch.object(AdvancedDNSInspector, "_resolve_ptr", return_value=["spoofed.otherhost.org"]), \
         patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('9.9.9.9', 0))]):
        res_mismatch = AdvancedDNSInspector.verify_fcrdns("1.2.3.4")
        assert res_mismatch["is_fcrdns_valid"] is False
        assert res_mismatch["status"] == "MISMATCH"


def test_typosquatting_lookalike_generator():
    from app.network.typosquat_generator import TyposquattingGenerator
    with patch("socket.gethostbyname") as mock_ghbn:
        # Mock that one lookalike resolves
        def ghbn_impl(host):
            if "paypal" in host:
                return "192.0.2.1"
            raise socket.gaierror("Name or service not known")
        mock_ghbn.side_effect = ghbn_impl

        res = TyposquattingGenerator.analyze("paypal.com", max_check=10)
        assert res["tested"] is True
        assert len(res["lookalikes"]) > 0
        assert res["total_generated"] > 0
        techniques = [l["technique"].lower() for l in res["lookalikes"]]
        assert any("omission" in t or "transposition" in t or "homoglyph" in t or "replacement" in t or "adjacent" in t for t in techniques)


def test_reverse_tracking_identifier_pivoter():
    from app.network.tracking_pivots import TrackingIdentifierPivoter
    with patch("httpx.Client.get") as mock_get:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "sister-shop.com\nbrand-network.com"
        mock_get.return_value = resp

        html = """
        <html>
        <head>
          <!-- Google tag (gtag.js) -->
          <script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>
          <script>
            window.dataLayer = window.dataLayer || [];
            gtag('config', 'G-ABC1234567');
          </script>
        </head>
        <body>Adsense: pub-9876543210123456</body>
        </html>
        """
        pivots = TrackingIdentifierPivoter.extract_and_pivot("source-shop.com", html_content=html)
        assert pivots["tested"] is True
        assert pivots["total_identifiers"] >= 2
        idents = [i["identifier"] for i in pivots["tracking_identifiers"]]
        assert "G-ABC1234567" in idents
        assert "pub-9876543210123456" in idents
        assert "sister-shop.com" in pivots["related_domains_from_analytics"]


def test_investigation_snapshot_differ():
    from app.network.snapshot_differ import InvestigationSnapshotDiffer
    # Baseline comparison (no previous)
    base = InvestigationSnapshotDiffer.compare({"resolved_ips": ["1.1.1.1"]})
    assert base["has_historical_baseline"] is False

    # Second comparison with changes
    prev = {
        "resolved_ips": ["1.1.1.1"],
        "dns_records": {"ns": ["ns1.old.com"], "a": ["1.1.1.1"]},
        "tls_profile": {"live_cert": {"fingerprint_sha256": "OLD_CERT_FP"}},
        "attack_surface": {"subdomains": [{"subdomain": "www.test.com"}]},
        "risk_scores": {"maliciousness": {"score": 20}}
    }
    curr = {
        "resolved_ips": ["2.2.2.2"],
        "dns_records": {"ns": ["ns1.new.com"], "a": ["2.2.2.2"]},
        "tls_profile": {"live_cert": {"fingerprint_sha256": "NEW_CERT_FP"}},
        "attack_surface": {"subdomains": [{"subdomain": "www.test.com"}, {"subdomain": "staging.test.com"}]},
        "risk_scores": {"maliciousness": {"score": 75}}
    }
    diff = InvestigationSnapshotDiffer.compare(curr, previous_data=prev, previous_job_id="job-123", previous_timestamp="2026-10-01T00:00:00Z")
    assert diff["has_historical_baseline"] is True
    assert diff["baseline_job_id"] == "job-123"
    assert diff["delta_summary"]["ip_changed"] is True
    assert diff["delta_summary"]["cert_changed"] is True
    assert diff["delta_summary"]["ns_changed"] is True
    assert diff["delta_summary"]["new_subdomains_count"] == 1
    event_types = [e["type"] for e in diff["timeline_events"]]
    assert "IP_MIGRATION" in event_types
    assert "CERTIFICATE_RENEWAL" in event_types
    assert "NAMESERVER_CHANGE" in event_types
    assert "NEW_SUBDOMAINS_DISCOVERED" in event_types
    assert "RISK_POSTURE_CHANGE" in event_types


def test_web_archive_inspector_availability():
    from app.network.web_archive import WebArchiveInspector
    # Test dual-target www/apex inspection logic and availability parser
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "archived_snapshots": {
            "closest": {
                "available": True,
                "url": "http://web.archive.org/web/20261011095858/https://www.folksam.se/",
                "timestamp": "20261011095858",
                "status": "200"
            }
        }
    }
    with patch("httpx.Client.get", return_value=mock_resp):
        res = WebArchiveInspector.inspect("folksam.se")
        assert res["archived"] is True
        assert res["snapshot_count"] >= 1
        assert "folksam.se" in res["wayback_calendar_url"]
        assert len(res["recent_snapshots"]) >= 1
        assert res["recent_snapshots"][0]["status_code"] == "200"


def test_domain_relations_direct_vs_shared():
    from app.analyzers.domain_relations import DomainRelationDiscovery
    # Test that SAN / cryptographic siblings are direct_affiliates and multi-tenant IPs are shared_infrastructure_neighbors
    rel = DomainRelationDiscovery.discover(
        target="folksam.se",
        is_ip=False,
        resolved_ips=["150.171.109.194"],
        dns_data={"ns": ["ns1.ports.se"], "a": ["150.171.109.194"]},
        whois_data={"org": "Folksam Omsesidig Livforsakring"},
        net_info={"org": "Baffin Bay Networks AB", "isp": "Microsoft Azure"},
        co_hosted_primary=["unrelated-shop.se", "thirdparty-blog.nu"],
        primary_ip="150.171.109.194",
        sibling_domains=["kpa.se", "folksamlopension.se"],
        budget_s=5.0
    )
    assert "direct_affiliates" in rel
    assert "shared_infrastructure_neighbors" in rel
    # Cryptographic siblings from sibling_domains should be in direct_affiliates
    direct_names = [d["domain"] for d in rel["direct_affiliates"]]
    assert "kpa.se" in direct_names or "folksamlopension.se" in direct_names
    # Co-hosted domains on shared DDoS/Cloud IP should be in shared_infrastructure_neighbors
    shared_names = [s["domain"] for s in rel["shared_infrastructure_neighbors"]]
    assert "unrelated-shop.se" in shared_names or "thirdparty-blog.nu" in shared_names
    # Direct affiliates should be marked with connection_type == "direct"
    for d in rel["direct_affiliates"]:
        assert d.get("connection_type") == "direct"
        assert d.get("is_direct") is True



