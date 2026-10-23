import pytest
from unittest.mock import patch, MagicMock
import subprocess

from app.network.subfinder_dnsx import SubfinderDnsxScanner
from app.network.subdomain_mapper import SubdomainMapper
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.core.entity_graph_builder import EntityGraphBuilder


# ============================================================================
# 1. TARGET CLEANING & SANITIZATION TESTS
# ============================================================================

def test_clean_domain_target_valid_domains():
    assert SubfinderDnsxScanner.clean_domain_target("example.com") == "example.com"
    assert SubfinderDnsxScanner.clean_domain_target("Sub.Test-Domain.co.uk") == "sub.test-domain.co.uk"
    assert SubfinderDnsxScanner.clean_domain_target("  FOO.BAR.ORG. ") == "foo.bar.org"
    assert SubfinderDnsxScanner.clean_domain_target("sub-1.sub-2.domain.org") == "sub-1.sub-2.domain.org"


def test_clean_domain_target_urls():
    assert SubfinderDnsxScanner.clean_domain_target("https://api.github.com/v1/repos") == "api.github.com"
    assert SubfinderDnsxScanner.clean_domain_target("http://admin:secret@test.example.com:8443/path?query=1") == "test.example.com"
    assert SubfinderDnsxScanner.clean_domain_target("//cdn.cloudflare.net/static/bundle.js") == "cdn.cloudflare.net"
    assert SubfinderDnsxScanner.clean_domain_target("portal.company.com:8080/dashboard") == "portal.company.com"


def test_clean_domain_target_rejections():
    # IP addresses should be rejected (subfinder is for domains)
    assert SubfinderDnsxScanner.clean_domain_target("127.0.0.1") is None
    assert SubfinderDnsxScanner.clean_domain_target("192.168.1.1") is None
    assert SubfinderDnsxScanner.clean_domain_target("10.0.0.1") is None
    assert SubfinderDnsxScanner.clean_domain_target("::1") is None
    assert SubfinderDnsxScanner.clean_domain_target("2001:db8::1") is None

    # Empty, localhost, invalid inputs
    assert SubfinderDnsxScanner.clean_domain_target("") is None
    assert SubfinderDnsxScanner.clean_domain_target("   ") is None
    assert SubfinderDnsxScanner.clean_domain_target(None) is None
    assert SubfinderDnsxScanner.clean_domain_target("localhost") is None
    assert SubfinderDnsxScanner.clean_domain_target("notadomain") is None

    # Injection attempts
    assert SubfinderDnsxScanner.clean_domain_target("example.com; rm -rf /") is None
    assert SubfinderDnsxScanner.clean_domain_target("example.com | ls") is None
    assert SubfinderDnsxScanner.clean_domain_target("example.com && whoami") is None
    assert SubfinderDnsxScanner.clean_domain_target("`id`.example.com") is None
    assert SubfinderDnsxScanner.clean_domain_target("$(id).example.com") is None


# ============================================================================
# 2. OUTPUT PARSING TESTS (ANSI COLOR CODES, MULTI-IPS, DEDUPLICATION)
# ============================================================================

def test_parse_output_clean_dnsx_format():
    raw = """
api.target.com [A] [192.0.2.1]
portal.target.com [A] [192.0.2.2]
mail.target.com [A] [192.0.2.3]
"""
    results = SubfinderDnsxScanner.parse_output(raw)
    assert len(results) == 3
    subs = {r["subdomain"]: r["ips"] for r in results}
    assert subs["api.target.com"] == ["192.0.2.1"]
    assert subs["portal.target.com"] == ["192.0.2.2"]
    assert subs["mail.target.com"] == ["192.0.2.3"]
    assert all(r["status"] == "active" for r in results)
    assert all(r["discovered_from"] == "Subfinder + dnsx" for r in results)


def test_parse_output_with_ansi_escape_colors():
    # dnsx default output has ANSI colored brackets and values
    raw = "\x1b[36mdev.target.com\x1b[0m [\x1b[35mA\x1b[0m] [\x1b[32m198.51.100.10\x1b[0m]\n" \
          "\x1b[36mstage.target.com\x1b[0m [\x1b[35mA\x1b[0m] [\x1b[32m198.51.100.20\x1b[0m]\n"
    results = SubfinderDnsxScanner.parse_output(raw)
    assert len(results) == 2
    assert results[0]["subdomain"] == "dev.target.com"
    assert results[0]["ips"] == ["198.51.100.10"]
    assert results[1]["subdomain"] == "stage.target.com"
    assert results[1]["ips"] == ["198.51.100.20"]


def test_parse_output_multiple_ips_and_duplicates():
    raw = """
cluster.target.com [A] [192.0.2.10, 192.0.2.11]
cluster.target.com [A] [192.0.2.12]
cluster.target.com [A] [192.0.2.10]
cdn.target.com 192.0.2.99
dormant.target.com
"""
    results = SubfinderDnsxScanner.parse_output(raw)
    sub_map = {r["subdomain"]: r for r in results}

    assert "cluster.target.com" in sub_map
    assert sorted(sub_map["cluster.target.com"]["ips"]) == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    assert sub_map["cluster.target.com"]["status"] == "active"

    assert "cdn.target.com" in sub_map
    assert sub_map["cdn.target.com"]["ips"] == ["192.0.2.99"]

    assert "dormant.target.com" in sub_map
    assert sub_map["dormant.target.com"]["ips"] == []
    assert sub_map["dormant.target.com"]["status"] == "unresolving"


def test_parse_output_empty_or_malformed():
    assert SubfinderDnsxScanner.parse_output("") == []
    assert SubfinderDnsxScanner.parse_output("    \n\n  ") == []
    assert SubfinderDnsxScanner.parse_output("no domains or ips here at all!!!") == []


# ============================================================================
# 3. DISCOVER SUBDOMAINS PIPELINE EXECUTION & MOCKING TESTS
# ============================================================================

def test_discover_subdomains_invalid_target():
    res = SubfinderDnsxScanner.discover_subdomains("192.168.1.1")
    assert not res["executed"]
    assert res["total_discovered"] == 0
    assert "not a valid domain" in res["error"]


def test_discover_subdomains_missing_binaries():
    with patch.object(SubfinderDnsxScanner, "_find_binary", return_value=None):
        res = SubfinderDnsxScanner.discover_subdomains("target.com")
        assert not res["executed"]
        assert not res["available"]
        assert "not found" in res["error"]


def test_discover_subdomains_successful_mock():
    mock_dnsx_stdout = """
api.target.com [A] [192.0.2.1]
auth.target.com [A] [192.0.2.2, 192.0.2.3]
"""

    mock_p1 = MagicMock()
    mock_p1.stdout = MagicMock()
    mock_p1.wait.return_value = 0

    mock_p2 = MagicMock()
    mock_p2.communicate.return_value = (mock_dnsx_stdout, "")

    with patch.object(SubfinderDnsxScanner, "_find_binary", side_effect=lambda name: f"/usr/local/bin/{name}"), \
         patch("subprocess.Popen", side_effect=[mock_p1, mock_p2]):

        res = SubfinderDnsxScanner.discover_subdomains("Target.Com")

        assert res["executed"] is True
        assert res["available"] is True
        assert res["target_domain"] == "target.com"
        assert res["total_discovered"] == 2
        assert len(res["subdomains"]) == 2
        assert "192.0.2.1" in res["discovered_ips"]
        assert "192.0.2.2" in res["discovered_ips"]
        assert "192.0.2.3" in res["discovered_ips"]
        assert res["error"] is None


def test_discover_subdomains_timeout():
    mock_p1 = MagicMock()
    mock_p1.stdout = MagicMock()
    mock_p2 = MagicMock()
    mock_p2.communicate.side_effect = subprocess.TimeoutExpired(cmd="subfinder | dnsx", timeout=2)

    with patch.object(SubfinderDnsxScanner, "_find_binary", side_effect=lambda name: f"/usr/local/bin/{name}"), \
         patch("subprocess.Popen", side_effect=[mock_p1, mock_p2]):

        res = SubfinderDnsxScanner.discover_subdomains("target.com", timeout=2)
        assert res["executed"] is True
        assert res["total_discovered"] == 0
        assert "timed out" in res["error"]
        assert mock_p1.kill.called or mock_p2.kill.called


# ============================================================================
# 4. SUBDOMAIN MAPPER INTEGRATION TESTS
# ============================================================================

def test_subdomain_mapper_subfinder_integration():
    subfinder_results = [
        {
            "subdomain": "vpn.example.com",
            "ips": ["198.51.100.5"],
            "status": "active",
            "status_label": "Active (Resolving)",
            "discovered_from": "Subfinder + dnsx",
            "sources": ["Subfinder", "dnsx"]
        },
        {
            "subdomain": "jira.example.com",
            "ips": [],
            "status": "unresolving",
            "status_label": "Unresolved (Dormant)",
            "discovered_from": "Subfinder + dnsx",
            "sources": ["Subfinder", "dnsx"]
        }
    ]

    surface = SubdomainMapper.map_surface(
        root_domain="example.com",
        ct_subdomains=[],
        tls_sans=[],
        dns_cnames=[],
        sibling_domains=[],
        subfinder_results=subfinder_results
    )

    assert surface["total_discovered"] >= 2
    sub_names = [s["subdomain"] for s in surface["subdomains"]]
    assert "vpn.example.com" in sub_names
    assert "jira.example.com" in sub_names

    vpn_entry = next(s for s in surface["subdomains"] if s["subdomain"] == "vpn.example.com")
    assert "198.51.100.5" in vpn_entry["ips"]
    assert "Subfinder" in vpn_entry["discovered_from"] or "Subfinder" in vpn_entry["sources"]


# ============================================================================
# 5. DOMAIN ANALYZER & URL ANALYZER INTEGRATION TESTS
# ============================================================================

def test_domain_analyzer_subfinder_integration():
    mock_scan_res = {
        "executed": True,
        "available": True,
        "command": "subfinder -silent -d testdomain.com | dnsx -silent -a -resp",
        "target_domain": "testdomain.com",
        "total_discovered": 1,
        "subdomains": [
            {
                "subdomain": "api.testdomain.com",
                "domain": "api.testdomain.com",
                "ips": ["192.0.2.55"],
                "status": "active",
                "status_label": "Active (Resolving)",
                "discovered_from": "Subfinder + dnsx",
                "sources": ["Subfinder", "dnsx"]
            }
        ],
        "discovered_ips": ["192.0.2.55"],
        "error": None
    }

    with patch.object(SubfinderDnsxScanner, "discover_subdomains", return_value=mock_scan_res), \
         patch("socket.gethostbyname", return_value="192.0.2.1"), \
         patch("app.network.shodan_client.ShodanClient.lookup", return_value={"configured": False, "target": "testdomain.com"}), \
         patch("app.network.dork_scanner.DorkArtifactScanner.scan", return_value={"scanned": True, "artifacts": []}):

        result = DomainAnalyzer.analyze("testdomain.com")
        assert "subfinder_dnsx" in result
        assert result["subfinder_dnsx"]["total_discovered"] == 1
        assert result["subfinder_dnsx"]["discovered_ips"] == ["192.0.2.55"]
        assert any("Subfinder" in f.get("title", "") for f in result.get("risk_flags", []))


def test_url_analyzer_subfinder_integration():
    mock_scan_res = {
        "executed": True,
        "available": True,
        "command": "subfinder -silent -d urltest.org | dnsx -silent -a -resp",
        "target_domain": "urltest.org",
        "total_discovered": 2,
        "subdomains": [
            {"subdomain": "cdn.urltest.org", "ips": ["192.0.2.100"]},
            {"subdomain": "api.urltest.org", "ips": ["192.0.2.101"]}
        ],
        "discovered_ips": ["192.0.2.100", "192.0.2.101"],
        "error": None
    }

    with patch.object(SubfinderDnsxScanner, "discover_subdomains", return_value=mock_scan_res), \
         patch("socket.gethostbyname", return_value="192.0.2.100"):

        url_res = URLAnalyzer.analyze_url("https://urltest.org/path/login")
        assert "subfinder_dnsx" in url_res
        assert url_res["subfinder_dnsx"]["total_discovered"] == 2
        assert "cdn.urltest.org" in url_res["subdomains"]
        assert "api.urltest.org" in url_res["subdomains"]
        assert any("Subdomain Discovery" in ind for ind in url_res.get("indicators", []))


# ============================================================================
# 6. ENTITY GRAPH HIERARCHY TESTS (PARENT/CHILD RELATIONSHIPS)
# ============================================================================

def test_entity_graph_subfinder_hierarchy():
    mock_job = MagicMock()
    mock_job.job_id = "test-job-subfinder"
    mock_job.filename = "targetcorp.com"
    mock_job.original_filename = "targetcorp.com"
    mock_job.category = "domain"
    mock_job.findings = []
    mock_job.hashes = {"sha256": "1234567890abcdef"}
    mock_job.domain_info = {
        "target": "targetcorp.com",
        "is_ip": False,
        "attack_surface": {
            "subdomains": [
                {
                    "subdomain": "auth.targetcorp.com",
                    "status": "active",
                    "ips": ["198.51.100.42"]
                }
            ]
        }
    }

    graph = EntityGraphBuilder.build(mock_job)

    # Verify node creation
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert "di_target" in nodes
    assert nodes["di_target"]["label"] == "targetcorp.com"

    sub_nodes = [n for n in graph["nodes"] if n.get("full_label") == "auth.targetcorp.com" or n.get("label") == "auth.targetcorp.com"]
    assert len(sub_nodes) == 1
    sub_node = sub_nodes[0]
    assert sub_node["parentId"] == "di_target"
    assert sub_node["isChild"] is True

    ip_nodes = [n for n in graph["nodes"] if n.get("full_label") == "198.51.100.42" or n.get("label") == "198.51.100.42"]
    assert len(ip_nodes) == 1
    ip_node = ip_nodes[0]
    assert ip_node["parentId"] == sub_node["id"]
    assert ip_node["isChild"] is True

    # Verify edge hierarchy: auth.targetcorp.com -> targetcorp.com (SUBDOMAIN_OF)
    subdomain_edges = [
        e for e in graph["edges"]
        if e["label"] == "SUBDOMAIN_OF"
    ]
    assert len(subdomain_edges) >= 1

    # Verify edge hierarchy: 198.51.100.42 -> auth.targetcorp.com (RESOLVES_TO)
    resolves_edges = [
        e for e in graph["edges"]
        if e["label"] == "RESOLVES_TO"
    ]
    assert len(resolves_edges) >= 1
