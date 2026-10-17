import pytest
from types import SimpleNamespace
from app.core.entity_graph_builder import EntityGraphBuilder
from app.core.incident_correlator import IncidentCorrelator

def test_entity_graph_builder_domain_url_hierarchy():
    job = SimpleNamespace(
        job_id="test_hier_job_1",
        filename="threat_sample.pdf",
        original_filename="threat_sample.pdf",
        category="pdf",
        file_size=4096,
        hashes={"sha256": "aabbccddeeff00112233"},
        risk=SimpleNamespace(level="CRITICAL", verdict="Malicious"),
        urls=[
            {"url": "http://evil-c2.com/site1", "risk": "high", "http_status": 200},
            {"url": "http://evil-c2.com/site2", "risk": "critical", "http_status": 404},
            {"url": "https://trusted-bank.org/login", "risk": "clean", "http_status": 200},
        ]
    )

    graph = EntityGraphBuilder.build(job)
    nodes = {n["id"]: n for n in graph["nodes"]}

    # Check evil-c2.com domain node
    c2_domains = [n for n in graph["nodes"] if n["type"] == "domain" and "evil-c2.com" in n["label"]]
    assert len(c2_domains) == 1, "Expected exactly 1 evil-c2.com domain node"
    c2_dom = c2_domains[0]
    assert c2_dom["childrenCount"] == 2, f"Expected 2 children for evil-c2.com, got {c2_dom['childrenCount']}"
    assert len(c2_dom["childIds"]) == 2

    # Check child URLs
    child_urls = [n for n in graph["nodes"] if n["type"] == "url" and "evil-c2.com" in n["full_label"]]
    assert len(child_urls) == 2, f"Expected 2 child URLs, got {len(child_urls)}"
    for u in child_urls:
        assert u["parentId"] == c2_dom["id"], "Child URL parentId must point to evil-c2.com"
        assert u["isChild"] is True
        assert u["hierarchyRelation"] == "child_endpoint"
        assert u["id"] in c2_dom["childIds"]

    # Check hierarchy edges
    hier_edges = [
        e for e in graph["edges"]
        if e.get("is_hierarchy") and e["source"] == c2_dom["id"]
    ]
    assert len(hier_edges) == 2, f"Expected 2 hierarchy edges from evil-c2.com, got {len(hier_edges)}"
    for e in hier_edges:
        assert e["type"] == "parent_child"
        assert e["label"] == "child endpoint"


def test_incident_correlator_campaign_graph_domain_url_hierarchy():
    job = SimpleNamespace(
        job_id="job_campaign_hier_1",
        filename="payload.exe",
        original_filename="payload.exe",
        category="pe",
        file_size=8192,
        hashes={"sha256": "9988776655443322"},
        risk=SimpleNamespace(level="CRITICAL", verdict="Malicious"),
    )

    ioc_data = {
        "domains": [
            {"domain": "target-corp.com", "occurrences": 1, "is_shared": True, "seen_in_files": [{"job_id": "job_campaign_hier_1"}]}
        ],
        "urls": [
            {"url": "http://target-corp.com/api/v1/telemetry", "occurrences": 1, "is_shared": True, "seen_in_files": [{"job_id": "job_campaign_hier_1"}]},
            {"url": "http://target-corp.com/login", "occurrences": 1, "is_shared": True, "seen_in_files": [{"job_id": "job_campaign_hier_1"}]},
        ]
    }

    graph = IncidentCorrelator._build_campaign_graph([job], ioc_data)
    nodes = {n["id"]: n for n in graph["nodes"]}

    dom_node = next((n for n in graph["nodes"] if n["type"] == "domain" and "target-corp.com" in n["label"]), None)
    assert dom_node is not None, "Domain target-corp.com must exist in campaign graph"
    assert dom_node["childrenCount"] == 2, f"Expected 2 children on target-corp.com, got {dom_node['childrenCount']}"

    url_nodes = [n for n in graph["nodes"] if n["type"] == "url" and "target-corp.com" in n["full_label"]]
    assert len(url_nodes) == 2
    for u in url_nodes:
        assert u["parentId"] == dom_node["id"]
        assert u["isChild"] is True
        assert u["hierarchyRelation"] == "child_endpoint"

    hier_edges = [e for e in graph["edges"] if e.get("is_hierarchy") and e["source"] == dom_node["id"]]
    assert len(hier_edges) == 2
    for e in hier_edges:
        assert e["type"] == "parent_child"


def test_entity_graph_subnet_ip_hierarchy():
    """
    Asserts that:
    - 10.10.10.0 has a parent-child relationship with 10.10.10.34
    - 10.10.10.0 does NOT have a relationship with 10.10.20.12
    - 10.10.20.12 has a relationship with 10.10.20.0
    """
    nodes = [
        {"id": "net_10_10_10", "label": "Network 10.10.10.0/24", "full_label": "10.10.10.0", "type": "network", "details": {"cidr": "10.10.10.0/24"}},
        {"id": "net_10_10_20", "label": "Network 10.10.20.0", "full_label": "10.10.20.0", "type": "subnet", "details": {"ip": "10.10.20.0"}},
        {"id": "ip_34", "label": "IP: 10.10.10.34", "full_label": "10.10.10.34", "type": "ip", "details": {"ip": "10.10.10.34"}},
        {"id": "ip_12", "label": "IP: 10.10.20.12", "full_label": "10.10.20.12", "type": "ip", "details": {"ip": "10.10.20.12"}},
        {"id": "ip_external", "label": "IP: 8.8.8.8", "full_label": "8.8.8.8", "type": "ip", "details": {"ip": "8.8.8.8"}},
    ]
    edges = []

    EntityGraphBuilder._enrich_parent_child_hierarchies(nodes, edges)

    node_by_id = {n["id"]: n for n in nodes}

    # 10.10.10.34 is child of net_10_10_10
    assert node_by_id["ip_34"]["parentId"] == "net_10_10_10"
    assert node_by_id["ip_34"]["hierarchyRelation"] == "subnet_member"
    assert "ip_34" in node_by_id["net_10_10_10"]["childIds"]

    # 10.10.20.12 is NOT child of net_10_10_10
    assert "ip_12" not in node_by_id["net_10_10_10"].get("childIds", [])
    # 10.10.20.12 is child of net_10_10_20
    assert node_by_id["ip_12"]["parentId"] == "net_10_10_20"
    assert "ip_12" in node_by_id["net_10_10_20"]["childIds"]

    # 8.8.8.8 has no subnet parent
    assert node_by_id["ip_external"].get("parentId") is None


def test_entity_graph_multilevel_domain_hierarchy():
    """
    Asserts domain nesting:
    folksam.se -> api.folksam.se -> auth.api.folksam.se
    """
    nodes = [
        {"id": "dom_root", "label": "folksam.se", "full_label": "folksam.se", "type": "domain", "details": {"domain": "folksam.se"}},
        {"id": "dom_api", "label": "api.folksam.se", "full_label": "api.folksam.se", "type": "domain", "details": {"domain": "api.folksam.se"}},
        {"id": "dom_auth", "label": "auth.api.folksam.se", "full_label": "auth.api.folksam.se", "type": "domain", "details": {"domain": "auth.api.folksam.se"}},
        {"id": "dom_other", "label": "otherbank.com", "full_label": "otherbank.com", "type": "domain", "details": {"domain": "otherbank.com"}},
    ]
    edges = []

    EntityGraphBuilder._enrich_parent_child_hierarchies(nodes, edges)

    node_by_id = {n["id"]: n for n in nodes}

    assert node_by_id["dom_api"]["parentId"] == "dom_root"
    assert "dom_api" in node_by_id["dom_root"]["childIds"]

    # auth.api.folksam.se must be child of closest parent: api.folksam.se
    assert node_by_id["dom_auth"]["parentId"] == "dom_api"
    assert "dom_auth" in node_by_id["dom_api"]["childIds"]

    # otherbank.com has no parent
    assert node_by_id["dom_other"].get("parentId") is None

