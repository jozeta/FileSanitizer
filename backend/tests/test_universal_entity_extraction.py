import pytest
from app.core.job_manager import job_manager
from app.core.entity_extractor import EntityExtractor
from app.core.entity_graph_builder import EntityGraphBuilder
from app.core.incident_correlator import IncidentCorrelator

def test_entity_extractor_all_7_types():
    job = job_manager.create_job(
        b"Incident report authored by John Doe lead engineer Jane Smith. Suspect workstation DESKTOP-VICTIM logged on user jdoe and admin_root. Outbound exfiltration to attacker@darkops-c2.org and evil-corp.com. Beaconing observed to 198.51.100.55. Warning keyword detected: confidential api_key leaked!",
        "threat_sample.txt"
    )
    job.category = "text"
    job.extracted_code = "attacker@darkops-c2.org evil-corp.com 198.51.100.55 DESKTOP-VICTIM jdoe confidential api_key"
    job.document_metadata = {
        "Author": "John Doe",
        "Creator": "Jane Smith"
    }

    entities = EntityExtractor.extract_all(job)

    email_vals = [e["value"] for e in entities.get("emails", [])]
    domain_vals = [d["value"] for d in entities.get("domains", [])]
    ip_vals = [i["value"] for i in entities.get("ips", [])]
    host_vals = [h["value"] for h in entities.get("hostnames", [])]
    user_vals = [u["value"] for u in entities.get("usernames", [])]
    name_vals = [n["value"] for n in entities.get("names", [])]
    kw_vals = [k["value"] for k in entities.get("keywords", [])]

    assert "attacker@darkops-c2.org" in email_vals
    assert any("darkops-c2.org" in d or "evil-corp.com" in d for d in domain_vals)
    assert "198.51.100.55" in ip_vals
    assert any("DESKTOP-VICTIM" in h for h in host_vals)
    assert any("jdoe" in u or "admin_root" in u for u in user_vals)
    assert any("John Doe" in n or "Jane Smith" in n for n in name_vals)
    assert any("confidential" in k or "api_key" in k for k in kw_vals)

def test_entity_graph_builder_includes_forensic_nodes():
    job = job_manager.create_job(
        b"Contact billing at billing@malicious-fake-invoice.com or 203.0.113.88. Workstation WIN-FINANCE-01 user fin_clerk.",
        "invoice_review.pdf"
    )
    job.category = "pdf"
    job.extracted_code = "billing@malicious-fake-invoice.com 203.0.113.88 WIN-FINANCE-01 user fin_clerk"
    job.document_metadata = {"Author": "Robert Fincher"}

    graph = EntityGraphBuilder.build(job)
    nodes = graph.get("nodes", [])
    node_types = {n.get("type") for n in nodes}
    labels = {n.get("label") for n in nodes}

    assert "email" in node_types
    assert any("billing@malicious-fake-invoice.com" in (l or "") for l in labels)
    assert "ip" in node_types
    assert any("203.0.113.88" in (l or "") for l in labels)
    assert "hostname" in node_types
    assert any("WIN-FINANCE-01" in (l or "") for l in labels)
    assert "user" in node_types
    assert any("fin_clerk" in (l or "") for l in labels)
    assert ("name" in node_types or "person" in node_types)
    assert any("Robert Fincher" in (l or "") for l in labels)

def test_threat_graph_correlates_shared_entities():
    job1 = job_manager.create_job(
        b"Drop file on DC01.local user backup_svc with c2@covert-domain.org",
        "payload1.docx"
    )
    job1.category = "office"
    job1.extracted_code = "DC01.local user backup_svc with c2@covert-domain.org"
    job1.document_metadata = {"Author": "APT Actor 42"}

    job2 = job_manager.create_job(
        b"Exfiltrate from DC01.local user backup_svc to c2@covert-domain.org",
        "payload2.exe"
    )
    job2.category = "pe"
    job2.extracted_code = "from DC01.local user backup_svc to c2@covert-domain.org"
    job2.document_metadata = {"Author": "APT Actor 42"}

    ioc_data = IncidentCorrelator._correlate_iocs([job1, job2])
    assert ioc_data["shared_email_count"] >= 1
    assert ioc_data["shared_hostname_count"] >= 1
    assert ioc_data["shared_user_count"] >= 1
    assert ioc_data["shared_name_count"] >= 1

    campaign_graph = IncidentCorrelator._build_campaign_graph([job1, job2], ioc_data)
    shared_node_types = {n["type"] for n in campaign_graph["nodes"] if n.get("is_shared")}
    assert "email" in shared_node_types
    assert "hostname" in shared_node_types
    assert "user" in shared_node_types
    assert ("name" in shared_node_types or "person" in shared_node_types)
