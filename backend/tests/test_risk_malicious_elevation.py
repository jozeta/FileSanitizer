"""
Risk engine: a confirmed-malicious reputation hit should yield a MALICIOUS verdict,
not merely HIGH RISK. Previously only ClamAV could set MALICIOUS, so a file flagged
by multiple VirusTotal vendors (or ThreatFox/MalwareBazaar/OTX) was understated.
"""

from app.analyzers.base import Finding
from app.analyzers.risk_engine import RiskEngine


def test_critical_reputation_finding_yields_malicious():
    findings = [Finding(
        category="reputation",
        severity="critical",
        title="VirusTotal Detections (40/70 vendors)",
        description="File hash flagged as malicious by 40 vendors.",
    )]
    res = RiskEngine.evaluate(findings, clamav_status="CLEAN", category="pdf")
    assert res.level == "MALICIOUS"


def test_high_severity_reputation_is_not_auto_malicious():
    findings = [Finding(
        category="reputation",
        severity="high",
        title="VirusTotal Detections (3/70 vendors)",
        description="Only a few vendors flagged this.",
    )]
    res = RiskEngine.evaluate(findings, clamav_status="CLEAN", category="pdf")
    assert res.level != "MALICIOUS"


def test_critical_non_reputation_finding_stays_high_risk():
    # A critical heuristic/active-content finding is HIGH RISK, not MALICIOUS: the
    # elevation is scoped to authoritative reputation confirmations only.
    findings = [Finding(
        category="active_content",
        severity="critical",
        title="Embedded executable payload",
        description="Structural anomaly.",
    )]
    res = RiskEngine.evaluate(findings, clamav_status="CLEAN", category="pdf")
    assert res.level == "HIGH RISK"
