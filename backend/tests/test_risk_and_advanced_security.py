import pytest
from app.analyzers.risk_engine import RiskEngine
from app.analyzers.base import Finding
from app.analyzers.text_analyzer import TextAnalyzer
from app.sanitizers.text_sanitizer import TextSanitizer
from app.sanitizers.base import SanitizationOptions

def test_risk_engine_clean():
    res = RiskEngine.evaluate(
        findings=[],
        clamav_status="CLEAN",
        category="image"
    )
    assert res.level == "CLEAN"
    assert res.score == 0
    assert "No active content" in res.recommendation

def test_risk_engine_malware_detection():
    findings = [
        Finding(
            category="malware",
            severity="critical",
            title="Malware Detected: Win.Trojan.Agent",
            description="Malicious signature found"
        )
    ]
    res = RiskEngine.evaluate(
        findings=findings,
        clamav_status="MALICIOUS",
        category="office"
    )
    assert res.level == "MALICIOUS"
    assert res.score == 100
    assert res.allow_download_original is False
    assert res.allow_sanitization is False
    assert "MALICIOUS CONTENT DETECTED" in res.recommendation

def test_risk_engine_high_risk_macro():
    findings = [
        Finding(
            category="macro",
            severity="critical",
            title="MACROS DETECTED",
            description="Active VBA macros"
        )
    ]
    res = RiskEngine.evaluate(
        findings=findings,
        clamav_status="CLEAN",
        category="office",
        has_macros=True
    )
    assert res.level == "HIGH RISK"
    assert res.suggested_profile == "maximum"
    assert any("macros" in r.lower() for r in res.reasons)

def test_csv_formula_injection_and_sanitization(temp_dir):
    csv_path = temp_dir / "financial_report.csv"
    payload = "Name,Amount\nJohn,100\n=cmd|' /C calc'!A0,500\n+powershell -enc evil,200\n"
    csv_path.write_text(payload)

    analyzer = TextAnalyzer()
    res = analyzer.analyze(csv_path, csv_path.name, "text/csv")
    assert res.data["has_csv_injection"] is True

    # Sanitize CSV
    clean_csv = temp_dir / "clean_financial_report.csv"
    sanitizer = TextSanitizer()
    opts = SanitizationOptions()
    clean_res = sanitizer.sanitize(csv_path, clean_csv, opts, csv_path.name)
    assert clean_res.success is True

    clean_content = clean_csv.read_text()
    # Cells starting with = and + should now be quoted
    assert "'=cmd" in clean_content
    assert "'+powershell" in clean_content
