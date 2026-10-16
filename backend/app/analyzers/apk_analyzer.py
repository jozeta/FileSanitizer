"""
Android Application Package (APK) Forensic Security & Reverse Engineering Analyzer.
Comprehensive static & technical analysis for .apk, .aab, .xapk packages and Dalvik Executable (.dex) files.

Features:
- Pure-Python & Androguard hybrid analysis engine
- AndroidManifest.xml binary (AXML) decoding & pretty XML reconstruction
- Multi-DEX Bytecode Disassembly (Dalvik / Smali instructions, opcodes, registers)
- High-level Java & Kotlin Decompiler (DecompilerDAD & structured AST reconstruction)
- Embedded Source Code & Scripts inspection (.java, .kt, .js, React Native bundle, .sh, .xml, .json)
- Native ELF Libraries (.so) dissection (Architecture, JNI exports, imported symbols, Checksec mitigations)
- Categorized Strings & Hardcoded Secrets Search (API keys, AWS, Firebase, JWT, private keys)
- Online Threat Intelligence & Hash Checking (Koodous, VirusTotal, MalwareBazaar, Google Play)
- Dangerous Permissions Matrix mapped to MITRE ATT&CK for Mobile
- Component Attack Surface analysis (Activities, Services, Receivers, Providers, Intent Filters, Deep links)
- Security Compliance & Vulnerabilities Audit (Debuggable, Backup, Cleartext, Root, Dropper, Overlay, Accessibility)
- X.509 Certificate Chain & Code Signing Verification (v1/v2/v3 signatures, debug keystore detection)
"""

import io
import re
import math
import struct
import zipfile
import hashlib
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger
from app.network.threat_intelligence import ThreatIntelligenceAggregator

# Silence verbose Androguard debug logging from loguru
try:
    from loguru import logger as loguru_logger
    loguru_logger.remove()
except Exception:
    pass

@contextmanager
def tolerant_zip_environment():
    """Tolerates malformed extra fields and tampered CRC-32 checksums used in anti-analysis tricks."""
    tampered_items: List[Tuple[str, str]] = []
    orig_decode = zipfile.ZipInfo._decodeExtra
    orig_crc = zipfile.ZipExtFile._update_crc

    def tolerant_decode(self):
        try:
            orig_decode(self)
        except zipfile.BadZipFile as e:
            tampered_items.append((getattr(self, "filename", "unknown"), f"Malformed ZIP extra field: {e}"))

    def tolerant_crc(self, newdata):
        try:
            orig_crc(self, newdata)
        except zipfile.BadZipFile as e:
            tampered_items.append((getattr(self, "name", "unknown"), f"Tampered CRC-32 checksum: {e}"))

    zipfile.ZipInfo._decodeExtra = tolerant_decode
    zipfile.ZipExtFile._update_crc = tolerant_crc
    try:
        yield tampered_items
    finally:
        zipfile.ZipInfo._decodeExtra = orig_decode
        zipfile.ZipExtFile._update_crc = orig_crc

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) of a byte sequence."""
    if not data:
        return 0.0
    occ: Dict[int, int] = {}
    for b in data:
        occ[b] = occ.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in occ.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

# Try importing Androguard for advanced decompilation and DEX analysis
try:
    from androguard.core.apk import APK as AndroguardAPK
    from androguard.core.dex import DEX as AndroguardDEX
    from androguard.core.analysis.analysis import Analysis as AndroguardAnalysis
    from androguard.decompiler.decompiler import DecompilerDAD
    import lxml.etree as etree
    ANDROGUARD_AVAILABLE = True
except Exception:
    ANDROGUARD_AVAILABLE = False

# Try importing pyelftools for native .so inspection
try:
    from elftools.elf.elffile import ELFFile
    ELF_AVAILABLE = True
except Exception:
    ELF_AVAILABLE = False


# Dangerous Android Permissions with threat classification and MITRE Mobile mapping
DANGEROUS_PERMISSIONS = {
    # SMS & Telephony Fraud / 2FA Interception
    "android.permission.SEND_SMS": {
        "title": "Send SMS Messages (Premium SMS Fraud / C2 Exfiltration)",
        "severity": "critical",
        "category": "telephony",
        "description": "Can send SMS messages in the background without user confirmation, commonly abused for premium-rate SMS toll fraud and C2 telemetry exfiltration.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.RECEIVE_SMS": {
        "title": "Receive & Intercept SMS Messages (2FA OTP Theft)",
        "severity": "critical",
        "category": "telephony",
        "description": "Can intercept incoming SMS messages, commonly abused by banking trojans to steal two-factor authentication (2FA) one-time passcodes.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.READ_SMS": {
        "title": "Read Stored SMS Messages",
        "severity": "high",
        "category": "telephony",
        "description": "Can read all stored SMS messages on the device, exposing personal messages, banking alerts, and verification codes.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.RECEIVE_MMS": {
        "title": "Receive MMS Multimedia Messages",
        "severity": "medium",
        "category": "telephony",
        "description": "Can monitor incoming MMS multimedia messages.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.READ_PHONE_STATE": {
        "title": "Read Device Phone State & Telephony Identifiers",
        "severity": "high",
        "category": "telephony",
        "description": "Accesses device phone numbers, cellular network info, ongoing call status, and unique hardware identifiers (IMEI/IMSI).",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },
    "android.permission.CALL_PHONE": {
        "title": "Initiate Autonomous Phone Calls",
        "severity": "high",
        "category": "telephony",
        "description": "Can initiate phone calls directly without passing through the dialer user interface, potentially calling premium toll numbers.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "title": "Intercept Outgoing Phone Calls",
        "severity": "high",
        "category": "telephony",
        "description": "Can monitor, redirect, or abort outgoing phone calls.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.READ_CALL_LOG": {
        "title": "Read Phone Call History",
        "severity": "high",
        "category": "telephony",
        "description": "Can read the user's complete call log, including incoming, outgoing, and missed call metadata.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.WRITE_CALL_LOG": {
        "title": "Modify Phone Call History",
        "severity": "medium",
        "category": "telephony",
        "description": "Can modify the device call log, enabling attackers to erase evidence of unauthorized calls.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    "android.permission.USE_SIP": {
        "title": "Make / Receive SIP VoIP Calls",
        "severity": "medium",
        "category": "telephony",
        "description": "Allows app to use Session Initiation Protocol (SIP) services.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },

    # Surveillance & Audio/Video Wiretapping
    "android.permission.RECORD_AUDIO": {
        "title": "Record Ambient Audio (Microphone Wiretap)",
        "severity": "critical",
        "category": "surveillance",
        "description": "Can record audio from the microphone at any time without notification, enabling stealth ambient eavesdropping.",
        "mitre": "T1417",
        "mitre_name": "Audio Capture"
    },
    "android.permission.CAMERA": {
        "title": "Capture Photos & Video (Camera Surveillance)",
        "severity": "critical",
        "category": "surveillance",
        "description": "Can capture photos and record video streams from device cameras without explicit user consent.",
        "mitre": "T1426",
        "mitre_name": "Video Capture"
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "title": "Precise GPS Location Tracking",
        "severity": "high",
        "category": "location",
        "description": "Can monitor real-time physical GPS coordinates with high precision.",
        "mitre": "T1430",
        "mitre_name": "Location Tracking"
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "title": "Cellular/Wi-Fi Location Tracking",
        "severity": "medium",
        "category": "location",
        "description": "Can access approximate physical location derived from network cell towers and Wi-Fi access points.",
        "mitre": "T1430",
        "mitre_name": "Location Tracking"
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "title": "Continuous Background Location Tracking",
        "severity": "high",
        "category": "location",
        "description": "Allows persistent location monitoring even when the application is closed or not in use.",
        "mitre": "T1430",
        "mitre_name": "Location Tracking"
    },

    # Overlay & Accessibility Exploitation (Banking Trojans & Keyloggers)
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "title": "Draw On Top of Other Apps (Screen Overlay / Cloaking)",
        "severity": "critical",
        "category": "overlay",
        "description": "Can draw floating window overlays above banking, email, or login screens to trick users into entering credentials (Overlay Hijacking).",
        "mitre": "T1444",
        "mitre_name": "Masquerading / Input Capture"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "title": "Accessibility Service Abuse (Autonomous Clicks & Keylogger)",
        "severity": "critical",
        "category": "accessibility",
        "description": "Requests full Accessibility Service permissions. Malicious trojans abuse this to read all on-screen text, log keystrokes, steal 2FA codes, and automatically grant permissions.",
        "mitre": "T1448",
        "mitre_name": "Abuse Accessibility Features"
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "title": "Device Administrator Privileges (Lockout / Anti-Uninstall)",
        "severity": "critical",
        "category": "admin",
        "description": "Requests Android Device Administrator rights, allowing the app to lock the screen, wipe the device, and prevent user uninstallation (ransomware behavior).",
        "mitre": "T1407",
        "mitre_name": "Device Administrator Privileges"
    },

    # Persistence & Autostart
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "title": "Execute Automatically at Boot (Reboot Persistence)",
        "severity": "high",
        "category": "persistence",
        "description": "Registers a broadcast receiver triggered immediately when the Android OS finishes booting, enabling persistent background startup.",
        "mitre": "T1402",
        "mitre_name": "Broadcast Receivers"
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "title": "Bypass Battery Optimization (Permanent Background Execution)",
        "severity": "high",
        "category": "persistence",
        "description": "Requests exemption from Android Doze mode and battery saving, keeping malware alive in the background indefinitely.",
        "mitre": "T1402",
        "mitre_name": "Broadcast Receivers"
    },
    "android.permission.WAKE_LOCK": {
        "title": "Prevent Device Sleep (WakeLock)",
        "severity": "low",
        "category": "persistence",
        "description": "Prevents the processor from sleeping or screen from dimming.",
        "mitre": "T1402",
        "mitre_name": "Broadcast Receivers"
    },

    # Package Management & Droppers
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "title": "Request Package Installation (Secondary Payload Dropper)",
        "severity": "critical",
        "category": "dropper",
        "description": "Allows the app to prompt the user to install auxiliary APK files, commonly used by dropper trojans to deliver secondary payloads.",
        "mitre": "T1476",
        "mitre_name": "Deliver Malicious App via Other Means"
    },
    "android.permission.INSTALL_PACKAGES": {
        "title": "Silent Application Installation (System Dropper)",
        "severity": "critical",
        "category": "dropper",
        "description": "Can silently install packages without user confirmation if granted system or root permissions.",
        "mitre": "T1476",
        "mitre_name": "Deliver Malicious App via Other Means"
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "title": "Enumerate All Installed Applications (App Enumeration)",
        "severity": "medium",
        "category": "reconnaissance",
        "description": "Allows the app to query all installed packages on the device, typically used to detect banking apps, crypto wallets, or security tools.",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },

    # Contacts & Account Harvesting
    "android.permission.READ_CONTACTS": {
        "title": "Harvest Address Book Contacts",
        "severity": "high",
        "category": "privacy",
        "description": "Can read all names, phone numbers, and email addresses stored in the user's address book.",
        "mitre": "T1432",
        "mitre_name": "Access Contact List"
    },
    "android.permission.WRITE_CONTACTS": {
        "title": "Modify Address Book Contacts",
        "severity": "medium",
        "category": "privacy",
        "description": "Can add, edit, or delete contact records in the user's address book.",
        "mitre": "T1432",
        "mitre_name": "Access Contact List"
    },
    "android.permission.GET_ACCOUNTS": {
        "title": "Access Device Accounts",
        "severity": "medium",
        "category": "privacy",
        "description": "Can query registered account identifiers (Google, WhatsApp, Exchange) configured on the device.",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },

    # Storage Access
    "android.permission.READ_EXTERNAL_STORAGE": {
        "title": "Read Shared External Storage",
        "severity": "medium",
        "category": "storage",
        "description": "Can read photos, documents, and downloaded files on shared external storage.",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "title": "Write Shared External Storage",
        "severity": "medium",
        "category": "storage",
        "description": "Can create, modify, or delete files on shared external storage.",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "title": "All Files Access (Broad Storage Control)",
        "severity": "high",
        "category": "storage",
        "description": "Requests unrestricted all-files access across external storage, introduced in Android 11.",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    }
}

# Android SDK API Level to Human-Readable OS Version
ANDROID_API_LEVELS = {
    14: "Android 4.0 (Ice Cream Sandwich)",
    15: "Android 4.0.3 (Ice Cream Sandwich)",
    16: "Android 4.1 (Jelly Bean)",
    17: "Android 4.2 (Jelly Bean)",
    18: "Android 4.3 (Jelly Bean)",
    19: "Android 4.4 (KitKat)",
    21: "Android 5.0 (Lollipop)",
    22: "Android 5.1 (Lollipop)",
    23: "Android 6.0 (Marshmallow)",
    24: "Android 7.0 (Nougat)",
    25: "Android 7.1 (Nougat)",
    26: "Android 8.0 (Oreo)",
    27: "Android 8.1 (Oreo)",
    28: "Android 9.0 (Pie)",
    29: "Android 10",
    30: "Android 11",
    31: "Android 12",
    32: "Android 12L",
    33: "Android 13 (Tiramisu)",
    34: "Android 14 (Upside Down Cake)",
    35: "Android 15 (Vanilla Ice Cream)"
}

# Suspicious DEX Heuristics & Malicious API Signatures (MobSF & Threat Model Mapped)
DEX_API_SIGNATURES = [
    # Cryptographic Weaknesses & Broken Algorithms (CWE-327, CWE-328, CWE-329, CWE-338)
    {
        "pattern": re.compile(r'(?:AES|DES|DESede|Blowfish|RC4)/ECB', re.I),
        "api": "Cipher Mode: ECB",
        "title": "Insecure Cipher Mode (Electronic Codebook / ECB)",
        "severity": "high",
        "category": "crypto",
        "description": "Uses Electronic Codebook (ECB) mode for symmetric block ciphers without initialization vector.",
        "risk_explanation": "ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving visual and statistical patterns. Attackers can deduce structures, manipulate block order, and replay payloads without cracking the secret key.",
        "remediation": "Switch to authenticated encryption algorithms such as AES/GCM/NoPadding with a unique cryptographically random 96-bit or 128-bit IV for each message.",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)["\']|MessageDigest;->getInstance\([^)]*(?:MD5|SHA-?1)', re.I),
        "api": "MessageDigest(MD5/SHA-1)",
        "title": "Broken Hash Function (MD5 / SHA-1)",
        "severity": "high",
        "category": "crypto",
        "description": "Instantiates legacy collision-prone hash algorithms (MD5 or SHA-1).",
        "risk_explanation": "Practical collision attacks exist for MD5 and SHA-1. Malicious actors can generate certificate collisions, forge signatures, and easily reverse credential hashes using precomputed rainbow tables.",
        "remediation": "Upgrade hashing routines to SHA-256, SHA-384, or SHA-512 for data integrity, and Argon2id, bcrypt, or PBKDF2 for password storage.",
        "cwe": "CWE-328: Use of Weak Hash",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|RC4|ARCFOUR|Blowfish)', re.I),
        "api": "Cipher.getInstance(DES/RC4/Blowfish)",
        "title": "Deprecated Legacy Cipher (DES / RC4 / Blowfish)",
        "severity": "critical",
        "category": "crypto",
        "description": "Initializes deprecated or broken symmetric encryption algorithms.",
        "risk_explanation": "DES uses an insecure 56-bit key space brute-forceable in hours. Blowfish suffers from 64-bit block collision vulnerabilities (Sweet32 attack). RC4 exhibits severe statistical keystream biases enabling plaintext recovery.",
        "remediation": "Standardize exclusively on AES-256 or ChaCha20-Poly1305 with modern authenticated encryption modes.",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'new\s+IvParameterSpec\s*\(|IvParameterSpec;\-><init>', re.I),
        "api": "IvParameterSpec()",
        "title": "Symmetric IV Parameter Specification",
        "severity": "medium",
        "category": "crypto",
        "description": "Instantiates an Initialization Vector (IV) for block cipher encryption.",
        "risk_explanation": "If the IV is static, hardcoded, or derived from a predictable seed, attackers can recover plaintexts or forge ciphertext blocks. In GCM mode, reusing an IV with the same key completely destroys authenticity and confidentiality.",
        "remediation": "Always generate unique, unpredictable IVs using java.security.SecureRandom for every single encryption invocation.",
        "cwe": "CWE-329: Generation of Predictable IV with CBC Mode",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },
    {
        "pattern": re.compile(r'java/util/Random;->(?:nextInt|nextBytes)|java/lang/Math;->random', re.I),
        "api": "java.util.Random / Math.random()",
        "title": "Predictable Linear PRNG (Non-Cryptographic Randomness)",
        "severity": "medium",
        "category": "crypto",
        "description": "Generates random numbers using standard predictable pseudo-random algorithms.",
        "risk_explanation": "Standard PRNG seeds can be reverse-engineered after observing consecutive output values, allowing attackers to predict authentication tokens, session IDs, or encryption keys.",
        "remediation": "Use java.security.SecureRandom for security tokens, cryptographic keys, IVs, and salts.",
        "cwe": "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    },

    # Network & TLS MitM Bypasses (CWE-295, CWE-297)
    {
        "pattern": re.compile(r'TrustAll(?:Trust)?Manager|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|checkClientTrusted\s*\([^)]*\)\s*\{\s*\}|X509TrustManager', re.I),
        "api": "X509TrustManager.checkServerTrusted()",
        "title": "SSL/TLS Certificate Validation Bypass (TrustAllTrustManager)",
        "severity": "critical",
        "category": "network_tls",
        "description": "Defines custom X509TrustManager that accepts untrusted, expired, or self-signed certificates.",
        "risk_explanation": "A hallmark flaw enabling Man-in-the-Middle (MitM) attacks. Anyone on the local network (rogue Wi-Fi, DNS spoofer, ISP adversary) can intercept, inspect, and modify encrypted HTTPS traffic without triggering security warnings.",
        "remediation": "Remove empty TrustManagers and let the Android system certificate validation handle TLS handshakes, or configure certificate pinning via network_security_config.xml.",
        "cwe": "CWE-295: Improper Certificate Validation",
        "owasp_mobile": "M3: Insecure Communication",
        "mitre": "T1557",
        "mitre_name": "Man-in-the-Middle"
    },
    {
        "pattern": re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier|setHostnameVerifier\s*\(|verify\s*\([^)]*\)\s*\{\s*return\s+true', re.I),
        "api": "ALLOW_ALL_HOSTNAME_VERIFIER",
        "title": "Disabled TLS Hostname Verification",
        "severity": "critical",
        "category": "network_tls",
        "description": "Instructs HTTP client or SSLSocket to bypass hostname verification against certificate Common Name / SAN.",
        "risk_explanation": "Permits any valid certificate issued for any domain to impersonate the application's backend server, completely nullifying TLS server authentication.",
        "remediation": "Never return true blindly in HostnameVerifier.verify(). Use default OkHttp or HttpsURLConnection hostname verifiers.",
        "cwe": "CWE-297: Improper Validation of Certificate with Host Mismatch",
        "owasp_mobile": "M3: Insecure Communication",
        "mitre": "T1557",
        "mitre_name": "Man-in-the-Middle"
    },
    {
        "pattern": re.compile(r'SSLSocketFactory;->createSocket|javax/net/ssl/SSLSocket', re.I),
        "api": "SSLSocket / SSLSocketFactory",
        "title": "Raw Low-Level SSLSocket Handshake",
        "severity": "medium",
        "category": "network_tls",
        "description": "Initiates low-level raw SSL/TLS socket connections.",
        "risk_explanation": "Raw SSLSockets in Android do not perform hostname verification automatically. Without manual post-handshake verification, traffic remains susceptible to MitM interception.",
        "remediation": "Use high-level HTTP client libraries like OkHttp or HttpsURLConnection which enforce hostname and certificate chain validation out-of-the-box.",
        "cwe": "CWE-295: Improper Certificate Validation",
        "owasp_mobile": "M3: Insecure Communication",
        "mitre": "T1557",
        "mitre_name": "Man-in-the-Middle"
    },

    # WebView Security & JavaScript Bridge (CWE-749, CWE-79, CWE-489)
    {
        "pattern": re.compile(r'addJavascriptInterface|android/webkit/WebView;->addJavascriptInterface', re.I),
        "api": "WebView.addJavascriptInterface()",
        "title": "WebView JavaScript Bridge RCE (addJavascriptInterface)",
        "severity": "critical",
        "category": "webview",
        "description": "Exposes native Java object instances to JavaScript running in the WebView.",
        "risk_explanation": "On Android < 4.2 (API 17), this vulnerability allows arbitrary code execution via reflection. On newer systems, hostile web pages or injected XSS scripts can still invoke exposed public methods to steal user tokens or trigger unauthorized local actions.",
        "remediation": "Ensure targetSdkVersion >= 17, annotate only necessary methods with @JavascriptInterface, and restrict WebView navigation exclusively to trusted first-party HTTPS origins.",
        "cwe": "CWE-749: Exposed Dangerous Method or Function",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1404",
        "mitre_name": "Exploitation for Privilege Escalation"
    },
    {
        "pattern": re.compile(r'setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs', re.I),
        "api": "setAllowUniversalAccessFromFileURLs()",
        "title": "Universal Cross-Origin File Access in WebView",
        "severity": "high",
        "category": "webview",
        "description": "Enables JavaScript loaded from file:// URLs to access content from any origin, including local sandboxed files and remote domains.",
        "risk_explanation": "Attackers who deliver an HTML payload to the device storage can execute cross-origin requests to read and exfiltrate private SQLite databases, SharedPreferences, and session tokens.",
        "remediation": "Explicitly disable file access via setAllowUniversalAccessFromFileURLs(false) and setAllowFileAccessFromFileURLs(false).",
        "cwe": "CWE-79: Cross-site Scripting (XSS)",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    },
    {
        "pattern": re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)|android/webkit/WebSettings;->setAllowFileAccess', re.I),
        "api": "WebSettings.setAllowFileAccess(true)",
        "title": "WebView Local Filesystem Scheme Access Enabled",
        "severity": "medium",
        "category": "webview",
        "description": "Enables loading of local file:// URLs in WebView components.",
        "risk_explanation": "If the WebView loads attacker-controlled URLs via intent parameters, malicious HTML files can read and exfiltrate application sandbox files located at /data/data/<package>/.",
        "remediation": "Set setAllowFileAccess(false) and use androidx.webkit.WebViewAssetLoader to serve local assets safely over virtual https:// domains.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    },
    {
        "pattern": re.compile(r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)|android/webkit/WebView;->setWebContentsDebuggingEnabled', re.I),
        "api": "WebView.setWebContentsDebuggingEnabled(true)",
        "title": "WebView Chrome DevTools Remote Debugging Enabled",
        "severity": "high",
        "category": "webview",
        "description": "Enables Chrome DevTools remote debugging for all WebViews in the process.",
        "risk_explanation": "Allows anyone with physical or adb access to connect DevTools, inspect DOM contents, execute arbitrary JavaScript, view session cookies, and steal authentication credentials.",
        "remediation": "Wrap call in BuildConfig.DEBUG check: WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG).",
        "cwe": "CWE-489: Active Debug Code",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },

    # Telephony & SMS Fraud (CWE-250, CWE-200)
    {
        "pattern": re.compile(r'android/telephony/SmsManager;->(?:sendTextMessage|sendMultipartTextMessage|sendDataMessage)', re.I),
        "api": "SmsManager.sendTextMessage()",
        "title": "Autonomous Background SMS Transmission (Toll Fraud / C2 Exfil)",
        "severity": "critical",
        "category": "telephony_sms",
        "description": "Transmits SMS messages programmatically in the background without UI interaction.",
        "risk_explanation": "Signature capability of mobile toll fraud malware (FluBot, FakeCalls, Joker). Sends stealth SMS messages to premium-rate numbers incurring financial theft or exfiltrates stolen credentials to attacker phone numbers.",
        "remediation": "Delegate SMS transmission to the system dialer application using Intent(Intent.ACTION_SENDTO) so the user explicitly approves message delivery.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    {
        "pattern": re.compile(r'android\.provider\.Telephony\.SMS_RECEIVED|android/provider/Telephony\$Sms\$Intents', re.I),
        "api": "SMS_RECEIVED Broadcast Receiver",
        "title": "Incoming SMS Interception (2FA OTP Passcode Theft)",
        "severity": "critical",
        "category": "telephony_sms",
        "description": "Monitors or registers broadcast receivers for incoming SMS messages.",
        "risk_explanation": "Chief vector for mobile banking trojans to intercept one-time verification passwords (2FA OTP) sent by financial institutions, allowing attackers to authorize fraudulent transactions.",
        "remediation": "Use Google Play Services SMS Retriever API which allows verification without requesting dangerous SMS read/receive permissions.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },
    {
        "pattern": re.compile(r'android/telephony/TelephonyManager;->(?:getDeviceId|getSubscriberId|getImei|getMeid|getSimSerialNumber|getLine1Number)', re.I),
        "api": "TelephonyManager (IMEI/IMSI/SIM Serials)",
        "title": "Persistent Hardware & SIM Identifier Harvesting",
        "severity": "high",
        "category": "telephony_sms",
        "description": "Queries non-resettable hardware identifiers (IMEI, IMSI, SIM Serial, phone number).",
        "risk_explanation": "Malware exfiltrates hardware identifiers to fingerprint infected devices, tie them to victim identities, and coordinate targeted botnet commands.",
        "remediation": "Use user-resettable advertising identifiers (AAID) or app-specific UUIDs instead of non-resettable hardware serial numbers.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },

    # Surveillance & Wiretapping (CWE-250, CWE-200)
    {
        "pattern": re.compile(r'android/media/MediaRecorder;->(?:start|setAudioSource)|android/media/AudioRecord;->startRecording', re.I),
        "api": "MediaRecorder / AudioRecord (start)",
        "title": "Microphone Audio Recording / Ambient Wiretapping",
        "severity": "critical",
        "category": "surveillance",
        "description": "Activates device microphone hardware to record ambient audio or telephone calls.",
        "risk_explanation": "Abused by Commercial Spyware (Pegasus, Predator, FinFisher) and RATs to eavesdrop on private room conversations and record phone calls in real-time.",
        "remediation": "Ensure audio recording is explicitly initiated by the user, displays a prominent foreground notification, and complies with Android background audio restrictions.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1417",
        "mitre_name": "Audio Capture"
    },
    {
        "pattern": re.compile(r'android/hardware/Camera;->open|android/hardware/camera2/CameraManager;->openCamera', re.I),
        "api": "Camera.open() / CameraManager.openCamera()",
        "title": "Stealth Camera Access / Video Surveillance",
        "severity": "critical",
        "category": "surveillance",
        "description": "Directly opens camera hardware to take photos or record video streams.",
        "risk_explanation": "Spyware and stalkerware abuse background camera access to covertly capture photographs of the victim and their surroundings without displaying an onscreen preview.",
        "remediation": "Use Android CameraX with an active viewfinder preview or invoke the system camera via MediaStore.ACTION_IMAGE_CAPTURE.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1426",
        "mitre_name": "Video Capture"
    },
    {
        "pattern": re.compile(r'android/location/LocationManager;->(?:requestLocationUpdates|getLastKnownLocation)|com/google/android/gms/location/FusedLocationProviderClient', re.I),
        "api": "LocationManager / FusedLocationProviderClient",
        "title": "Persistent GPS & Geographic Location Tracking",
        "severity": "high",
        "category": "surveillance",
        "description": "Subscribes to continuous GPS coordinates and cellular tower location updates.",
        "risk_explanation": "Enables stalkerware and surveillance tools to trace physical movements, daily routines, and exact coordinates 24/7.",
        "remediation": "Request ACCESS_COARSE_LOCATION when precise coordinates are not strictly necessary, and discontinue location tracking when the app is backgrounded.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1430",
        "mitre_name": "Location Tracking"
    },
    {
        "pattern": re.compile(r'android/service/notification/NotificationListenerService', re.I),
        "api": "NotificationListenerService",
        "title": "Notification Listener & Push Message Interception",
        "severity": "critical",
        "category": "surveillance",
        "description": "Registers a service to intercept and inspect all incoming system notifications.",
        "risk_explanation": "Banking malware intercepts push notifications from financial apps, Telegram, WhatsApp, and SMS to capture 2FA tokens and suppress security alerts from security tools.",
        "remediation": "Do not request NotificationListenerService access unless developing a dedicated notification management utility.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1412",
        "mitre_name": "Access Call Log / SMS"
    },

    # Accessibility Service & Keylogging Abuse (CWE-250)
    {
        "pattern": re.compile(r'android/accessibilityservice/AccessibilityService|performGlobalAction|findAccessibilityNodeInfosByViewId|getRootInActiveWindow', re.I),
        "api": "AccessibilityService (DOM Inspection / Injections)",
        "title": "Accessibility Service DOM Scraping & Automated Gestures",
        "severity": "critical",
        "category": "accessibility",
        "description": "Hooks into Android AccessibilityService APIs to inspect UI hierarchies and inject automated touch gestures.",
        "risk_explanation": "The single most dangerous permission abused by modern Android banking trojans (SharkBot, TeaBot, Godfather). Used to read all onscreen text, steal passwords, bypass 2FA, grant itself permissions, and perform automated fraudulent fund transfers (ATS).",
        "remediation": "Do not declare or request AccessibilityService unless building an official assistive technology for users with disabilities.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1448",
        "mitre_name": "Abuse Accessibility Features"
    },

    # Screen Overlay & Tapjacking (CWE-1021)
    {
        "pattern": re.compile(r'android/view/WindowManager\$LayoutParams;->type\s*=\s*(?:2003|2006|2038)|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT', re.I),
        "api": "TYPE_APPLICATION_OVERLAY / TYPE_SYSTEM_ALERT",
        "title": "System Alert Window Overlay Injection (Tapjacking / Phishing)",
        "severity": "critical",
        "category": "overlay",
        "description": "Creates floating window overlays drawn on top of all other running applications.",
        "risk_explanation": "Used by banking malware to detect when the victim opens a legitimate banking app, instantly drawing a pixel-perfect fake login screen on top to harvest credentials and credit card details.",
        "remediation": "Protect sensitive activities with setFilterTouchesWhenObscured(true) and android:filterTouchesWhenObscured=\"true\".",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1411",
        "mitre_name": "Input Capture"
    },

    # Device Admin & Mobile Ransomware (CWE-250)
    {
        "pattern": re.compile(r'android/app/admin/DevicePolicyManager;->(?:lockNow|wipeData|resetPassword)', re.I),
        "api": "DevicePolicyManager (lockNow / wipeData / resetPassword)",
        "title": "Device Administrator Screen Lock & Remote Wipe (Ransomware)",
        "severity": "critical",
        "category": "device_admin",
        "description": "Invokes DevicePolicyManager to lock the screen, change the device lockscreen PIN, or erase all user data.",
        "risk_explanation": "Hallmark behavior of Android ransomware (DoubleLocker, Koler, Svpeng). Tricks victims into granting Device Administrator privileges, immediately locks the screen, resets the PIN, and displays a ransom demand.",
        "remediation": "Enterprise DevicePolicyManager APIs should only be utilized in verified Enterprise Mobility Management (EMM) or MDM agent applications.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1407",
        "mitre_name": "Device Administrator Privileges"
    },

    # Dynamic Code Loading, Droppers & Reflection (CWE-94, CWE-78, CWE-470)
    {
        "pattern": re.compile(r'dalvik/system/(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)', re.I),
        "api": "DexClassLoader / InMemoryDexClassLoader",
        "title": "Runtime Dalvik Executable / Dynamic DEX Loading",
        "severity": "critical",
        "category": "code_loading",
        "description": "Loads and executes external Dalvik bytecode (.dex, .jar, .apk) at runtime.",
        "risk_explanation": "Core mechanic of dropper malware (Hydra, Alien, Anatsa). Clean stub APKs pass app store security reviews and subsequently download encrypted secondary payload DEX files from C2 servers to execute malware.",
        "remediation": "Bundle all executable logic into the primary APK. If dynamic loading is required, enforce strict cryptographic digital signature verification on loaded code.",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "owasp_mobile": "M7: Client Code Quality",
        "mitre": "T1437",
        "mitre_name": "Application Layer Protocol / Dynamic Loading"
    },
    {
        "pattern": re.compile(r'java/lang/Runtime;->exec|java/lang/ProcessBuilder', re.I),
        "api": "Runtime.exec() / ProcessBuilder",
        "title": "Native Operating System Shell Command Execution",
        "severity": "critical",
        "category": "code_loading",
        "description": "Executes command-line shell processes (/system/bin/sh, su, toybox).",
        "risk_explanation": "Used by exploit kits to run shell scripts, dump system configuration, establish reverse shell connections, or invoke root elevation utilities.",
        "remediation": "Avoid spawning shell processes. Use native Android SDK APIs for system management.",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "owasp_mobile": "M7: Client Code Quality",
        "mitre": "T1404",
        "mitre_name": "Exploitation for Privilege Escalation"
    },
    {
        "pattern": re.compile(r'java/lang/reflect/Method;->invoke', re.I),
        "api": "Method.invoke()",
        "title": "Dynamic Method Reflection Invocation",
        "severity": "high",
        "category": "code_loading",
        "description": "Invokes Java/Android methods dynamically by name at runtime.",
        "risk_explanation": "Extensively leveraged by mobile malware to conceal calls to hidden or restricted system APIs from static analyzers, obfuscating strings to evade automated sandbox scans.",
        "remediation": "Rely on standard compile-time type-safe references and avoid dynamic reflection for core security operations.",
        "cwe": "CWE-470: Use of Externally-Controlled Input to Select Classes or Code",
        "owasp_mobile": "M9: Reverse Engineering",
        "mitre": "T1626",
        "mitre_name": "Obfuscated Files or Information"
    },
    {
        "pattern": re.compile(r'java/lang/Class;->forName', re.I),
        "api": "Class.forName()",
        "title": "Dynamic Class Resolution & Reflection",
        "severity": "medium",
        "category": "code_loading",
        "description": "Dynamically resolves class types by string name at runtime.",
        "risk_explanation": "Used alongside reflection to dynamically instantiate hidden classes or unexported Android internals.",
        "remediation": "Use static class literals rather than string-based reflection.",
        "cwe": "CWE-470: Use of Externally-Controlled Input to Select Classes or Code",
        "owasp_mobile": "M9: Reverse Engineering",
        "mitre": "T1626",
        "mitre_name": "Obfuscated Files or Information"
    },

    # Root Privilege Escalation & Detection (CWE-250)
    {
        "pattern": re.compile(r'/system/bin/su|/system/xbin/su|/sbin/su|/system/app/Superuser|com\.noshufou\.android\.su|eu\.chainfire\.supersu|com\.topjohnwu\.magisk', re.I),
        "api": "su / Superuser / Magisk Checks",
        "title": "Root Elevation / su Binary Execution & Magisk Detection",
        "severity": "critical",
        "category": "root_privilege",
        "description": "Interacts with or probes for su, Superuser, and Magisk root management binaries.",
        "risk_explanation": "Malware queries root paths to detect if it can escalate privileges to root or to verify if it is running in an analyst environment before executing anti-analysis evasion.",
        "remediation": "Use reputable hardware-backed root verification like Google Play Integrity API rather than simple filesystem path checks.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp_mobile": "M8: Code Tampering",
        "mitre": "T1404",
        "mitre_name": "Exploitation for Privilege Escalation"
    },

    # Anti-Analysis, Evasion & Virtualization (CWE-489, CWE-754, CWE-693)
    {
        "pattern": re.compile(r'android/os/Debug;->(?:isDebuggerConnected|waitingForDebugger)', re.I),
        "api": "Debug.isDebuggerConnected()",
        "title": "Anti-Debugging (isDebuggerConnected Probe)",
        "severity": "medium",
        "category": "anti_analysis",
        "description": "Checks if a JDWP/Dalvik debugger is currently attached.",
        "risk_explanation": "Malware terminates or alters its execution behavior if an analyst attaches a debugger like IDA Pro or Android Studio.",
        "remediation": "Do not embed debugger detection in production apps; use standard ProGuard / R8 code obfuscation.",
        "cwe": "CWE-489: Active Debug Code",
        "owasp_mobile": "M9: Reverse Engineering",
        "mitre": "T1622",
        "mitre_name": "Debugger Evasion"
    },
    {
        "pattern": re.compile(r'goldfish|generic_x86|vbox86p|nox|Genymotion|sdk_google_phone|qemu\.sf\.fake_camera|init\.goldfish\.rc', re.I),
        "api": "Emulator Hardware Fingerprints",
        "title": "Virtualization & Android Emulator Detection",
        "severity": "high",
        "category": "anti_analysis",
        "description": "Inspects system build properties, hardware fingerprints, and drivers for QEMU, Genymotion, or Nox.",
        "risk_explanation": "Threat actors deploy sandbox evasion routines so that when automated malware analysis sandboxes run the APK, the malware stays dormant and exhibits clean behavior.",
        "remediation": "Standard enterprise applications should avoid brittle emulator checks that break automated QA testing pipelines.",
        "cwe": "CWE-754: Improper Check for Unusual or Exceptional Conditions",
        "owasp_mobile": "M9: Reverse Engineering",
        "mitre": "T1622",
        "mitre_name": "Virtualization / Sandbox Evasion"
    },
    {
        "pattern": re.compile(r'frida-server|/data/local/tmp/frida|27042|com\.saurik\.substrate|de\.robv\.android\.xposed', re.I),
        "api": "Frida / Xposed Framework Artifacts",
        "title": "Frida & Xposed Dynamic Hooking Framework Detection",
        "severity": "high",
        "category": "anti_analysis",
        "description": "Detects memory hooks, open ports, and filesystem artifacts associated with Frida and Xposed.",
        "risk_explanation": "Malware detects reverse engineers attempting to bypass SSL pinning or trace Dalvik methods using dynamic instrumentation.",
        "remediation": "Combine server-side attestation (Play Integrity API) with client-side code hardening.",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp_mobile": "M9: Reverse Engineering",
        "mitre": "T1622",
        "mitre_name": "Virtualization / Sandbox Evasion"
    },

    # Target Discovery & Reconnaissance (CWE-200)
    {
        "pattern": re.compile(r'android/content/pm/PackageManager;->(?:getInstalledPackages|getInstalledApplications|queryIntentActivities)', re.I),
        "api": "PackageManager.getInstalledPackages()",
        "title": "Installed Application Enumeration (Target Discovery)",
        "severity": "high",
        "category": "app_enumeration",
        "description": "Queries the complete list of installed applications on the Android device.",
        "risk_explanation": "Used by banking trojans to discover if the victim has specific targeted banking apps, cryptocurrency wallets (MetaMask, Coinbase), or antivirus tools installed, triggering corresponding overlay payloads.",
        "remediation": "Use specific <queries> declarations in AndroidManifest.xml rather than enumerating all installed packages.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },

    # Clipboard Theft & Hijacking (CWE-200)
    {
        "pattern": re.compile(r'android/content/ClipboardManager;->(?:getPrimaryClip|getText|setPrimaryClip)', re.I),
        "api": "ClipboardManager (getPrimaryClip / setPrimaryClip)",
        "title": "Clipboard Data Access & Hijacking (Crypto Clipper)",
        "severity": "medium",
        "category": "clipboard",
        "description": "Reads or alters text stored in the system clipboard.",
        "risk_explanation": "Crypto-clipper malware constantly monitors the clipboard for Bitcoin, Ethereum, and TRON wallet addresses and silently replaces them with the attacker's wallet address upon copy.",
        "remediation": "Only access clipboard content in direct response to explicit user paste actions.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M2: Insecure Data Storage",
        "mitre": "T1414",
        "mitre_name": "Credentials from Web Browsers / Clipboard"
    },
    # Insecure Storage / World-Readable/Writable (CWE-276, CWE-732)
    {
        "pattern": re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getSharedPreferences\([^,]+,\s*[12]\)|openOrCreateDatabase\([^,]+,\s*[12]', re.I),
        "api": "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE",
        "title": "Insecure World-Readable/Writable Storage (CWE-276)",
        "severity": "critical",
        "category": "storage",
        "description": "Configures SharedPreferences or SQLite databases with world-readable (0x0001) or world-writable (0x0002) permissions.",
        "risk_explanation": "Any other application on the device can read or overwrite private application preferences, sensitive credentials, tokens, and local databases.",
        "remediation": "Use MODE_PRIVATE (0x0000) or EncryptedSharedPreferences from AndroidX Security library.",
        "cwe": "CWE-276: Incorrect Default Permissions",
        "owasp_mobile": "M2: Insecure Data Storage",
        "mitre": "T1409",
        "mitre_name": "Access Stored Application Data"
    },
    # WebView File Access from URLs (CWE-79, CWE-200)
    {
        "pattern": re.compile(r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', re.I),
        "api": "setAllowUniversalAccessFromFileURLs(true)",
        "title": "WebView Universal / File Access from URLs Enabled",
        "severity": "critical",
        "category": "webview",
        "description": "Allows JavaScript running in a file:// scheme context to access content from any origin, including other local files.",
        "risk_explanation": "Permits attackers who trick the WebView into rendering a local HTML file to steal private databases, cookies, and local cached tokens (Same-Origin Policy bypass).",
        "remediation": "Call setAllowUniversalAccessFromFileURLs(false) and setAllowFileAccessFromFileURLs(false).",
        "cwe": "CWE-346: Origin Validation Error",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },
    {
        "pattern": re.compile(r'setSafeBrowsingEnabled\s*\(\s*false\s*\)', re.I),
        "api": "setSafeBrowsingEnabled(false)",
        "title": "WebView Safe Browsing Protection Disabled",
        "severity": "medium",
        "category": "webview",
        "description": "Explicitly disables Google Safe Browsing malware and phishing protections for WebView instances.",
        "risk_explanation": "Users browsing web content inside the application will not be warned about known phishing sites, malicious APK downloads, or exploit kits.",
        "remediation": "Keep Safe Browsing enabled: setSafeBrowsingEnabled(true).",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
    },
    # Dynamic Native Library Loading (CWE-114)
    {
        "pattern": re.compile(r'System;->loadLibrary|System;->load\s*\(|System\.loadLibrary|System\.load\(', re.I),
        "api": "System.loadLibrary() / System.load()",
        "title": "Dynamic Native JNI Library Loading",
        "severity": "low",
        "category": "code_loading",
        "description": "Loads native shared libraries (.so) into Dalvik runtime process space.",
        "risk_explanation": "Malware frequently wraps malicious payload routines in native C/C++ libraries (.so) to evade Dalvik bytecode decompilers and static analysis heuristics.",
        "remediation": "Audit bundled native .so libraries for imported symbols, JNI exports, and hardening mitigations.",
        "cwe": "CWE-114: Process Control",
        "owasp_mobile": "M7: Client Code Quality",
        "mitre": "T1437",
        "mitre_name": "Dynamic Code Loading"
    },
    # Screen Recording & Media Projection (CWE-200)
    {
        "pattern": re.compile(r'MediaProjectionManager|createVirtualDisplay|MediaProjection;->start', re.I),
        "api": "MediaProjectionManager / createVirtualDisplay",
        "title": "Real-Time Screen Capture & Streaming (MediaProjection)",
        "severity": "critical",
        "category": "surveillance",
        "description": "Captures real-time device screen framebuffer contents using Android MediaProjection APIs.",
        "risk_explanation": "Used by advanced Android spyware (Predator, Pegasus, CraxsRAT) to live-stream the victim's device screen to C2 servers.",
        "remediation": "Ensure MediaProjection is only used in authorized screen-sharing or accessibility applications with explicit foreground disclosure.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp_mobile": "M1: Improper Platform Usage",
        "mitre": "T1426",
        "mitre_name": "Screen Capture"
    },
    # Static PRNG Seeding (CWE-338)
    {
        "pattern": re.compile(r'SecureRandom;->setSeed\s*\([B|I|J]|new\s+Random\s*\(', re.I),
        "api": "SecureRandom.setSeed() / Insecure Random",
        "title": "Insecure Pseudo-Random Number Generation (Predictable Seeds)",
        "severity": "high",
        "category": "crypto",
        "description": "Applies a predictable seed to SecureRandom or uses java.util.Random for security-critical values.",
        "risk_explanation": "Manually seeding SecureRandom resets its entropy pool to a deterministic state, making generated session tokens, encryption keys, and IVs predictable by adversaries.",
        "remediation": "Do not call setSeed() with static data; allow SecureRandom to self-seed from /dev/urandom.",
        "cwe": "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator",
        "owasp_mobile": "M5: Insufficient Cryptography",
        "mitre": "T1573",
        "mitre_name": "Encrypted Channel"
    }
]

# Sensitive Permission Combinations (Malware & Spyware Signatures)
SENSITIVE_PERMISSION_COMBOS = [
    {
        "id": "OVERLAY_AND_ACCESSIBILITY",
        "title": "Banking Trojan Overlay & Accessibility Keylogging Combination",
        "severity": "critical",
        "required": ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "description": "Combines screen overlay injection (SYSTEM_ALERT_WINDOW) with accessibility keystroke capture and ATS (BIND_ACCESSIBILITY_SERVICE). Hallmark signature of sophisticated mobile banking trojans (Anatsa, TeaBot, SharkBot).",
        "mitre": "T1448",
        "mitre_name": "Abuse Accessibility Features"
    },
    {
        "id": "AUTOSTART_AND_SMS",
        "title": "Reboot Persistence & Stealth SMS Interception / Toll Fraud",
        "severity": "critical",
        "required": ["android.permission.RECEIVE_BOOT_COMPLETED"],
        "any_of": ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
        "description": "Executes autonomously at boot and intercepts/transmits SMS messages in the background. Typical of mobile toll fraud trojans and 2FA interceptors.",
        "mitre": "T1402",
        "mitre_name": "Broadcast Receivers / Access SMS"
    },
    {
        "id": "AV_SURVEILLANCE",
        "title": "Comprehensive Audio & Visual Wiretapping (Spyware / RAT)",
        "severity": "critical",
        "required": ["android.permission.RECORD_AUDIO", "android.permission.CAMERA"],
        "description": "Simultaneously requests ambient microphone recording and camera video capture without requiring user presence. Typical of spyware and commercial surveillance toolkits.",
        "mitre": "T1417",
        "mitre_name": "Audio / Video Capture"
    },
    {
        "id": "LOCATION_AND_AUDIO",
        "title": "Covert Geolocation Tracking & Audio Eavesdropping",
        "severity": "critical",
        "required": ["android.permission.RECORD_AUDIO"],
        "any_of": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"],
        "description": "Combines continuous physical GPS tracking with microphone recording, enabling 24/7 ambient eavesdropping of the user's whereabouts.",
        "mitre": "T1430",
        "mitre_name": "Location Tracking / Audio Capture"
    },
    {
        "id": "INSTALLER_AND_INTERNET",
        "title": "Autonomous Remote Dropper / Secondary Payload Downloader",
        "severity": "critical",
        "required": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
        "description": "Allows application to download external packages over the Internet and prompt silent or trick installs, characteristic of mobile droppers.",
        "mitre": "T1476",
        "mitre_name": "Deliver Malicious App via Other Means"
    },
    {
        "id": "ADMIN_AND_OVERLAY",
        "title": "Device Administrator Screen Lockout & Ransomware Combination",
        "severity": "critical",
        "required": ["android.permission.BIND_DEVICE_ADMIN", "android.permission.SYSTEM_ALERT_WINDOW"],
        "description": "Combines Device Administration rights with overlay drawing to lock down the screen and prevent removal, characteristic of mobile ransomware.",
        "mitre": "T1407",
        "mitre_name": "Device Administrator Privileges"
    },
    {
        "id": "CONTACTS_AND_TELEPHONY_HARVEST",
        "title": "Mass Identity & Address Book Harvesting",
        "severity": "high",
        "required": ["android.permission.READ_CONTACTS"],
        "any_of": ["android.permission.READ_PHONE_STATE", "android.permission.READ_CALL_LOG", "android.permission.GET_ACCOUNTS"],
        "description": "Collects user identity, phone numbers, contact book entries, and call metadata, often exfiltrated for predatory lending or extortion schemes.",
        "mitre": "T1432",
        "mitre_name": "Access Contact List"
    }
]

# Third-Party Android SDK Catalog for Supply Chain & CycloneDX SBOM
ANDROID_SDK_CATALOG = [
    {
        "id": "firebase-core",
        "name": "Firebase Core / Analytics",
        "group": "com.google.firebase",
        "artifact": "firebase-analytics",
        "category": "Analytics & Cloud",
        "patterns": ["com.google.firebase.", "com/google/firebase/"],
        "description": "Google Firebase mobile backend and analytics SDK."
    },
    {
        "id": "firebase-messaging",
        "name": "Firebase Cloud Messaging (FCM)",
        "group": "com.google.firebase",
        "artifact": "firebase-messaging",
        "category": "Cloud Messaging",
        "patterns": ["com.google.firebase.messaging", "FirebaseMessagingService"],
        "description": "Google Cloud Messaging push notifications."
    },
    {
        "id": "play-services-ads",
        "name": "Google Mobile Ads (AdMob)",
        "group": "com.google.android.gms",
        "artifact": "play-services-ads",
        "category": "Monetization & Advertising",
        "patterns": ["com.google.android.gms.ads", "com/google/android/gms/ads/"],
        "description": "Google AdMob advertising and monetization SDK."
    },
    {
        "id": "play-services-base",
        "name": "Google Play Services Base",
        "group": "com.google.android.gms",
        "artifact": "play-services-base",
        "category": "Platform Services",
        "patterns": ["com.google.android.gms.common", "com/google/android/gms/common/"],
        "description": "Google Play Services core runtime client."
    },
    {
        "id": "okhttp",
        "name": "Square OkHttp",
        "group": "com.squareup.okhttp3",
        "artifact": "okhttp",
        "category": "Networking & HTTP",
        "patterns": ["okhttp3.", "com.squareup.okhttp3", "okhttp3/OkHttpClient"],
        "description": "Square OkHttp HTTP & HTTP/2 client library for Android."
    },
    {
        "id": "retrofit",
        "name": "Square Retrofit",
        "group": "com.squareup.retrofit2",
        "artifact": "retrofit",
        "category": "Networking & REST",
        "patterns": ["retrofit2.", "com.squareup.retrofit2"],
        "description": "Type-safe HTTP REST client for Android and Java."
    },
    {
        "id": "gson",
        "name": "Google Gson",
        "group": "com.google.code.gson",
        "artifact": "gson",
        "category": "Serialization & JSON",
        "patterns": ["com.google.gson.", "com/google/gson/"],
        "description": "Google JSON serialization and deserialization library."
    },
    {
        "id": "glide",
        "name": "Bumptech Glide",
        "group": "com.github.bumptech.glide",
        "artifact": "glide",
        "category": "Media & Image Loading",
        "patterns": ["com.bumptech.glide.", "com/bumptech/glide/"],
        "description": "Fast and efficient image loading and caching framework."
    },
    {
        "id": "picasso",
        "name": "Square Picasso",
        "group": "com.squareup.picasso",
        "artifact": "picasso",
        "category": "Media & Image Loading",
        "patterns": ["com.squareup.picasso.", "com/squareup/picasso/"],
        "description": "Image downloading and caching library for Android."
    },
    {
        "id": "facebook-sdk",
        "name": "Meta / Facebook Android SDK",
        "group": "com.facebook.android",
        "artifact": "facebook-android-sdk",
        "category": "Social & Attribution",
        "patterns": ["com.facebook.FacebookSdk", "com.facebook.login", "com/facebook/"],
        "description": "Meta Facebook authentication, graph API, and analytics."
    },
    {
        "id": "react-native",
        "name": "Meta React Native",
        "group": "com.facebook.react",
        "artifact": "react-native",
        "category": "Cross-Platform Framework",
        "patterns": ["com.facebook.react.", "assets/index.android.bundle"],
        "description": "Meta React Native cross-platform mobile application runtime."
    },
    {
        "id": "flutter",
        "name": "Google Flutter Engine",
        "group": "io.flutter",
        "artifact": "flutter-embedding",
        "category": "Cross-Platform Framework",
        "patterns": ["io.flutter.", "libflutter.so", "assets/flutter_assets/"],
        "description": "Google Flutter cross-platform UI framework and Dart runtime."
    },
    {
        "id": "unity",
        "name": "Unity 3D Engine",
        "group": "com.unity3d.player",
        "artifact": "unity-classes",
        "category": "Game Engine",
        "patterns": ["com.unity3d.player.", "libunity.so", "assets/bin/Data/"],
        "description": "Unity 3D cross-platform game development engine."
    },
    {
        "id": "appsflyer",
        "name": "AppsFlyer SDK",
        "group": "com.appsflyer",
        "artifact": "af-android-sdk",
        "category": "Attribution & Analytics",
        "patterns": ["com.appsflyer.", "AppsFlyerLib"],
        "description": "Mobile attribution, marketing measurement, and deep-linking SDK."
    },
    {
        "id": "adjust",
        "name": "Adjust SDK",
        "group": "com.adjust.sdk",
        "artifact": "adjust-android",
        "category": "Attribution & Analytics",
        "patterns": ["com.adjust.sdk.", "com/adjust/sdk/"],
        "description": "Mobile app attribution and analytics platform."
    },
    {
        "id": "rxjava",
        "name": "ReactiveX RxJava",
        "group": "io.reactivex.rxjava3",
        "artifact": "rxjava",
        "category": "Reactive Programming",
        "patterns": ["io.reactivex.", "rx.Observable"],
        "description": "Reactive Extensions for the JVM."
    },
    {
        "id": "kotlinx-coroutines",
        "name": "KotlinX Coroutines",
        "group": "org.jetbrains.kotlinx",
        "artifact": "kotlinx-coroutines-core",
        "category": "Concurrency & Asynchrony",
        "patterns": ["kotlinx.coroutines.", "kotlinx/coroutines/"],
        "description": "Library support for Kotlin coroutines."
    },
    {
        "id": "androidx-core",
        "name": "AndroidX Core & AppCompat",
        "group": "androidx.core",
        "artifact": "core",
        "category": "Platform Jetpack",
        "patterns": ["androidx.core.", "androidx.appcompat."],
        "description": "AndroidX Jetpack compatibility suite."
    },
    {
        "id": "androidx-room",
        "name": "AndroidX Room Persistence",
        "group": "androidx.room",
        "artifact": "room-runtime",
        "category": "Data & Persistence",
        "patterns": ["androidx.room.", "androidx/room/"],
        "description": "AndroidX Room SQLite object mapping library."
    },
    {
        "id": "fastjson",
        "name": "Alibaba Fastjson",
        "group": "com.alibaba",
        "artifact": "fastjson",
        "category": "Serialization & JSON",
        "patterns": ["com.alibaba.fastjson.", "com/alibaba/fastjson/"],
        "description": "Fast JSON parser and generator for Java.",
        "known_vulnerabilities": ["CVE-2022-25845 (Deserialization RCE vulnerability in Fastjson < 1.2.83)"]
    },
    {
        "id": "jackson",
        "name": "FasterXML Jackson",
        "group": "com.fasterxml.jackson.core",
        "artifact": "jackson-databind",
        "category": "Serialization & JSON",
        "patterns": ["com.fasterxml.jackson.", "com/fasterxml/jackson/"],
        "description": "Multi-format data-binding library for Java."
    },
    {
        "id": "apache-commons-collections",
        "name": "Apache Commons Collections",
        "group": "org.apache.commons",
        "artifact": "commons-collections4",
        "category": "Utility Framework",
        "patterns": ["org.apache.commons.collections", "org/apache/commons/collections"],
        "description": "Apache Commons Collections data structures.",
        "known_vulnerabilities": ["CVE-2015-7501 (InvokerTransformer Deserialization RCE in versions < 3.2.2)"]
    }
]

# Capture The Flag (CTF) and Secret Extraction Patterns
CTF_PATTERNS = [
    (re.compile(r'(?<![a-zA-Z])flag\{[^\}\s]{4,100}\}', re.I), "Standard CTF Flag (flag{...})"),
    (re.compile(r'(?<![a-zA-Z])ctf\{[^\}\s]{4,100}\}', re.I), "CTF Flag (ctf{...})"),
    (re.compile(r'(?<![a-zA-Z])picoCTF\{[^\}\s]{4,100}\}', re.I), "PicoCTF Flag"),
    (re.compile(r'(?<![a-zA-Z])HTB\{[^\}\s]{4,100}\}', re.I), "HackTheBox Flag (HTB{...})"),
    (re.compile(r'(?<![a-zA-Z])THM\{[^\}\s]{4,100}\}', re.I), "TryHackMe Flag (THM{...})"),
    (re.compile(r'(?<![a-zA-Z])SEC\{[^\}\s]{4,100}\}', re.I), "Security Flag (SEC{...})"),
]

SECRET_PATTERNS = [
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{30,40}\b'), "Google Cloud / Maps API Key", "high"),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), "AWS Access Key ID", "critical"),
    (re.compile(r'gh[pousr]_[0-9A-Za-z]{36,255}'), "GitHub Personal Access Token", "critical"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack Bot / User Token", "critical"),
    (re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}'), "Slack Incoming Webhook", "high"),
    (re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{50,75}'), "Discord Webhook URL", "high"),
    (re.compile(r'\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b'), "Telegram Bot API Token", "critical"),
    (re.compile(r'\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,34}\b'), "Stripe API Key", "critical"),
    (re.compile(r'\bAC[a-f0-9]{32}\b'), "Twilio Account SID", "high"),
    (re.compile(r'\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b'), "SendGrid API Key", "critical"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Cryptographic Private Key", "critical"),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), "JSON Web Token (JWT)", "medium"),
]

def generate_cyclonedx_android_sbom(data: Dict[str, Any], detected_sdks: List[Dict[str, Any]], file_hash_sha256: str) -> Dict[str, Any]:
    """Generates a standard CycloneDX v1.4 JSON Software Bill of Materials (SBOM) for an Android package."""
    import uuid
    pkg_name = data.get("package_name") or "unknown-android-package"
    ver_name = data.get("version_name") or "1.0"

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-16T12:00:00Z",
            "tools": [
                {
                    "vendor": "FileSanitizer",
                    "name": "ApkAnalyzer",
                    "version": "2.0"
                }
            ],
            "component": {
                "bom-ref": f"pkg:apk/{pkg_name}@{ver_name}",
                "type": "application",
                "name": pkg_name,
                "version": ver_name,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": file_hash_sha256
                    }
                ],
                "description": f"Android Application Package ({data.get('app_name') or pkg_name})"
            }
        },
        "components": []
    }

    for sdk in detected_sdks:
        purl = f"pkg:maven/{sdk['group']}/{sdk['artifact']}@{sdk.get('version', 'unknown')}"
        comp = {
            "bom-ref": purl,
            "type": "library",
            "group": sdk["group"],
            "name": sdk["name"],
            "version": sdk.get("version", "detected"),
            "description": sdk.get("description", ""),
            "purl": purl,
            "properties": [
                {"name": "category", "value": sdk.get("category", "General SDK")},
                {"name": "detection_method", "value": "Static Dalvik Namespace & Asset Inspection"}
            ]
        }
        if sdk.get("known_vulnerabilities"):
            comp["vulnerabilities"] = [
                {"id": v.split()[0], "description": v} for v in sdk["known_vulnerabilities"]
            ]
        bom["components"].append(comp)

    return bom


class AxmlDecoder:
    """
    Pure-Python Android Binary XML (AXML) Decoder for AndroidManifest.xml.
    Decodes elements, attributes, namespaces, and strings.
    """
    CHUNK_STRING_POOL = 0x001C0001
    CHUNK_RESOURCE_MAP = 0x00080180
    CHUNK_START_TAG = 0x00100102
    CHUNK_END_TAG = 0x00100103

    TYPE_STRING = 3
    TYPE_INT_DEC = 16
    TYPE_INT_HEX = 17
    TYPE_INT_BOOLEAN = 18

    def __init__(self, data: bytes):
        self.data = data
        self.strings: List[str] = []
        self.package_name: str = ""
        self.version_code: Optional[int] = None
        self.version_name: Optional[str] = None
        self.min_sdk_version: Optional[int] = None
        self.target_sdk_version: Optional[int] = None
        self.compile_sdk_version: Optional[int] = None
        self.permissions: List[str] = []
        self.activities: List[Dict[str, Any]] = []
        self.services: List[Dict[str, Any]] = []
        self.receivers: List[Dict[str, Any]] = []
        self.providers: List[Dict[str, Any]] = []
        self.deep_links: List[Dict[str, Any]] = []
        self.application_attributes: Dict[str, Any] = {}
        self.is_valid_axml: bool = False

    def decode(self) -> bool:
        if len(self.data) < 8:
            return False

        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic != 0x00080003:
            # Fallback: check if plaintext XML
            try:
                txt = self.data.decode("utf-8", errors="ignore")
                if "<manifest" in txt:
                    self._parse_plaintext_xml(txt)
                    return True
            except Exception:
                pass
            return False

        self.is_valid_axml = True
        offset = 8
        element_stack = []

        while offset + 8 <= len(self.data):
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", self.data, offset)
            if chunk_size == 0 or offset + chunk_size > len(self.data):
                break

            full_chunk_type = struct.unpack_from("<I", self.data, offset)[0]

            if full_chunk_type == self.CHUNK_STRING_POOL or chunk_type == 1:
                self._parse_string_pool(offset, chunk_size)
            elif full_chunk_type == self.CHUNK_START_TAG or chunk_type == 0x0102:
                elem = self._parse_start_tag(offset)
                if elem:
                    element_stack.append(elem)
                    self._process_element(elem)
            elif full_chunk_type == self.CHUNK_END_TAG or chunk_type == 0x0103:
                if element_stack:
                    element_stack.pop()

            offset += chunk_size

        return True

    def _parse_plaintext_xml(self, txt: str):
        pkg_m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', txt)
        if pkg_m:
            self.package_name = pkg_m.group(1)

        vc_m = re.search(r'android:versionCode\s*=\s*["\'](\d+)["\']', txt)
        if vc_m:
            self.version_code = int(vc_m.group(1))
        vn_m = re.search(r'android:versionName\s*=\s*["\']([^"\']+)["\']', txt)
        if vn_m:
            self.version_name = vn_m.group(1)

        min_sdk = re.search(r'android:minSdkVersion\s*=\s*["\'](\d+)["\']', txt)
        if min_sdk:
            self.min_sdk_version = int(min_sdk.group(1))
        target_sdk = re.search(r'android:targetSdkVersion\s*=\s*["\'](\d+)["\']', txt)
        if target_sdk:
            self.target_sdk_version = int(target_sdk.group(1))

        for p in re.findall(r'<uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            if p not in self.permissions:
                self.permissions.append(p)

        if 'android:debuggable="true"' in txt:
            self.application_attributes["debuggable"] = True
        if 'android:allowBackup="true"' in txt:
            self.application_attributes["allowBackup"] = True
        if 'android:usesCleartextTraffic="true"' in txt:
            self.application_attributes["usesCleartextTraffic"] = True

        for act in re.findall(r'<activity[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            self.activities.append({"name": act, "exported": 'android:exported="true"' in txt})
        for srv in re.findall(r'<service[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            self.services.append({"name": srv, "exported": 'android:exported="true"' in txt})
        for rcv in re.findall(r'<receiver[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            self.receivers.append({"name": rcv, "exported": 'android:exported="true"' in txt})
        for prv in re.findall(r'<provider[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            self.providers.append({"name": prv, "exported": 'android:exported="true"' in txt})

        # Deep Links / Custom Schemes in plaintext XML fallback
        for act_block in re.finditer(r'<activity[^>]*android:name\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</activity>', txt, re.DOTALL):
            act_name = act_block.group(1)
            act_content = act_block.group(2)
            is_exp = 'android:exported="true"' in act_block.group(0)
            for d_scheme in re.findall(r'<data[^>]*android:scheme\s*=\s*["\']([^"\']+)["\']', act_content):
                host_m = re.search(r'android:host\s*=\s*["\']([^"\']+)["\']', act_content)
                path_m = re.search(r'android:path\s*=\s*["\']([^"\']+)["\']', act_content)
                self.deep_links.append({
                    "activity": act_name,
                    "scheme": d_scheme,
                    "host": host_m.group(1) if host_m else "",
                    "path": path_m.group(1) if path_m else "",
                    "is_custom_scheme": d_scheme.lower() not in ("http", "https"),
                    "exported": is_exp
                })

    def _parse_string_pool(self, offset: int, chunk_size: int):
        try:
            (string_count, style_count, flags, strings_start, styles_start) = struct.unpack_from("<IIIII", self.data, offset + 8)
            is_utf8 = bool(flags & (1 << 8))

            string_offsets = []
            for i in range(min(string_count, 5000)):
                off = struct.unpack_from("<I", self.data, offset + 28 + i * 4)[0]
                string_offsets.append(off)

            base_strings_offset = offset + strings_start
            for off in string_offsets:
                str_ptr = base_strings_offset + off
                if str_ptr >= len(self.data):
                    continue

                if is_utf8:
                    length = self.data[str_ptr + 1] if str_ptr + 1 < len(self.data) else 0
                    end = self.data.find(b"\x00", str_ptr + 2)
                    raw_str = self.data[str_ptr + 2:end] if end != -1 else self.data[str_ptr + 2:str_ptr + 2 + length]
                    self.strings.append(raw_str.decode("utf-8", errors="ignore"))
                else:
                    length = struct.unpack_from("<H", self.data, str_ptr)[0]
                    str_bytes = self.data[str_ptr + 2:str_ptr + 2 + length * 2]
                    self.strings.append(str_bytes.decode("utf-16le", errors="ignore"))
        except Exception:
            pass

    def _get_string(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""

    def _parse_start_tag(self, offset: int) -> Optional[Dict[str, Any]]:
        try:
            line_num, comment_idx, ns_idx, name_idx = struct.unpack_from("<IIII", self.data, offset + 8)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", self.data, offset + 24)

            tag_name = self._get_string(name_idx)
            attrs = {}

            cur_attr_off = offset + attr_start
            for _ in range(attr_count):
                if cur_attr_off + 20 > len(self.data):
                    break
                a_ns, a_name, a_raw_val, a_val_type, a_val_data = struct.unpack_from("<IIIIi", self.data, cur_attr_off)
                attr_name = self._get_string(a_name)
                val = None
                if a_raw_val != 0xFFFFFFFF and 0 <= a_raw_val < len(self.strings):
                    val = self._get_string(a_raw_val)
                elif a_val_type == self.TYPE_STRING and 0 <= a_val_data < len(self.strings):
                    val = self._get_string(a_val_data)
                elif a_val_type == self.TYPE_INT_BOOLEAN:
                    val = bool(a_val_data != 0)
                elif a_val_type in [self.TYPE_INT_DEC, self.TYPE_INT_HEX]:
                    val = a_val_data
                else:
                    val = a_val_data

                if attr_name:
                    attrs[attr_name] = val

                cur_attr_off += attr_size or 20

            return {"tag": tag_name, "attributes": attrs}
        except Exception:
            return None

    def _process_element(self, elem: Dict[str, Any]):
        tag = elem.get("tag", "")
        attrs = elem.get("attributes", {})

        if tag == "manifest":
            self.package_name = str(attrs.get("package", ""))
            self.version_code = attrs.get("versionCode")
            self.version_name = str(attrs.get("versionName", "")) if "versionName" in attrs else None
            if "compileSdkVersion" in attrs:
                self.compile_sdk_version = attrs.get("compileSdkVersion")
        elif tag == "uses-sdk":
            self.min_sdk_version = attrs.get("minSdkVersion")
            self.target_sdk_version = attrs.get("targetSdkVersion")
        elif tag in ["uses-permission", "permission"]:
            perm_name = str(attrs.get("name", ""))
            if perm_name and perm_name not in self.permissions:
                self.permissions.append(perm_name)
        elif tag == "application":
            for k in ["debuggable", "allowBackup", "usesCleartextTraffic", "testOnly", "hasCode", "name", "theme", "label"]:
                if k in attrs:
                    self.application_attributes[k] = attrs[k]
        elif tag == "activity":
            name = str(attrs.get("name", ""))
            exported = attrs.get("exported")
            self.activities.append({"name": name, "exported": exported, "label": attrs.get("label")})
        elif tag == "service":
            name = str(attrs.get("name", ""))
            exported = attrs.get("exported")
            self.services.append({"name": name, "exported": exported})
        elif tag == "receiver":
            name = str(attrs.get("name", ""))
            exported = attrs.get("exported")
            self.receivers.append({"name": name, "exported": exported})
        elif tag == "provider":
            name = str(attrs.get("name", ""))
            exported = attrs.get("exported")
            authorities = str(attrs.get("authorities", ""))
            self.providers.append({"name": name, "exported": exported, "authorities": authorities})


class DexParser:
    """
    Pure-Python parser for Dalvik Executable (.dex) bytecode.
    Extracts string pool, classes, API patterns, hardcoded secrets, and network IOCs.
    """
    def __init__(self, data: bytes):
        self.data = data
        self.is_valid = False
        self.version = ""
        self.strings: List[str] = []
        self.classes: List[str] = []
        self.method_calls: List[str] = []
        self.urls: Set[str] = set()
        self.ips: Set[str] = set()
        self.detected_apis: List[Dict[str, Any]] = []

    def get_header_info(self) -> Dict[str, Any]:
        """Extracts complete Dalvik Executable (.dex) header metadata and structural statistics."""
        if len(self.data) < 0x70 or not self.data.startswith(b"dex\n"):
            return {
                "is_valid": False,
                "version": "",
                "file_size": len(self.data),
                "header_size": 0,
                "checksum": "",
                "signature": "",
                "string_ids_size": 0,
                "type_ids_size": 0,
                "proto_ids_size": 0,
                "field_ids_size": 0,
                "method_ids_size": 0,
                "class_defs_size": 0,
                "is_stub": len(self.data) <= 112
            }
        try:
            version = self.data[4:7].decode("ascii", errors="ignore")
            checksum = f"0x{struct.unpack_from('<I', self.data, 0x08)[0]:08x}"
            signature = self.data[0x0C:0x20].hex()
            file_size, header_size, endian_tag = struct.unpack_from("<III", self.data, 0x20)
            string_ids_size = struct.unpack_from("<I", self.data, 0x38)[0]
            type_ids_size = struct.unpack_from("<I", self.data, 0x40)[0]
            proto_ids_size = struct.unpack_from("<I", self.data, 0x48)[0]
            field_ids_size = struct.unpack_from("<I", self.data, 0x50)[0]
            method_ids_size = struct.unpack_from("<I", self.data, 0x58)[0]
            class_defs_size = struct.unpack_from("<I", self.data, 0x60)[0]

            is_stub = (len(self.data) <= 112) or (class_defs_size == 0)

            return {
                "is_valid": True,
                "version": version,
                "file_size": file_size,
                "header_size": header_size,
                "checksum": checksum,
                "signature": signature,
                "string_ids_size": string_ids_size,
                "type_ids_size": type_ids_size,
                "proto_ids_size": proto_ids_size,
                "field_ids_size": field_ids_size,
                "method_ids_size": method_ids_size,
                "class_defs_size": class_defs_size,
                "is_stub": is_stub
            }
        except Exception:
            return {
                "is_valid": False,
                "version": "",
                "file_size": len(self.data),
                "is_stub": len(self.data) <= 112
            }

    def parse(self, max_strings: int = 10000) -> bool:
        if len(self.data) < 0x70 or not self.data.startswith(b"dex\n"):
            return False

        try:
            self.version = self.data[4:7].decode("ascii", errors="ignore")
            string_ids_size, string_ids_off = struct.unpack_from("<II", self.data, 0x38)
            self.is_valid = True

            count = min(string_ids_size, max_strings)
            for i in range(count):
                off_ptr = string_ids_off + i * 4
                if off_ptr + 4 > len(self.data):
                    break
                str_data_off = struct.unpack_from("<I", self.data, off_ptr)[0]
                if str_data_off >= len(self.data):
                    continue

                pos = str_data_off
                length = 0
                shift = 0
                while pos < len(self.data):
                    b = self.data[pos]
                    pos += 1
                    length |= (b & 0x7f) << shift
                    if (b & 0x80) == 0:
                        break
                    shift += 7
                    if shift > 28:
                        break

                end = self.data.find(b"\x00", pos)
                if end != -1:
                    str_bytes = self.data[pos:end]
                else:
                    str_bytes = self.data[pos:pos + min(length, 256)]

                s = str_bytes.decode("utf-8", errors="ignore")
                if s:
                    self.strings.append(s)
                    if s.startswith("L") and s.endswith(";") and "/" in s:
                        self.classes.append(s[1:-1].replace("/", "."))

            # Fallback to raw string scan if table empty
            if not self.strings:
                raw_strings = re.findall(b'[\x20-\x7E]{4,}', self.data)
                for rs in raw_strings:
                    try:
                        s = rs.decode('utf-8', errors='ignore')
                        self.strings.append(s)
                        for c_match in re.findall(r'L([a-zA-Z0-9_/$]+);', s):
                            if '/' in c_match:
                                self.classes.append(c_match.replace('/', '.'))
                        if s.startswith("L") and s.endswith(";") and "/" in s:
                            self.classes.append(s[1:-1].replace("/", "."))
                    except Exception:
                        pass

            self._analyze_strings()
            return True
        except Exception as e:
            logger.debug(f"DEX parse error: {e}")
            return False

    def _analyze_strings(self):
        url_regex = re.compile(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', re.I)
        ip_regex = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

        joined_sample = " \n ".join(self.strings)

        for u in url_regex.findall(joined_sample):
            if not any(ign in u.lower() for ign in ["schemas.android.com", "w3.org", "apache.org/xml", "android.googlesource.com"]):
                self.urls.add(u)

        for ip in ip_regex.findall(joined_sample):
            if not ip.startswith(("0.", "127.", "255.", "192.168.", "10.")):
                self.ips.add(ip)

        for sig in DEX_API_SIGNATURES:
            pattern = sig["pattern"]
            matches = pattern.findall(joined_sample)
            if matches:
                self.detected_apis.append({
                    "api": matches[0] if matches else sig.get("api", sig["title"]),
                    "title": sig["title"],
                    "severity": sig["severity"],
                    "category": sig.get("category", "general"),
                    "description": sig.get("description", sig["title"]),
                    "risk_explanation": sig.get("risk_explanation", ""),
                    "remediation": sig.get("remediation", ""),
                    "cwe": sig.get("cwe", ""),
                    "owasp_mobile": sig.get("owasp_mobile", ""),
                    "mitre": sig.get("mitre", ""),
                    "mitre_name": sig.get("mitre_name", ""),
                    "count": len(matches),
                    "evidence": matches[:5]
                })


class EmbeddedSourceAnalyzer:
    """
    Scans and audits embedded Java, Kotlin, React Native / JavaScript, Shell,
    and XML configuration files bundled inside an APK.
    """
    SOURCE_EXTS = {
        ".java": "java",
        ".kt": "kotlin",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".bundle": "javascript",
        ".sh": "shell",
        ".bat": "shell",
        ".py": "python",
        ".lua": "lua",
        ".xml": "xml",
        ".json": "json",
        ".properties": "properties"
    }

    SECURITY_PATTERNS = [
        (re.compile(r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\bexec\s*\(|\bspawn\s*\(|\bsystem\s*\(|/bin/sh|/bin/bash)', re.I), "Command Execution / Subprocess Spawning", "malicious"),
        (re.compile(r'(?:Class\.forName|Method\.invoke|DexClassLoader|InMemoryDexClassLoader|PathClassLoader)', re.I), "Dynamic Code Loading & Reflection", "suspicious"),
        (re.compile(r'(?:/system/bin/su|/system/xbin/su|/sbin/su|which\s+su|isDeviceRooted|test-keys|Superuser\.apk)', re.I), "Root & Jailbreak Detection Evasion", "suspicious"),
        (re.compile(r'(?:setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface|setAllowFileAccess\s*\(\s*true\s*\)|setAllowContentAccess\s*\(\s*true\s*\))', re.I), "Insecure WebView DOM & JavaScript Bridge", "suspicious"),
        (re.compile(r'AIza[0-9A-Za-z\-_]{20,40}'), "Hardcoded Google API Key", "suspicious"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "Hardcoded AWS Access Key", "malicious"),
        (re.compile(r'https?://[a-zA-Z0-9_\-]+\.firebaseio\.com', re.I), "Hardcoded Firebase Database Endpoint", "suspicious"),
        (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "Hardcoded JSON Web Token (JWT)", "suspicious"),
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Embedded Cryptographic Private Key", "malicious"),
        (re.compile(r'http://[a-zA-Z0-9_\-\.:]+', re.I), "Insecure Cleartext HTTP Protocol", "suspicious"),
        (re.compile(r'(?:rawQuery\s*\(|execSQL\s*\()', re.I), "Direct SQL Execution Hook", "suspicious")
    ]

    IGNORED_HTTP_SCHEMAS = (
        "http://schemas.android.com/",
        "http://schemas.microsoft.com/",
        "http://www.w3.org/",
        "http://xml.apache.org/",
        "http://java.sun.com/",
        "http://ns.adobe.com/",
        "http://purl.org/"
    )

    @classmethod
    def scan_archive_sources(cls, zf: zipfile.ZipFile, max_files: int = 40) -> List[Dict[str, Any]]:
        results = []
        # Sort so scripts and code files (.sh, .js, .bundle, .java, .kt, .py) appear before XML layout files
        def _sort_key(item: zipfile.ZipInfo) -> int:
            fn = item.filename.lower()
            if fn.endswith((".sh", ".bat", ".py", ".lua")):
                return 0
            if fn.endswith((".bundle", ".js", ".ts", ".jsx", ".tsx")):
                return 1
            if fn.endswith((".java", ".kt")):
                return 2
            if fn.endswith((".properties", ".json")):
                return 3
            return 4

        sorted_items = sorted(zf.infolist(), key=_sort_key)
        for item in sorted_items:
            if len(results) >= max_files:
                break
            fname_lower = item.filename.lower()
            if any(fname_lower.endswith(ext) for ext in cls.SOURCE_EXTS) or fname_lower.endswith("index.android.bundle"):
                if item.file_size == 0 or item.file_size > 2 * 1024 * 1024:
                    continue

                ext = Path(fname_lower).suffix or ".bundle"
                ftype = cls.SOURCE_EXTS.get(ext, "javascript" if "bundle" in fname_lower else "other")

                try:
                    data = zf.read(item.filename)
                    text = data.decode("utf-8", errors="ignore")
                    findings_list = []
                    danger = "clean"

                    for pat, title, d_level in cls.SECURITY_PATTERNS:
                        matches = pat.findall(text)
                        if matches:
                            if title == "Insecure Cleartext HTTP Protocol":
                                valid_matches = [m for m in matches if not any(m.lower().startswith(s) for s in cls.IGNORED_HTTP_SCHEMAS)]
                                if not valid_matches:
                                    continue
                            findings_list.append(title)
                            if d_level == "malicious":
                                danger = "malicious"
                            elif d_level == "suspicious" and danger != "malicious":
                                danger = "suspicious"

                    if findings_list or len(results) < 15:
                        results.append({
                            "filename": item.filename,
                            "file_type": ftype,
                            "size": item.file_size,
                            "content_preview": text[:15000],
                            "suspicious_findings": findings_list,
                            "danger_level": danger
                        })
                except Exception:
                    pass
        return results


class NativeLibraryAnalyzer:
    """
    Audits embedded native .so libraries for architectures, JNI bindings, and Checksec mitigations.
    """
    @classmethod
    def inspect_native_libraries(cls, zf: zipfile.ZipFile, max_libs: int = 15) -> List[Dict[str, Any]]:
        lib_details = []
        if not ELF_AVAILABLE:
            return lib_details

        so_files = [i for i in zf.infolist() if i.filename.lower().endswith(".so") and not i.is_dir()]
        for item in so_files[:max_libs]:
            try:
                raw_bytes = zf.read(item.filename)
                stream = io.BytesIO(raw_bytes)
                elf = ELFFile(stream)

                arch = f"{elf.get_machine_arch()} ({'64-bit' if elf.elfclass == 64 else '32-bit'})"
                is_pie = elf.header['e_type'] == 'ET_DYN'

                # Mitigations
                has_nx = True
                has_relro = "NO"
                for seg in elf.iter_segments():
                    if seg.header['p_type'] == 'PT_GNU_STACK':
                        if seg.header['p_flags'] & 0x1:  # Executable
                            has_nx = False
                    elif seg.header['p_type'] == 'PT_GNU_RELRO':
                        has_relro = "PARTIAL"

                has_canary = False
                jni_exports = []
                imported_symbols = []
                suspicious_calls = []

                # Symbol table inspection
                for sec_name in ['.dynsym', '.symtab']:
                    sec = elf.get_section_by_name(sec_name)
                    if sec:
                        for sym in sec.iter_symbols():
                            s_name = sym.name
                            if not s_name:
                                continue
                            if s_name == "__stack_chk_fail":
                                has_canary = True
                            if s_name.startswith("Java_") or s_name == "JNI_OnLoad":
                                if s_name not in jni_exports:
                                    jni_exports.append(s_name)
                            if s_name in ["system", "popen", "execve", "ptrace", "mprotect", "dlopen", "fork"]:
                                if s_name not in suspicious_calls:
                                    suspicious_calls.append(s_name)
                            if len(imported_symbols) < 50 and not s_name.startswith("Java_"):
                                imported_symbols.append(s_name)

                lib_details.append({
                    "filename": item.filename,
                    "architecture": arch,
                    "file_size": item.file_size,
                    "jni_exports": jni_exports[:30],
                    "checksec": {
                        "nx": has_nx,
                        "pie": is_pie,
                        "canary": has_canary,
                        "relro": has_relro
                    },
                    "imported_symbols": imported_symbols[:30],
                    "suspicious_calls": suspicious_calls
                })
            except Exception as e:
                logger.debug(f"Native SO inspection note for {item.filename}: {e}")

        return lib_details


ANDROID_PACKERS = [
    {
        "name": "Qihoo 360 (Jiagu)",
        "markers": ["assets/libjiagu.so", "assets/libjiagu_art.so", "assets/libjiagu_x86.so", "libjiagu.so"],
        "description": "Qihoo 360 Jiagu native dynamic DEX decryptor and code protector."
    },
    {
        "name": "SecNeo (Bangcle)",
        "markers": ["assets/libsecmain.so", "assets/libsecexe.so", "assets/bangcleplugin", "assets/secData0.jar", "libSecShell.so"],
        "description": "SecNeo / Bangcle enterprise hardening wrapper, frequently abused by droppers."
    },
    {
        "name": "Tencent Legu",
        "markers": ["assets/libshell.so", "assets/libBugly.so", "assets/0OO00oo.dat", "assets/o0oooOO0ooOo.dat", "libshell.so"],
        "description": "Tencent Legu / Tencent Shell binary obfuscator and memory DEX injector."
    },
    {
        "name": "Baidu Protect",
        "markers": ["assets/libbaiduprotect.so", "assets/baiduprotect1.jar", "libbaiduprotect.so"],
        "description": "Baidu mobile code encryption and native protector."
    },
    {
        "name": "APKProtector / Ijiami",
        "markers": ["assets/ijm_lib/", "assets/apkprotector/", "libapkprotector.so"],
        "description": "APKProtector / Ijiami anti-tamper and reverse engineering protection stub."
    },
    {
        "name": "Alibaba Mobile Security (AliProtection)",
        "markers": ["assets/libmobisec.so", "assets/libsgmain.so", "libmobisec.so"],
        "description": "Alibaba Security app wrapper and dynamic payload decryptor."
    }
]


class ApkAnalyzer(BaseAnalyzer):
    """
    Comprehensive forensic reverse engineering & security analyzer for Android Application Packages (APK).
    """
    @property
    def name(self) -> str:
        return "ApkAnalyzer"

    @classmethod
    def is_apk(cls, file_path: Path, filename: str = "") -> bool:
        """Check if file is an Android APK or DEX binary."""
        name_lower = filename.lower()
        if name_lower.endswith((".apk", ".aab", ".xapk", ".dex")):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"dex\n"):
                    return True
                if header.startswith(b"PK\x03\x04"):
                    with zipfile.ZipFile(file_path, "r") as zf:
                        nl = zf.namelist()
                        if "AndroidManifest.xml" in nl or any(n.endswith(".dex") for n in nl):
                            return True
        except Exception:
            pass
        return False

    @staticmethod
    def _format_asn1_name(name_obj) -> str:
        """Format an asn1crypto.x509.Name or string DN into standard readable X.500 format."""
        if not name_obj:
            return ""
        if hasattr(name_obj, "human_friendly") and callable(getattr(name_obj, "human_friendly")):
            return name_obj.human_friendly()
        if hasattr(name_obj, "human_friendly") and isinstance(name_obj.human_friendly, str):
            return name_obj.human_friendly
        if hasattr(name_obj, "native") and isinstance(name_obj.native, dict):
            key_map = {
                "common_name": "CN",
                "organization_name": "O",
                "organizational_unit_name": "OU",
                "locality_name": "L",
                "state_or_province_name": "ST",
                "country_name": "C",
                "email_address": "emailAddress",
            }
            parts = [f"{key_map.get(k, k)}={v}" for k, v in name_obj.native.items() if v]
            if parts:
                return ", ".join(parts)
        return str(name_obj)

    def _parse_manifest_tree(self, m_xml, data: Dict[str, Any]):
        """Extract application attributes, components, intent-filters, and security flags from parsed manifest XML."""
        if m_xml is None:
            return
        ns = "{http://schemas.android.com/apk/res/android}"

        # Application Attributes & Security Flags
        app_elem = m_xml.find("application")
        if app_elem is not None:
            debuggable_val = app_elem.get(f"{ns}debuggable")
            if debuggable_val is not None:
                is_dbg = debuggable_val.lower() == "true"
                data["security_flags"]["debuggable"] = is_dbg

            backup_val = app_elem.get(f"{ns}allowBackup")
            if backup_val is not None:
                is_bak = backup_val.lower() == "true"
                data["security_flags"]["allowBackup"] = is_bak
                data["security_flags"]["allow_backup"] = is_bak

            cleartext_val = app_elem.get(f"{ns}usesCleartextTraffic")
            if cleartext_val is not None:
                is_clear = cleartext_val.lower() == "true"
                data["security_flags"]["usesCleartextTraffic"] = is_clear
                data["security_flags"]["uses_cleartext_traffic"] = is_clear

            nsc = app_elem.get(f"{ns}networkSecurityConfig")
            if nsc:
                data["security_flags"]["networkSecurityConfig"] = nsc

        # Activities & Activity Aliases
        parsed_activities = []
        for tag in ["activity", "activity-alias"]:
            for act in m_xml.iter(tag):
                act_name = act.get(f"{ns}name") or act.get(f"{ns}targetActivity") or ""
                if not act_name:
                    continue
                act_exp = act.get(f"{ns}exported")
                label = act.get(f"{ns}label", "")
                perm = act.get(f"{ns}permission", "")
                filters = []
                for ifilter in act.findall("intent-filter"):
                    actions = [a.get(f"{ns}name") for a in ifilter.findall("action") if a.get(f"{ns}name")]
                    cats = [c.get(f"{ns}name") for c in ifilter.findall("category") if c.get(f"{ns}name")]
                    data_tags = []
                    for dtag in ifilter.findall("data"):
                        d_scheme = dtag.get(f"{ns}scheme") or ""
                        d_host = dtag.get(f"{ns}host") or ""
                        d_path = dtag.get(f"{ns}path") or dtag.get(f"{ns}pathPrefix") or dtag.get(f"{ns}pathPattern") or ""
                        d_mime = dtag.get(f"{ns}mimeType") or ""
                        if d_scheme or d_host or d_path or d_mime:
                            data_tags.append({"scheme": d_scheme, "host": d_host, "path": d_path, "mime": d_mime})
                    filters.append({"actions": actions, "categories": cats, "data": data_tags})
                is_exp = (act_exp.lower() == "true") if act_exp is not None else (len(filters) > 0)
                is_main = any("android.intent.action.MAIN" in f.get("actions", []) for f in filters)
                is_launcher = any("android.intent.category.LAUNCHER" in f.get("categories", []) for f in filters)
                parsed_activities.append({
                    "name": act_name,
                    "exported": is_exp,
                    "permission": perm,
                    "label": label,
                    "is_main": is_main,
                    "is_launcher": is_launcher,
                    "intent_filters": filters
                })
        if parsed_activities:
            data["components"]["activities"] = parsed_activities
            deep_links = []
            for act in parsed_activities:
                for ifilter in act.get("intent_filters", []):
                    for d in ifilter.get("data", []):
                        sch = d.get("scheme", "")
                        if sch:
                            deep_links.append({
                                "activity": act.get("name", ""),
                                "scheme": sch,
                                "host": d.get("host", ""),
                                "path": d.get("path", ""),
                                "is_custom_scheme": sch.lower() not in ("http", "https"),
                                "exported": act.get("exported", False)
                            })
            if deep_links:
                data["deep_links"] = deep_links

        # Services
        parsed_services = []
        for srv in m_xml.iter("service"):
            srv_name = srv.get(f"{ns}name") or ""
            if not srv_name:
                continue
            srv_exp = srv.get(f"{ns}exported")
            perm = srv.get(f"{ns}permission", "")
            filters = []
            for ifilter in srv.findall("intent-filter"):
                actions = [a.get(f"{ns}name") for a in ifilter.findall("action") if a.get(f"{ns}name")]
                cats = [c.get(f"{ns}name") for c in ifilter.findall("category") if c.get(f"{ns}name")]
                filters.append({"actions": actions, "categories": cats})
            is_exp = (srv_exp.lower() == "true") if srv_exp is not None else (len(filters) > 0)
            parsed_services.append({
                "name": srv_name,
                "exported": is_exp,
                "permission": perm,
                "intent_filters": filters
            })
        if parsed_services:
            data["components"]["services"] = parsed_services

        # Receivers
        parsed_receivers = []
        for rcv in m_xml.iter("receiver"):
            rcv_name = rcv.get(f"{ns}name") or ""
            if not rcv_name:
                continue
            rcv_exp = rcv.get(f"{ns}exported")
            perm = rcv.get(f"{ns}permission", "")
            filters = []
            for ifilter in rcv.findall("intent-filter"):
                actions = [a.get(f"{ns}name") for a in ifilter.findall("action") if a.get(f"{ns}name")]
                cats = [c.get(f"{ns}name") for c in ifilter.findall("category") if c.get(f"{ns}name")]
                filters.append({"actions": actions, "categories": cats})
            is_exp = (rcv_exp.lower() == "true") if rcv_exp is not None else (len(filters) > 0)
            is_boot = any(any("BOOT_COMPLETED" in a for a in f.get("actions", [])) for f in filters)
            is_sms = any(any("SMS_RECEIVED" in a for a in f.get("actions", [])) for f in filters)
            parsed_receivers.append({
                "name": rcv_name,
                "exported": is_exp,
                "permission": perm,
                "is_boot": is_boot,
                "is_sms": is_sms,
                "intent_filters": filters
            })
        if parsed_receivers:
            data["components"]["receivers"] = parsed_receivers

        # Providers
        parsed_providers = []
        for prv in m_xml.iter("provider"):
            prv_name = prv.get(f"{ns}name") or ""
            if not prv_name:
                continue
            prv_exp = prv.get(f"{ns}exported")
            auth = prv.get(f"{ns}authorities", "")
            is_exp = (prv_exp.lower() == "true") if prv_exp is not None else False
            parsed_providers.append({
                "name": prv_name,
                "exported": is_exp,
                "authorities": auth,
                "read_permission": prv.get(f"{ns}readPermission", ""),
                "write_permission": prv.get(f"{ns}writePermission", "")
            })
        if parsed_providers:
            data["components"]["providers"] = parsed_providers

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        name_lower = filename.lower()

        # Compute cryptographic hashes for Threat Intelligence lookup
        hasher_md5 = hashlib.md5()
        hasher_sha1 = hashlib.sha1()
        hasher_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher_md5.update(chunk)
                hasher_sha1.update(chunk)
                hasher_sha256.update(chunk)

        md5_hex = hasher_md5.hexdigest()
        sha1_hex = hasher_sha1.hexdigest()
        sha256_hex = hasher_sha256.hexdigest()

        data: Dict[str, Any] = {
            "is_apk": True,
            "filename": filename,
            "file_size": Path(file_path).stat().st_size,
            "package_name": "",
            "app_name": "",
            "version_code": "1",
            "version_name": "1.0",
            "min_sdk": None,
            "min_sdk_label": "",
            "target_sdk": None,
            "target_sdk_label": "",
            "compile_sdk": None,
            "manifest_xml": "",
            "security_flags": {
                "debuggable": False,
                "allow_backup": False,
                "uses_cleartext_traffic": False,
                "test_only": False,
                "network_security_config": False
            },
            "permissions": [],
            "dangerous_permissions": [],
            "components": {
                "activities_count": 0,
                "exported_activities_count": 0,
                "services_count": 0,
                "exported_services_count": 0,
                "receivers_count": 0,
                "exported_receivers_count": 0,
                "providers_count": 0,
                "exported_providers_count": 0,
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": []
            },
            "exported_components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": []
            },
            "signing_info": {
                "has_signature": False,
                "has_v1_signature": False,
                "has_v2_or_v3_signature": False,
                "is_debug_key": False,
                "is_self_signed": False,
                "subject": "",
                "issuer": "",
                "serial_number": "",
                "valid_from": "",
                "valid_until": "",
                "sha256_fingerprint": "",
                "certificates": []
            },
            "dex_info": {
                "dex_count": 0,
                "classes_count": 0,
                "total_strings_count": 0,
                "detected_apis": []
            },
            "classes": [],
            "embedded_source_files": [],
            "native_architectures": [],
            "native_libraries": [],
            "native_so_details": [],
            "categorized_strings": {
                "total_count": 0,
                "urls": [],
                "ips": [],
                "secrets_and_keys": [],
                "shell_commands": [],
                "crypto_algorithms": [],
                "sensitive_paths": [],
                "suspicious_apis": []
            },
            "packer_info": {
                "is_packed": False,
                "packer_name": "",
                "matched_markers": [],
                "description": ""
            },
            "malware_signatures": [],
            "keystore_audit": {
                "is_aosp_debug_testkey": False,
                "is_masquerading_identity": False,
                "masquerade_details": "",
                "validity_anomaly": False,
                "validity_details": "",
                "janus_vulnerability": False,
                "janus_details": ""
            },
            "online_intel": {
                "sha256": sha256_hex,
                "sha1": sha1_hex,
                "md5": md5_hex,
                "package_name": "",
                "koodous_url": f"https://koodous.com/apks/{sha256_hex}",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hex}",
                "malwarebazaar_url": f"https://bazaar.abuse.ch/sample/{sha256_hex}/",
                "google_play_url": "",
                "apkpure_url": "",
                "play_store_status": "unverified",
                "play_store_title": "",
                "play_store_details": "",
                "overall_verdict": "unknown",
                "threat_tags": [],
                "malware_families": [],
                "feeds": {},
                "exfiltration_tokens": {
                    "telegram_bots": [],
                    "discord_webhooks": [],
                    "firebase_databases": []
                },
                "ioc_reputation": {
                    "queried_count": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "details": []
                }
            },
            "security_audit": [],
            "network_security_config": {
                "found": False,
                "config_file": "",
                "cleartext_permitted": False,
                "trusts_user_certs": False,
                "has_pinning": False,
                "details": []
            },
            "embedded_assets": [],
            "iocs": {
                "urls": [],
                "ips": []
            },
            "mitre_mobile_techniques": [],
            "archive_security": {
                "zip_slip": {"detected": False, "paths": []},
                "decompression_ratio": 1.0,
                "zip_bomb_risk": False,
                "total_uncompressed_bytes": 0,
                "total_compressed_bytes": 0,
                "duplicate_entries": {"detected": False, "entries": []},
                "extension_mismatches": [],
                "polyglot_and_trailing": {
                    "has_trailing_data": False,
                    "trailing_bytes_count": 0,
                    "has_prepended_header": False,
                    "prepended_type": "",
                    "details": ""
                },
                "nested_archives": [],
                "multi_dex_inventory": [],
                "verdict": "CLEAN"
            },
            "dependencies": [],
            "cyclonedx_sbom": {},
            "secrets_and_ctf": {
                "detected": False,
                "ctf_flags": [],
                "secrets": [],
                "total_count": 0
            },
            "deep_links": [],
            "sensitive_permission_combos": [],
            "risk_score": 0,
            "risk_level": "CLEAN"
        }

        # Handle standalone .dex file
        if name_lower.endswith(".dex"):
            return self._analyze_standalone_dex(file_path, filename, md5_hex, sha1_hex, sha256_hex)

        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"dex\n"):
                    return self._analyze_standalone_dex(file_path, filename, md5_hex, sha1_hex, sha256_hex)
        except Exception:
            pass

        # Parse APK Container
        try:
            all_strings_collected: Set[str] = set()

            # 1. Primary Analysis using Androguard when available
            andro_apk = None
            if ANDROGUARD_AVAILABLE:
                try:
                    andro_apk = AndroguardAPK(str(file_path))
                    if andro_apk.is_valid_APK():
                        pkg = andro_apk.get_package()
                        data["package_name"] = pkg or ""
                        data["app_name"] = andro_apk.get_app_name() or ""
                        data["version_code"] = str(andro_apk.get_androidversion_code() or "1")
                        data["version_name"] = str(andro_apk.get_androidversion_name() or "1.0")
                        data["min_sdk"] = andro_apk.get_min_sdk_version()
                        data["target_sdk"] = andro_apk.get_target_sdk_version()
                        data["permissions"] = andro_apk.get_permissions() or []

                        # Format manifest XML string and parse rich component & security attributes
                        try:
                            m_xml = andro_apk.get_android_manifest_xml()
                            if m_xml is not None:
                                data["manifest_xml"] = etree.tostring(m_xml, pretty_print=True, encoding="unicode")
                                self._parse_manifest_tree(m_xml, data)
                        except Exception as m_err:
                            logger.debug(f"Manifest tree parse error: {m_err}")

                        # Fallback simple component names if tree parse produced empty
                        if not data["components"]["activities"] and andro_apk.get_activities():
                            data["components"]["activities"] = [{"name": a, "exported": False} for a in andro_apk.get_activities()]
                        if not data["components"]["services"] and andro_apk.get_services():
                            data["components"]["services"] = [{"name": s, "exported": False} for s in andro_apk.get_services()]
                        if not data["components"]["receivers"] and andro_apk.get_receivers():
                            data["components"]["receivers"] = [{"name": r, "exported": False} for r in andro_apk.get_receivers()]
                        if not data["components"]["providers"] and andro_apk.get_providers():
                            data["components"]["providers"] = [{"name": p, "exported": False} for p in andro_apk.get_providers()]

                        # Signatures & Certs
                        data["signing_info"]["has_v1_signature"] = andro_apk.is_signed_v1()
                        data["signing_info"]["has_v2_or_v3_signature"] = andro_apk.is_signed_v2() or andro_apk.is_signed_v3()
                        data["signing_info"]["has_signature"] = andro_apk.is_signed()
                except Exception as ag_err:
                    logger.debug(f"Androguard APK parse note: {ag_err}")

            # 2. Resilient Container Dissection & Multi-DEX Processing
            with tolerant_zip_environment() as tampered_zip_items:
                if tampered_zip_items:
                    findings.append(Finding(
                        category="evasion",
                        severity="critical",
                        title="Anti-Analysis ZIP Evasion (Malformed Headers / Tampered CRC)",
                        description=f"APK archive contains malformed or tampered ZIP structures designed to crash automated analysis tools: {'; '.join(f'{f} ({r})' for f, r in tampered_zip_items[:4])}",
                        details={"tampered_files": [dict(file=f, reason=r) for f, r in tampered_zip_items]}
                    ))

                # Open resilient ZIP handle
                zf = zipfile.ZipFile(file_path, "r")

                # 2a. Comprehensive Structural Archive Security Audit (Checklist Sec 1)
                self._inspect_archive_security(file_path, zf, andro_apk, data, findings)

                def get_apk_bytes(name: str) -> Optional[bytes]:
                    if andro_apk is not None:
                        try:
                            b = andro_apk.get_file(name)
                            if b:
                                return b
                        except Exception:
                            pass
                    try:
                        return zf.read(name)
                    except Exception:
                        return None

                namelist = []
                if andro_apk is not None:
                    try:
                        namelist = andro_apk.get_files()
                    except Exception:
                        namelist = zf.namelist()
                else:
                    namelist = zf.namelist()

                # Parse AndroidManifest.xml via AxmlDecoder to enrich or fallback
                if "AndroidManifest.xml" in namelist:
                    manifest_bytes = get_apk_bytes("AndroidManifest.xml")
                    if manifest_bytes:
                        try:
                            axml = AxmlDecoder(manifest_bytes)
                            if axml.decode():
                                if not data["package_name"]:
                                    data["package_name"] = axml.package_name
                                if not data["version_code"] or data["version_code"] == "1":
                                    data["version_code"] = str(axml.version_code or "1")
                                if not data["version_name"] or data["version_name"] == "1.0":
                                    data["version_name"] = str(axml.version_name or "1.0")
                                if not data["min_sdk"]:
                                    data["min_sdk"] = axml.min_sdk_version
                                if not data["target_sdk"]:
                                    data["target_sdk"] = axml.target_sdk_version
                                if not data["compile_sdk"]:
                                    data["compile_sdk"] = axml.compile_sdk_version
                                if not data["permissions"]:
                                    data["permissions"] = axml.permissions
                                if not data["components"]["activities"]:
                                    data["components"]["activities"] = axml.activities
                                if not data["components"]["services"]:
                                    data["components"]["services"] = axml.services
                                if not data["components"]["receivers"]:
                                    data["components"]["receivers"] = axml.receivers
                                if not data["components"]["providers"]:
                                    data["components"]["providers"] = axml.providers
                                if not data["deep_links"] and getattr(axml, "deep_links", None):
                                    data["deep_links"] = axml.deep_links
                                for k, v in axml.application_attributes.items():
                                    data["security_flags"][k] = v
                                    if k == "allowBackup":
                                        data["security_flags"]["allow_backup"] = v
                                    elif k == "usesCleartextTraffic":
                                        data["security_flags"]["uses_cleartext_traffic"] = v
                                if not data["manifest_xml"] and manifest_bytes:
                                    try:
                                        txt_cand = manifest_bytes.decode("utf-8", errors="ignore")
                                        if "<manifest" in txt_cand:
                                            data["manifest_xml"] = txt_cand
                                    except Exception:
                                        pass
                        except Exception as ax_err:
                            logger.debug(f"AxmlDecoder fallback parse note: {ax_err}")

                # Set SDK labels
                if data["min_sdk"]:
                    try:
                        sdk_int = int(data["min_sdk"])
                        data["min_sdk_label"] = ANDROID_API_LEVELS.get(sdk_int, f"API {sdk_int}")
                    except Exception:
                        data["min_sdk_label"] = f"API {data['min_sdk']}"
                if data["target_sdk"]:
                    try:
                        sdk_int = int(data["target_sdk"])
                        data["target_sdk_label"] = ANDROID_API_LEVELS.get(sdk_int, f"API {sdk_int}")
                    except Exception:
                        data["target_sdk_label"] = f"API {data['target_sdk']}"

                # Update online intel URLs with resolved package name
                pkg = data["package_name"]
                data["online_intel"]["package_name"] = pkg
                if pkg:
                    data["online_intel"]["google_play_url"] = f"https://play.google.com/store/apps/details?id={pkg}"
                    data["online_intel"]["apkpure_url"] = f"https://apkpure.com/search?q={pkg}"

                # Process Dangerous Permissions Matrix
                danger_perms_list = []
                for p in data["permissions"]:
                    clean_p = p.strip()
                    if clean_p in DANGEROUS_PERMISSIONS:
                        spec = DANGEROUS_PERMISSIONS[clean_p]
                        danger_perms_list.append({
                            "permission": clean_p,
                            "title": spec["title"],
                            "severity": spec["severity"],
                            "category": spec["category"],
                            "description": spec["description"],
                            "mitre": spec.get("mitre"),
                            "mitre_name": spec.get("mitre_name")
                        })
                        findings.append(Finding(
                            category="permission",
                            severity=spec["severity"],
                            title=f"Dangerous Permission: {spec['title']}",
                            description=f"App requests '{clean_p}'. {spec['description']}",
                            details={"permission": clean_p, "mitre": spec.get("mitre")}
                        ))
                data["dangerous_permissions"] = danger_perms_list

                # Evaluate Sensitive Permission Combinations (Checklist Sec 2 & 3)
                self._evaluate_sensitive_permission_combos(data, findings)

                # Update component counts
                acts = data["components"]["activities"]
                srvs = data["components"]["services"]
                rcvs = data["components"]["receivers"]
                prvs = data["components"]["providers"]

                data["components"]["activities_count"] = len(acts)
                data["components"]["services_count"] = len(srvs)
                data["components"]["receivers_count"] = len(rcvs)
                data["components"]["providers_count"] = len(prvs)

                data["exported_components"]["activities"] = [a["name"] for a in acts if a.get("exported")]
                data["exported_components"]["services"] = [s["name"] for s in srvs if s.get("exported")]
                data["exported_components"]["receivers"] = [r["name"] for r in rcvs if r.get("exported")]
                data["exported_components"]["providers"] = [p["name"] for p in prvs if p.get("exported")]

                data["components"]["exported_activities_count"] = len(data["exported_components"]["activities"])
                data["components"]["exported_services_count"] = len(data["exported_components"]["services"])
                data["components"]["exported_receivers_count"] = len(data["exported_components"]["receivers"])
                data["components"]["exported_providers_count"] = len(data["exported_components"]["providers"])

                # Security flags audit
                if data["security_flags"].get("debuggable"):
                    findings.append(Finding(
                        category="configuration",
                        severity="critical",
                        title="Android Application Debuggable Flag Enabled (android:debuggable=true)",
                        description="Application allows interactive debugger attachment (JDWP) and ptrace memory tampering in production.",
                        details={"flag": "android:debuggable"}
                    ))
                if data["security_flags"].get("allowBackup"):
                    findings.append(Finding(
                        category="configuration",
                        severity="high",
                        title="Android Data Backup Permitted (android:allowBackup=true)",
                        description="Application allows full sandbox data extraction via 'adb backup', risking leakage of private databases and tokens.",
                        details={"flag": "android:allowBackup"}
                    ))
                if data["security_flags"].get("usesCleartextTraffic"):
                    findings.append(Finding(
                        category="network",
                        severity="high",
                        title="Cleartext HTTP Network Traffic Allowed",
                        description="Application explicitly allows unencrypted plain HTTP communications, vulnerable to Man-in-the-Middle eavesdropping.",
                        details={"flag": "android:usesCleartextTraffic"}
                    ))

                # 3. Multi-DEX Processing & Dalvik Bytecode Disassembly
                dex_file_names = [n for n in namelist if n.endswith(".dex")]
                data["dex_info"]["dex_count"] = len(dex_file_names)
                classes_extracted = []

                # Filter out dummy/empty stub DEX files (e.g. anti-analysis DEX parser bomb with 400+ stubs)
                valid_dex_entries: List[Tuple[str, bytes]] = []
                dummy_dex_count = 0
                for df in dex_file_names:
                    raw_dex = get_apk_bytes(df)
                    if not raw_dex:
                        continue
                    if len(raw_dex) <= 112:
                        dummy_dex_count += 1
                        continue
                    valid_dex_entries.append((df, raw_dex))

                if dummy_dex_count > 5:
                    findings.append(Finding(
                        category="evasion",
                        severity="critical",
                        title="Multi-DEX Parser Bomb / Anti-Analysis Evasion",
                        description=f"APK bundles {dummy_dex_count} empty Dalvik executable stubs (<=112 bytes) designed to exhaust reverse-engineering parsers and static analysis engines.",
                        details={"dummy_dex_count": dummy_dex_count}
                    ))

                # Extract strings & scan MobSF signatures via pure DexParser on all valid DEX files (blazing fast)
                all_dex_classes = []
                for df, dex_bytes in valid_dex_entries:
                    try:
                        dp = DexParser(dex_bytes)
                        if dp.parse():
                            for s in dp.strings:
                                all_strings_collected.add(s)
                            for c in dp.classes:
                                all_dex_classes.append(c)
                            for api in dp.detected_apis:
                                if not any(a["title"] == api["title"] for a in data["dex_info"]["detected_apis"]):
                                    data["dex_info"]["detected_apis"].append(api)
                                    if api.get("severity") in ["critical", "high"]:
                                        findings.append(Finding(
                                            category="active_content",
                                            severity=api["severity"],
                                            title=f"DEX API: {api['title']}",
                                            description=f"Dalvik bytecode invokes {api['title']} ({api['count']} references). {api.get('description', '')}",
                                            details=api
                                        ))
                    except Exception as dex_err:
                        logger.debug(f"DexParser error on {df}: {dex_err}")

                # Use Androguard DEX for method instruction disassembly and DAD decompilation on primary DEX files
                if ANDROGUARD_AVAILABLE and valid_dex_entries:
                    try:
                        primary_dex_entries = valid_dex_entries[:4]
                        dex_objs = []
                        dx = AndroguardAnalysis()
                        for df, dex_bytes in primary_dex_entries:
                            d_obj = AndroguardDEX(dex_bytes)
                            dx.add(d_obj)
                            try:
                                d_obj.set_decompiler(DecompilerDAD(d_obj, dx))
                            except Exception:
                                pass
                            dex_objs.append(d_obj)

                        # Separate app classes from third-party/framework classes
                        app_classes_raw = []
                        other_classes_raw = []
                        pkg_prefix = data["package_name"] or ""

                        for d_obj in dex_objs:
                            for cls_item in d_obj.get_classes():
                                c_name = cls_item.get_name()
                                if c_name.startswith("L") and c_name.endswith(";"):
                                    c_name = c_name[1:-1].replace("/", ".")

                                if pkg_prefix and c_name.startswith(pkg_prefix):
                                    app_classes_raw.append((d_obj, cls_item, c_name))
                                else:
                                    other_classes_raw.append((d_obj, cls_item, c_name))

                        # Select up to 120 classes, prioritizing package-owned classes
                        selected_classes_raw = (app_classes_raw + other_classes_raw)[:120]

                        for d_obj, cls_item, c_name in selected_classes_raw:
                            methods_list = []
                            for m in cls_item.get_methods():
                                instructions = []
                                try:
                                    for ins in m.get_instructions():
                                        instructions.append(f"{ins.get_name()} {ins.get_output()}")
                                except Exception:
                                    pass

                                methods_list.append({
                                    "name": m.get_name(),
                                    "descriptor": m.get_descriptor(),
                                    "access_flags": m.get_access_flags_string(),
                                    "instructions_count": len(instructions),
                                    "instructions": instructions[:80],
                                    "source": ""
                                })

                            # Attempt authentic Java source decompilation via DecompilerDAD
                            cls_src = None
                            try:
                                cls_src = cls_item.get_source()
                            except Exception:
                                cls_src = None

                            cls_pkg = c_name.rsplit(".", 1)[0] if "." in c_name else ""
                            cls_simple = c_name.split(".")[-1]

                            if not cls_src or len(cls_src.strip()) < 10:
                                # Clean pseudo-Java fallback with annotated bytecode
                                m_blocks = []
                                for m_item in methods_list:
                                    m_lines = [f"    // Method: {m_item['name']}{m_item['descriptor']} [{m_item['access_flags']}]"]
                                    for ins in m_item.get("instructions", []):
                                        m_lines.append(f"    {ins}")
                                    m_blocks.append("\n".join(m_lines))
                                cls_src = f"// Reconstructed Dalvik Class\npackage {cls_pkg};\n\npublic class {cls_simple} {{\n" + "\n\n".join(m_blocks) + "\n}"

                            classes_extracted.append({
                                "name": c_name,
                                "package": cls_pkg,
                                "superclass": cls_item.get_superclassname(),
                                "access_flags": cls_item.get_access_flags_string(),
                                "methods_count": len(methods_list),
                                "methods": methods_list,
                                "source_code": cls_src
                            })

                        data["dex_info"]["classes_count"] = len(all_dex_classes) if all_dex_classes else sum(len(d.get_classes()) for d in dex_objs)
                        data["dex_info"]["total_strings_count"] = len(all_strings_collected)
                    except Exception as dex_err:
                        logger.debug(f"Androguard DEX processing note: {dex_err}")

                # Pure-Python DEX Fallback if classes not populated
                if not classes_extracted and all_dex_classes:
                    for c in all_dex_classes[:30]:
                        classes_extracted.append({
                            "name": c,
                            "package": c.rsplit(".", 1)[0] if "." in c else "",
                            "superclass": "java.lang.Object",
                            "access_flags": "public",
                            "methods_count": 0,
                            "methods": [],
                            "source_code": f"// Class: {c}\n// Dalvik class extracted from bytecode container\npublic class {c.split('.')[-1]} {{\n}}"
                        })
                    data["dex_info"]["classes_count"] = len(all_dex_classes)
                    data["dex_info"]["total_strings_count"] = len(all_strings_collected)

                data["classes"] = classes_extracted

                # Concealed Package Name inference (AXML Obfuscation check)
                if not data["package_name"] and (classes_extracted or all_dex_classes):
                    raw_pool = [c["package"] for c in classes_extracted if c.get("package")] or [
                        c.rsplit(".", 1)[0] for c in all_dex_classes if "." in c
                    ]
                    candidate_pkgs = [
                        p for p in raw_pool
                        if not p.startswith(("android.", "androidx.", "java.", "kotlin.", "kotlinx."))
                    ]
                    if candidate_pkgs:
                        inferred_pkg = Counter(candidate_pkgs).most_common(1)[0][0]
                        data["package_name"] = inferred_pkg
                        data["online_intel"]["package_name"] = inferred_pkg
                        findings.append(Finding(
                            category="evasion",
                            severity="high",
                            title="Concealed Application Package Name (AXML Obfuscation)",
                            description=f"APK manifest omits or scrambles the standard 'package' attribute to thwart automated analysis. Inferred package identity from Dalvik class definitions: '{inferred_pkg}'."
                        ))

                # High-Entropy Encrypted Asset & Second-Stage Payload Scanner
                for af in [n for n in namelist if n.startswith(("assets/", "res/raw/"))]:
                    try:
                        raw_asset = get_apk_bytes(af)
                        if raw_asset and len(raw_asset) > 100_000:
                            ent = calculate_shannon_entropy(raw_asset)
                            if ent >= 7.85:
                                findings.append(Finding(
                                    category="evasion",
                                    severity="critical",
                                    title=f"Encrypted / Packed Second-Stage Payload ({af})",
                                    description=f"Asset '{af}' ({len(raw_asset):,} bytes) exhibits near-maximum Shannon entropy ({ent:.2f}/8.00), indicative of an encrypted second-stage DEX/ELF payload dropped at runtime.",
                                    details={"asset": af, "size": len(raw_asset), "entropy": round(ent, 4)}
                                ))
                            elif raw_asset[:4] in (b"dex\n", b"\x7fELF", b"PK\x03\x04"):
                                findings.append(Finding(
                                    category="active_content",
                                    severity="critical",
                                    title=f"Hidden Executable Dropper Payload ({af})",
                                    description=f"File '{af}' is disguised in assets but contains raw executable headers ({raw_asset[:4]!r}).",
                                    details={"asset": af, "size": len(raw_asset)}
                                ))
                    except Exception:
                        pass

                # 4. Embedded Source Code & Scripts Analysis (.java, .kt, .js, .sh, .xml)
                embedded_sources = EmbeddedSourceAnalyzer.scan_archive_sources(zf)
                data["embedded_source_files"] = embedded_sources
                for src in embedded_sources:
                    if src["danger_level"] == "malicious":
                        findings.append(Finding(
                            category="active_content",
                            severity="critical",
                            title=f"Malicious Embedded Script: {src['filename']}",
                            description=f"File contains suspicious active constructs: {', '.join(src['suspicious_findings'])}",
                            details=src
                        ))
                    elif src["danger_level"] == "suspicious":
                        findings.append(Finding(
                            category="active_content",
                            severity="high",
                            title=f"Suspicious Embedded Code: {src['filename']}",
                            description=f"File contains suspicious constructs: {', '.join(src['suspicious_findings'])}",
                            details=src
                        ))

                # 5. Native .so Libraries Inspection
                native_libs = [n for n in namelist if n.lower().endswith(".so") and not n.endswith("/")]
                data["native_libraries"] = native_libs
                archs = set()
                for nl in native_libs:
                    parts = nl.split("/")
                    if len(parts) >= 2 and parts[0] == "lib":
                        archs.add(parts[1])
                data["native_architectures"] = sorted(list(archs))

                so_details = NativeLibraryAnalyzer.inspect_native_libraries(zf)
                data["native_so_details"] = so_details
                for so in so_details:
                    if so.get("suspicious_calls"):
                        findings.append(Finding(
                            category="binary",
                            severity="high",
                            title=f"Native Binary Suspicious Syscalls: {Path(so['filename']).name}",
                            description=f"Native library invokes sensitive OS functions: {', '.join(so['suspicious_calls'])}",
                            details=so
                        ))

                # 6. Strings Categorization & Hardcoded Secrets Table
                self._categorize_all_strings(all_strings_collected, data)

                # 7. Code Signing & Certificate Verification (v1 JAR and v2/v3 APK Signing Block)
                if andro_apk is not None:
                    try:
                        data["signing_info"]["has_signature"] = bool(andro_apk.is_signed())
                        data["signing_info"]["has_v1_signature"] = bool(andro_apk.is_signed_v1())
                        data["signing_info"]["has_v2_or_v3_signature"] = bool(andro_apk.is_signed_v2() or andro_apk.is_signed_v3())

                        andro_certs = andro_apk.get_certificates()
                        if andro_certs:
                            for idx, c in enumerate(andro_certs):
                                issuer_str = self._format_asn1_name(getattr(c, "issuer", None))
                                subject_str = self._format_asn1_name(getattr(c, "subject", None))
                                raw_fp = getattr(c, "sha256_fingerprint", "")
                                if not raw_fp and hasattr(c, "sha256"):
                                    raw_fp = c.sha256.hex() if isinstance(c.sha256, bytes) else str(c.sha256)
                                sha256_fp = raw_fp.upper() if raw_fp else ""
                                is_debug = "android@android.com" in issuer_str.lower() or "debug" in issuer_str.lower() or "android debug" in subject_str.lower()
                                is_self = bool(getattr(c, "self_signed", False) or issuer_str == subject_str)

                                sn = hex(c.serial_number) if hasattr(c, "serial_number") and isinstance(c.serial_number, int) else str(getattr(c, "serial_number", ""))
                                v_from = str(getattr(c, "not_valid_before", ""))
                                v_until = str(getattr(c, "not_valid_after", ""))

                                cert_entry = {
                                    "index": idx,
                                    "issuer": issuer_str,
                                    "subject": subject_str,
                                    "serial_number": sn,
                                    "valid_from": v_from,
                                    "valid_until": v_until,
                                    "sha256_fingerprint": sha256_fp,
                                    "is_debug_key": is_debug,
                                    "is_self_signed": is_self
                                }
                                data["signing_info"]["certificates"].append(cert_entry)

                                if idx == 0:
                                    data["signing_info"].update({
                                        "issuer": issuer_str,
                                        "subject": subject_str,
                                        "serial_number": sn,
                                        "valid_from": v_from,
                                        "valid_until": v_until,
                                        "sha256_fingerprint": sha256_fp,
                                        "is_debug_key": is_debug,
                                        "is_self_signed": is_self
                                    })

                                if is_debug:
                                    findings.append(Finding(
                                        category="signing",
                                        severity="high",
                                        title="Signed with Insecure AOSP / Android Debug TestKey",
                                        description=f"APK is signed with a publicly known test/debug certificate ('{issuer_str}'). Debug-signed applications must never be released in production and indicate either amateur compilation or malware dropper distribution.",
                                        details=cert_entry
                                    ))
                    except Exception as sig_err:
                        logger.debug(f"Androguard signature extraction error: {sig_err}")

                # Fallback to pure-Python PKCS#7 extraction if certificates still empty
                if not data["signing_info"]["certificates"]:
                    cert_files = [n for n in namelist if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
                    if cert_files:
                        data["signing_info"]["has_signature"] = True
                        data["signing_info"]["has_v1_signature"] = True
                        cert_bytes = zf.read(cert_files[0])
                        self._parse_x509_certificate(cert_bytes, data["signing_info"], findings)

                # 7b. Network Security Configuration Audit
                self._analyze_network_security_config(zf, data, findings)

                # 7c. Known Android Packers & Code Obfuscator Signatures
                self._detect_packers(namelist, data, findings)

                # 7d. Specialized Android Malware Family Signatures
                self._detect_specialized_malware_signatures(andro_apk, data, findings)

                # 7e. Keystore Intelligence, Brand Masquerading & Janus Audit
                self._audit_keystore_vulnerabilities(data, findings)

                # 7f. Covert Exfiltration Channels & CTI IoC Pivoting
                self._extract_exfiltration_tokens_and_pivot_iocs(all_strings_collected, data, findings)

                # 7g. Live Google Play Authenticity & Multi-Feed CTI Probing
                self._perform_online_reputation_probes(sha256_hex, data, findings)

                # 7h. Android SDK Inventory & CycloneDX v1.4 SBOM (Checklist Sec 8 & 11)
                self._detect_sdks_and_generate_sbom(all_strings_collected, all_dex_classes, namelist, sha256_hex, data, findings)

                # 7i. Capture The Flag (CTF) Flags & Hardcoded Cloud Credentials Audit (Checklist Sec 9 & 12)
                self._scan_secrets_and_ctf(all_strings_collected, namelist, zf, data, findings)

                # 8. Synthesize MITRE ATT&CK for Mobile Techniques
                mitre_map = {}
                for dp in data["dangerous_permissions"]:
                    if dp.get("mitre"):
                        mitre_map[dp["mitre"]] = dp["mitre_name"]
                for sc in data.get("sensitive_permission_combos", []):
                    if sc.get("mitre"):
                        mitre_map[sc["mitre"]] = sc["mitre_name"]
                for api in data["dex_info"]["detected_apis"]:
                    if api.get("mitre"):
                        mitre_map[api["mitre"]] = api["mitre_name"]
                for sig in data.get("malware_signatures", []):
                    if sig.get("family") == "VPN Proxy / Traffic Interceptor":
                        mitre_map["T1401"] = "Adversary-in-the-Middle"
                    elif sig.get("family") == "SMS Stealer / 2FA Interceptor":
                        mitre_map["T1412"] = "Capture SMS Messages"
                    elif sig.get("family") == "Spyware / Remote Access Trojan (RAT)":
                        mitre_map["T1430"] = "Location Tracking"
                        mitre_map["T1429"] = "Audio Capture"
                data["mitre_mobile_techniques"] = [{"id": k, "name": v} for k, v in mitre_map.items()]

                # 9. Automated Security Compliance Audit Checklist
                self._build_security_audit(data)

                # 10. Compute Risk Score & Disposition
                crit_count = sum(1 for f in findings if f.severity == "critical")
                high_count = sum(1 for f in findings if f.severity == "high")
                med_count = sum(1 for f in findings if f.severity == "medium")
                score = min(100, crit_count * 30 + high_count * 15 + med_count * 5)
                data["risk_score"] = score
                if score >= 60 or crit_count > 0:
                    data["risk_level"] = "CRITICAL"
                elif score >= 35 or high_count > 0:
                    data["risk_level"] = "HIGH"
                elif score >= 15:
                    data["risk_level"] = "MEDIUM"
                else:
                    data["risk_level"] = "LOW"

        except Exception as e:
            logger.error(f"APK analysis failed: {e}", exc_info=True)
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Malformed or Corrupted APK Archive",
                description=f"Could not dissect Android APK package structures: {e}"
            ))

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )

    def _analyze_standalone_dex(self, file_path: Path, filename: str, md5: str, sha1: str, sha256: str) -> AnalyzerResult:
        """Analyze standalone Dalvik Executable (.dex) file."""
        findings: List[Finding] = []
        data: Dict[str, Any] = {
            "is_apk": False,
            "is_standalone_dex": True,
            "filename": filename,
            "file_size": Path(file_path).stat().st_size,
            "package_name": "Standalone DEX",
            "version_code": "1",
            "version_name": "1.0",
            "dex_info": {
                "dex_count": 1,
                "classes_count": 0,
                "total_strings_count": 0,
                "detected_apis": []
            },
            "classes": [],
            "embedded_source_files": [],
            "native_architectures": [],
            "native_libraries": [],
            "native_so_details": [],
            "categorized_strings": {
                "total_count": 0,
                "urls": [],
                "ips": [],
                "secrets_and_keys": [],
                "shell_commands": [],
                "crypto_algorithms": [],
                "sensitive_paths": [],
                "suspicious_apis": []
            },
            "online_intel": {
                "sha256": sha256,
                "sha1": sha1,
                "md5": md5,
                "package_name": "Standalone DEX",
                "koodous_url": f"https://koodous.com/apks/{sha256}",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256}",
                "malwarebazaar_url": f"https://bazaar.abuse.ch/sample/{sha256}/"
            },
            "security_audit": [],
            "network_security_config": {
                "found": False,
                "config_file": "",
                "cleartext_permitted": False,
                "trusts_user_certs": False,
                "has_pinning": False,
                "details": []
            },
            "iocs": {"urls": [], "ips": []},
            "mitre_mobile_techniques": [],
            "archive_security": {
                "zip_slip": {"detected": False, "paths": []},
                "decompression_ratio": 1.0,
                "zip_bomb_risk": False,
                "total_uncompressed_bytes": Path(file_path).stat().st_size,
                "total_compressed_bytes": Path(file_path).stat().st_size,
                "duplicate_entries": {"detected": False, "entries": []},
                "extension_mismatches": [],
                "polyglot_and_trailing": {
                    "has_trailing_data": False,
                    "trailing_bytes_count": 0,
                    "has_prepended_header": False,
                    "prepended_type": "",
                    "details": ""
                },
                "nested_archives": [],
                "multi_dex_inventory": [],
                "verdict": "CLEAN"
            },
            "dependencies": [],
            "cyclonedx_sbom": {},
            "secrets_and_ctf": {
                "detected": False,
                "ctf_flags": [],
                "secrets": [],
                "total_count": 0
            },
            "deep_links": [],
            "sensitive_permission_combos": [],
            "risk_score": 0,
            "risk_level": "LOW"
        }

        try:
            with open(file_path, "rb") as f:
                dex_bytes = f.read()

            dp = DexParser(dex_bytes)
            if dp.parse():
                hdr = dp.get_header_info()
                data["archive_security"]["multi_dex_inventory"].append({
                    "name": filename,
                    "size": Path(file_path).stat().st_size,
                    "dex_version": hdr.get("version", "035"),
                    "checksum": hdr.get("checksum", ""),
                    "signature": hdr.get("signature", ""),
                    "classes_count": hdr.get("class_defs_size", len(dp.classes)),
                    "strings_count": hdr.get("string_ids_size", len(dp.strings)),
                    "methods_count": hdr.get("method_ids_size", 0),
                    "is_stub": hdr.get("is_stub", False)
                })

                data["dex_info"]["total_strings_count"] = len(dp.strings)
                data["dex_info"]["classes_count"] = len(dp.classes)
                data["dex_info"]["detected_apis"] = dp.detected_apis
                data["iocs"]["urls"] = list(dp.urls)[:100]
                data["iocs"]["ips"] = list(dp.ips)[:100]

                classes_list = []
                for c in dp.classes[:30]:
                    classes_list.append({
                        "name": c,
                        "package": c.rsplit(".", 1)[0] if "." in c else "",
                        "superclass": "java.lang.Object",
                        "access_flags": "public",
                        "methods_count": 0,
                        "methods": [],
                        "source_code": f"// Class: {c}\n// Dalvik class extracted from bytecode\npublic class {c.split('.')[-1]} {{\n}}"
                    })
                data["classes"] = classes_list

                self._categorize_all_strings(set(dp.strings), data)
                self._detect_sdks_and_generate_sbom(set(dp.strings), dp.classes, [], sha256, data, findings)
                self._scan_secrets_and_ctf(set(dp.strings), [], None, data, findings)

                for api in dp.detected_apis:
                    findings.append(Finding(
                        category="active_content",
                        severity=api["severity"],
                        title=f"DEX API: {api['title']}",
                        description=f"Dalvik bytecode invokes {api['title']} ({api['count']} references).",
                        details=api
                    ))

                crit_count = sum(1 for f in findings if f.severity == "critical")
                high_count = sum(1 for f in findings if f.severity == "high")
                score = min(100, crit_count * 30 + high_count * 15)
                data["risk_score"] = score
                data["risk_level"] = "CRITICAL" if score >= 60 else ("HIGH" if score >= 35 else "MEDIUM")

        except Exception as e:
            findings.append(Finding(
                category="structure",
                severity="high",
                title="Corrupted Dalvik Executable (DEX)",
                description=str(e)
            ))

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )

    def _categorize_all_strings(self, strings_set: Set[str], data: Dict[str, Any]):
        """Categorize extracted strings into IOCs, API keys, shell commands, and crypto."""
        urls = set()
        ips = set()
        secrets = []
        shell_cmds = set()
        crypto = set()
        paths = set()
        suspicious_apis = set()

        url_pat = re.compile(r'https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\'"<>\\]*)?', re.I)
        ip_pat = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        google_api = re.compile(r'AIza[0-9A-Za-z-_]{35}')
        aws_key = re.compile(r'AKIA[0-9A-Z]{16}')
        jwt_token = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
        sh_pat = re.compile(r'\b(su|/system/bin/su|/bin/sh|/bin/bash|busybox|chmod|chown|mount|reboot)\b')

        for s in strings_set:
            if len(s) < 3 or len(s) > 500:
                continue

            for u in url_pat.findall(s):
                if not any(ign in u.lower() for ign in ["schemas.android.com", "w3.org", "apache.org"]):
                    urls.add(u)
            for ip in ip_pat.findall(s):
                if not ip.startswith(("0.", "127.", "255.", "192.168.", "10.")):
                    ips.add(ip)

            if google_api.search(s):
                secrets.append({"type": "Google Cloud API Key", "value": s[:40]})
            elif aws_key.search(s):
                secrets.append({"type": "AWS Access Key ID", "value": s[:20]})
            elif jwt_token.search(s):
                secrets.append({"type": "JSON Web Token (JWT)", "value": s[:45] + "..."})

            if sh_pat.search(s):
                shell_cmds.add(s[:50])

            if any(c in s for c in ["AES/ECB", "DES/ECB", "RSA/ECB", "MD5", "SHA-256", "TrustAll"]):
                crypto.add(s)

            if s.startswith(("/data/data/", "/system/", "/proc/", "/sdcard/")):
                paths.add(s)

            if any(a in s for a in ["SmsManager", "MediaRecorder", "Camera", "DexClassLoader", "AccessibilityService"]):
                suspicious_apis.add(s)

        data["categorized_strings"] = {
            "total_count": len(strings_set),
            "urls": sorted(list(urls))[:100],
            "ips": sorted(list(ips))[:100],
            "secrets_and_keys": secrets[:20],
            "shell_commands": sorted(list(shell_cmds))[:40],
            "crypto_algorithms": sorted(list(crypto))[:40],
            "sensitive_paths": sorted(list(paths))[:40],
            "suspicious_apis": sorted(list(suspicious_apis))[:40]
        }
        data["iocs"]["urls"] = data["categorized_strings"]["urls"]
        data["iocs"]["ips"] = data["categorized_strings"]["ips"]

    def _build_security_audit(self, data: Dict[str, Any]):
        """Construct automated security compliance and vulnerability audit checklist."""
        audit = []

        # 1. Debuggable
        is_debug = data["security_flags"].get("debuggable", False)
        audit.append({
            "check": "Debuggable Mode",
            "status": "FAIL" if is_debug else "PASS",
            "severity": "critical" if is_debug else "info",
            "title": "Application Debug Mode (android:debuggable)",
            "description": "Debuggable apps allow runtime memory manipulation, code injection, and ptrace attachment via JDWP.",
            "recommendation": "Set android:debuggable=\"false\" in release builds."
        })

        # 2. Backup Allowed
        is_backup = data["security_flags"].get("allowBackup", False)
        audit.append({
            "check": "Application Backup",
            "status": "WARN" if is_backup else "PASS",
            "severity": "high" if is_backup else "info",
            "title": "Application Sandbox Backup (android:allowBackup)",
            "description": "Allowing backup enables unauthorized extraction of private SQLite databases and credentials via adb backup.",
            "recommendation": "Set android:allowBackup=\"false\" unless cloud backup is specifically required."
        })

        # 3. Cleartext Traffic
        nsc = data.get("network_security_config", {})
        is_cleartext = data["security_flags"].get("usesCleartextTraffic", False) or nsc.get("cleartext_permitted", False)
        audit.append({
            "check": "Cleartext Network Traffic",
            "status": "FAIL" if is_cleartext else "PASS",
            "severity": "high" if is_cleartext else "info",
            "title": "Cleartext HTTP Network Traffic",
            "description": "Plain HTTP traffic transmits sensitive user data unencrypted across the network, vulnerable to MitM intercept.",
            "recommendation": "Enforce HTTPS traffic and use network_security_config.xml."
        })

        # 4. Code Signing Debug Keystore
        is_debug_keystore = data["signing_info"].get("is_debug_key", False)
        audit.append({
            "check": "Code Signing Integrity",
            "status": "FAIL" if is_debug_keystore else "PASS",
            "severity": "high" if is_debug_keystore else "info",
            "title": "Release Keystore Signing Verification",
            "description": "Public Android Debug Keystores (CN=Android Debug) lack release verification and should never be deployed in production.",
            "recommendation": "Sign production APKs with a secure, private X.509 release keystore."
        })

        # 5. Exported Components
        exp_count = sum(len(data["exported_components"][k]) for k in ["activities", "services", "receivers", "providers"])
        audit.append({
            "check": "IPC Attack Surface",
            "status": "WARN" if exp_count > 5 else "PASS",
            "severity": "medium" if exp_count > 5 else "info",
            "title": f"Exported Components Surface ({exp_count} Exported)",
            "description": "Exported activities and services can be invoked by any other application on the Android device.",
            "recommendation": "Set android:exported=\"false\" on internal components or enforce custom android:permission."
        })

        # 6. Dynamic Code Loading
        has_dropper = any("Dynamic DEX" in a["title"] for a in data["dex_info"]["detected_apis"])
        audit.append({
            "check": "Dynamic Code Loading",
            "status": "FAIL" if has_dropper else "PASS",
            "severity": "critical" if has_dropper else "info",
            "title": "Runtime Bytecode Loading (DexClassLoader)",
            "description": "Dynamic classloading can download and execute secondary untrusted code bypassing static scanning.",
            "recommendation": "Avoid loading secondary bytecode at runtime or enforce cryptographic hash verification."
        })

        # 7. Accessibility Service
        has_access = any("BIND_ACCESSIBILITY_SERVICE" in p for p in data["permissions"])
        audit.append({
            "check": "Accessibility Abuse",
            "status": "FAIL" if has_access else "PASS",
            "severity": "critical" if has_access else "info",
            "title": "Accessibility Service Permissions",
            "description": "Accessibility permissions allow automated UI interaction, screen scraping, and keylogging.",
            "recommendation": "Do not request accessibility services unless application is a genuine accessibility aid."
        })

        # 8. Overlay Cloaking
        has_overlay = any("SYSTEM_ALERT_WINDOW" in p for p in data["permissions"])
        audit.append({
            "check": "Screen Overlay Hijacking",
            "status": "WARN" if has_overlay else "PASS",
            "severity": "high" if has_overlay else "info",
            "title": "Draw On Top of Other Apps (SYSTEM_ALERT_WINDOW)",
            "description": "Can be used to draw spoofed login overlays on top of banking and credential screens.",
            "recommendation": "Use standard dialogs rather than SYSTEM_ALERT_WINDOW overlay layers."
        })

        # 9. Network Security Config & User CAs (MitM Protection)
        if nsc.get("found"):
            if nsc.get("trusts_user_certs"):
                audit.append({
                    "check": "User CA Trust Anchors",
                    "status": "FAIL",
                    "severity": "critical",
                    "title": "User-Installed CA Certificates Trusted (<certificates src=\"user\" />)",
                    "description": "Application trusts user-installed certificates, allowing adversaries or network proxy tools to decrypt all TLS traffic via custom root CAs.",
                    "recommendation": "Restrict trust anchors exclusively to system certificates: <trust-anchors><certificates src=\"system\" /></trust-anchors>."
                })
            else:
                audit.append({
                    "check": "User CA Trust Anchors",
                    "status": "PASS",
                    "severity": "info",
                    "title": "User CA Trust Restricting (Production Compliant)",
                    "description": "Application enforces system CA trust anchors only, preventing user-installed root CA traffic interception.",
                    "recommendation": "Maintain system-only trust anchors for production release builds."
                })
        else:
            audit.append({
                "check": "Network Security Config",
                "status": "WARN",
                "severity": "medium",
                "title": "Missing Network Security Config (network_security_config.xml)",
                "description": "No network security config XML declared, defaulting to platform default certificate validation behavior.",
                "recommendation": "Declare res/xml/network_security_config.xml and enforce HTTPS with certificate pinning."
            })

        # 10. Cryptographic Robustness
        has_weak_crypto = any(a.get("category") == "crypto" and a.get("severity") in ["critical", "high"] for a in data["dex_info"]["detected_apis"])
        audit.append({
            "check": "Cryptographic Robustness",
            "status": "FAIL" if has_weak_crypto else "PASS",
            "severity": "high" if has_weak_crypto else "info",
            "title": "Cryptographic Algorithm Hardening (ECB / Broken Hashes)",
            "description": "Checks for obsolete symmetric ciphers (DES/RC4/Blowfish), broken hash digests (MD5/SHA-1), and ECB cipher modes.",
            "recommendation": "Migrate all cryptographic operations to AES-256-GCM and SHA-256/SHA-512."
        })

        # 11. Official Store Authenticity
        ps_status = data.get("online_intel", {}).get("play_store_status")
        if ps_status == "verified":
            audit.append({
                "check": "Store Authenticity",
                "status": "PASS",
                "severity": "info",
                "title": "Verified Google Play Store Application",
                "description": f"Package identity '{data.get('package_name')}' is indexed and verified in Google Play Store.",
                "recommendation": "Maintain signature consistency and key rotation through Play App Signing."
            })
        elif ps_status == "unlisted_sideloaded":
            audit.append({
                "check": "Store Authenticity",
                "status": "WARN",
                "severity": "high",
                "title": "Unlisted / Sideloaded Application",
                "description": f"Package identity '{data.get('package_name')}' was not found on Google Play Store (sideloaded distribution).",
                "recommendation": "Verify whether package is intended exclusively for private/enterprise distribution."
            })

        # 12. Janus Vulnerability (CVE-2017-13156)
        is_janus = data.get("keystore_audit", {}).get("janus_vulnerability", False)
        audit.append({
            "check": "Janus Vulnerability (CVE-2017-13156)",
            "status": "FAIL" if is_janus else "PASS",
            "severity": "high" if is_janus else "info",
            "title": "Janus APK Signature Scheme Immunity",
            "description": "Vulnerable to DEX header prepending without invalidating signature if signed exclusively with v1 scheme." if is_janus else "Protected by APK Signature Scheme v2/v3 whole-file verification.",
            "recommendation": "Sign APK with APK Signature Scheme v2/v3/v4 to ensure whole-file cryptographic integrity."
        })

        # 13. VPN Traffic Interception
        has_vpn = any("android.net.VpnService" in str(s) or "vpn" in s.get("name", "").lower() for s in data.get("components", {}).get("services", []))
        if has_vpn:
            audit.append({
                "check": "VPN Traffic Interception",
                "status": "FAIL",
                "severity": "critical",
                "title": "Android VpnService Declared",
                "description": "Application can redirect all device traffic through a local proxy loopback, frequently abused by droppers for TLS interception.",
                "recommendation": "Remove VpnService unless application is an approved enterprise VPN client."
            })

        # 14. Binary Protection & Anti-Analysis
        is_packed = data.get("packer_info", {}).get("is_packed", False)
        packer_name = data.get("packer_info", {}).get("packer_name", "None")
        audit.append({
            "check": "Binary Protection & Obfuscation",
            "status": "WARN" if is_packed else "PASS",
            "severity": "medium" if is_packed else "info",
            "title": f"Code Protector Detection ({packer_name if is_packed else 'Standard Packaging'})",
            "description": f"Packer signature detected: {packer_name}" if is_packed else "No commercial packers detected in application root/assets.",
            "recommendation": "Evaluate native unpacker impact on performance and audit dynamic load operations."
        })

        # 15. Archive Structural Integrity & Evasion (Checklist Sec 1)
        arch_sec = data.get("archive_security", {})
        arch_vuln = arch_sec.get("verdict") == "VULNERABLE"
        arch_susp = arch_sec.get("verdict") == "SUSPICIOUS"
        audit.append({
            "check": "Archive Structural Integrity",
            "status": "FAIL" if arch_vuln else ("WARN" if arch_susp else "PASS"),
            "severity": "critical" if arch_vuln else ("high" if arch_susp else "info"),
            "title": f"APK Archive Structure ({arch_sec.get('verdict', 'CLEAN')})",
            "description": "Critical structural anomalies detected (Zip Slip, Zip Bomb, concealed executables, or polyglot headers)." if arch_vuln else ("Suspicious archive structures (trailing data, duplicate entries, or nested archives)." if arch_susp else "ZIP container structure and entry metadata comply with standard Android packaging conventions."),
            "recommendation": "Inspect and sanitize archive entry paths and remove polyglots or hidden executables."
        })

        # 16. Sensitive Permission Combinations (Checklist Sec 2 & 3)
        combos = data.get("sensitive_permission_combos", [])
        has_combos = len(combos) > 0
        audit.append({
            "check": "Sensitive Permission Combinations",
            "status": "FAIL" if any(c["severity"] == "critical" for c in combos) else ("WARN" if has_combos else "PASS"),
            "severity": "critical" if any(c["severity"] == "critical" for c in combos) else ("high" if has_combos else "info"),
            "title": f"Permission Synergy Analysis ({len(combos)} Dangerous Combos Detected)" if has_combos else "Permission Synergy Compliant",
            "description": f"Detected malicious permission synergies: {', '.join(c['title'] for c in combos[:2])}." if has_combos else "No hazardous permission pairings (e.g. autostart+SMS, overlay+accessibility, mic+camera) detected.",
            "recommendation": "Decouple dangerous permission pairings and adhere to the principle of least privilege."
        })

        # 17. Deep Links & Custom Schemes (Checklist Sec 2 & 3)
        deep_links = data.get("deep_links", [])
        exported_custom = [dl for dl in deep_links if dl.get("is_custom_scheme") and dl.get("exported")]
        sample_schemes = ', '.join(f"{d.get('scheme')}://" for d in exported_custom[:3])
        audit.append({
            "check": "Deep Link IPC Attack Surface",
            "status": "WARN" if exported_custom else "PASS",
            "severity": "medium" if exported_custom else "info",
            "title": f"Deep Link Custom Schemes ({len(exported_custom)} Exported Custom Schemes)" if exported_custom else "Deep Links Secure",
            "description": f"Exported activities handle custom URL schemes ({sample_schemes}), exposed to app link spoofing and untrusted parameter injection." if exported_custom else "Deep links enforce standard HTTPS app links or non-exported handlers.",
            "recommendation": "Enforce Android App Links with SHA-256 assetlinks.json verification or require permission checks."
        })

        # 18. Hardcoded Secrets & CTF Flags (Checklist Sec 9 & 12)
        sec_info = data.get("secrets_and_ctf", {})
        sec_count = len(sec_info.get("secrets", []))
        flags_count = len(sec_info.get("ctf_flags", []))
        has_secrets = sec_count > 0 or flags_count > 0
        audit.append({
            "check": "Embedded Secrets & CTF Artifacts",
            "status": "FAIL" if sec_count > 0 else ("WARN" if flags_count > 0 else "PASS"),
            "severity": "critical" if sec_count > 0 else ("high" if flags_count > 0 else "info"),
            "title": f"Hardcoded Secrets ({sec_count} Secrets, {flags_count} CTF Flags)" if has_secrets else "No Static Credentials Discovered",
            "description": f"Found embedded sensitive API keys, cloud tokens, or CTF flags in Dalvik bytecode string pool or assets." if has_secrets else "No hardcoded AWS, Google Cloud, private keys, or tokens identified in bytecode strings.",
            "recommendation": "Store sensitive API secrets securely in Android Keystore or fetch dynamically via authenticated backend."
        })

        # 19. Supply Chain & Vulnerable Dependencies (Checklist Sec 8 & 11)
        deps = data.get("dependencies", [])
        vuln_deps = [d for d in deps if d.get("known_vulnerabilities")]
        audit.append({
            "check": "Supply Chain & Dependency Security",
            "status": "FAIL" if vuln_deps else "PASS",
            "severity": "critical" if vuln_deps else "info",
            "title": f"Third-Party SDK Vulnerabilities ({len(vuln_deps)} Vulnerable SDKs Detected)" if vuln_deps else f"Third-Party SDKs ({len(deps)} Identified, All Clean)",
            "description": f"Identified bundled libraries with known CVE advisories: {', '.join(d['name'] for d in vuln_deps)}." if vuln_deps else f"Detected {len(deps)} third-party Android libraries/frameworks with no active known CVE advisories.",
            "recommendation": "Update outdated third-party SDKs to secure patched versions."
        })

        data["security_audit"] = audit

    def _analyze_network_security_config(self, zf: zipfile.ZipFile, data: Dict[str, Any], findings: List[Finding]):
        """
        Parses and audits Android Network Security Configuration (res/xml/network_security_config.xml).
        Detects cleartext traffic permissions, user CA trust anchors (MitM vulnerability),
        and certificate pinning policies.
        """
        nsc_data = {
            "found": False,
            "config_file": "",
            "cleartext_permitted": False,
            "trusts_user_certs": False,
            "has_pinning": False,
            "details": []
        }

        namelist = zf.namelist()
        target_file = None
        for name in namelist:
            if "network_security_config" in name.lower():
                target_file = name
                break

        if not target_file:
            for name in namelist:
                if name.startswith("res/xml/") and name.endswith(".xml"):
                    try:
                        raw = zf.read(name)
                        if b"network-security-config" in raw or b"cleartextTrafficPermitted" in raw or b"trust-anchors" in raw:
                            target_file = name
                            break
                    except Exception:
                        pass

        if not target_file:
            data["network_security_config"] = nsc_data
            return

        try:
            raw_bytes = zf.read(target_file)
            nsc_data["found"] = True
            nsc_data["config_file"] = target_file

            # Extract strings either from binary AXML or plaintext XML
            extracted_strings = []
            if raw_bytes.startswith(b"\x03\x00\x08\x00"):
                decoder = AxmlDecoder(raw_bytes)
                if decoder.decode():
                    extracted_strings = decoder.strings
            else:
                txt = raw_bytes.decode("utf-8", errors="ignore")
                extracted_strings = [txt]

            joined_text = " ".join(extracted_strings).lower()

            # Check 1: Cleartext Traffic Permitted
            if "cleartexttrafficpermitted" in joined_text:
                if re.search(r'cleartexttrafficpermitted["\s:=]+true', joined_text) or ('cleartexttrafficpermitted' in joined_text and 'true' in joined_text):
                    nsc_data["cleartext_permitted"] = True
                    nsc_data["details"].append("Cleartext HTTP traffic is explicitly permitted in network security configuration.")
                    findings.append(Finding(
                        category="network",
                        severity="high",
                        title="Network Security Config: Cleartext HTTP Permitted",
                        description=f"Configuration '{target_file}' explicitly permits unencrypted cleartext HTTP traffic (cleartextTrafficPermitted=true).",
                        details={"config_file": target_file, "cwe": "CWE-319", "owasp": "M3: Insecure Communication"}
                    ))

            # Check 2: Trust User Certificates (User CA Trust Anchor)
            if "certificates" in joined_text and "user" in joined_text:
                nsc_data["trusts_user_certs"] = True
                nsc_data["details"].append("Trusts user-installed CA certificates (<certificates src=\"user\" />), enabling trivial Man-in-the-Middle (MitM) TLS interception via custom root CAs.")
                findings.append(Finding(
                    category="network",
                    severity="critical",
                    title="Network Security Config: User CAs Trusted (MitM Vulnerability)",
                    description=f"Configuration '{target_file}' trusts user-installed certificate authorities. Attackers or proxy tools can decrypt all HTTPS traffic.",
                    details={"config_file": target_file, "cwe": "CWE-295", "owasp": "M3: Insecure Communication"}
                ))

            # Check 3: Certificate Pinning
            if "pin-set" in joined_text or ("pin" in joined_text and "digest" in joined_text):
                nsc_data["has_pinning"] = True
                nsc_data["details"].append("Certificate public key pinning (<pin-set>) is configured.")
            else:
                nsc_data["details"].append("No certificate public key pinning (<pin-set>) defined in configuration.")

        except Exception as e:
            logger.debug(f"Network security config parsing error: {e}")

        data["network_security_config"] = nsc_data

    def _parse_x509_certificate(self, cert_bytes: bytes, sig_info: Dict[str, Any], findings: List[Finding]):
        """Extract and inspect X.509 certificate from PKCS#7 block in META-INF/*.RSA."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = None
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            except Exception:
                start = cert_bytes.find(b"\x30\x82")
                while start != -1:
                    try:
                        seq_len = struct.unpack_from(">H", cert_bytes, start + 2)[0]
                        candidate = cert_bytes[start:start + seq_len + 4]
                        cert = x509.load_der_x509_certificate(candidate, default_backend())
                        if cert:
                            break
                    except Exception:
                        pass
                    start = cert_bytes.find(b"\x30\x82", start + 1)

            if cert:
                subject_str = cert.subject.rfc4514_string()
                issuer_str = cert.issuer.rfc4514_string()
                sha256_fp = hashlib.sha256(cert.public_bytes(x509.Encoding.DER)).hexdigest()

                sig_info["subject"] = subject_str
                sig_info["issuer"] = issuer_str
                sig_info["serial_number"] = str(cert.serial_number)
                sig_info["valid_from"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
                sig_info["valid_until"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)
                sig_info["sha256_fingerprint"] = sha256_fp

                if "Android Debug" in subject_str or "Android Debug" in issuer_str or "CN=Android Debug" in subject_str:
                    sig_info["is_debug_key"] = True
                    findings.append(Finding(
                        category="signature",
                        severity="high",
                        title="Android Debug Signing Certificate Detected",
                        description="Application is signed with a public development Android Debug keystore (CN=Android Debug). Debug builds lack release integrity safeguards and should never be deployed in production.",
                        details=sig_info
                    ))

                if subject_str == issuer_str:
                    sig_info["is_self_signed"] = True

        except Exception as e:
            logger.debug(f"Certificate parsing note: {e}")

    def _detect_packers(self, namelist: List[str], data: Dict[str, Any], findings: List[Finding]):
        """Detects known Android application packers, protectors, and dynamic unpackers."""
        for packer in ANDROID_PACKERS:
            matched = []
            for marker in packer["markers"]:
                for n in namelist:
                    if marker in n or n.endswith(marker):
                        matched.append(n)
            if matched:
                data["packer_info"] = {
                    "is_packed": True,
                    "packer_name": packer["name"],
                    "matched_markers": matched[:5],
                    "description": packer["description"]
                }
                findings.append(Finding(
                    category="evasion",
                    severity="high",
                    title=f"Code Protector / Packer Detected: {packer['name']}",
                    description=f"APK contains binary artifacts matching {packer['name']}: {', '.join(matched[:3])}. {packer['description']}",
                    details={"packer": packer["name"], "artifacts": matched[:5]}
                ))
                break

    def _detect_specialized_malware_signatures(self, andro_apk: Any, data: Dict[str, Any], findings: List[Finding]):
        """Detects specialized Android malware family behaviors: Banking Trojans, SMS Stealers, RATs, and VPN Hijacking."""
        signatures = []
        perms = set(data.get("permissions", []))
        detected_apis = {a["title"] for a in data.get("dex_info", {}).get("detected_apis", [])}

        # 1. Android VPN Service Hijacking / Local Proxy Dropper
        vpn_services = []
        if andro_apk is not None:
            try:
                for s in andro_apk.get_services():
                    filters = andro_apk.get_intent_filters("service", s)
                    if "android.net.VpnService" in filters.get("action", []):
                        vpn_services.append(s)
            except Exception:
                pass
        if not vpn_services:
            for s in data.get("components", {}).get("services", []):
                s_name = s.get("name", "")
                if "vpn" in s_name.lower():
                    vpn_services.append(s_name)

        if vpn_services:
            sig = {
                "family": "VPN Proxy / Traffic Interceptor",
                "title": "VPN-Hijacking Proxy / MitM Service",
                "severity": "critical",
                "description": "Registers an Android VpnService to establish a local proxy tunnel. In banking droppers, this is leveraged to bypass SSL pinning and intercept banking API communications.",
                "indicators": vpn_services
            }
            signatures.append(sig)
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title="Malware Signature: VPN-Hijacking Proxy / Local Interceptor (android.net.VpnService)",
                description=f"Service '{vpn_services[0]}' registers 'android.net.VpnService'. Allows the application to route all device network traffic through a local loopback to decrypt, inspect, and tamper with banking API traffic.",
                details={"services": vpn_services}
            ))

        # 2. Banking Trojan Overlay Cloaking & Task Enumeration
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms or "SYSTEM_ALERT_WINDOW" in str(perms)
        has_access = any("ACCESSIBILITY" in p for p in perms)
        has_task_enum = any("Task" in a or "Process" in a for a in detected_apis) or any("getRunningAppProcesses" in s for s in data.get("categorized_strings", {}).get("suspicious_apis", []))

        if has_overlay and (has_access or has_task_enum):
            sig = {
                "family": "Banking Trojan (Overlay & Credential Stealer)",
                "title": "Screen Overlay Hijacking & Background Task Monitoring",
                "severity": "critical",
                "description": "Combines SYSTEM_ALERT_WINDOW overlay permissions with accessibility or process monitoring to detect when targeted banking apps open and inject fraudulent login overlays.",
                "indicators": ["SYSTEM_ALERT_WINDOW", "Accessibility/Task Enumeration"]
            }
            signatures.append(sig)
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title="Malware Signature: Android Banking Trojan (Overlay Cloaking & Task Hijacking)",
                description="Application combines overlay drawing permissions with accessibility services or task enumeration APIs. Characteristic of banking trojans (e.g., Anatsa, TeaBot, Godfather) injecting spoofed credential login screens over banking applications.",
                details={"has_overlay": has_overlay, "has_access": has_access, "has_task_enum": has_task_enum}
            ))

        # 3. 2FA Interceptor & SMS Stealer
        has_sms_rcv = "android.permission.RECEIVE_SMS" in perms or "RECEIVE_SMS" in str(perms)
        has_notif_listener = any("NotificationListenerService" in s.get("name", "") for s in data.get("components", {}).get("services", []))
        if andro_apk is not None and not has_notif_listener:
            try:
                for s in andro_apk.get_services():
                    filters = andro_apk.get_intent_filters("service", s)
                    if "android.service.notification.NotificationListenerService" in filters.get("action", []):
                        has_notif_listener = True
            except Exception:
                pass

        if has_sms_rcv or has_notif_listener:
            sig = {
                "family": "SMS Stealer / 2FA Interceptor",
                "title": "2FA SMS Interception & Notification Scraping",
                "severity": "critical",
                "description": "Intersects SMS traffic or registers a NotificationListenerService to intercept incoming One-Time Passwords (OTPs) and banking verification codes.",
                "indicators": ["RECEIVE_SMS" if has_sms_rcv else "", "NotificationListenerService" if has_notif_listener else ""]
            }
            signatures.append(sig)
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title="Malware Signature: 2FA Interceptor & SMS Stealer (Priority Hijacking / Notification Scraping)",
                description="Application declares SMS intercept capability or NotificationListenerService to harvest incoming authentication codes without user awareness.",
                details={"has_sms_rcv": has_sms_rcv, "has_notif_listener": has_notif_listener}
            ))

        # 4. Android RAT & Spyware
        has_audio = "android.permission.RECORD_AUDIO" in perms or "RECORD_AUDIO" in str(perms)
        has_camera = "android.permission.CAMERA" in perms or "CAMERA" in str(perms)
        has_location = any("LOCATION" in p for p in perms)
        has_keylog = any("Accessibility" in a for a in detected_apis) or any("getText" in s for s in data.get("categorized_strings", {}).get("suspicious_apis", []))

        if (has_audio or has_camera) and has_location and (has_access or has_keylog):
            sig = {
                "family": "Spyware / Remote Access Trojan (RAT)",
                "title": "Surreptitious Audio/Camera Recording & Keylogging",
                "severity": "critical",
                "description": "Requests covert media recording, continuous geolocation tracking, and accessibility-based keystroke capture, characteristic of Android RATs (e.g., SpyNote, AhMyth, CraxsRAT).",
                "indicators": ["RECORD_AUDIO/CAMERA", "LOCATION", "Accessibility Keylogging"]
            }
            signatures.append(sig)
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title="Malware Signature: Android Remote Access Trojan (RAT) / Keylogger",
                description="Application combines background microphone/camera access, continuous GPS location tracking, and accessibility event monitoring to operate as an intrusive surveillance RAT.",
                details={"audio": has_audio, "camera": has_camera, "location": has_location, "keylogging": has_keylog}
            ))

        # 5. Device Administrator Anti-Uninstall Persistence
        has_dev_admin = any("DeviceAdminReceiver" in r.get("name", "") for r in data.get("components", {}).get("receivers", []))
        if has_dev_admin:
            sig = {
                "family": "Anti-Uninstall Persistence",
                "title": "Device Administrator Elevation",
                "severity": "high",
                "description": "Declares DeviceAdminReceiver to hijack administrative device policy, preventing standard application uninstallation.",
                "indicators": ["DeviceAdminReceiver"]
            }
            signatures.append(sig)
            findings.append(Finding(
                category="evasion",
                severity="high",
                title="Malware Signature: Device Administrator Hijacking (Anti-Uninstall Persistence)",
                description="Application registers DeviceAdminReceiver. Malware abuses device administrator privileges to block users from uninstalling the package through Android system settings.",
                details={"has_dev_admin": True}
            ))

        data["malware_signatures"] = signatures

    def _audit_keystore_vulnerabilities(self, data: Dict[str, Any], findings: List[Finding]):
        """Audits signing keystore authenticity, brand masquerading, validity spans, and Janus vulnerability."""
        sig_info = data.get("signing_info", {})
        issuer = sig_info.get("issuer", "")
        subject = sig_info.get("subject", "")
        pkg = data.get("package_name", "")
        v1 = sig_info.get("has_v1_signature", False)
        v2v3 = sig_info.get("has_v2_or_v3_signature", False)
        min_sdk = data.get("min_sdk")

        keystore_audit = {
            "is_aosp_debug_testkey": sig_info.get("is_debug_key", False),
            "is_masquerading_identity": False,
            "masquerade_details": "",
            "validity_anomaly": False,
            "validity_details": "",
            "janus_vulnerability": False,
            "janus_details": ""
        }

        # Check Brand Masquerading / Certificate Spoofing
        known_orgs = {
            "wikimedia": "org.wikipedia",
            "google": "com.google",
            "microsoft": "com.microsoft",
            "apple": "com.apple",
            "whatsapp": "com.whatsapp",
            "telegram": "org.telegram",
            "facebook": "com.facebook"
        }
        subj_lower = (subject + " " + issuer).lower()
        for org, expected_pkg in known_orgs.items():
            if org in subj_lower and not pkg.startswith(expected_pkg):
                keystore_audit["is_masquerading_identity"] = True
                keystore_audit["masquerade_details"] = f"Certificate claims '{org.capitalize()}' identity in Subject/Issuer, but application package '{pkg}' does not belong to {expected_pkg}."
                findings.append(Finding(
                    category="signing",
                    severity="high",
                    title="Certificate Identity Masquerading / Spoofed Subject",
                    description=keystore_audit["masquerade_details"],
                    details={"issuer": issuer, "subject": subject, "package_name": pkg}
                ))
                break

        # Check Janus Vulnerability (CVE-2017-13156)
        min_sdk_int = int(min_sdk) if min_sdk and str(min_sdk).isdigit() else 21
        if v1 and not v2v3 and min_sdk_int < 28:
            keystore_audit["janus_vulnerability"] = True
            keystore_audit["janus_details"] = "APK is signed exclusively with APK Signature Scheme v1 without v2/v3 block. Vulnerable to Janus (CVE-2017-13156) allowing malicious Dalvik bytecode to be prepended to the APK on Android 5.0-7.1.2."
            findings.append(Finding(
                category="signing",
                severity="high",
                title="Janus Vulnerability Susceptibility (CVE-2017-13156)",
                description=keystore_audit["janus_details"],
                details={"has_v1": v1, "has_v2_or_v3": v2v3, "min_sdk": min_sdk}
            ))

        # Check Certificate Validity Span Anomaly
        valid_from = sig_info.get("valid_from", "")
        valid_until = sig_info.get("valid_until", "")
        if valid_from and valid_until:
            try:
                year_from = int(valid_from[:4])
                year_until = int(valid_until[:4])
                span = year_until - year_from
                if span > 35 or span < 0:
                    keystore_audit["validity_anomaly"] = True
                    keystore_audit["validity_details"] = f"Anomalous certificate validity span: {span} years ({valid_from[:10]} to {valid_until[:10]})."
            except Exception:
                pass

        data["keystore_audit"] = keystore_audit

    def _extract_exfiltration_tokens_and_pivot_iocs(self, all_strings: Set[str], data: Dict[str, Any], findings: List[Finding]):
        """Extracts Telegram bot tokens, Discord webhooks, Firebase DBs, and pivots top IoCs through CTI feeds."""
        joined_text = " \n ".join(all_strings)
        exfil = {
            "telegram_bots": [],
            "discord_webhooks": [],
            "firebase_databases": []
        }

        # Telegram Bot Token
        tg_matches = re.findall(r'api\.telegram\.org/bot([0-9]{8,10}:[a-zA-Z0-9_-]{35})', joined_text)
        if tg_matches:
            exfil["telegram_bots"] = list(set(tg_matches))
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title="Covert Exfiltration Channel: Hardcoded Telegram Bot API Token",
                description=f"APK embeds {len(exfil['telegram_bots'])} Telegram Bot token(s). Cybercriminals abuse Telegram Bot APIs as a covert Command & Control (C2) and data exfiltration channel.",
                details={"tokens": [t[:12] + "..." for t in exfil["telegram_bots"]]}
            ))

        # Discord Webhook
        discord_matches = re.findall(r'discord(?:app)?\.com/api/webhooks/([0-9]{17,20}/[a-zA-Z0-9_-]{50,75})', joined_text)
        if discord_matches:
            exfil["discord_webhooks"] = list(set(discord_matches))
            findings.append(Finding(
                category="active_content",
                severity="high",
                title="Covert Exfiltration Channel: Discord Webhook Endpoint",
                description=f"APK embeds {len(exfil['discord_webhooks'])} Discord Webhook(s). Threat actors use Discord webhooks to exfiltrate credentials and device logs.",
                details={"webhooks": [w[:15] + "..." for w in exfil["discord_webhooks"]]}
            ))

        # Firebase Realtime Database
        firebase_matches = re.findall(r'https?://([a-zA-Z0-9-]+)\.firebaseio\.com', joined_text)
        if firebase_matches:
            exfil["firebase_databases"] = list(set(firebase_matches))
            findings.append(Finding(
                category="network",
                severity="medium",
                title="Cloud Backend Endpoint: Firebase Realtime Database",
                description=f"APK references Firebase databases: {', '.join(exfil['firebase_databases'][:3])}. Test if database rules enforce authentication.",
                details={"databases": exfil["firebase_databases"]}
            ))

        data["online_intel"]["exfiltration_tokens"] = exfil

        # Pivot Top Extracted Network IoCs (Domains / IPs) through CTI Aggregator
        ioc_rep = {
            "queried_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "details": []
        }
        candidate_iocs = list(data.get("iocs", {}).get("urls", []))[:3] + list(data.get("iocs", {}).get("ips", []))[:3]
        for ind in candidate_iocs:
            try:
                ind_type = "ip" if re.match(r'^\d+\.\d+\.\d+\.\d+$', ind) else ("url" if ind.startswith("http") else "domain")
                cti = ThreatIntelligenceAggregator.aggregate_intelligence(ind, ind_type)
                ioc_rep["queried_count"] += 1
                if cti.get("overall_verdict") == "malicious":
                    ioc_rep["malicious_count"] += 1
                    findings.append(Finding(
                        category="network",
                        severity="critical",
                        title=f"Embedded Malicious Network IoC ({cti['indicator']})",
                        description=f"Network indicator '{cti['indicator']}' embedded in Dalvik bytecode is confirmed malicious across threat feeds (tags: {', '.join(cti.get('threat_tags', [])[:3])}).",
                        details=cti
                    ))
                elif cti.get("overall_verdict") == "suspicious":
                    ioc_rep["suspicious_count"] += 1
                ioc_rep["details"].append({
                    "indicator": ind,
                    "type": ind_type,
                    "verdict": cti.get("overall_verdict", "unknown"),
                    "tags": cti.get("threat_tags", [])
                })
            except Exception:
                pass

        data["online_intel"]["ioc_reputation"] = ioc_rep

    def _perform_online_reputation_probes(self, sha256_hex: str, data: Dict[str, Any], findings: List[Finding]):
        """Executes live Google Play Store authenticity and multi-feed hash lookups."""
        pkg = data.get("package_name", "")
        # 1. Google Play Store Prober
        if pkg and pkg not in ("Unknown", "Standalone DEX") and "." in pkg:
            try:
                play_res = ThreatIntelligenceAggregator.probe_google_play_store(pkg)
                data["online_intel"]["play_store_status"] = play_res.get("status", "unverified")
                data["online_intel"]["play_store_title"] = play_res.get("title", "")
                data["online_intel"]["play_store_details"] = play_res.get("details", "")

                if play_res.get("status") == "unlisted_sideloaded":
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title="Sideloaded / Unverified Android Application (Not Found on Google Play Store)",
                        description=f"Package identity '{pkg}' is NOT listed in the official Google Play Store directory. Over 95% of Android droppers and banking trojans are distributed out-of-store via sideloading.",
                        details=play_res
                    ))
            except Exception as e:
                logger.debug(f"Play store probe error: {e}")

        # 2. Multi-Feed Hash Threat Intelligence (MalwareBazaar, VirusTotal, CIRCL)
        try:
            cti_res = ThreatIntelligenceAggregator.aggregate_intelligence(sha256_hex, "sha256")
            data["online_intel"]["overall_verdict"] = cti_res.get("overall_verdict", "unknown")
            data["online_intel"]["threat_tags"] = cti_res.get("threat_tags", [])
            data["online_intel"]["malware_families"] = cti_res.get("malware_families", [])
            data["online_intel"]["feeds"] = cti_res.get("feeds", {})

            if cti_res.get("overall_verdict") == "malicious":
                fam_str = ", ".join(cti_res.get("malware_families", [])) or ", ".join(cti_res.get("threat_tags", []))
                findings.append(Finding(
                    category="active_content",
                    severity="critical",
                    title=f"Online Threat Intelligence: Confirmed Malicious Android Binary ({fam_str or 'Malware'})",
                    description=f"File hash '{sha256_hex}' is flagged as malicious across global threat intelligence feeds. Threat families / tags detected: {fam_str or 'Android Dropper'}.",
                    details=cti_res
                ))
        except Exception as e:
            logger.debug(f"Hash CTI probe error: {e}")

    def _inspect_archive_security(self, file_path: Path, zf: zipfile.ZipFile, andro_apk: Any, data: Dict[str, Any], findings: List[Finding]):
        """
        Inspects structural archive security, Zip Slip, duplicate entries, compression ratio,
        concealed executables, polyglot & trailing data, and multi-DEX headers.
        """
        arch_sec = {
            "zip_slip": {"detected": False, "paths": []},
            "decompression_ratio": 1.0,
            "zip_bomb_risk": False,
            "total_uncompressed_bytes": 0,
            "total_compressed_bytes": 0,
            "duplicate_entries": {"detected": False, "entries": []},
            "extension_mismatches": [],
            "polyglot_and_trailing": {
                "has_trailing_data": False,
                "trailing_bytes_count": 0,
                "has_prepended_header": False,
                "prepended_type": "",
                "details": ""
            },
            "nested_archives": [],
            "multi_dex_inventory": [],
            "verdict": "CLEAN"
        }

        # 1. Zip Slip / Path Traversal
        slip_paths = []
        for item in zf.infolist():
            fn = item.filename
            if fn.startswith("/") or fn.startswith("\\") or "../" in fn or "..\\" in fn:
                slip_paths.append(fn)
        if slip_paths:
            arch_sec["zip_slip"]["detected"] = True
            arch_sec["zip_slip"]["paths"] = slip_paths[:20]
            findings.append(Finding(
                category="structure",
                severity="critical",
                title="Zip Slip / Path Traversal Vulnerability Detected",
                description=f"APK archive contains {len(slip_paths)} entry path(s) with directory traversal sequences ('../' or absolute paths), enabling arbitrary filesystem overwrites during package extraction.",
                details={"paths": slip_paths[:10]}
            ))

        # 2. Decompression Ratio & Zip Bomb Risk
        total_uncompressed = sum(item.file_size for item in zf.infolist())
        total_compressed = sum(item.compress_size for item in zf.infolist())
        arch_sec["total_uncompressed_bytes"] = total_uncompressed
        arch_sec["total_compressed_bytes"] = total_compressed
        if total_compressed > 0:
            ratio = total_uncompressed / total_compressed
            arch_sec["decompression_ratio"] = round(ratio, 2)
            if ratio > 50 and total_uncompressed > 20 * 1024 * 1024:
                arch_sec["zip_bomb_risk"] = True
                findings.append(Finding(
                    category="structure",
                    severity="critical",
                    title="Zip Bomb / High Decompression Ratio Detected",
                    description=f"APK exhibits an abnormal compression ratio of {ratio:.1f}:1 ({total_uncompressed / (1024*1024):.1f} MB uncompressed vs {total_compressed / (1024*1024):.1f} MB compressed), risking Denial of Service / resource exhaustion.",
                    details={"ratio": round(ratio, 2), "uncompressed": total_uncompressed, "compressed": total_compressed}
                ))

        # 3. Duplicate Central Directory Entries
        raw_names = zf.namelist()
        name_counts = Counter(raw_names)
        dups = [name for name, count in name_counts.items() if count > 1]
        if dups:
            arch_sec["duplicate_entries"]["detected"] = True
            arch_sec["duplicate_entries"]["entries"] = dups[:20]
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Duplicate ZIP Archive Entries Detected",
                description=f"Archive contains {len(dups)} duplicate entry name(s) ({', '.join(dups[:3])}). Ambiguities in central directory parsing can be exploited to bypass security scanners or deliver alternate payloads to different Android runtime loaders.",
                details={"duplicates": dups[:10]}
            ))

        # 4. Extension & Magic Byte Mismatches (Concealed Executables)
        mismatches = []
        for item in zf.infolist()[:120]:
            if item.is_dir() or item.file_size < 4:
                continue
            fn = item.filename
            fn_lower = fn.lower()
            ext = Path(fn_lower).suffix
            if ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".wav", ".txt", ".json", ".xml", ".dat", ".bin", ".pdf", ".svg", ".properties"]:
                try:
                    head = zf.read(fn)[:64]
                    if head.startswith(b"\x7fELF"):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "ELF Shared Library / Executable (.so)",
                            "magic_hex": head[:8].hex(),
                            "reason": "Embedded native ELF executable disguised with benign non-executable extension."
                        })
                    elif head.startswith(b"dex\n"):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "Dalvik Executable (.dex)",
                            "magic_hex": head[:8].hex(),
                            "reason": "Dalvik bytecode executable disguised with benign non-executable extension."
                        })
                    elif head.startswith(b"PK\x03\x04") and not fn.startswith("META-INF/"):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "ZIP / APK / JAR Archive",
                            "magic_hex": head[:8].hex(),
                            "reason": "ZIP archive disguised with non-archive extension."
                        })
                    elif head.startswith(b"#!") or (b"/bin/sh" in head or b"/bin/bash" in head):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "Unix Shell Script",
                            "magic_hex": head[:8].hex(),
                            "reason": "Executable shell script disguised with non-script extension."
                        })
                    elif head.startswith(b"MZ"):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "Windows PE Executable (.exe/.dll)",
                            "magic_hex": head[:8].hex(),
                            "reason": "Windows PE binary disguised inside mobile package."
                        })
                    elif head.startswith(b"\xca\xfe\xba\xbe"):
                        mismatches.append({
                            "filename": fn,
                            "declared_ext": ext,
                            "actual_type": "Java Compiled Bytecode (.class)",
                            "magic_hex": head[:8].hex(),
                            "reason": "Compiled Java class file disguised with non-Java extension."
                        })
                except Exception:
                    pass

        arch_sec["extension_mismatches"] = mismatches
        for m in mismatches:
            findings.append(Finding(
                category="evasion",
                severity="critical",
                title=f"Concealed Executable / Extension Mismatch: {Path(m['filename']).name}",
                description=f"Entry '{m['filename']}' declares extension '{m['declared_ext']}', but actual header magic confirms it is a {m['actual_type']}. Hallmark stealth dropper technique.",
                details=m
            ))

        # 5. Polyglot and Trailing Data Inspection
        try:
            file_size = Path(file_path).stat().st_size
            with open(file_path, "rb") as f:
                head = f.read(64)
                if head.startswith(b"dex\n"):
                    arch_sec["polyglot_and_trailing"]["has_prepended_header"] = True
                    arch_sec["polyglot_and_trailing"]["prepended_type"] = "Dalvik DEX (Janus CVE-2017-13156)"
                    arch_sec["polyglot_and_trailing"]["details"] = "File begins with Dalvik DEX header magic (dex\\n) before ZIP structures. Classic Janus Polyglot APK attack (CVE-2017-13156)."
                    findings.append(Finding(
                        category="evasion",
                        severity="critical",
                        title="Janus Polyglot APK Detected (DEX Header Prepended / CVE-2017-13156)",
                        description="APK begins with Dalvik DEX magic (dex\\n) followed by ZIP local headers. This polyglot construct exploits Android ART/Dalvik and PackageManager parser discrepancies to execute modified bytecode without invalidating v1 signatures.",
                        details={"prepended_magic": head[:8].hex()}
                    ))
                elif head.startswith(b"\x7fELF"):
                    arch_sec["polyglot_and_trailing"]["has_prepended_header"] = True
                    arch_sec["polyglot_and_trailing"]["prepended_type"] = "ELF Executable"
                    arch_sec["polyglot_and_trailing"]["details"] = "File begins with ELF executable header magic before ZIP structures."
                    findings.append(Finding(
                        category="evasion",
                        severity="critical",
                        title="ELF Polyglot APK Detected (Prepended Native Binary)",
                        description="APK begins with ELF header magic (\\x7fELF) prepended to ZIP container.",
                        details={"prepended_magic": head[:8].hex()}
                    ))

                # Check trailing data past EOCD
                search_len = min(file_size, 65536)
                f.seek(file_size - search_len)
                tail = f.read(search_len)
                eocd_idx = tail.rfind(b"PK\x05\x06")
                if eocd_idx != -1:
                    eocd_pos = (file_size - search_len) + eocd_idx
                    if eocd_pos + 22 <= file_size:
                        comment_len = struct.unpack_from("<H", tail, eocd_idx + 20)[0]
                        expected_end = eocd_pos + 22 + comment_len
                        if file_size > expected_end + 32:
                            trailing_bytes = file_size - expected_end
                            arch_sec["polyglot_and_trailing"]["has_trailing_data"] = True
                            arch_sec["polyglot_and_trailing"]["trailing_bytes_count"] = trailing_bytes
                            arch_sec["polyglot_and_trailing"]["details"] = f"Archive contains {trailing_bytes} extraneous byte(s) appended after ZIP End of Central Directory."
                            findings.append(Finding(
                                category="evasion",
                                severity="high",
                                title="Extraneous Trailing Data Appended Past ZIP EOCD",
                                description=f"APK contains {trailing_bytes} byte(s) of trailing data appended past the ZIP End of Central Directory. Droppers leverage trailing bytes to store encrypted secondary payloads or C2 configs without corrupting ZIP extraction.",
                                details={"trailing_bytes": trailing_bytes, "expected_end": expected_end, "actual_size": file_size}
                            ))
        except Exception as e:
            logger.debug(f"Polyglot/trailing check error: {e}")

        # 6. Nested Archives
        for item in zf.infolist():
            fn = item.filename
            fn_lower = fn.lower()
            if any(fn_lower.endswith(ext) for ext in [".apk", ".jar", ".zip", ".aar", ".war"]):
                if not fn.startswith("META-INF/"):
                    arch_sec["nested_archives"].append({
                        "filename": fn,
                        "size": item.file_size,
                        "type": Path(fn_lower).suffix[1:].upper()
                    })

        # 7. Multi-DEX Structural Inventory
        dex_items = [i for i in zf.infolist() if i.filename.lower().endswith(".dex")]
        for d_item in dex_items:
            try:
                raw_dex = zf.read(d_item.filename)
                dp = DexParser(raw_dex)
                hdr = dp.get_header_info()
                arch_sec["multi_dex_inventory"].append({
                    "name": d_item.filename,
                    "size": d_item.file_size,
                    "dex_version": hdr.get("version", "035"),
                    "checksum": hdr.get("checksum", ""),
                    "signature": hdr.get("signature", ""),
                    "classes_count": hdr.get("class_defs_size", 0),
                    "strings_count": hdr.get("string_ids_size", 0),
                    "methods_count": hdr.get("method_ids_size", 0),
                    "is_stub": hdr.get("is_stub", False)
                })
            except Exception:
                arch_sec["multi_dex_inventory"].append({
                    "name": d_item.filename,
                    "size": d_item.file_size,
                    "dex_version": "unknown",
                    "checksum": "",
                    "signature": "",
                    "classes_count": 0,
                    "strings_count": 0,
                    "methods_count": 0,
                    "is_stub": d_item.file_size <= 112
                })

        # Overall Archive Security Verdict
        if arch_sec["zip_slip"]["detected"] or arch_sec["zip_bomb_risk"] or len(arch_sec["extension_mismatches"]) > 0 or arch_sec["polyglot_and_trailing"]["has_prepended_header"]:
            arch_sec["verdict"] = "VULNERABLE"
        elif arch_sec["duplicate_entries"]["detected"] or arch_sec["polyglot_and_trailing"]["has_trailing_data"] or len(arch_sec["nested_archives"]) > 0:
            arch_sec["verdict"] = "SUSPICIOUS"
        else:
            arch_sec["verdict"] = "CLEAN"

        data["archive_security"] = arch_sec

    def _evaluate_sensitive_permission_combos(self, data: Dict[str, Any], findings: List[Finding]):
        """Evaluates sensitive combinations of permissions frequently leveraged by malware."""
        perms = set(data.get("permissions", []))
        triggered = []

        for combo in SENSITIVE_PERMISSION_COMBOS:
            req = combo["required"]
            if all(r in perms for r in req):
                any_of = combo.get("any_of")
                if not any_of or any(a in perms for a in any_of):
                    matched_perms = [p for p in perms if p in req or (any_of and p in any_of)]
                    combo_entry = {
                        "id": combo["id"],
                        "title": combo["title"],
                        "severity": combo["severity"],
                        "permissions": matched_perms,
                        "description": combo["description"],
                        "mitre": combo.get("mitre"),
                        "mitre_name": combo.get("mitre_name")
                    }
                    triggered.append(combo_entry)
                    findings.append(Finding(
                        category="permission",
                        severity=combo["severity"],
                        title=f"Sensitive Permission Combination: {combo['title']}",
                        description=f"App simultaneously requests: {', '.join(matched_perms)}. {combo['description']}",
                        details=combo_entry
                    ))

        data["sensitive_permission_combos"] = triggered

    def _detect_sdks_and_generate_sbom(self, all_strings: Set[str], all_dex_classes: List[str], namelist: List[str], sha256_hex: str, data: Dict[str, Any], findings: List[Finding]):
        """Detects third-party Android SDKs and libraries, and generates a CycloneDX v1.4 SBOM."""
        detected_sdks = []
        seen_sdk_ids = set()

        classes_set = set(all_dex_classes)
        joined_classes = " \n ".join(all_dex_classes)
        joined_names = " \n ".join(namelist)

        for sdk in ANDROID_SDK_CATALOG:
            sdk_id = sdk["id"]
            if sdk_id in seen_sdk_ids:
                continue

            matched = False
            for pat in sdk["patterns"]:
                if any(pat in c for c in classes_set) or pat in joined_names or pat in joined_classes:
                    matched = True
                    break
                if not matched:
                    for s in all_strings:
                        if pat in s:
                            matched = True
                            break
                if matched:
                    break

            if matched:
                seen_sdk_ids.add(sdk_id)
                entry = {
                    "id": sdk_id,
                    "name": sdk["name"],
                    "group": sdk["group"],
                    "artifact": sdk["artifact"],
                    "category": sdk["category"],
                    "version": sdk.get("version", "detected"),
                    "description": sdk["description"],
                    "purl": f"pkg:maven/{sdk['group']}/{sdk['artifact']}",
                    "known_vulnerabilities": sdk.get("known_vulnerabilities", [])
                }
                detected_sdks.append(entry)

                if sdk.get("known_vulnerabilities"):
                    for vuln in sdk["known_vulnerabilities"]:
                        findings.append(Finding(
                            category="dependency",
                            severity="critical",
                            title=f"Vulnerable Android Library Dependency: {sdk['name']}",
                            description=f"Application bundles {sdk['name']} with known security advisory: {vuln}.",
                            details={"sdk": sdk["name"], "vulnerability": vuln}
                        ))

        data["dependencies"] = detected_sdks
        data["cyclonedx_sbom"] = generate_cyclonedx_android_sbom(data, detected_sdks, sha256_hex)

    def _scan_secrets_and_ctf(self, all_strings: Set[str], namelist: List[str], zf: Optional[zipfile.ZipFile], data: Dict[str, Any], findings: List[Finding]):
        """Scans Dalvik string pool, manifest, configuration files, and assets for CTF flags and sensitive credentials."""
        ctf_flags = []
        secrets = []
        seen_flags = set()
        seen_secrets = set()

        # 1. CTF Flags in Dalvik bytecode string pool
        for s in all_strings:
            for pat, flag_type in CTF_PATTERNS:
                for match in pat.findall(s):
                    if match not in seen_flags:
                        seen_flags.add(match)
                        ctf_flags.append({
                            "flag": match,
                            "type": flag_type,
                            "source": "Dalvik Bytecode String Pool"
                        })
                        findings.append(Finding(
                            category="security_risk",
                            severity="high",
                            title=f"CTF Flag Captured: {match}",
                            description=f"Discovered {flag_type} embedded directly in Dalvik bytecode string pool: '{match}'.",
                            details={"flag": match, "type": flag_type}
                        ))

        # Check small text assets and XML configs for CTF flags if zf available
        if zf is not None:
            for name in namelist:
                if name.endswith((".xml", ".json", ".txt", ".properties", ".html", ".js")) and not name.startswith("res/drawable"):
                    try:
                        info = zf.getinfo(name)
                        if info.file_size < 200_000:
                            content = zf.read(name).decode("utf-8", errors="ignore")
                            for pat, flag_type in CTF_PATTERNS:
                                for match in pat.findall(content):
                                    if match not in seen_flags:
                                        seen_flags.add(match)
                                        ctf_flags.append({
                                            "flag": match,
                                            "type": flag_type,
                                            "source": name
                                        })
                                        findings.append(Finding(
                                            category="security_risk",
                                            severity="high",
                                            title=f"CTF Flag Captured: {match}",
                                            description=f"Discovered {flag_type} embedded in file '{name}': '{match}'.",
                                            details={"flag": match, "type": flag_type, "file": name}
                                        ))
                    except Exception:
                        pass

        # 2. Hardcoded Secrets & Cloud Credentials
        for s in all_strings:
            if len(s) < 10 or len(s) > 300:
                continue
            for pat, sec_type, sev in SECRET_PATTERNS:
                match = pat.search(s)
                if match:
                    val = match.group(0)
                    if val not in seen_secrets:
                        seen_secrets.add(val)
                        secrets.append({
                            "type": sec_type,
                            "value": val,
                            "severity": sev,
                            "source": "Dalvik Bytecode String Pool"
                        })
                        if sev in ["critical", "high"]:
                            findings.append(Finding(
                                category="security_risk",
                                severity=sev,
                                title=f"Hardcoded Secret: {sec_type}",
                                description=f"Found hardcoded {sec_type} in Dalvik bytecode: '{val[:16]}...'",
                                details={"type": sec_type, "value": val[:30]}
                            ))

        data["secrets_and_ctf"] = {
            "detected": bool(ctf_flags or secrets),
            "ctf_flags": ctf_flags,
            "secrets": secrets,
            "total_count": len(ctf_flags) + len(secrets)
        }
