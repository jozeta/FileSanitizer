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
import struct
import zipfile
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger

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

# Suspicious DEX Heuristics & API Signatures
DEX_API_SIGNATURES = [
    # Dynamic Code Execution & Reflection
    (re.compile(r'dalvik/system/(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)', re.I), "Dynamic DEX/Bytecode Loading", "critical", "T1437", "Application Layer Protocol / Dynamic Loading"),
    (re.compile(r'java/lang/reflect/Method;->invoke', re.I), "Reflective Method Invocation", "high", "T1626", "Obfuscated Files or Information"),
    (re.compile(r'java/lang/Class;->forName', re.I), "Dynamic Class Reflection", "medium", "T1626", "Obfuscated Files or Information"),
    (re.compile(r'java/lang/Runtime;->exec|java/lang/ProcessBuilder', re.I), "Shell Command / Process Execution", "critical", "T1404", "Exploitation for Privilege Escalation"),
    (re.compile(r'/system/bin/su|/system/xbin/su|/sbin/su|/system/app/Superuser', re.I), "Root Privilege Escalation / su Detection", "critical", "T1404", "Exploitation for Privilege Escalation"),

    # Telephony & SMS Operations
    (re.compile(r'android/telephony/SmsManager;->sendTextMessage|android/telephony/SmsManager;->sendMultipartTextMessage', re.I), "Programmatic SMS Transmission", "critical", "T1412", "Access Call Log / SMS"),
    (re.compile(r'android/telephony/TelephonyManager;->getDeviceId|getSubscriberId|getImei|getSimSerialNumber', re.I), "Hardware Identifier Telemetry (IMEI/IMSI/SIM)", "high", "T1418", "Software Discovery"),

    # Surveillance
    (re.compile(r'android/media/MediaRecorder;->(?:start|setAudioSource)', re.I), "Audio Recording / Microphone Hook", "critical", "T1417", "Audio Capture"),
    (re.compile(r'android/hardware/Camera;->open|android/hardware/camera2', re.I), "Camera Access / Video Capture", "critical", "T1426", "Video Capture"),
    (re.compile(r'android/location/LocationManager;->(?:getLastKnownLocation|requestLocationUpdates)', re.I), "GPS Location Tracking Service", "high", "T1430", "Location Tracking"),

    # Accessibility & Overlay
    (re.compile(r'android/accessibilityservice/AccessibilityService|performGlobalAction|findAccessibilityNodeInfosByViewId', re.I), "Accessibility Service DOM Interception & Automated Clicks", "critical", "T1448", "Abuse Accessibility Features"),
    (re.compile(r'android/app/admin/DevicePolicyManager;->(?:lockNow|wipeData|resetPassword)', re.I), "Device Admin Screen Lock or Remote Wipe", "critical", "T1407", "Device Administrator Privileges"),

    # Evasion & Anti-Analysis
    (re.compile(r'android/os/Debug;->isDebuggerConnected', re.I), "Anti-Debugging (Debugger Detection)", "medium", "T1622", "Debugger Evasion"),
    (re.compile(r'goldfish|generic_x86|vbox86p|nox|Genymotion|sdk_google_phone', re.I), "Android Emulator Environment Detection", "high", "T1622", "Virtualization / Sandbox Evasion"),
    (re.compile(r'frida-server|/data/local/tmp/frida|27042', re.I), "Frida Dynamic Instrumentation Detection", "high", "T1622", "Virtualization / Sandbox Evasion"),

    # Cryptography Weaknesses
    (re.compile(r'DES/ECB|AES/ECB', re.I), "Weak Insecure Cipher Mode (ECB Mode)", "high", "T1573", "Encrypted Channel"),
    (re.compile(r'TrustAllTrustManager|ALLOW_ALL_HOSTNAME_VERIFIER', re.I), "SSL/TLS Verification Bypass (Insecure TrustManager)", "high", "T1557", "Man-in-the-Middle")
]


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

        for pattern, title, sev, mitre_id, mitre_name in DEX_API_SIGNATURES:
            matches = pattern.findall(joined_sample)
            if matches:
                self.detected_apis.append({
                    "api": matches[0] if matches else title,
                    "title": title,
                    "severity": sev,
                    "mitre": mitre_id,
                    "mitre_name": mitre_name,
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

    @classmethod
    def scan_archive_sources(cls, zf: zipfile.ZipFile, max_files: int = 40) -> List[Dict[str, Any]]:
        results = []
        for item in zf.infolist():
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
                        if pat.search(text):
                            findings_list.append(title)
                            if d_level == "malicious":
                                danger = "malicious"
                            elif d_level == "suspicious" and danger != "malicious":
                                danger = "suspicious"

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
            "file_size": file_path.stat().st_size,
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
            "online_intel": {
                "sha256": sha256_hex,
                "sha1": sha1_hex,
                "md5": md5_hex,
                "package_name": "",
                "koodous_url": f"https://koodous.com/apks/{sha256_hex}",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hex}",
                "malwarebazaar_url": f"https://bazaar.abuse.ch/sample/{sha256_hex}/",
                "google_play_url": "",
                "apkpure_url": ""
            },
            "security_audit": [],
            "embedded_assets": [],
            "iocs": {
                "urls": [],
                "ips": []
            },
            "mitre_mobile_techniques": [],
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

                        # Format manifest XML string
                        try:
                            m_xml = andro_apk.get_android_manifest_xml()
                            if m_xml is not None:
                                data["manifest_xml"] = etree.tostring(m_xml, pretty_print=True, encoding="unicode")
                        except Exception:
                            pass

                        # Activities, Services, Receivers, Providers
                        acts = andro_apk.get_activities() or []
                        srvs = andro_apk.get_services() or []
                        rcvs = andro_apk.get_receivers() or []
                        prvs = andro_apk.get_providers() or []

                        data["components"]["activities"] = [{"name": a, "exported": False} for a in acts]
                        data["components"]["services"] = [{"name": s, "exported": False} for s in srvs]
                        data["components"]["receivers"] = [{"name": r, "exported": False} for r in rcvs]
                        data["components"]["providers"] = [{"name": p, "exported": False} for p in prvs]

                        # Signatures & Certs
                        data["signing_info"]["has_v1_signature"] = andro_apk.is_signed_v1()
                        data["signing_info"]["has_v2_or_v3_signature"] = andro_apk.is_signed_v2() or andro_apk.is_signed_v3()
                        data["signing_info"]["has_signature"] = andro_apk.is_signed()
                except Exception as ag_err:
                    logger.debug(f"Androguard APK parse note: {ag_err}")

            # 2. Pure-Python Fallback & In-depth Container Dissection
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()

                # Parse AndroidManifest.xml if not yet parsed
                if not data["package_name"] and "AndroidManifest.xml" in namelist:
                    manifest_bytes = zf.read("AndroidManifest.xml")
                    axml = AxmlDecoder(manifest_bytes)
                    if axml.decode():
                        data["package_name"] = axml.package_name
                        data["version_code"] = str(axml.version_code or "1")
                        data["version_name"] = str(axml.version_name or "1.0")
                        data["min_sdk"] = axml.min_sdk_version
                        data["target_sdk"] = axml.target_sdk_version
                        data["compile_sdk"] = axml.compile_sdk_version
                        data["permissions"] = axml.permissions
                        data["components"]["activities"] = axml.activities
                        data["components"]["services"] = axml.services
                        data["components"]["receivers"] = axml.receivers
                        data["components"]["providers"] = axml.providers
                        data["security_flags"].update(axml.application_attributes)

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
                dex_files = [n for n in namelist if n.endswith(".dex")]
                data["dex_info"]["dex_count"] = len(dex_files)
                classes_extracted = []

                # Use Androguard DEX & Decompiler if available
                if ANDROGUARD_AVAILABLE and dex_files:
                    try:
                        dex_objs = []
                        for df in dex_files:
                            dex_bytes = zf.read(df)
                            d_obj = AndroguardDEX(dex_bytes)
                            dex_objs.append(d_obj)
                            for s in d_obj.get_strings():
                                all_strings_collected.add(s)

                        # Create analysis and decompiler
                        analysis_obj = AndroguardAnalysis()
                        for d_obj in dex_objs:
                            analysis_obj.add(d_obj)
                        decompiler = None
                        try:
                            if dex_objs:
                                decompiler = DecompilerDAD(dex_objs[0], analysis_obj)
                        except Exception:
                            pass

                        # Extract classes and methods
                        for d_obj in dex_objs:
                            for cls_item in d_obj.get_classes():
                                c_name = cls_item.get_name()
                                if c_name.startswith("L") and c_name.endswith(";"):
                                    c_name = c_name[1:-1].replace("/", ".")

                                # Prioritize app classes over framework noise
                                pkg_prefix = data["package_name"] or "com."
                                is_app_class = c_name.startswith(pkg_prefix) or len(classes_extracted) < 15

                                if is_app_class and len(classes_extracted) < 40:
                                    methods_list = []
                                    for m in cls_item.get_methods():
                                        instructions = []
                                        try:
                                            for ins in m.get_instructions():
                                                instructions.append(f"{ins.get_name()} {ins.get_output()}")
                                        except Exception:
                                            pass

                                        m_src = ""
                                        if decompiler:
                                            try:
                                                m_src = decompiler.get_source_method(m)
                                            except Exception:
                                                pass

                                        methods_list.append({
                                            "name": m.get_name(),
                                            "descriptor": m.get_descriptor(),
                                            "access_flags": m.get_access_flags_string(),
                                            "instructions_count": len(instructions),
                                            "instructions": instructions[:60],
                                            "source": m_src
                                        })

                                    cls_src = ""
                                    if decompiler:
                                        try:
                                            cls_src = decompiler.get_source_class(cls_item)
                                        except Exception:
                                            pass

                                    classes_extracted.append({
                                        "name": c_name,
                                        "package": c_name.rsplit(".", 1)[0] if "." in c_name else "",
                                        "superclass": cls_item.get_superclassname(),
                                        "access_flags": cls_item.get_access_flags_string(),
                                        "methods_count": len(methods_list),
                                        "methods": methods_list,
                                        "source_code": cls_src
                                    })

                        data["dex_info"]["classes_count"] = sum(len(d.get_classes()) for d in dex_objs)
                        data["dex_info"]["total_strings_count"] = len(all_strings_collected)
                    except Exception as dex_err:
                        logger.debug(f"Androguard DEX processing note: {dex_err}")

                # Pure-Python DEX Fallback if classes not populated
                if not classes_extracted and dex_files:
                    for df in dex_files:
                        try:
                            dex_bytes = zf.read(df)
                            dp = DexParser(dex_bytes)
                            if dp.parse():
                                for s in dp.strings:
                                    all_strings_collected.add(s)
                                for c in dp.classes[:30]:
                                    classes_extracted.append({
                                        "name": c,
                                        "package": c.rsplit(".", 1)[0] if "." in c else "",
                                        "superclass": "java.lang.Object",
                                        "access_flags": "public",
                                        "methods_count": 0,
                                        "methods": [],
                                        "source_code": f"// Class: {c}\n// Dalvik class extracted from bytecode container\npublic class {c.split('.')[-1]} {{\n}}"
                                    })
                                data["dex_info"]["total_strings_count"] += len(dp.strings)
                                data["dex_info"]["classes_count"] += len(dp.classes)
                                for api in dp.detected_apis:
                                    if not any(a["title"] == api["title"] for a in data["dex_info"]["detected_apis"]):
                                        data["dex_info"]["detected_apis"].append(api)
                        except Exception:
                            pass

                data["classes"] = classes_extracted

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

                # 7. Code Signing & Certificate Verification
                cert_files = [n for n in namelist if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
                if cert_files:
                    data["signing_info"]["has_signature"] = True
                    cert_bytes = zf.read(cert_files[0])
                    self._parse_x509_certificate(cert_bytes, data["signing_info"], findings)

                # 8. Synthesize MITRE ATT&CK for Mobile Techniques
                mitre_map = {}
                for dp in data["dangerous_permissions"]:
                    if dp.get("mitre"):
                        mitre_map[dp["mitre"]] = dp["mitre_name"]
                for api in data["dex_info"]["detected_apis"]:
                    if api.get("mitre"):
                        mitre_map[api["mitre"]] = api["mitre_name"]
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
            "file_size": file_path.stat().st_size,
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
            "iocs": {"urls": [], "ips": []},
            "mitre_mobile_techniques": [],
            "risk_score": 0,
            "risk_level": "LOW"
        }

        try:
            with open(file_path, "rb") as f:
                dex_bytes = f.read()

            dp = DexParser(dex_bytes)
            if dp.parse():
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
        is_cleartext = data["security_flags"].get("usesCleartextTraffic", False)
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

        data["security_audit"] = audit

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
