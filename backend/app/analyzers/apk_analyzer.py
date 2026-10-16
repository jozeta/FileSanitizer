"""
Android Application Package (APK) Forensic Security & Privacy Analyzer.
Analyzes .apk, .aab, .xapk packages and Dalvik Executable (.dex) files.
Evaluates:
- Android Binary XML (AXML) decoding for AndroidManifest.xml
- Package metadata, versioning, and min/target SDK versions
- Security flags: android:debuggable, android:allowBackup, android:usesCleartextTraffic
- Dangerous permissions matrix (SMS, Camera, Microphone, Location, Overlay, Accessibility, Device Admin)
- Application attack surface: Exported Activities, Services, Receivers (BOOT_COMPLETED), Content Providers
- DEX Bytecode analysis: string pools, reflection, dynamic loading, shell commands, SMS/telephony APIs, C2 URLs
- APK Code Signing & Certificate X.509 triage (debug key detection, self-signed checks)
- Native ELF libraries (.so) and embedded assets/payloads
- MITRE ATT&CK for Mobile mapping
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
    "android.permission.READ_CALL_LOG": {
        "title": "Read Telephone Call Logs",
        "severity": "high",
        "category": "telephony",
        "description": "Access to full historical inbound and outbound phone calls, contact names, and call durations.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log"
    },
    "android.permission.WRITE_CALL_LOG": {
        "title": "Modify Telephone Call Logs",
        "severity": "high",
        "category": "telephony",
        "description": "Can alter or delete telephone call history to hide unauthorized incoming or outgoing calls.",
        "mitre": "T1412",
        "mitre_name": "Access Call Log"
    },
    "android.permission.CALL_PHONE": {
        "title": "Initiate Telephone Calls",
        "severity": "high",
        "category": "telephony",
        "description": "Can dial telephone numbers directly without user interaction, potentially incurring toll charges.",
        "mitre": "T1412",
        "mitre_name": "Call Phone"
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "title": "Intercept Outgoing Phone Calls",
        "severity": "high",
        "category": "telephony",
        "description": "Can monitor, redirect, or prevent outgoing phone calls.",
        "mitre": "T1412",
        "mitre_name": "Call Control"
    },
    "android.permission.READ_PHONE_STATE": {
        "title": "Read Phone State & Hardware Identifiers (IMEI/IMSI)",
        "severity": "high",
        "category": "privacy",
        "description": "Can access cellular network information, phone number, carrier, and persistent hardware identifiers (IMEI/IMSI).",
        "mitre": "T1418",
        "mitre_name": "Software Discovery"
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
        "title": "Device Administration Privilege (Ransomware / Anti-Uninstall)",
        "severity": "critical",
        "category": "device_admin",
        "description": "Requests Android Device Administrator access, enabling screen locking, remote wiping, password resets, and preventing app uninstallation.",
        "mitre": "T1407",
        "mitre_name": "Device Administrator Privileges"
    },

    # Persistence & Droppers
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "title": "Auto-Start at Device Boot (Persistence)",
        "severity": "medium",
        "category": "persistence",
        "description": "Automatically wakes up and launches background services as soon as the Android device completes booting.",
        "mitre": "T1402",
        "mitre_name": "Broadcast Receivers"
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "title": "Request Package Installation (Payload Dropper)",
        "severity": "high",
        "category": "dropper",
        "description": "Can prompt users to install secondary APK packages, frequently utilized by trojan droppers to download stage-2 payloads.",
        "mitre": "T1476",
        "mitre_name": "Deliver Malicious App via Other Means"
    },
    "android.permission.INSTALL_PACKAGES": {
        "title": "Silent Package Installation (System Dropper)",
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
        # Extract package name
        pkg_m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', txt)
        if pkg_m:
            self.package_name = pkg_m.group(1)

        # Extract versionCode / versionName
        vc_m = re.search(r'android:versionCode\s*=\s*["\'](\d+)["\']', txt)
        if vc_m:
            self.version_code = int(vc_m.group(1))
        vn_m = re.search(r'android:versionName\s*=\s*["\']([^"\']+)["\']', txt)
        if vn_m:
            self.version_name = vn_m.group(1)

        # Extract SDK versions
        min_sdk = re.search(r'android:minSdkVersion\s*=\s*["\'](\d+)["\']', txt)
        if min_sdk:
            self.min_sdk_version = int(min_sdk.group(1))
        target_sdk = re.search(r'android:targetSdkVersion\s*=\s*["\'](\d+)["\']', txt)
        if target_sdk:
            self.target_sdk_version = int(target_sdk.group(1))

        # Permissions
        for p in re.findall(r'<uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']', txt):
            if p not in self.permissions:
                self.permissions.append(p)

        # Application flags
        if 'android:debuggable="true"' in txt:
            self.application_attributes["debuggable"] = True
        if 'android:allowBackup="true"' in txt:
            self.application_attributes["allowBackup"] = True
        if 'android:usesCleartextTraffic="true"' in txt:
            self.application_attributes["usesCleartextTraffic"] = True

        # Components
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
            _, _, _, string_count, style_count, flags, strings_offset, _ = struct.unpack_from(
                "<HHIIIIII", self.data, offset
            )
            is_utf8 = bool(flags & 0x00000100)
            offsets_start = offset + 28
            str_data_base = offset + strings_offset

            for i in range(string_count):
                if offsets_start + (i + 1) * 4 > len(self.data):
                    break
                s_off = struct.unpack_from("<I", self.data, offsets_start + i * 4)[0]
                target = str_data_base + s_off
                if target >= len(self.data):
                    continue

                if is_utf8:
                    pos = target
                    if self.data[pos] & 0x80:
                        pos += 2
                    else:
                        pos += 1
                    if pos < len(self.data) and (self.data[pos] & 0x80):
                        u8_len = ((self.data[pos] & 0x7F) << 8) | self.data[pos + 1]
                        pos += 2
                    elif pos < len(self.data):
                        u8_len = self.data[pos]
                        pos += 1
                    else:
                        u8_len = 0
                    s_bytes = self.data[pos:pos + u8_len]
                    self.strings.append(s_bytes.decode("utf-8", errors="ignore"))
                else:
                    pos = target
                    u16_char_len = struct.unpack_from("<H", self.data, pos)[0]
                    pos += 2
                    if u16_char_len & 0x8000:
                        u16_char_len = ((u16_char_len & 0x7FFF) << 16) | struct.unpack_from("<H", self.data, pos)[0]
                        pos += 2
                    s_bytes = self.data[pos:pos + u16_char_len * 2]
                    self.strings.append(s_bytes.decode("utf-16le", errors="ignore"))
        except Exception as e:
            logger.debug(f"AXML string pool parse exception: {e}")

    def _get_string(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""

    def _parse_start_tag(self, offset: int) -> Optional[Dict[str, Any]]:
        try:
            _, _, _, line_num, comment, ns_idx, name_idx, attr_start, attr_size, attr_count, _, _, _ = struct.unpack_from(
                "<HHIIIIHHHHHH", self.data, offset
            )
            tag_name = self._get_string(name_idx)
            attrs = {}

            cur_attr_off = offset + attr_start
            for _ in range(attr_count):
                if cur_attr_off + 20 > len(self.data):
                    break
                a_ns, a_name, a_raw_val, a_val_size, a_val_type, a_val_data = struct.unpack_from(
                    "<IIIBBI", self.data, cur_attr_off
                )
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
    Extracts string pool, method calls, API patterns, hardcoded secrets, and network IOCs.
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

            # If string table is empty or truncated, fallback to raw ASCII/UTF-8 string scanning across the bytecode
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

            # Scan extracted strings for URLs, IPs, API patterns
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

        # Detect dangerous API signatures
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


class ApkAnalyzer(BaseAnalyzer):
    """
    Comprehensive forensic analyzer for Android Application Packages (APK).
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
                    # Check ZIP namelist
                    with zipfile.ZipFile(file_path, "r") as zf:
                        nl = zf.namelist()
                        if "AndroidManifest.xml" in nl or any(n.endswith(".dex") for n in nl):
                            return True
        except Exception:
            pass
        return False

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        data: Dict[str, Any] = {
            "is_apk": True,
            "filename": filename,
            "file_size": file_path.stat().st_size,
            "package_name": "",
            "app_name": "",
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "min_sdk_label": "",
            "target_sdk": None,
            "target_sdk_label": "",
            "compile_sdk": None,
            "application_attributes": {},
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
            "signing_info": {
                "has_signature": False,
                "is_debug_key": False,
                "is_self_signed": False,
                "is_expired": False,
                "subject": "",
                "issuer": "",
                "serial_number": "",
                "valid_from": "",
                "valid_until": "",
                "sha256_fingerprint": "",
                "signature_scheme": "v1 (JAR)"
            },
            "dex_info": {
                "dex_count": 0,
                "classes_count": 0,
                "total_strings_count": 0,
                "detected_apis": []
            },
            "native_libraries": [],
            "embedded_assets": [],
            "iocs": {
                "urls": [],
                "ips": []
            },
            "mitre_mobile_techniques": [],
            "risk_score": 0,
            "risk_level": "CLEAN"
        }

        # Check if standalone DEX file
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"dex\n"):
                    return self._analyze_standalone_dex(file_path, filename)
        except Exception:
            pass

        # Parse APK (ZIP container)
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()

                # 1. Parse AndroidManifest.xml
                if "AndroidManifest.xml" in namelist:
                    manifest_bytes = zf.read("AndroidManifest.xml")
                    axml = AxmlDecoder(manifest_bytes)
                    if axml.decode():
                        data["package_name"] = axml.package_name
                        data["version_code"] = axml.version_code
                        data["version_name"] = axml.version_name
                        data["min_sdk"] = axml.min_sdk_version
                        data["min_sdk_label"] = ANDROID_API_LEVELS.get(axml.min_sdk_version, f"API {axml.min_sdk_version}") if axml.min_sdk_version else "Unknown"
                        data["target_sdk"] = axml.target_sdk_version
                        data["target_sdk_label"] = ANDROID_API_LEVELS.get(axml.target_sdk_version, f"API {axml.target_sdk_version}") if axml.target_sdk_version else "Unknown"
                        data["compile_sdk"] = axml.compile_sdk_version
                        data["application_attributes"] = axml.application_attributes

                        # Process permissions
                        data["permissions"] = axml.permissions
                        for p in axml.permissions:
                            p_info = DANGEROUS_PERMISSIONS.get(p)
                            if p_info:
                                data["dangerous_permissions"].append({
                                    "permission": p,
                                    "title": p_info["title"],
                                    "severity": p_info["severity"],
                                    "category": p_info["category"],
                                    "description": p_info["description"],
                                    "mitre": p_info["mitre"],
                                    "mitre_name": p_info["mitre_name"]
                                })

                        # Process components
                        data["components"]["activities"] = axml.activities[:50]
                        data["components"]["activities_count"] = len(axml.activities)
                        data["components"]["exported_activities_count"] = sum(1 for a in axml.activities if a.get("exported") is True)

                        data["components"]["services"] = axml.services[:50]
                        data["components"]["services_count"] = len(axml.services)
                        data["components"]["exported_services_count"] = sum(1 for s in axml.services if s.get("exported") is True)

                        data["components"]["receivers"] = axml.receivers[:50]
                        data["components"]["receivers_count"] = len(axml.receivers)
                        data["components"]["exported_receivers_count"] = sum(1 for r in axml.receivers if r.get("exported") is True)

                        data["components"]["providers"] = axml.providers[:50]
                        data["components"]["providers_count"] = len(axml.providers)
                        data["components"]["exported_providers_count"] = sum(1 for pr in axml.providers if pr.get("exported") is True)

                        # Check Debuggable flag
                        if axml.application_attributes.get("debuggable") is True:
                            findings.append(Finding(
                                category="configuration",
                                severity="critical",
                                title="Application Debuggable Flag Enabled (android:debuggable=true)",
                                description="The AndroidManifest explicitly configures android:debuggable='true'. This enables arbitrary process memory inspection, code injection via JDWP, and complete app hijacking on physical devices.",
                                details={"attribute": "android:debuggable", "value": True}
                            ))

                        # Check Cleartext Traffic
                        if axml.application_attributes.get("usesCleartextTraffic") is True:
                            findings.append(Finding(
                                category="network",
                                severity="medium",
                                title="Cleartext HTTP Traffic Allowed (android:usesCleartextTraffic=true)",
                                description="Application opts out of Android's default HTTPS enforcement, permitting transmission of sensitive data over unencrypted HTTP.",
                                details={"attribute": "android:usesCleartextTraffic", "value": True}
                            ))

                        # Check AllowBackup flag
                        if axml.application_attributes.get("allowBackup") is True:
                            findings.append(Finding(
                                category="storage",
                                severity="low",
                                title="ADB Backup Enabled (android:allowBackup=true)",
                                description="Application data and databases can be extracted via ADB backup without root permissions.",
                                details={"attribute": "android:allowBackup", "value": True}
                            ))

                        # Check Outdated Target SDK
                        if axml.target_sdk_version and axml.target_sdk_version < 28:
                            findings.append(Finding(
                                category="configuration",
                                severity="high",
                                title=f"Outdated Target SDK ({data['target_sdk_label']})",
                                description=f"Application targets Android API {axml.target_sdk_version} (< API 28 / Android 9). This bypasses modern runtime permission enforcement and background execution limits.",
                                details={"target_sdk": axml.target_sdk_version}
                            ))

                # 2. Parse DEX Bytecode files (classes.dex, classes2.dex, etc.)
                dex_files = [n for n in namelist if n.endswith(".dex")]
                data["dex_info"]["dex_count"] = len(dex_files)
                all_urls = set()
                all_ips = set()
                all_classes = set()
                aggregated_apis: Dict[str, Dict[str, Any]] = {}

                for df in dex_files:
                    try:
                        dex_data = zf.read(df)
                        dp = DexParser(dex_data)
                        if dp.parse():
                            data["dex_info"]["total_strings_count"] += len(dp.strings)
                            all_classes.update(dp.classes)
                            all_urls.update(dp.urls)
                            all_ips.update(dp.ips)

                            for api in dp.detected_apis:
                                title = api["title"]
                                if title not in aggregated_apis:
                                    aggregated_apis[title] = api
                                else:
                                    aggregated_apis[title]["count"] += api["count"]
                    except Exception as de:
                        logger.debug(f"Error parsing {df}: {de}")

                data["dex_info"]["classes_count"] = len(all_classes)
                data["dex_info"]["detected_apis"] = list(aggregated_apis.values())
                data["iocs"]["urls"] = list(all_urls)[:100]
                data["iocs"]["ips"] = list(all_ips)[:100]

                # 3. Parse Code Signing Certificate in META-INF/
                sig_files = [n for n in namelist if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
                if sig_files:
                    data["signing_info"]["has_signature"] = True
                    cert_bytes = zf.read(sig_files[0])
                    self._parse_x509_certificate(cert_bytes, data["signing_info"], findings)

                # 4. Catalog Native Libraries (lib/*.so)
                so_files = [n for n in namelist if n.startswith("lib/") and n.endswith(".so")]
                data["native_libraries"] = so_files
                if so_files:
                    archs = list(set(n.split("/")[1] for n in so_files if len(n.split("/")) > 2))
                    data["native_architectures"] = archs

                # 5. Catalog Embedded Assets & Secondary Executables
                assets = [n for n in namelist if (n.startswith("assets/") or n.startswith("res/raw/")) and not n.endswith("/")]
                suspicious_assets = [
                    a for a in assets
                    if a.lower().endswith((".apk", ".dex", ".jar", ".so", ".exe", ".sh", ".bin", ".dat", ".zip"))
                ]
                data["embedded_assets"] = suspicious_assets
                if suspicious_assets:
                    findings.append(Finding(
                        category="payload",
                        severity="high",
                        title=f"Embedded Executable Assets Detected ({len(suspicious_assets)} Files)",
                        description=f"APK bundles suspicious secondary binaries in assets: {', '.join(suspicious_assets[:5])}",
                        details={"assets": suspicious_assets}
                    ))

                # 6. Generate Findings for Dangerous Permissions
                for dp in data["dangerous_permissions"]:
                    findings.append(Finding(
                        category="permission",
                        severity=dp["severity"],
                        title=f"Dangerous Android Permission: {dp['permission']}",
                        description=f"{dp['title']}: {dp['description']}",
                        details=dp
                    ))

                # 7. Generate Findings for Dangerous DEX APIs
                for api in data["dex_info"]["detected_apis"]:
                    findings.append(Finding(
                        category="active_content",
                        severity=api["severity"],
                        title=f"Malicious API Call: {api['title']}",
                        description=f"Bytecode invokes sensitive API associated with {api.get('mitre_name', 'adverse capability')} ({api['count']} invocations). Evidence: {', '.join(api['evidence'][:3])}",
                        details=api
                    ))

                # 8. Synthesize MITRE Mobile ATT&CK Matrix
                mitre_set = {}
                for dp in data["dangerous_permissions"]:
                    if dp.get("mitre"):
                        mitre_set[dp["mitre"]] = dp["mitre_name"]
                for api in data["dex_info"]["detected_apis"]:
                    if api.get("mitre"):
                        mitre_set[api["mitre"]] = api["mitre_name"]

                data["mitre_mobile_techniques"] = [
                    {"id": k, "name": v} for k, v in mitre_set.items()
                ]

                # Compute Overall Risk Score & Level
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

    def _analyze_standalone_dex(self, file_path: Path, filename: str) -> AnalyzerResult:
        """Analyze standalone Dalvik Executable (.dex) file."""
        findings: List[Finding] = []
        data: Dict[str, Any] = {
            "is_apk": False,
            "is_standalone_dex": True,
            "filename": filename,
            "file_size": file_path.stat().st_size,
            "dex_info": {
                "dex_count": 1,
                "classes_count": 0,
                "total_strings_count": 0,
                "detected_apis": []
            },
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

    def _parse_x509_certificate(self, cert_bytes: bytes, sig_info: Dict[str, Any], findings: List[Finding]):
        """Extract and inspect X.509 certificate from PKCS#7 block in META-INF/*.RSA."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            # In PKCS#7 .RSA files, search for standard X.509 SEQUENCE tag
            cert = None
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            except Exception:
                # Often wrapped inside PKCS#7 signedData: search for DER sequence
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

                # Check if Debug Key
                if "Android Debug" in subject_str or "Android Debug" in issuer_str or "CN=Android Debug" in subject_str:
                    sig_info["is_debug_key"] = True
                    findings.append(Finding(
                        category="signature",
                        severity="high",
                        title="Android Debug Signing Certificate Detected",
                        description="Application is signed with a public development Android Debug keystore (CN=Android Debug). Debug builds lack release integrity safeguards and should never be deployed in production.",
                        details=sig_info
                    ))

                # Check if self-signed
                if subject_str == issuer_str:
                    sig_info["is_self_signed"] = True

        except Exception as e:
            logger.debug(f"Certificate parsing note: {e}")
