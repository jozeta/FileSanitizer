import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
import jwt
import secrets
import hashlib
from pydantic import BaseModel, Field

from app.config import settings, get_effective_jobs_dir
from app.core.logging_config import logger

SETTINGS_FILE_NAME = "settings.json"

DEFAULT_SETTINGS: Dict[str, Any] = {
    # Global scanning engine toggles
    "global_checks": {
        "clamav_enabled": True,
        "yara_enabled": True,
        "virustotal_enabled": True,
        "crowdstrike_enabled": True,
        "circl_hashlookup_enabled": True,
        "malwarebazaar_enabled": True,
        "abuseipdb_enabled": False,
        "alienvault_otx_enabled": False,
        "hybrid_analysis_enabled": False,
        "mxtoolbox_enabled": False,
        "ipinfo_enabled": True,
        "rdap_enabled": True,
        "url_reputation_enabled": True,
        "url_screenshot_enabled": True,
        "shodan_enabled": True,
    },
    # Format-specific checks
    "format_checks": {
        "executable": {
            "check_sections_entropy": True,
            "check_suspicious_imports": True,
            "check_authenticode_signature": True,
            "check_packers_upx": True,
            "check_disassembly": True,
            "check_capabilities": True,
            "check_anti_analysis": True,
            "check_virustotal": True,
            "check_crowdstrike": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "elf": {
            "check_elf_header": True,
            "check_elf_symbols": True,
            "check_elf_sections": True,
            "check_segments_memory": True,
            "check_security_hardening": True,
            "check_virustotal": True,
            "check_crowdstrike": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "macho": {
            "check_macho_slices": True,
            "check_load_commands": True,
            "check_code_signature": True,
            "check_virustotal": True,
            "check_crowdstrike": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "office": {
            "check_vba_macros": True,
            "check_olevba_inspection": True,
            "check_vba_stomping": True,
            "check_activex": True,
            "check_ole_objects": True,
            "check_external_relationships": True,
            "check_remote_templates": True,
            "check_revisions_comments": True,
            "check_dde_links": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "pdf": {
            "check_javascript": True,
            "check_didier_pdfid": True,
            "check_launch_actions": True,
            "check_embedded_files": True,
            "check_open_actions": True,
            "check_xfa_acroforms": True,
            "check_incremental_updates": True,
            "check_external_uris": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "archive": {
            "check_zip_bomb": True,
            "check_path_traversal": True,
            "check_executables": True,
            "check_nested_archives": True,
            "check_encryption_passwords": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "jar": {
            "check_manifest_entrypoint": True,
            "check_permissions": True,
            "check_bytecode_dangerous_apis": True,
            "check_embedded_binaries": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "image": {
            "check_exif": True,
            "check_gps": True,
            "check_icc": True,
            "check_xmp_iptc": True,
            "check_comments": True,
            "check_steganography_slack": True,
            "check_ai_provenance": True,
            "check_virustotal": True,
            "check_clamav": True,
        },
        "email": {
            "check_headers": True,
            "check_tracking_pixels": True,
            "check_attachments": True,
            "check_links": True,
            "check_domain_dns_rdap": True,
            "check_spf_dkim_dmarc": True,
            "check_thread_hijacking": True,
            "check_phishing_urgency": True,
            "check_virustotal": True,
            "check_clamav": True,
        },
        "script": {
            "check_obfuscation": True,
            "check_base64_decode": True,
            "check_process_spawning": True,
            "check_network_cradle": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "svg_html": {
            "check_javascript": True,
            "check_event_handlers": True,
            "check_external_resources": True,
            "check_iframes_forms": True,
            "check_virustotal": True,
            "check_clamav": True,
        },
        "text": {
            "check_urls": True,
            "check_suspicious_scripts": True,
            "check_virustotal": True,
            "check_clamav": True,
        },
        "extension": {
            "check_manifest_permissions": True,
            "check_background_scripts": True,
            "check_content_scripts": True,
            "check_webstore_telemetry": True,
            "check_virustotal": True,
            "check_clamav": True,
        },
        "domain": {
            "check_whois_rdap": True,
            "check_dns_records": True,
            "check_subdomains": True,
            "check_ssl_tls_cert": True,
            "check_mx_reputation": True,
            "check_virustotal": True,
        },
        "applescript": {
            "check_osa_decompilation": True,
            "check_apple_events": True,
            "check_keychain_access": True,
            "check_privilege_escalation": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "pcap": {
            "check_conversations_flows": True,
            "check_dns_queries": True,
            "check_tls_certificates": True,
            "check_http_ftp_traffic": True,
            "check_plaintext_credentials": True,
            "check_extracted_payloads": True,
            "check_virustotal": True,
            "check_clamav": True,
            "check_yara": True,
        },
        "evtx": {
            "check_log_clearing": True,
            "check_privilege_escalation": True,
            "check_ransomware_indicators": True,
            "check_account_manipulation": True,
            "check_powershell_scriptblocks": True,
            "check_scheduled_tasks": True,
            "check_process_spawning": True,
            "check_network_connections": True,
            "check_defender_tampering": True,
        }
    },
    # Curated Monitored Event IDs for Windows EVTX Timeline (Incident Response, Malware, Ransomware, Auditing, Sysmon, Execution, Persistence)
    "evtx_timeline_event_ids": [
        # Logon / Logoff / Authentication & RDP
        4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776,
        4778, 4779, 1149, 21, 24, 25,
        # Process Execution, Sysmon & Injection
        4688, 4689, 1, 7, 8, 10, 25,
        # Services & Scheduled Tasks Persistence
        7045, 4697, 7036, 7040, 4698, 4699, 4700, 4701, 4702, 106, 200, 201,
        # Account Manipulation & Privilege Escalation
        4720, 4722, 4724, 4726, 4738, 4728, 4732, 4756, 4673, 4674, 4703,
        # Anti-Forensics & Defender Tampering
        1102, 104, 1100, 5001, 5004, 5007, 1116, 1117, 1118, 1119,
        # PowerShell Scripting & Object Access
        4104, 4103, 400, 600, 5379, 4663,
        # Network & Lateral Movement (SMB Shares)
        5140, 5145, 5142, 5144, 5156, 5158, 3, 22,
        # File System, Registry & Named Pipes
        2, 6, 9, 11, 12, 13, 14, 15, 17, 18
    ],
    # Configurable Event ID Threat / Severity Classification Matrix
    "evtx_severity_rules": {
        "1102": "critical",
        "104": "critical",
        "1100": "critical",
        "5001": "critical",
        "5007": "critical",
        "1116": "critical",
        "1117": "critical",
        "4732": "critical",
        "8": "critical",
        "10": "critical",
        "25": "critical",
        "4728": "high",
        "4756": "high",
        "4720": "high",
        "4724": "high",
        "7045": "high",
        "4697": "high",
        "4698": "high",
        "4672": "high",
        "5004": "high",
        "6": "high",
        "9": "high",
        "17": "high",
        "5142": "high",
        "4104": "medium",
        "4625": "medium",
        "4648": "medium",
        "5145": "medium",
        "4771": "medium",
        "1149": "medium",
        "4738": "medium",
        "4673": "medium",
        "4674": "medium",
        "4703": "medium",
        "4699": "medium",
        "4701": "medium",
        "4702": "low",
        "106": "medium",
        "5379": "medium",
        "5144": "medium",
        "4769": "medium",
        "4722": "medium",
        "4726": "medium",
        "7040": "medium",
        "2": "high",
        "12": "medium",
        "14": "medium",
        "15": "medium",
        "18": "medium",
        "22": "medium",
        "5140": "low",
        "4768": "low",
        "4776": "low",
        "4103": "low",
        "1": "info",
        "3": "info",
        "4": "info",
        "5": "info",
        "7": "info",
        "11": "info",
        "13": "info",
        "21": "info",
        "24": "info",
        "25": "info",
        "400": "info",
        "600": "info",
        "4624": "info",
        "4634": "info",
        "4647": "info",
        "4663": "info",
        "4688": "info",
        "4689": "info",
        "4700": "info",
        "4778": "info",
        "4779": "info",
        "5156": "info",
        "5158": "info",
        "7036": "info",
        "1118": "info",
        "1119": "info",
        "200": "info",
        "201": "info"
    },
    # Forensic Time Display & Timezone Normalization Preferences
    "time_display": {
        "format": "24h",               # "24h" or "12h"
        "time_zone": "UTC",            # "UTC", "local", or IANA timezone string e.g. "America/New_York", "Europe/Stockholm"
        "show_timezone_suffix": True,  # e.g. "(UTC)"
        "show_milliseconds": False     # e.g. ".123"
    },
    # UI and Dashboard Display Preferences
    "ui_preferences": {
        "show_telemetry_diagnostics": False,  # Hidden by default
        "check_for_updates": True,           # Check GitHub for new versions on startup
    },
    # Pluggable Service API Keys
    "api_keys": {
        "virustotal_api_key": "",
        "safe_browsing_api_key": "",
        "urlhaus_api_key": "",
        "abuseipdb_api_key": "",
        "alienvault_otx_api_key": "",
        "threatfox_api_key": "",
        "urlscan_api_key": "",
        "hybrid_analysis_api_key": "",
        "mxtoolbox_api_key": "",
        "ipinfo_api_key": "",
        "shodan_api_key": "",
    },

    # External Connection Policies (Granular switches to disable outbound network touches)
    "external_connections": {
        "allow_all_external": True,
        "allow_http_status_and_redirects": True,
        "allow_screenshots": True,
        "allow_tls_inspection": True,
        "allow_threat_intel_lookups": True,
        "allow_geolocation_lookups": True,
        "allow_clamav_official_updates": True,
    },
    # Aggregated Usage Statistics
    "statistics": {
        "total_files_analyzed": 0,
        "total_files_sanitized": 0,
        "malware_detected_count": 0,
        "high_risk_count": 0,
        "clean_count": 0,
        "total_bytes_processed": 0,
        "severity_distribution": {
            "clean": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
            "malware": 0
        },
        "daily_uploads": {},
        "categories_count": {
            "pdf": 0,
            "office": 0,
            "image": 0,
            "archive": 0,
            "svg_html": 0,
            "email": 0,
            "text": 0,
            "binary": 0
        },
        "findings_breakdown": {
            "macro": 0,
            "javascript": 0,
            "antivirus": 0,
            "url": 0,
            "metadata": 0,
            "structure": 0,
            "watchlist": 0
        },
        "sanitization_formats": {
            "original": 0,
            "pdf": 0,
            "png": 0
        }
    },
    # Upload History Log
    "upload_history_enabled": True,
    "upload_history": [],
    # Dangerous URL file extensions (Admin configurable)
    "dangerous_url_extensions": [
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".apk",
        ".dll", ".jar", ".msi", ".hta", ".cpl", ".pif", ".elf"
    ],
    # Admin Warninglist / Watchlist
    "warninglist": [
        {
            "id": "wl-1",
            "name": "Confidentiality Notice",
            "pattern": "confidential",
            "is_regex": False,
            "severity": "medium",
            "description": "Flags mentions of confidential corporate information",
            "enabled": True
        },
        {
            "id": "wl-2",
            "name": "Wire Transfer / Payment Request",
            "pattern": "wire transfer",
            "is_regex": False,
            "severity": "high",
            "description": "Flags wire transfer or financial payment requests",
            "enabled": True
        },
        {
            "id": "wl-3",
            "name": "Plaintext Password Exposure",
            "pattern": r"password\s*[:=]\s*\S+",
            "is_regex": True,
            "severity": "critical",
            "description": "Detects plaintext password assignments via RegEx",
            "enabled": True
        },
        {
            "id": "wl-se-pnr",
            "name": "Swedish Personal Identity Number",
            "pattern": r"\b(19|20)?\d{6}[-+]?\d{4}\b",
            "is_regex": True,
            "severity": "high",
            "description": "Swedish Personal Identity Number (Personnummer 10 or 12 digits)",
            "enabled": True
        },
        {
            "id": "wl-credit-card",
            "name": "Credit Card Number Sequence",
            "pattern": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            "is_regex": True,
            "severity": "critical",
            "description": "Credit card number sequences (Visa, MasterCard, Amex 16-digit blocks)",
            "enabled": True
        },
        {
            "id": "wl-email-addr",
            "name": "Email Address Pattern",
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "is_regex": True,
            "severity": "medium",
            "description": "Email address pattern in text or document metadata",
            "enabled": True
        },
        {
            "id": "wl-se-orgnr",
            "name": "Swedish Corporate ID (Organisationsnummer)",
            "pattern": r"\b\d{6}-\d{4}\b",
            "is_regex": True,
            "severity": "low",
            "description": "Swedish Corporate Registration Number (Organisationsnummer)",
            "enabled": True
        },
        {
            "id": "wl-iban",
            "name": "International Bank Account Number (IBAN)",
            "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
            "is_regex": True,
            "severity": "high",
            "description": "International Bank Account Number (IBAN)",
            "enabled": True
        },
        {
            "id": "wl-jwt-token",
            "name": "JSON Web Token (JWT) Leaked Credential",
            "pattern": r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b",
            "is_regex": True,
            "severity": "critical",
            "description": "Detects leaked JSON Web Tokens (JWT) or Bearer authorization headers",
            "enabled": True
        },
        {
            "id": "wl-api-key",
            "name": "Hardcoded API Key / Secret Token",
            "pattern": r"(?i)(api[_-]?key|secret[_-]?token|access[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
            "is_regex": True,
            "severity": "critical",
            "description": "Detects hardcoded API keys and authentication secrets",
            "enabled": True
        }
    ],
    # Custom ImHex-like Search & Hex Highlighting Patterns
    "custom_hex_patterns": [
        {
            "id": "pat-1",
            "name": "Shellcode NOP Sled",
            "type": "hex",
            "pattern": "90 90 90 90",
            "color": "#ef4444",
            "description": "x86 NOP instruction sequence commonly used in buffer overflow exploits",
            "enabled": True
        },
        {
            "id": "pat-2",
            "name": "PowerShell Command Invoke",
            "type": "string",
            "pattern": "powershell",
            "color": "#8b5cf6",
            "description": "Reference to PowerShell interpreter or command line execution",
            "enabled": True
        },
        {
            "id": "pat-3",
            "name": "Base64 High Density Block",
            "type": "regex",
            "pattern": "[A-Za-z0-9+/=]{40,}",
            "color": "#f59e0b",
            "description": "Continuous base64 payload block",
            "enabled": True
        }
    ],
    # Supported File Formats for Hex & Forensic Analysis
    "file_formats": [
        {
            "id": "pe",
            "name": "Portable Executable (PE / EXE / DLL)",
            "default_extension": ".exe",
            "magic_bytes": "4D 5A",
            "extensions": [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv"],
            "magic_signatures": ["4D 5A"],
            "is_system": True,
            "enabled": True,
            "description": "Microsoft Windows Portable Executable 32/64-bit binaries and Dynamic Link Libraries (DLLs)."
        },
        {
            "id": "elf",
            "name": "Executable and Linkable Format (ELF)",
            "default_extension": ".elf",
            "magic_bytes": "7F 45 4C 46",
            "extensions": [".elf", ".so", ".bin", ".o"],
            "magic_signatures": ["7F 45 4C 46"],
            "is_system": True,
            "enabled": True,
            "description": "Standard binary and shared object format for Unix/Linux systems."
        },
        {
            "id": "macho",
            "name": "Mach-O Binary (macOS)",
            "default_extension": ".bin",
            "magic_bytes": "FE ED FA CE",
            "extensions": [".bin", ".dylib", ".o", ".bundle"],
            "magic_signatures": ["FE ED FA CE", "FE ED FA CF", "CE FA ED FE", "CF FA ED FE", "CA FE BA BE"],
            "is_system": True,
            "enabled": True,
            "description": "Mach Object binary file format for macOS and iOS (including Fat universal binaries)."
        },
        {
            "id": "zip",
            "name": "ZIP Archive",
            "default_extension": ".zip",
            "magic_bytes": "50 4B 03 04",
            "extensions": [".zip", ".zipx"],
            "magic_signatures": ["50 4B 03 04", "50 4B 05 06", "50 4B 07 08"],
            "is_system": True,
            "enabled": True,
            "description": "PKZIP compressed archive container format."
        },
        {
            "id": "rar",
            "name": "RAR Archive",
            "default_extension": ".rar",
            "magic_bytes": "52 61 72 21 1A 07 00",
            "extensions": [".rar"],
            "magic_signatures": ["52 61 72 21 1A 07 00", "52 61 72 21 1A 07 01 00"],
            "is_system": True,
            "enabled": True,
            "description": "Roshal Archive compressed container (supporting RAR 4.x and RAR 5.x signatures)."
        },
        {
            "id": "pdf",
            "name": "PDF Document",
            "default_extension": ".pdf",
            "magic_bytes": "25 50 44 46",
            "extensions": [".pdf"],
            "magic_signatures": ["25 50 44 46"],
            "is_system": True,
            "enabled": True,
            "description": "Adobe Portable Document Format with objects and cross-reference tables."
        },
        {
            "id": "7z",
            "name": "7-Zip Archive",
            "default_extension": ".7z",
            "magic_bytes": "37 7A BC AF 27 1C",
            "extensions": [".7z"],
            "magic_signatures": ["37 7A BC AF 27 1C"],
            "is_system": True,
            "enabled": True,
            "description": "7-Zip compressed archive container with high compression ratio."
        },
        {
            "id": "cfb",
            "name": "Compound File Binary (CFB / OLE2 / Office)",
            "default_extension": ".doc",
            "magic_bytes": "D0 CF 11 E0 A1 B1 1A E1",
            "extensions": [".doc", ".xls", ".ppt", ".msi"],
            "magic_signatures": ["D0 CF 11 E0 A1 B1 1A E1"],
            "is_system": True,
            "enabled": True,
            "description": "Microsoft Compound File Binary / OLE2 format used by legacy Office (DOC, XLS, PPT) and MSI installers."
        },
        {
            "id": "class",
            "name": "Java Bytecode Class",
            "default_extension": ".class",
            "magic_bytes": "CA FE BA BE",
            "extensions": [".class"],
            "magic_signatures": ["CA FE BA BE"],
            "is_system": True,
            "enabled": True,
            "description": "Compiled Java virtual machine bytecode class file."
        },
        {
            "id": "crx",
            "name": "Chrome Extension (CRX)",
            "default_extension": ".crx",
            "magic_bytes": "43 72 32 34",
            "extensions": [".crx"],
            "magic_signatures": ["43 72 32 34"],
            "is_system": True,
            "enabled": True,
            "description": "Google Chrome packed extension package format (CRX2/CRX3)."
        },
        {
            "id": "png",
            "name": "PNG Image",
            "default_extension": ".png",
            "magic_bytes": "89 50 4E 47 0D 0A 1A 0A",
            "extensions": [".png"],
            "magic_signatures": ["89 50 4E 47 0D 0A 1A 0A"],
            "is_system": True,
            "enabled": True,
            "description": "Portable Network Graphics lossless raster image format."
        },
        {
            "id": "jpeg",
            "name": "JPEG Image",
            "default_extension": ".jpg",
            "magic_bytes": "FF D8 FF E0",
            "extensions": [".jpg", ".jpeg", ".jpe", ".jfif", ".jif"],
            "magic_signatures": ["FF D8 FF E0", "FF D8 FF E1", "FF D8 FF E2", "FF D8 FF DB", "FF D8 FF EE", "FF D8 FF"],
            "is_system": True,
            "enabled": True,
            "description": "Joint Photographic Experts Group lossy image format (JFIF/EXIF/SPIFF)."
        },
        {
            "id": "gif",
            "name": "GIF Image",
            "default_extension": ".gif",
            "magic_bytes": "47 49 46 38 37 61",
            "extensions": [".gif"],
            "magic_signatures": ["47 49 46 38 37 61", "47 49 46 38 39 61"],
            "is_system": True,
            "enabled": True,
            "description": "Graphics Interchange Format bitmap image stream (GIF87a / GIF89a)."
        },
        {
            "id": "webp",
            "name": "WebP Image",
            "default_extension": ".webp",
            "magic_bytes": "52 49 46 46",
            "extensions": [".webp"],
            "magic_signatures": ["52 49 46 46"],
            "is_system": True,
            "enabled": True,
            "description": "Google WebP image container (RIFF format)."
        },
        {
            "id": "tar",
            "name": "TAR Archive",
            "default_extension": ".tar",
            "magic_bytes": "75 73 74 61 72",
            "extensions": [".tar"],
            "magic_signatures": ["75 73 74 61 72"],
            "is_system": True,
            "enabled": True,
            "description": "POSIX Tape Archive format."
        },
        {
            "id": "pcap",
            "name": "Network Packet Capture (PCAP / PCAPNG)",
            "default_extension": ".pcap",
            "magic_bytes": "D4 C3 B2 A1",
            "extensions": [".pcap", ".pcapng", ".cap"],
            "magic_signatures": ["D4 C3 B2 A1", "A1 B2 C3 D4", "4D 3C B2 A1", "A1 B2 3C 4D", "0A 0D 0D 0A"],
            "is_system": True,
            "enabled": True,
            "description": "Network packet capture format (libpcap / Wireshark / PCAP Next Generation)."
        },
    ],
    # Default Dictionary for Password-Protected Archive Auto-Unlocking Pipeline
    "archive_passwords": [
        "infected", "password", "1234", "123456", "clean", "malware",
        "secret", "virus", "Sample123", "Velvet", "test", "archive", "qwerty"
    ],
    # Format-Specific Sanitization & Content Disarm & Reconstruction (CDR) Policies
    "cdr_policies": {
        "pdf": {
            "format_name": "PDF Documents",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_javascript", "remove_embedded_files",
                "remove_external_links", "flatten_document", "rasterize_pages"
            ],
            "allowed_output_formats": ["original", "png"]
        },
        "office": {
            "format_name": "Office Documents (DOCX/XLSX/PPTX)",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_macros", "remove_embedded_files",
                "remove_external_links", "remove_comments"
            ],
            "allowed_output_formats": ["original", "pdf"]
        },
        "image": {
            "format_name": "Images & Photos (JPEG/PNG/GIF/WebP)",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_gps", "remove_author", "remove_timestamps",
                "reencode_image", "flatten_image"
            ],
            "allowed_output_formats": ["original", "png", "jpg", "pdf"]
        },
        "email": {
            "format_name": "Email Messages (EML/MSG)",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_embedded_files", "strip_active_content",
                "remove_external_links"
            ],
            "allowed_output_formats": ["original", "pdf"]
        },
        "archive": {
            "format_name": "Compressed Archives (ZIP/RAR)",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_embedded_files"
            ],
            "allowed_output_formats": ["original"]
        },
        "svg_html": {
            "format_name": "SVG & Web HTML Documents",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "strip_active_content", "strip_external_resources"
            ],
            "allowed_output_formats": ["original", "png", "jpg"]
        },
        "text": {
            "format_name": "Plain Text & CSV Spreadsheets",
            "enabled": True,
            "allowed_options": [
                "remove_metadata"
            ],
            "allowed_output_formats": ["original"]
        },
        "executable": {
            "format_name": "Executables & Binaries (PE/ELF/Mach-O)",
            "enabled": False,
            "allowed_options": [
                "remove_embedded_files"
            ],
            "allowed_output_formats": ["original"]
        },
        "script": {
            "format_name": "Scripts (PowerShell/Bash/VBS)",
            "enabled": False,
            "allowed_options": [
                "remove_external_links"
            ],
            "allowed_output_formats": ["original"]
        },
        "pcap": {
            "format_name": "Network Packet Captures (PCAP)",
            "enabled": False,
            "allowed_options": [
                "strip_unencrypted_credentials", "strip_malicious_payloads", "sanitize_ip_anonymization"
            ],
            "allowed_output_formats": ["original", "pcap"],
            "description": "Network trace sanitization: scrubs cleartext credentials, removes dangerous payload transfers, and anonymizes internal subnet ranges. Disabled by default (analysis-only)."
        },
        "evtx": {
            "format_name": "Windows Event Logs (EVTX)",
            "enabled": False,
            "allowed_options": [
                "anonymize_hosts_and_users", "strip_raw_xml_details"
            ],
            "allowed_output_formats": ["original", "evtx"],
            "description": "Windows Event Logs forensic triage container. CDR disabled by default (forensic artifact preservation)."
        },
        "rtf": {
            "format_name": "Rich Text Format (RTF)",
            "enabled": True,
            "allowed_options": [
                "remove_metadata", "remove_embedded_files", "remove_external_links"
            ],
            "allowed_output_formats": ["original", "pdf"],
            "description": "Rich text documents with OLE package stripping and sanitization."
        },
        "jar": {
            "format_name": "Java Archives (JAR/WAR/CLASS)",
            "enabled": False,
            "allowed_options": [
                "remove_embedded_files"
            ],
            "allowed_output_formats": ["original"],
            "description": "Java archive inspection. CDR disarm disabled by default."
        },
        "applescript": {
            "format_name": "AppleScript & Compiled Scripts (SCPT)",
            "enabled": False,
            "allowed_options": [
                "remove_external_links"
            ],
            "allowed_output_formats": ["original"],
            "description": "macOS AppleScript / OSA inspection. CDR disabled by default."
        },
        "domain": {
            "format_name": "Domain & Host Lookups",
            "enabled": False,
            "allowed_options": [],
            "allowed_output_formats": ["original"],
            "description": "OSINT Domain and IP intelligence lookup. Analysis-only (CDR not applicable)."
        }
    }
}

class SettingsStore:
    _instance = None
    _lock = threading.Lock()
    _history_lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._data = None
                cls._instance._last_mtime = 0
                cls._instance._load()
        return cls._instance

    def _get_config_dir(self) -> Path:
        base = Path(get_effective_jobs_dir()) / "config"
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        return base

    def _get_settings_file(self) -> Path:
        return self._get_config_dir() / SETTINGS_FILE_NAME

    def _get_history_file(self) -> Path:
        return self._get_config_dir() / "upload_history.json"

    def _check_reload(self) -> None:
        try:
            file_path = self._get_settings_file()
            if file_path.exists():
                mtime = file_path.stat().st_mtime
                if mtime > getattr(self, "_last_mtime", 0):
                    self._load()
        except Exception:
            pass

    def _load(self) -> None:
        file_path = self._get_settings_file()
        if file_path.exists():
            try:
                self._last_mtime = file_path.stat().st_mtime
                with open(file_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                # Deep merge with defaults so newly added keys are always present
                merged = json.loads(json.dumps(DEFAULT_SETTINGS))
                for section in ["global_checks", "format_checks", "api_keys", "external_connections", "statistics"]:
                    if section in saved and isinstance(saved[section], dict):
                        if section == "format_checks":
                            for fmt, flags in saved[section].items():
                                if fmt in merged[section] and isinstance(flags, dict):
                                    merged[section][fmt].update(flags)
                                else:
                                    merged[section][fmt] = flags
                        elif section == "statistics":
                            for sk, sv in saved[section].items():
                                if isinstance(sv, dict) and sk in merged[section] and isinstance(merged[section][sk], dict):
                                    merged[section][sk].update(sv)
                                else:
                                    merged[section][sk] = sv
                        else:
                            merged[section].update(saved[section])
                if "dangerous_url_extensions" in saved and isinstance(saved["dangerous_url_extensions"], list):
                    merged["dangerous_url_extensions"] = list(saved["dangerous_url_extensions"])
                else:
                    merged["dangerous_url_extensions"] = list(DEFAULT_SETTINGS["dangerous_url_extensions"])

                if "warninglist" in saved and isinstance(saved["warninglist"], list):
                    def_names = {r["id"]: r.get("name") for r in DEFAULT_SETTINGS["warninglist"] if "id" in r}
                    merged_rules = []
                    for r in saved["warninglist"]:
                        rule_copy = dict(r)
                        if not rule_copy.get("name"):
                            rule_copy["name"] = def_names.get(rule_copy.get("id")) or rule_copy.get("description", "")[:50] or rule_copy.get("pattern", "Rule")
                        merged_rules.append(rule_copy)
                    saved_ids = {r.get("id") for r in merged_rules}
                    for def_r in DEFAULT_SETTINGS["warninglist"]:
                        if def_r["id"] not in saved_ids:
                            merged_rules.append(def_r)
                    merged["warninglist"] = merged_rules

                if "upload_history_enabled" in saved:
                    merged["upload_history_enabled"] = bool(saved["upload_history_enabled"])

                if "archive_passwords" in saved and isinstance(saved["archive_passwords"], list):
                    merged["archive_passwords"] = list(saved["archive_passwords"])
                else:
                    merged["archive_passwords"] = list(DEFAULT_SETTINGS["archive_passwords"])

                if "cdr_policies" in saved and isinstance(saved["cdr_policies"], dict):
                    merged_cdr = json.loads(json.dumps(DEFAULT_SETTINGS["cdr_policies"]))
                    for fmt, pol in saved["cdr_policies"].items():
                        if fmt in merged_cdr and isinstance(pol, dict):
                            merged_cdr[fmt].update(pol)
                        else:
                            merged_cdr[fmt] = pol
                    merged["cdr_policies"] = merged_cdr
                else:
                    merged["cdr_policies"] = json.loads(json.dumps(DEFAULT_SETTINGS["cdr_policies"]))

                if "evtx_timeline_event_ids" in saved and isinstance(saved["evtx_timeline_event_ids"], list):
                    merged_ids = list(saved["evtx_timeline_event_ids"])
                    for def_id in DEFAULT_SETTINGS["evtx_timeline_event_ids"]:
                        if def_id not in merged_ids:
                            merged_ids.append(def_id)
                    merged["evtx_timeline_event_ids"] = merged_ids
                else:
                    merged["evtx_timeline_event_ids"] = list(DEFAULT_SETTINGS["evtx_timeline_event_ids"])

                if "evtx_severity_rules" in saved and isinstance(saved["evtx_severity_rules"], dict):
                    merged_sev = dict(DEFAULT_SETTINGS.get("evtx_severity_rules", {}))
                    merged_sev.update(saved["evtx_severity_rules"])
                    merged["evtx_severity_rules"] = merged_sev
                else:
                    merged["evtx_severity_rules"] = dict(DEFAULT_SETTINGS.get("evtx_severity_rules", {}))

                if "time_display" in saved and isinstance(saved["time_display"], dict):
                    merged_td = dict(DEFAULT_SETTINGS.get("time_display", {}))
                    merged_td.update(saved["time_display"])
                    merged["time_display"] = merged_td
                else:
                    merged["time_display"] = dict(DEFAULT_SETTINGS.get("time_display", {}))

                if "ui_preferences" in saved and isinstance(saved["ui_preferences"], dict):
                    merged_ui = dict(DEFAULT_SETTINGS.get("ui_preferences", {}))
                    merged_ui.update(saved["ui_preferences"])
                    merged["ui_preferences"] = merged_ui
                else:
                    merged["ui_preferences"] = dict(DEFAULT_SETTINGS.get("ui_preferences", {}))

                # One-time migration: if upload_history.json does not exist yet, migrate any saved history
                hist_file = self._get_history_file()
                if not hist_file.exists() and "upload_history" in saved and isinstance(saved["upload_history"], list) and saved["upload_history"]:
                    try:
                        tmp_hist = hist_file.with_suffix(".tmp")
                        with open(tmp_hist, "w", encoding="utf-8") as hf:
                            json.dump(saved["upload_history"][:1000], hf, indent=2)
                        os.replace(tmp_hist, hist_file)
                    except Exception as he:
                        logger.warning(f"Error migrating upload history: {he}")

                self._data = merged
                logger.info("Loaded persisted dynamic settings from disk")
                return
            except Exception as e:
                logger.warning(f"Error reading {file_path}, resetting to defaults: {e}")

        # Fallback to defaults + env vars
        data = json.loads(json.dumps(DEFAULT_SETTINGS))
        if settings.VIRUSTOTAL_API_KEY:
            data["api_keys"]["virustotal_api_key"] = settings.VIRUSTOTAL_API_KEY
            data["global_checks"]["virustotal_enabled"] = True
        if settings.SAFE_BROWSING_API_KEY:
            data["api_keys"]["safe_browsing_api_key"] = settings.SAFE_BROWSING_API_KEY
        if settings.URLHAUS_API_KEY:
            data["api_keys"]["urlhaus_api_key"] = settings.URLHAUS_API_KEY
        if settings.SHODAN_API_KEY:
            data["api_keys"]["shodan_api_key"] = settings.SHODAN_API_KEY
            data["global_checks"]["shodan_enabled"] = True
        self._data = data
        self._save()

    def _save(self) -> None:
        file_path = self._get_settings_file()
        try:
            tmp_file = file_path.with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp_file, file_path)
            self._last_mtime = file_path.stat().st_mtime
        except Exception as e:
            logger.error(f"Failed to persist settings to {file_path}: {e}")

    def get_all(self, mask_keys: bool = False) -> Dict[str, Any]:
        """Return a copy of the settings, optionally masking secret API keys for frontend display."""
        self._check_reload()
        copy_data = json.loads(json.dumps(self._data))
        if mask_keys:
            for k, v in copy_data.get("api_keys", {}).items():
                if v and len(v) > 8:
                    copy_data["api_keys"][k] = f"{v[:4]}...{v[-4:]}"
                elif v:
                    copy_data["api_keys"][k] = "********"
                else:
                    copy_data["api_keys"][k] = ""
        # Always include upload history enabled flag
        copy_data["upload_history_enabled"] = self._data.get("upload_history_enabled", True)
        copy_data["evtx_timeline_event_ids"] = list(self._data.get("evtx_timeline_event_ids", DEFAULT_SETTINGS["evtx_timeline_event_ids"]))
        copy_data["evtx_severity_rules"] = dict(self._data.get("evtx_severity_rules", DEFAULT_SETTINGS.get("evtx_severity_rules", {})))
        copy_data["time_display"] = dict(self._data.get("time_display", DEFAULT_SETTINGS.get("time_display", {})))
        copy_data["ui_preferences"] = dict(self._data.get("ui_preferences", DEFAULT_SETTINGS.get("ui_preferences", {})))
        return copy_data

    def get_time_display(self) -> Dict[str, Any]:
        self._check_reload()
        with self._lock:
            return dict(self._data.get("time_display", DEFAULT_SETTINGS.get("time_display", {})))

    def set_time_display(self, config: Dict[str, Any]) -> None:
        with self._lock:
            current = dict(self._data.get("time_display", DEFAULT_SETTINGS.get("time_display", {})))
            if "format" in config and config["format"] in ["24h", "12h"]:
                current["format"] = config["format"]
            if "time_zone" in config and isinstance(config["time_zone"], str) and config["time_zone"].strip():
                current["time_zone"] = config["time_zone"].strip()
            if "show_timezone_suffix" in config:
                current["show_timezone_suffix"] = bool(config["show_timezone_suffix"])
            if "show_milliseconds" in config:
                current["show_milliseconds"] = bool(config["show_milliseconds"])
            self._data["time_display"] = current
            self._save()

    def get_ui_preferences(self) -> Dict[str, Any]:
        self._check_reload()
        with self._lock:
            return dict(self._data.get("ui_preferences", DEFAULT_SETTINGS.get("ui_preferences", {})))

    def set_ui_preferences(self, config: Dict[str, Any]) -> None:
        with self._lock:
            current = dict(self._data.get("ui_preferences", DEFAULT_SETTINGS.get("ui_preferences", {})))
            if "show_telemetry_diagnostics" in config:
                current["show_telemetry_diagnostics"] = bool(config["show_telemetry_diagnostics"])
            if "check_for_updates" in config:
                current["check_for_updates"] = bool(config["check_for_updates"])
            self._data["ui_preferences"] = current
            self._save()

    def get_evtx_timeline_event_ids(self) -> List[int]:
        self._check_reload()
        with self._lock:
            return list(self._data.get("evtx_timeline_event_ids", DEFAULT_SETTINGS["evtx_timeline_event_ids"]))

    def set_evtx_timeline_event_ids(self, event_ids: List[int]) -> None:
        with self._lock:
            clean_ids = [int(x) for x in event_ids if str(x).isdigit()]
            self._data["evtx_timeline_event_ids"] = clean_ids
            self._save()

    def get_evtx_severity_rules(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._data.get("evtx_severity_rules", DEFAULT_SETTINGS.get("evtx_severity_rules", {})))

    def set_evtx_severity_rules(self, rules: Dict[str, str]) -> None:
        with self._lock:
            valid_sevs = {"critical", "high", "medium", "low", "info"}
            clean_rules = {
                str(k): str(v).lower()
                for k, v in rules.items()
                if str(k).isdigit() and str(v).lower() in valid_sevs
            }
            self._data["evtx_severity_rules"] = clean_rules
            self._save()

    def update(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update settings sections and persist."""
        if "global_checks" in updates and isinstance(updates["global_checks"], dict):
            self._data["global_checks"].update(updates["global_checks"])

        if "format_checks" in updates and isinstance(updates["format_checks"], dict):
            for fmt, flags in updates["format_checks"].items():
                if fmt in self._data["format_checks"]:
                    self._data["format_checks"][fmt].update(flags)
                else:
                    self._data["format_checks"][fmt] = flags

        if "api_keys" in updates and isinstance(updates["api_keys"], dict):
            for k, v in updates["api_keys"].items():
                # Avoid overwriting with masked strings e.g. "abcd...1234" or "********"
                if v is not None and not (isinstance(v, str) and ("..." in v or "*" in v)):
                    self._data["api_keys"][k] = v.strip()

        if "dangerous_url_extensions" in updates and isinstance(updates["dangerous_url_extensions"], list):
            self.set_dangerous_extensions(updates["dangerous_url_extensions"])

        if "evtx_timeline_event_ids" in updates and isinstance(updates["evtx_timeline_event_ids"], list):
            self.set_evtx_timeline_event_ids(updates["evtx_timeline_event_ids"])

        if "evtx_severity_rules" in updates and isinstance(updates["evtx_severity_rules"], dict):
            self.set_evtx_severity_rules(updates["evtx_severity_rules"])

        if "time_display" in updates and isinstance(updates["time_display"], dict):
            self.set_time_display(updates["time_display"])

        if "ui_preferences" in updates and isinstance(updates["ui_preferences"], dict):
            self.set_ui_preferences(updates["ui_preferences"])

        if "upload_history_enabled" in updates:
            self._data["upload_history_enabled"] = bool(updates["upload_history_enabled"])

        # Update VIRUSTOTAL_ENABLED automatically based on key presence or explicit toggle
        vt_key = self._data["api_keys"].get("virustotal_api_key", "").strip()
        if vt_key:
            self._data["global_checks"]["virustotal_enabled"] = True
        elif not updates.get("global_checks", {}).get("virustotal_enabled", False):
            self._data["global_checks"]["virustotal_enabled"] = False

        # Update HYBRID_ANALYSIS_ENABLED automatically based on key presence
        ha_key = self._data["api_keys"].get("hybrid_analysis_api_key", "").strip()
        if ha_key:
            self._data["global_checks"]["hybrid_analysis_enabled"] = True
        elif not updates.get("global_checks", {}).get("hybrid_analysis_enabled", False):
            self._data["global_checks"]["hybrid_analysis_enabled"] = False

        # Update SHODAN_ENABLED automatically based on key presence
        shodan_key = self._data["api_keys"].get("shodan_api_key", "").strip()
        if shodan_key:
            self._data["global_checks"]["shodan_enabled"] = True
        elif not updates.get("global_checks", {}).get("shodan_enabled", True):
            self._data["global_checks"]["shodan_enabled"] = False

        self._save()
        return self.get_all(mask_keys=True)

    def is_check_enabled(self, category: str, check_name: str) -> bool:
        """Query if a particular format check is enabled."""
        self._check_reload()
        fmt_checks = self._data.get("format_checks", {}).get(category, {})
        return fmt_checks.get(check_name, True)

    def get_format_checks(self, category: str) -> Dict[str, bool]:
        """Return all check flags for a given format category."""
        self._check_reload()
        return dict(self._data.get("format_checks", {}).get(category, {}))

    def get_global_checks(self) -> Dict[str, bool]:
        """Return all global scanner engine flags."""
        self._check_reload()
        return dict(self._data.get("global_checks", {}))

    def is_global_enabled(self, key: str) -> bool:
        """Query if a global scanner (clamav, yara, virustotal) is enabled."""
        self._check_reload()
        return self._data.get("global_checks", {}).get(key, True)

    def get_api_key(self, service: str) -> str:
        """Get actual unmasked API key for a service."""
        self._check_reload()
        key = self._data.get("api_keys", {}).get(service, "")
        if not key:
            # Fall back to env config
            if service == "virustotal_api_key":
                return settings.VIRUSTOTAL_API_KEY or ""
            elif service == "safe_browsing_api_key":
                return settings.SAFE_BROWSING_API_KEY or ""
            elif service == "urlhaus_api_key":
                return settings.URLHAUS_API_KEY or ""
            elif service == "shodan_api_key":
                return settings.SHODAN_API_KEY or ""
        return key

    # Upload History Log Methods
    def is_history_enabled(self) -> bool:
        self._check_reload()
        return bool(self._data.get("upload_history_enabled", True))

    def record_upload_history(self, entry: dict) -> None:
        """Append or update a file upload record in the dedicated history log (capped at 1000)."""
        if not self.is_history_enabled():
            return

        with self._history_lock:
            history_file = self._get_history_file()
            history: List[Dict[str, Any]] = []
            if history_file.exists():
                try:
                    with open(history_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            history = data
                except Exception as e:
                    logger.warning(f"Error reading {history_file}: {e}")
                    history = []
            elif "upload_history" in self._data and isinstance(self._data["upload_history"], list):
                history = list(self._data["upload_history"])

            job_id = entry.get("job_id")
            updated = False
            if job_id:
                for item in history:
                    if item.get("job_id") == job_id:
                        item.update(entry)
                        updated = True
                        break

            if not updated:
                history.insert(0, entry)

            if len(history) > 1000:
                history = history[:1000]

            try:
                tmp_file = history_file.with_suffix(".tmp")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(history, f, indent=2)
                os.replace(tmp_file, history_file)
            except Exception as e:
                logger.error(f"Failed to persist upload history to {history_file}: {e}")

            self._data["upload_history"] = history

    def get_upload_history(self) -> list:
        history_file = self._get_history_file()
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self._data["upload_history"] = data
                        return data
            except Exception as e:
                logger.warning(f"Error reading {history_file}: {e}")
        return list(self._data.get("upload_history", []))

    def clear_upload_history(self) -> None:
        with self._history_lock:
            history_file = self._get_history_file()
            try:
                tmp_file = history_file.with_suffix(".tmp")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump([], f, indent=2)
                os.replace(tmp_file, history_file)
            except Exception as e:
                logger.error(f"Failed to clear {history_file}: {e}")
            self._data["upload_history"] = []

    def toggle_upload_history(self, enabled: bool) -> None:
        self._data["upload_history_enabled"] = bool(enabled)
        self._save()

    # Warninglist / Watchlist Methods
    def get_warning_rules(self) -> List[Dict[str, Any]]:
        """Return list of all configured warning/watchlist rules."""
        return list(self._data.get("warninglist", []))

    def add_warning_rule(self, pattern: str, is_regex: bool = False, severity: str = "medium", description: str = "", name: str = "") -> Dict[str, Any]:
        """Add a new warning rule to the warninglist."""
        import uuid
        rule_id = f"wl-{uuid.uuid4().hex[:8]}"
        sev_norm = severity.lower() if severity.lower() in ["info", "informational", "low", "medium", "high", "critical"] else "medium"
        if sev_norm == "informational":
            sev_norm = "info"

        rule_name = name.strip() if name and name.strip() else (description.strip()[:50] if description and description.strip() else pattern.strip())

        new_rule = {
            "id": rule_id,
            "name": rule_name,
            "pattern": pattern.strip(),
            "is_regex": is_regex,
            "severity": sev_norm,
            "description": description.strip(),
            "enabled": True
        }
        if "warninglist" not in self._data:
            self._data["warninglist"] = []
        self._data["warninglist"].append(new_rule)
        self._save()
        return new_rule

    def delete_warning_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID."""
        rules = self._data.get("warninglist", [])
        before = len(rules)
        self._data["warninglist"] = [r for r in rules if r.get("id") != rule_id]
        if len(self._data["warninglist"]) < before:
            self._save()
            return True
        return False

    def toggle_warning_rule(self, rule_id: str) -> Optional[bool]:
        """Toggle enabled status of a warning rule."""
        for r in self._data.get("warninglist", []):
            if r.get("id") == rule_id:
                r["enabled"] = not r.get("enabled", True)
                self._save()
                return r["enabled"]
        return None

    def update_warning_rule(self, rule_id: str, pattern: str, is_regex: bool = False, severity: str = "medium", description: str = "", name: str = "") -> Optional[Dict[str, Any]]:
        """Update an existing warning rule's pattern, severity, regex mode, description, or name."""
        sev_norm = severity.lower() if severity.lower() in ["info", "informational", "low", "medium", "high", "critical"] else "medium"
        if sev_norm == "informational":
            sev_norm = "info"

        for r in self._data.get("warninglist", []):
            if r.get("id") == rule_id:
                if name and name.strip():
                    r["name"] = name.strip()
                elif not r.get("name"):
                    r["name"] = description.strip()[:50] if description else pattern.strip()
                r["pattern"] = pattern.strip()
                r["is_regex"] = is_regex
                r["severity"] = sev_norm
                r["description"] = description.strip()
                self._save()
                return r
        return None

    # Dangerous URL File Extensions Management
    def get_dangerous_extensions(self) -> List[str]:
        """Return list of configured dangerous URL file extensions."""
        exts = self._data.get("dangerous_url_extensions")
        if exts is None or not isinstance(exts, list):
            exts = list(DEFAULT_SETTINGS.get("dangerous_url_extensions", []))
        return list(exts)

    def set_dangerous_extensions(self, extensions: List[str]) -> List[str]:
        """Overwrite entire list of dangerous URL file extensions."""
        clean = []
        for ext in extensions:
            if not isinstance(ext, str):
                continue
            ext_c = ext.strip().lower()
            if not ext_c:
                continue
            if not ext_c.startswith("."):
                ext_c = f".{ext_c}"
            if ext_c not in clean:
                clean.append(ext_c)
        self._data["dangerous_url_extensions"] = clean
        self._save()
        return clean

    def add_dangerous_extension(self, extension: str) -> List[str]:
        """Add a single dangerous extension (e.g. .apk or apk)."""
        ext_c = extension.strip().lower()
        if not ext_c:
            return self.get_dangerous_extensions()
        if not ext_c.startswith("."):
            ext_c = f".{ext_c}"
        current = self.get_dangerous_extensions()
        if ext_c not in current:
            current.append(ext_c)
            self.set_dangerous_extensions(current)
        return self.get_dangerous_extensions()

    def remove_dangerous_extension(self, extension: str) -> List[str]:
        """Remove a dangerous extension."""
        ext_c = extension.strip().lower()
        if not ext_c.startswith("."):
            ext_c = f".{ext_c}"
        current = [e for e in self.get_dangerous_extensions() if e != ext_c]
        self.set_dangerous_extensions(current)
        return self.get_dangerous_extensions()

    # External Connection Policies
    def is_external_allowed(self, feature: str) -> bool:
        """
        Check if an outbound network function is allowed by admin policy.
        If allow_all_external is disabled, all outbound requests are blocked.
        """
        policy = self._data.get("external_connections", {})
        if not policy.get("allow_all_external", True):
            return False
        return policy.get(feature, True)

    def get_external_policy(self) -> Dict[str, bool]:
        """Return the current external connection policy."""
        return dict(self._data.get("external_connections", DEFAULT_SETTINGS["external_connections"]))

    def update_external_policy(self, updates: Dict[str, bool]) -> Dict[str, bool]:
        """Update granular external connection switches."""
        if "external_connections" not in self._data:
            self._data["external_connections"] = dict(DEFAULT_SETTINGS["external_connections"])
        self._data["external_connections"].update(updates)
        self._save()
        return dict(self._data["external_connections"])

    # Aggregated Usage Statistics
    def record_file_analysis(self, category: str, risk_level: str, findings: List[Any], file_size: int = 0) -> None:
        """Record telemetry event for uploaded and analyzed file."""
        stats = self._data.setdefault("statistics", dict(DEFAULT_SETTINGS["statistics"]))
        stats["total_files_analyzed"] = stats.get("total_files_analyzed", 0) + 1
        stats["total_bytes_processed"] = stats.get("total_bytes_processed", 0) + max(0, int(file_size))

        risk_norm = (risk_level or "CLEAN").upper()
        sev_dist = stats.setdefault("severity_distribution", {
            "clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "malware": 0
        })

        if "MALICIOUS" in risk_norm:
            stats["malware_detected_count"] = stats.get("malware_detected_count", 0) + 1
            sev_dist["malware"] = sev_dist.get("malware", 0) + 1
        elif "CRITICAL" in risk_norm:
            stats["high_risk_count"] = stats.get("high_risk_count", 0) + 1
            sev_dist["critical"] = sev_dist.get("critical", 0) + 1
        elif "HIGH" in risk_norm:
            stats["high_risk_count"] = stats.get("high_risk_count", 0) + 1
            sev_dist["high"] = sev_dist.get("high", 0) + 1
        elif "MEDIUM" in risk_norm:
            sev_dist["medium"] = sev_dist.get("medium", 0) + 1
        elif "LOW" in risk_norm:
            sev_dist["low"] = sev_dist.get("low", 0) + 1
        else:
            stats["clean_count"] = stats.get("clean_count", 0) + 1
            sev_dist["clean"] = sev_dist.get("clean", 0) + 1

        cat_key = category.lower() if category else "binary"
        cats = stats.setdefault("categories_count", {})
        cats[cat_key] = cats.get(cat_key, 0) + 1

        # Track daily uploads
        from datetime import datetime
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        daily = stats.setdefault("daily_uploads", {})
        daily[today_str] = daily.get(today_str, 0) + 1

        fb = stats.setdefault("findings_breakdown", {})
        for f in findings:
            cat = getattr(f, "category", "") or (f.get("category", "") if isinstance(f, dict) else "")
            cat_l = cat.lower()
            for key in ["macro", "javascript", "antivirus", "url", "metadata", "structure", "watchlist"]:
                if key in cat_l:
                    fb[key] = fb.get(key, 0) + 1

        self._save()

    def record_file_sanitization(self, target_format: str) -> None:
        """Record telemetry event when file sanitization is executed."""
        stats = self._data.setdefault("statistics", dict(DEFAULT_SETTINGS["statistics"]))
        stats["total_files_sanitized"] = stats.get("total_files_sanitized", 0) + 1
        fmt_key = target_format.lower() if target_format in ["pdf", "png"] else "original"
        sf = stats.setdefault("sanitization_formats", {})
        sf[fmt_key] = sf.get(fmt_key, 0) + 1
        self._save()

    def get_statistics(self) -> Dict[str, Any]:
        """Return the aggregated usage statistics with 30-day timeline."""
        from datetime import datetime, timedelta
        stats = json.loads(json.dumps(self._data.get("statistics", DEFAULT_SETTINGS["statistics"])))
        daily = stats.get("daily_uploads", {})
        now = datetime.utcnow()
        today_str = now.strftime("%Y-%m-%d")

        # Attribute any unassigned historic uploads to today if daily_uploads was empty
        if not daily.get(today_str) and stats.get("total_files_analyzed", 0) > 0:
            daily[today_str] = stats.get("total_files_analyzed", 0)

        timeline = []
        for i in range(29, -1, -1):
            d = now - timedelta(days=i)
            d_str = d.strftime("%Y-%m-%d")
            day_label = d.strftime("%b %d")
            cnt = daily.get(d_str, 0)
            timeline.append({
                "date": d_str,
                "day": day_label,
                "count": cnt
            })
        stats["last_30_days"] = timeline
        return stats

    # Custom ImHex-like Hex & Search Pattern Management
    def get_custom_hex_patterns(self) -> List[Dict[str, Any]]:
        """Return list of configured custom search & hex patterns."""
        pats = self._data.get("custom_hex_patterns")
        if pats is None or not isinstance(pats, list):
            pats = list(DEFAULT_SETTINGS.get("custom_hex_patterns", []))
            self._data["custom_hex_patterns"] = pats
        return list(pats)

    def add_custom_hex_pattern(self, name: str, pattern: str, p_type: str = "string", color: str = "#6366f1", description: str = "", offset: Optional[int] = None, length: Optional[int] = None, structure_type: str = "header", applies_to_format: Optional[str] = None, category: Optional[str] = None) -> Dict[str, Any]:
        """Add a new custom search / hex pattern."""
        pats = self.get_custom_hex_patterns()
        import uuid
        new_item = {
            "id": f"pat-{uuid.uuid4().hex[:8]}",
            "name": name.strip() or "Custom Pattern",
            "type": p_type.lower() if p_type.lower() in ["string", "regex", "hex", "struct_field"] else "string",
            "pattern": pattern.strip(),
            "color": color.strip() if color and color.startswith("#") else "#6366f1",
            "description": description.strip(),
            "offset": offset if offset is not None else None,
            "length": length if length is not None else None,
            "structure_type": structure_type if structure_type in ["header", "section", "data", "metadata", "directory", "footer"] else "header",
            "appliesToFormat": applies_to_format.strip() if applies_to_format else None,
            "category": category.strip() if category else "Custom Patterns",
            "enabled": True
        }
        pats.append(new_item)
        self._data["custom_hex_patterns"] = pats
        self._save()
        return new_item

    def update_custom_hex_pattern(self, pat_id: str, name: str, pattern: str, p_type: str = "string", color: str = "#6366f1", description: str = "", offset: Optional[int] = None, length: Optional[int] = None, structure_type: str = "header", applies_to_format: Optional[str] = None, category: Optional[str] = None, is_builtin: bool = False) -> Optional[Dict[str, Any]]:
        """Update an existing custom search / hex pattern or create override for built-in."""
        pats = self.get_custom_hex_patterns()
        found = False
        target_p = None
        for p in pats:
            if p.get("id") == pat_id:
                p["name"] = name.strip() or p.get("name", "Custom Pattern")
                p["pattern"] = pattern.strip()
                p["type"] = p_type.lower() if p_type.lower() in ["string", "regex", "hex", "struct_field"] else "string"
                p["color"] = color.strip() if color and color.startswith("#") else "#6366f1"
                p["description"] = description.strip()
                p["offset"] = offset
                p["length"] = length
                p["structure_type"] = structure_type or "header"
                if applies_to_format is not None:
                    p["appliesToFormat"] = applies_to_format.strip() if applies_to_format else None
                if category is not None:
                    p["category"] = category.strip() if category else p.get("category", "Custom")
                p["is_modified"] = True
                found = True
                target_p = p
                break

        if not found:
            # Add an override record for built-in or new pattern
            target_p = {
                "id": pat_id,
                "name": name.strip() or "Custom Pattern",
                "pattern": pattern.strip(),
                "type": p_type.lower() if p_type.lower() in ["string", "regex", "hex", "struct_field"] else "string",
                "color": color.strip() if color and color.startswith("#") else "#6366f1",
                "description": description.strip(),
                "offset": offset,
                "length": length,
                "structure_type": structure_type or "header",
                "appliesToFormat": applies_to_format.strip() if applies_to_format else None,
                "category": category.strip() if category else "Custom",
                "enabled": True,
                "is_builtin": is_builtin,
                "is_modified": True
            }
            pats.append(target_p)
            self._data["custom_hex_patterns"] = pats

        self._save()
        return target_p

    def reset_custom_hex_pattern(self, pat_id: str) -> bool:
        """Reset a modified built-in pattern back to system default."""
        pats = self.get_custom_hex_patterns()
        filtered = [p for p in pats if p.get("id") != pat_id]
        self._data["custom_hex_patterns"] = filtered
        self._save()
        return True

    def delete_custom_hex_pattern(self, pat_id: str) -> bool:
        """Delete a custom search / hex pattern by ID."""
        pats = self.get_custom_hex_patterns()
        initial_len = len(pats)
        filtered = [p for p in pats if p.get("id") != pat_id]
        if len(filtered) < initial_len:
            self._data["custom_hex_patterns"] = filtered
            self._save()
            return True
        return False

    def toggle_custom_hex_pattern(self, pat_id: str) -> Optional[bool]:
        """Toggle enabled state of a custom search / hex pattern."""
        pats = self.get_custom_hex_patterns()
        for p in pats:
            if p.get("id") == pat_id:
                p["enabled"] = not p.get("enabled", True)
                self._save()
                return p["enabled"]
        # If not found in custom_hex_patterns, it is a built-in pattern being toggled off
        new_override = {
            "id": pat_id,
            "name": pat_id,
            "pattern": "",
            "type": "string",
            "color": "#6366f1",
            "enabled": False,
            "is_modified": True,
            "is_builtin": True
        }
        pats.append(new_override)
        self._data["custom_hex_patterns"] = pats
        self._save()
        return False

    # Supported File Formats Management
    def get_file_formats(self) -> List[Dict[str, Any]]:
        """Return list of configured file formats with normalized multi-extension and signature arrays."""
        fmts = self._data.get("file_formats")
        if fmts is None or not isinstance(fmts, list) or len(fmts) == 0:
            fmts = list(DEFAULT_SETTINGS.get("file_formats", []))
            self._data["file_formats"] = fmts

        # Normalize extensions and magic_signatures arrays, and merge defaults for system formats
        def_fmt_map = {d["id"]: d for d in DEFAULT_SETTINGS.get("file_formats", [])}
        modified = False

        for f in fmts:
            fid = f.get("id")
            def_fmt = def_fmt_map.get(fid)

            # Ensure lists exist
            if "extensions" not in f or not isinstance(f.get("extensions"), list) or len(f.get("extensions", [])) == 0:
                def_ext = f.get("default_extension", "")
                f["extensions"] = [def_ext] if def_ext else []
                modified = True
            if "magic_signatures" not in f or not isinstance(f.get("magic_signatures"), list) or len(f.get("magic_signatures", [])) == 0:
                def_mag = f.get("magic_bytes", "")
                f["magic_signatures"] = [def_mag] if def_mag else []
                modified = True

            # For system formats, merge any newly introduced default extensions or signatures
            if def_fmt and f.get("is_system", False):
                curr_exts = f.get("extensions", [])
                for def_ext in def_fmt.get("extensions", []):
                    if def_ext not in curr_exts:
                        curr_exts.append(def_ext)
                        modified = True
                curr_sigs = f.get("magic_signatures", [])
                for def_sig in def_fmt.get("magic_signatures", []):
                    if def_sig not in curr_sigs:
                        curr_sigs.append(def_sig)
                        modified = True

            # Sync primary fields
            if f.get("extensions") and not f.get("default_extension"):
                f["default_extension"] = f["extensions"][0]
            if f.get("magic_signatures") and not f.get("magic_bytes"):
                f["magic_bytes"] = f["magic_signatures"][0]

        if modified:
            self._save()

        return list(fmts)

    def add_file_format(self, fmt_id: str, name: str, default_extension: str = "", magic_bytes: str = "", extensions: Optional[List[str]] = None, magic_signatures: Optional[List[str]] = None, description: str = "") -> Dict[str, Any]:
        """Add a custom file format."""
        fmts = self.get_file_formats()
        clean_id = (fmt_id or "").strip().lower()
        if not clean_id:
            import uuid
            clean_id = f"fmt_{uuid.uuid4().hex[:6]}"
        # Ensure unique id
        for f in fmts:
            if f.get("id") == clean_id:
                raise ValueError(f"File format with ID '{clean_id}' already exists.")

        # Clean extensions list
        ext_list: List[str] = []
        if extensions:
            for e in extensions:
                cleaned = e.strip().lower()
                if cleaned:
                    ext_list.append(cleaned if cleaned.startswith(".") else f".{cleaned}")
        if not ext_list and default_extension:
            cleaned = default_extension.strip().lower()
            ext_list.append(cleaned if cleaned.startswith(".") else f".{cleaned}")

        # Clean magic signatures list
        sig_list: List[str] = []
        if magic_signatures:
            for s in magic_signatures:
                cleaned = s.strip().upper()
                if cleaned:
                    sig_list.append(cleaned)
        if not sig_list and magic_bytes:
            sig_list.append(magic_bytes.strip().upper())

        primary_ext = ext_list[0] if ext_list else ".bin"
        primary_mag = sig_list[0] if sig_list else ""

        new_fmt = {
            "id": clean_id,
            "name": name.strip() or clean_id.upper(),
            "default_extension": primary_ext,
            "magic_bytes": primary_mag,
            "extensions": ext_list,
            "magic_signatures": sig_list,
            "is_system": False,
            "enabled": True,
            "description": description.strip()
        }
        fmts.append(new_fmt)
        self._data["file_formats"] = fmts
        self._save()
        return new_fmt

    def update_file_format(self, fmt_id: str, name: str, default_extension: str = "", magic_bytes: str = "", extensions: Optional[List[str]] = None, magic_signatures: Optional[List[str]] = None, description: str = "") -> Optional[Dict[str, Any]]:
        """Update an existing file format."""
        fmts = self.get_file_formats()
        for f in fmts:
            if f.get("id") == fmt_id:
                f["name"] = name.strip() or f.get("name", fmt_id)

                ext_list: List[str] = []
                if extensions is not None:
                    for e in extensions:
                        cleaned = e.strip().lower()
                        if cleaned:
                            ext_list.append(cleaned if cleaned.startswith(".") else f".{cleaned}")
                    f["extensions"] = ext_list
                elif default_extension:
                    cleaned = default_extension.strip().lower()
                    f["extensions"] = [cleaned if cleaned.startswith(".") else f".{cleaned}"]

                sig_list: List[str] = []
                if magic_signatures is not None:
                    for s in magic_signatures:
                        cleaned = s.strip().upper()
                        if cleaned:
                            sig_list.append(cleaned)
                    f["magic_signatures"] = sig_list
                elif magic_bytes:
                    f["magic_signatures"] = [magic_bytes.strip().upper()]

                if f.get("extensions"):
                    f["default_extension"] = f["extensions"][0]
                elif default_extension:
                    cleaned = default_extension.strip().lower()
                    f["default_extension"] = cleaned if cleaned.startswith(".") else f".{cleaned}"

                if f.get("magic_signatures"):
                    f["magic_bytes"] = f["magic_signatures"][0]
                elif magic_bytes:
                    f["magic_bytes"] = magic_bytes.strip().upper()

                f["description"] = description.strip()
                self._save()
                return f
        return None

    def delete_file_format(self, fmt_id: str) -> bool:
        """Delete a file format (prohibiting system default formats)."""
        fmts = self.get_file_formats()
        for f in fmts:
            if f.get("id") == fmt_id:
                if f.get("is_system", False):
                    raise ValueError("System default file formats cannot be deleted, only disabled.")
                filtered = [item for item in fmts if item.get("id") != fmt_id]
                self._data["file_formats"] = filtered
                self._save()
                return True
        return False

    def toggle_file_format(self, fmt_id: str) -> Optional[bool]:
        """Toggle enabled state of a file format."""
        fmts = self.get_file_formats()
        for f in fmts:
            if f.get("id") == fmt_id:
                f["enabled"] = not f.get("enabled", True)
                self._save()
                return f["enabled"]
        return None

    # Archive Password Unlocking Pipeline Dictionary
    def get_archive_passwords(self) -> List[str]:
        """Retrieve list of default/campaign passwords used for auto-unlocking encrypted archives."""
        self._check_reload()
        return list(self._data.get("archive_passwords", DEFAULT_SETTINGS["archive_passwords"]))

    def set_archive_passwords(self, passwords: List[str]) -> List[str]:
        """Set entire list of archive unlocking passwords."""
        cleaned: List[str] = []
        seen = set()
        for p in passwords:
            if p and isinstance(p, str):
                cp = p.strip()
                if cp and cp not in seen:
                    seen.add(cp)
                    cleaned.append(cp)
        self._data["archive_passwords"] = cleaned
        self._save()
        return cleaned

    def add_archive_password(self, password: str) -> List[str]:
        """Add a single password to the archive dictionary."""
        pw = (password or "").strip()
        pws = self.get_archive_passwords()
        if pw and pw not in pws:
            pws.append(pw)
            self._data["archive_passwords"] = pws
            self._save()
        return pws

    def delete_archive_password(self, password: str) -> List[str]:
        """Delete a password from the archive dictionary."""
        pw = (password or "").strip()
        pws = [p for p in self.get_archive_passwords() if p != pw]
        self._data["archive_passwords"] = pws
        self._save()
        return pws

    def get_cdr_policies(self) -> Dict[str, Any]:
        """Retrieve format-specific CDR and sanitization policies."""
        self._check_reload()
        return self._data.get("cdr_policies", DEFAULT_SETTINGS["cdr_policies"])

    def update_cdr_policy(self, format_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Update CDR policy for a specific file format/category."""
        self._check_reload()
        with self._lock:
            if "cdr_policies" not in self._data:
                self._data["cdr_policies"] = json.loads(json.dumps(DEFAULT_SETTINGS["cdr_policies"]))
            if format_id not in self._data["cdr_policies"]:
                self._data["cdr_policies"][format_id] = {}
            self._data["cdr_policies"][format_id].update(policy)
            self._save()
        return self._data["cdr_policies"]

    def set_cdr_policies(self, policies: Dict[str, Any]) -> Dict[str, Any]:
        """Overwrite entire CDR policies dictionary."""
        self._check_reload()
        with self._lock:
            self._data["cdr_policies"] = policies
            self._save()
        return self._data["cdr_policies"]

# JWT Auth Helpers
def verify_admin_login(username: str, password: str) -> bool:
    """Verify admin login credentials against configuration using constant-time comparison."""
    clean_user = (username or "").strip()
    clean_pass = (password or "").strip()
    expected_user = (getattr(settings, "ADMIN_USERNAME", "admin") or "admin").strip()
    expected_pass = (getattr(settings, "ADMIN_PASSWORD", "admin") or "admin").strip()

    user_ok = secrets.compare_digest(clean_user.encode("utf-8"), expected_user.encode("utf-8"))

    if expected_pass.startswith("sha256:"):
        expected_hash = expected_pass.split(":", 1)[1]
        pass_hash = hashlib.sha256(clean_pass.encode("utf-8")).hexdigest()
        pass_ok = secrets.compare_digest(pass_hash.encode("utf-8"), expected_hash.encode("utf-8"))
    else:
        pass_ok = secrets.compare_digest(clean_pass.encode("utf-8"), expected_pass.encode("utf-8"))

    return user_ok and pass_ok

def create_admin_token(username: str, expires_in_seconds: int = 86400) -> str:
    """Generate a signed JWT token for the authenticated admin."""
    payload = {
        "sub": username,
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in_seconds
    }
    return jwt.encode(payload, settings.ADMIN_SECRET_KEY, algorithm="HS256")

def verify_admin_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate an admin JWT token."""
    try:
        decoded = jwt.decode(token, settings.ADMIN_SECRET_KEY, algorithms=["HS256"])
        if decoded.get("role") == "admin":
            return decoded
        return None
    except Exception:
        return None

settings_store = SettingsStore()
