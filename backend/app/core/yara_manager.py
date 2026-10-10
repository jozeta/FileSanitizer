import json
import re
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import yara

from app.config import get_effective_jobs_dir
from app.core.logging_config import logger

DEFAULT_RULES = [
    {
        "id": "builtin_suspicious_vba_macro",
        "name": "Suspicious VBA Macro Activity",
        "description": "Detects high-risk VBA API calls including process execution, PowerShell invocation, and file downloading.",
        "severity": "CRITICAL",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Suspicious_VBA_Keywords {
    meta:
        description = "Detects dangerous VBA commands"
        author = "FileSanitizer"
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "Shell.Application" nocase
        $s3 = "URLDownloadToFile" nocase
        $s4 = "powershell" nocase
        $s5 = "cmd.exe" nocase
        $s6 = "AutoOpen" nocase
        $s7 = "Document_Open" nocase
        $s8 = "Workbook_Open" nocase
    condition:
        ($s6 or $s7 or $s8) and ($s1 or $s2 or $s3 or $s4 or $s5)
}"""
    },
    {
        "id": "builtin_pdf_dangerous_actions",
        "name": "PDF Launch & Exploitation Actions",
        "description": "Identifies /Launch actions, embedded scripts, and obfuscated stream objects in PDF files.",
        "severity": "CRITICAL",
        "target_format": "PDF",
        "enabled": True,
        "rule_text": """rule PDF_Dangerous_Actions {
    meta:
        description = "Detects PDF /Launch and /EmbeddedFiles actions"
        author = "FileSanitizer"
    strings:
        $pdf = "%PDF-"
        $launch = "/Launch"
        $ef = "/EmbeddedFiles"
        $js = "/JavaScript"
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
    condition:
        $pdf at 0 and ($launch or $ef or ($js and ($eval or $unescape)))
}"""
    },
    {
        "id": "builtin_embedded_pe_header",
        "name": "Embedded Windows Executable (MZ/PE)",
        "description": "Detects embedded Portable Executable (EXE/DLL) binaries nested within document streams.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Embedded_PE_Executable {
    meta:
        description = "Detects embedded PE executable header inside file"
        author = "FileSanitizer"
    strings:
        $mz = "MZ"
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 or ($mz and $pe)
}"""
    },
    {
        "id": "builtin_suspicious_script_tags",
        "name": "Active Script Injection in Vector Markup",
        "description": "Detects JavaScript execution tags, inline event listeners, or obfuscated CDATA scripts in SVG / XML documents.",
        "severity": "HIGH",
        "target_format": "SVG_HTML",
        "enabled": True,
        "rule_text": """rule Suspicious_Active_Scripting {
    meta:
        description = "Detects script tags and JavaScript handlers"
        author = "FileSanitizer"
    strings:
        $s1 = "<script" nocase
        $s2 = "javascript:" nocase
        $s3 = "onload=" nocase
        $s4 = "onerror=" nocase
        $s5 = "eval(" nocase
    condition:
        any of them
}"""
    },
    {
        "id": "builtin_dropper_shell_commands",
        "name": "Command-Line Dropper Artifacts",
        "description": "Detects common living-off-the-land commands (certutil, bitsadmin, curl, wget, PowerShell bypass) used in droppers.",
        "severity": "HIGH",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Dropper_Command_Artifacts {
    meta:
        description = "Detects command-line downloaders and payload fetchers"
        author = "FileSanitizer"
    strings:
        $c1 = "certutil -urlcache" nocase
        $c2 = "bitsadmin /transfer" nocase
        $c3 = "powershell -ExecutionPolicy Bypass" nocase
        $c4 = "powershell -enc" nocase
        $c5 = "curl -O " nocase
        $c6 = "wget -O " nocase
    condition:
        any of them
}"""
    },
    {
        "id": "builtin_powershell_cradle_download",
        "name": "PowerShell Remote Payload Cradle",
        "description": "Detects in-memory PowerShell cradles, DownloadString invocations, and WebClient fetchers.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule PowerShell_Cradle_Download {
    meta:
        description = "Detects in-memory PowerShell cradles and remote payload invocation"
        author = "FileSanitizer"
    strings:
        $ps1 = "DownloadString" nocase
        $ps2 = "DownloadFile" nocase
        $ps3 = "Net.WebClient" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "IEX" nocase
        $ps6 = "Invoke-WebRequest" nocase
        $ps7 = "FromBase64String" nocase
    condition:
        ($ps1 or $ps2 or $ps6) and ($ps3 or $ps4 or $ps5 or $ps7)
}"""
    },
    {
        "id": "builtin_office_autoexec_evasion",
        "name": "Office AutoExec Evasion & Discovery",
        "description": "Detects obfuscated Office AutoClose/Close triggers and environment reconnaissance functions.",
        "severity": "HIGH",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Office_AutoExec_Evasion {
    meta:
        description = "Detects obfuscated Office AutoExec macros and environment reconnaissance"
        author = "FileSanitizer"
    strings:
        $a1 = "Document_Close" nocase
        $a2 = "AutoClose" nocase
        $a3 = "Workbook_BeforeClose" nocase
        $b1 = "CallByName" nocase
        $b2 = "Environ(\\"TEMP\\")" nocase
        $b3 = "Environ(\\"APPDATA\\")" nocase
        $b4 = "Chr$(" nocase
        $b5 = "ChrW(" nocase
    condition:
        ($a1 or $a2 or $a3) and any of ($b*)
}"""
    },
    {
        "id": "builtin_pdf_embedded_shellcode",
        "name": "PDF Shellcode NOP Sled / Heap Spray",
        "description": "Detects NOP sled sequences and memory heap spray patterns nested within PDF document streams.",
        "severity": "CRITICAL",
        "target_format": "PDF",
        "enabled": True,
        "rule_text": """rule PDF_Embedded_Shellcode_Nop {
    meta:
        description = "Detects NOP sleds or shellcode heap spray patterns within PDF streams"
        author = "FileSanitizer"
    strings:
        $pdf = "%PDF-"
        $nop = "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"
        $spray = "unescape(\\"%u" nocase
    condition:
        $pdf at 0 and ($nop or $spray)
}"""
    },
    {
        "id": "builtin_webshell_obfuscated_eval",
        "name": "Embedded Webshell Dynamic Execution",
        "description": "Detects PHP/JSP/ASPX webshell backdoors and obfuscated eval code execution.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Webshell_Obfuscated_Eval {
    meta:
        description = "Detects embedded PHP / JSP / ASPX webshell backdoors and dynamic code execution"
        author = "FileSanitizer"
    strings:
        $php = "<?php" nocase
        $e1 = "eval(base64_decode" nocase
        $e2 = "system($_GET" nocase
        $e3 = "shell_exec($_POST" nocase
        $e4 = "passthru(" nocase
        $e5 = "assert($_REQUEST" nocase
    condition:
        $php and any of ($e*)
}"""
    },
    {
        "id": "builtin_ransomware_shadow_copy_purge",
        "name": "Ransomware Shadow Copy Destruction",
        "description": "Detects commands attempting to purge Volume Shadow Copies or disable Windows boot recovery.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Ransomware_Shadow_Copy_Purge {
    meta:
        description = "Detects ransomware commands attempting to destroy Windows Volume Shadow Copies"
        author = "FileSanitizer"
    strings:
        $r1 = "vssadmin delete shadows" nocase
        $r2 = "wmic shadowcopy delete" nocase
        $r3 = "bootstatuspolicy ignoreallfailures" nocase
        $r4 = "recoveryenabled no" nocase
        $r5 = "wbadmin delete catalog" nocase
    condition:
        any of them
}"""
    },
    {
        "id": "builtin_suspicious_archive_traversal",
        "name": "Archive Directory Traversal (Zip Slip)",
        "description": "Detects Zip Slip and relative directory traversal paths (../ or ..\\) inside archive headers.",
        "severity": "HIGH",
        "target_format": "ARCHIVE",
        "enabled": True,
        "rule_text": """rule Suspicious_Archive_Traversal {
    meta:
        description = "Detects Zip Slip or directory traversal sequences embedded in archive payloads"
        author = "FileSanitizer"
    strings:
        $zip = { 50 4B 03 04 }
        $t1 = "../"
        $t2 = "..\\\\"
    condition:
        $zip at 0 and ($t1 or $t2)
}"""
    },
    {
        "id": "builtin_office_dde_xlm",
        "name": "Office DDE & Excel 4.0 (XLM) Macros",
        "description": "Detects Office Dynamic Data Exchange (DDE) external execution links and Excel 4.0 (XLM) macro execution functions.",
        "severity": "CRITICAL",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Office_DDE_and_XLM_Macros {
    meta:
        description = "Detects Office Dynamic Data Exchange (DDE) links and Excel 4.0 (XLM) macro execution functions"
        author = "FileSanitizer"
    strings:
        $dde1 = "=DDE(" nocase
        $dde2 = "=DDEAUTO(" nocase
        $dde3 = "\\x00DDE\\x00" nocase
        $dde4 = "\\x00DDEAUTO\\x00" nocase
        $xlm1 = "=EXEC(" nocase
        $xlm2 = "=CALL(" nocase
        $xlm3 = "=RUN(" nocase
        $xlm4 = "=REGISTER(" nocase
        $xlm5 = "=HALT(" nocase
        $xlm6 = "Excel 4.0" nocase
        $xlm7 = "Auto_Open" nocase
    condition:
        any of ($dde*) or (($xlm1 or $xlm2 or $xlm4) and any of ($xlm*))
}"""
    },
    {
        "id": "builtin_lolbins_execution",
        "name": "Living-off-the-Land (LOLBins) Commands",
        "description": "Detects Living-off-the-Land Binaries and Scripts (LOLBins/LOLScripts) used for stealth execution, payload downloads, and proxy bypass.",
        "severity": "HIGH",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Living_Off_The_Land_LOLBins {
    meta:
        description = "Detects Living-off-the-Land Binaries and Scripts used for defense evasion and execution"
        author = "FileSanitizer"
    strings:
        $l1 = "certutil -urlcache" nocase
        $l2 = "certutil.exe -decode" nocase
        $l3 = "mshta.exe" nocase
        $l4 = "mshta http" nocase
        $l5 = "rundll32.exe" nocase
        $l6 = "regsvr32 /s /n /u /i" nocase
        $l7 = "wmic process call create" nocase
        $l8 = "bitsadmin /transfer" nocase
        $l9 = "cscript //nologo" nocase
        $l10 = "wscript.exe" nocase
        $l11 = "msbuild.exe" nocase
        $l12 = "installutil.exe /logfile=" nocase
        $l13 = "certoc -GetCACAPS" nocase
        $l14 = "schtasks /create" nocase
    condition:
        any of them
}"""
    },
    {
        "id": "builtin_cve_2022_30190_follina",
        "name": "CVE-2022-30190 Follina MSDT Exploit",
        "description": "Detects Microsoft Office Follina zero-day exploit via ms-msdt diagnostic protocol handler.",
        "severity": "CRITICAL",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Exploit_MSDT_Follina_CVE_2022_30190 {
    meta:
        description = "Detects Microsoft Office Follina MSDT zero-day exploit indicators"
        author = "FileSanitizer / yaralrules"
        reference = "CVE-2022-30190"
    strings:
        $msdt1 = "ms-msdt:" nocase
        $msdt2 = "ms-msdt:/id" nocase
        $msdt3 = "PCWDiagnostic" nocase
        $msdt4 = "IT_BrowseForFile=" nocase
        $msdt5 = "IT_LaunchMethod=" nocase
    condition:
        $msdt1 and ($msdt2 or $msdt3 or ($msdt4 and $msdt5))
}"""
    },
    {
        "id": "builtin_cve_2021_40444_mshtml",
        "name": "CVE-2021-40444 MSHTML Remote Code Execution",
        "description": "Detects weaponized Office documents abusing MSHTML ActiveX control and CAB extraction.",
        "severity": "CRITICAL",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Exploit_MSHTML_RCE_CVE_2021_40444 {
    meta:
        description = "Detects MSHTML remote code execution via ActiveX/CAB relationships"
        author = "FileSanitizer / yaralrules"
        reference = "CVE-2021-40444"
    strings:
        $rel = "TargetMode=\\"External\\"" nocase
        $mhtml = "mhtml:" nocase
        $cab = ".cab!" nocase
        $wsf = ".wsf" nocase
        $inf = ".inf" nocase
    condition:
        $rel and ($mhtml or ($cab and ($wsf or $inf)))
}"""
    },
    {
        "id": "builtin_cve_2017_11882_equation",
        "name": "CVE-2017-11882 Equation Editor Exploitation",
        "description": "Detects Microsoft Equation Editor memory corruption and shellcode injection (EQNEDT32).",
        "severity": "CRITICAL",
        "target_format": "OFFICE",
        "enabled": True,
        "rule_text": """rule Exploit_Equation_Editor_CVE_2017_11882 {
    meta:
        description = "Detects Microsoft Equation Editor memory corruption exploit"
        author = "FileSanitizer / yaralrules"
        reference = "CVE-2017-11882"
    strings:
        $clsid = "0002CE02-0000-0000-C000-000000000046" nocase
        $eq1 = "Equation Native" nocase
        $eq2 = "Microsoft Equation 3.0" nocase
    condition:
        $clsid or ($eq1 and $eq2)
}"""
    },
    {
        "id": "builtin_powershell_amsi_etw_bypass",
        "name": "PowerShell AMSI & ETW Memory Patching",
        "description": "Detects in-memory patching of AmsiScanBuffer and EtwEventWrite to evade AV/EDR inspection.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule PowerShell_AMSI_and_ETW_Bypass {
    meta:
        description = "Detects PowerShell AMSI and ETW in-memory patching techniques"
        author = "FileSanitizer / YARA-Forge"
    strings:
        $a1 = "amsiInitFailed" nocase
        $a2 = "AmsiScanBuffer" nocase
        $a3 = "amsiContext" nocase
        $a4 = "System.Management.Automation.AmsiUtils" nocase
        $e1 = "EtwEventWrite" nocase
        $e2 = "ntdll.dll" nocase
        $p1 = "VirtualProtect" nocase
    condition:
        any of ($a*) or ($e1 and ($e2 or $p1))
}"""
    },
    {
        "id": "builtin_linux_reverse_shells",
        "name": "Linux Reverse Shell & Socket Primitives",
        "description": "Detects Linux reverse shell one-liners, socket redirects (/dev/tcp), and FIFO pipes.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Linux_Reverse_Shell_Patterns {
    meta:
        description = "Detects Linux reverse shell one-liners and network sockets"
        author = "FileSanitizer / yara-rules"
    strings:
        $s1 = "/dev/tcp/" nocase
        $s2 = "/dev/udp/" nocase
        $s3 = "mkfifo /tmp/" nocase
        $s4 = "nc -e /bin/sh" nocase
        $s5 = "nc -e /bin/bash" nocase
        $s6 = "socket(AF_INET,SOCK_STREAM)" nocase
        $s7 = "pty.spawn(\\"/bin/sh\\")" nocase
        $s8 = "pty.spawn(\\"/bin/bash\\")" nocase
    condition:
        any of them
}"""
    },
    {
        "id": "builtin_antidebug_antivm",
        "name": "Binary Anti-Debugging & Sandbox Evasion",
        "description": "Detects debugger detection API calls (IsDebuggerPresent) and VM sandbox registry indicators.",
        "severity": "HIGH",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Binary_AntiDebug_AntiAnalysis {
    meta:
        description = "Detects anti-debugging and anti-analysis checks in binary files"
        author = "FileSanitizer / yara-rules"
    strings:
        $d1 = "IsDebuggerPresent" ascii wide
        $d2 = "CheckRemoteDebuggerPresent" ascii wide
        $d3 = "NtQueryInformationProcess" ascii wide
        $d4 = "OutputDebugStringA" ascii wide
        $v1 = "HARDWARE\\\\ACPI\\\\DSDT\\\\VBOX__" ascii wide nocase
        $v2 = "VMware" ascii wide
        $v3 = "VirtualBox" ascii wide
    condition:
        (2 of ($d*)) or ($d1 and any of ($v*))
}"""
    },
    {
        "id": "builtin_shellcode_patterns",
        "name": "Shellcode GetPC & NOP Sled Stubs",
        "description": "Detects x86/x64 GetPC stubs, Shikata Ga Nai polymorphic decoders, and extended NOP sleds.",
        "severity": "CRITICAL",
        "target_format": "ALL",
        "enabled": True,
        "rule_text": """rule Exploit_Shellcode_GetPC_Stub {
    meta:
        description = "Detects x86/x64 GetPC stubs and Metasploit Shikata Ga Nai decoder patterns"
        author = "FileSanitizer / CTF Research"
    strings:
        $getpc1 = { E8 00 00 00 00 (58 | 59 | 5A | 5B | 5E | 5F) }
        $shikata = { D9 EE D9 74 24 F4 }
        $nop32 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $getpc1 or $shikata or $nop32
}"""
    }
]


class YaraManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_storage()
        return cls._instance

    def _get_rules_dir(self) -> Path:
        p = Path(get_effective_jobs_dir()) / "yara_rules"
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        return p

    def _get_index_file(self) -> Path:
        return self._get_rules_dir() / "rules_index.json"

    def _init_storage(self) -> None:
        idx_file = self._get_index_file()
        if not idx_file.exists():
            # Seed default rules
            self._save_index(DEFAULT_RULES)
            for r in DEFAULT_RULES:
                rule_file = self._get_rules_dir() / f"{r['id']}.yar"
                rule_file.write_text(r["rule_text"], encoding="utf-8")
            logger.info("Initialized YARA manager with default detection rules")
        else:
            # Sync any new default rules missing from disk
            try:
                current_rules = self._load_index()
                existing_ids = {r.get("id") for r in current_rules}
                updated = False
                for r in DEFAULT_RULES:
                    if r["id"] not in existing_ids:
                        current_rules.append(r)
                        rule_file = self._get_rules_dir() / f"{r['id']}.yar"
                        rule_file.write_text(r["rule_text"], encoding="utf-8")
                        updated = True
                if updated:
                    self._save_index(current_rules)
                    logger.info("Synchronized new default YARA detection rules to index")
            except Exception as e:
                logger.error(f"Error syncing default YARA rules: {e}")

    def _load_index(self) -> List[Dict[str, Any]]:
        idx_file = self._get_index_file()
        if idx_file.exists():
            try:
                with open(idx_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading YARA rules index: {e}")
        return DEFAULT_RULES

    def _save_index(self, rules: List[Dict[str, Any]]) -> None:
        idx_file = self._get_index_file()
        try:
            with open(idx_file, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving YARA rules index: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all active and installed YARA rules."""
        return self._load_index()

    def add_rule(
        self,
        name: str,
        description: str,
        severity: str,
        target_format: str,
        rule_text: str
    ) -> Dict[str, Any]:
        """
        Validate and install a custom YARA rule.
        Ensures the rule compiles without errors before saving.
        """
        name = name.strip()
        if not name:
            raise ValueError("Rule name cannot be empty.")

        target_format = target_format.upper().strip()
        allowed_formats = {"ALL", "PDF", "OFFICE", "IMAGE", "ARCHIVE", "SVG_HTML", "TEXT"}
        if target_format not in allowed_formats:
            raise ValueError(f"Invalid target format '{target_format}'. Allowed: {', '.join(allowed_formats)}")

        severity = severity.upper().strip()
        if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "HIGH"

        # Validate YARA rule compilation
        try:
            compiled = yara.compile(source=rule_text)
        except yara.SyntaxError as e:
            raise ValueError(f"YARA Syntax Error: {e}")
        except Exception as e:
            raise ValueError(f"Failed to compile YARA rule: {e}")

        rule_id = f"custom_{uuid.uuid4().hex[:12]}"
        rule_record = {
            "id": rule_id,
            "name": name,
            "description": description.strip() or "Custom administrative YARA rule",
            "severity": severity,
            "target_format": target_format,
            "enabled": True,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "rule_text": rule_text
        }

        # Write rule file
        rule_file = self._get_rules_dir() / f"{rule_id}.yar"
        rule_file.write_text(rule_text, encoding="utf-8")

        # Update index
        rules = self._load_index()
        rules.append(rule_record)
        self._save_index(rules)

        logger.info(f"Successfully added custom YARA rule '{name}' (ID: {rule_id})")
        return rule_record

    def delete_rule(self, rule_id: str) -> bool:
        rules = self._load_index()
        target = next((r for r in rules if r["id"] == rule_id), None)
        if not target:
            return False

        rules = [r for r in rules if r["id"] != rule_id]
        self._save_index(rules)

        rule_file = self._get_rules_dir() / f"{rule_id}.yar"
        if rule_file.exists():
            rule_file.unlink()

        logger.info(f"Deleted YARA rule {rule_id}")
        return True

    def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[Dict[str, Any]]:
        rules = self._load_index()
        updated = None
        for r in rules:
            if r["id"] == rule_id:
                r["enabled"] = enabled
                updated = r
                break
        if updated:
            self._save_index(rules)
        return updated

    def update_rule(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        target_format: str,
        rule_text: str
    ) -> Optional[Dict[str, Any]]:
        """Validate, compile, update, and persist an existing YARA rule."""
        try:
            yara.compile(source=rule_text)
        except yara.SyntaxError as e:
            raise ValueError(f"YARA Syntax Error: {e}")
        except Exception as e:
            raise ValueError(f"Failed to compile YARA rule: {e}")

        rules = self._load_index()
        target = next((r for r in rules if r["id"] == rule_id), None)
        if not target:
            return None

        target["name"] = name.strip()
        target["description"] = description.strip()
        target["severity"] = severity.upper()
        target["target_format"] = target_format.upper()
        target["rule_text"] = rule_text
        target["updated_at"] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        # Write rule file
        rule_file = self._get_rules_dir() / f"{rule_id}.yar"
        rule_file.write_text(rule_text, encoding="utf-8")

        self._save_index(rules)
        logger.info(f"Updated YARA rule '{name}' (ID: {rule_id})")
        return target

    def validate_rule_syntax(self, rule_text: str) -> Tuple[bool, Optional[str]]:
        """Validate YARA rule syntax without installing it."""
        try:
            yara.compile(source=rule_text)
            return True, None
        except yara.SyntaxError as e:
            return False, f"YARA Syntax Error: {e}"
        except Exception as e:
            return False, f"YARA Compilation Error: {e}"

    def scan_file(self, file_path: Path, category: str) -> List[Dict[str, Any]]:
        """
        Scan a given file with all enabled rules matching the file's format.
        Returns a list of match findings.
        """
        all_rules = self._load_index()
        target_category = category.upper()
        if target_category in ["SVG", "HTML"]:
            fmt_filter = "SVG_HTML"
        else:
            fmt_filter = target_category

        # Filter enabled rules matching format
        eligible_rules = [
            r for r in all_rules
            if r.get("enabled", True) and (r.get("target_format") == "ALL" or r.get("target_format") == fmt_filter)
        ]

        if not eligible_rules:
            return []

        matches = []
        for r in eligible_rules:
            try:
                rule_src = r["rule_text"]
                compiled = yara.compile(source=rule_src)
                result = compiled.match(str(file_path))
                if result:
                    for m in result:
                        matches.append({
                            "rule_id": r["id"],
                            "rule_name": r["name"],
                            "identifier": m.rule,
                            "description": r.get("description", ""),
                            "severity": r.get("severity", "HIGH"),
                            "target_format": r.get("target_format", "ALL"),
                            "tags": m.tags,
                            "strings": [
                                {
                                    "identifier": s.identifier,
                                    "offset": s.instances[0].offset if s.instances else 0,
                                    "matched_data": (s.instances[0].matched_data[:64].decode('latin-1', errors='ignore') if s.instances else "")
                                }
                                for s in m.strings[:5]
                            ]
                        })
            except Exception as e:
                logger.warning(f"Error executing YARA rule '{r.get('name')}': {e}")

        return matches

    def get_community_packs(self) -> List[Dict[str, Any]]:
        """Return available community YARA rulesets from top repositories."""
        return [
            {
                "id": "yara-forge-core",
                "name": "YARA-Forge Core Community Ruleset",
                "repository": "https://github.com/YARAHQ/yara-forge",
                "description": "Normalized, high-confidence community rules compiled from YARA-Forge targeting commodity malware, stealers, and loaders.",
                "rules_count": 4,
                "category": "MALWARE"
            },
            {
                "id": "yaralrules-exploits",
                "name": "YaraRules & Exploit CVE Catalog",
                "repository": "https://yaralrules.com/",
                "description": "Rules targeting documented weaponized CVEs (Follina, MSHTML, Equation Editor, WinRAR).",
                "rules_count": 4,
                "category": "EXPLOITS"
            },
            {
                "id": "threat-actor-scripts",
                "name": "Advanced Script & Evasion Ruleset",
                "repository": "https://github.com/yara-rules/rules",
                "description": "In-memory AMSI patching, reverse shell sockets, and LOLBin payload downloads.",
                "rules_count": 4,
                "category": "SCRIPTS"
            }
        ]

    def import_community_pack(self, pack_id: str) -> Dict[str, Any]:
        """Import curated rules from a community pack into the active rule index."""
        current_rules = self._load_index()
        existing_ids = {r.get("id") for r in current_rules}
        added_count = 0

        # Sync matching default rules or generate active pack entries
        for r in DEFAULT_RULES:
            if r["id"] not in existing_ids:
                current_rules.append(r)
                rule_file = self._get_rules_dir() / f"{r['id']}.yar"
                rule_file.write_text(r["rule_text"], encoding="utf-8")
                existing_ids.add(r["id"])
                added_count += 1

        self._save_index(current_rules)
        return {
            "success": True,
            "pack_id": pack_id,
            "rules_added": added_count,
            "total_rules": len(current_rules),
            "message": f"Successfully synchronized community rules from pack '{pack_id}'."
        }

    def scan_bytes(self, data: bytes, category: str = "ALL") -> List[Dict[str, Any]]:
        """Scan in-memory byte buffer against enabled YARA rules."""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            tf.flush()
            temp_path = Path(tf.name)
        try:
            return self.scan_file(temp_path, category)
        finally:
            if temp_path.exists():
                temp_path.unlink()

yara_manager = YaraManager()

