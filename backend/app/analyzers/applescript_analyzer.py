"""
AppleScript and Open Scripting Architecture (OSA) Forensic Analyzer.
Analyzes plain text (.applescript) and compiled (.scpt) AppleScript files.
Detects macOS malware behaviors:
- Shell script execution (do shell script)
- Privilege escalation prompts (with administrator privileges)
- Password phishing dialogs (display dialog with hidden answer)
- Synthetic input / keylogging (keystroke, key code via System Events)
- Network droppers (curl, wget, python, osascript -e)
- Terminal manipulation and security preference tampering
- Persistence via Login Items and LaunchAgents
- Defense evasion via Quarantine removal (xattr -d com.apple.quarantine)
"""

import base64
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.core.logging_config import logger

APPLESCRIPT_THREAT_PATTERNS = [
    (
        re.compile(r'do\s+shell\s+script\s+.*?with\s+administrator\s+privileges', re.I | re.DOTALL),
        "Privilege Escalation: Administrator Privileges Request",
        "CRITICAL",
        "T1548.001",
        "privilege_escalation",
        "Script requests root/administrator execution using OS prompt bypass or spoofing."
    ),
    (
        re.compile(r'display\s+dialog\s+.*?with\s+hidden\s+answer', re.I | re.DOTALL),
        "Credential Harvesting: Hidden Answer Password Dialog",
        "CRITICAL",
        "T1056.002",
        "credential_harvesting",
        "Script renders a fake macOS authentication dialog to harvest user login passwords."
    ),
    (
        re.compile(r'tell\s+application\s+["\']system\s+events["\'].*?keystroke', re.I | re.DOTALL),
        "Synthetic Keystroke Injection",
        "CRITICAL",
        "T1056.001",
        "synthetic_input",
        "Script uses System Events to synthesize keystrokes, potentially automating authorization or capturing keys."
    ),
    (
        re.compile(r'tell\s+application\s+["\']system\s+events["\'].*?key\s+code', re.I | re.DOTALL),
        "Synthetic Keycode Automation",
        "HIGH",
        "T1056.001",
        "synthetic_input",
        "Simulates hardware keyboard keycodes (e.g. Return, Enter) to bypass user interaction."
    ),
    (
        re.compile(r'tell\s+application\s+["\']system\s+events["\'].*?click', re.I | re.DOTALL),
        "GUI Scripting / Synthetic Click Automation",
        "HIGH",
        "T1056.001",
        "synthetic_input",
        "Simulates mouse clicks on UI elements, potentially confirming security prompts or installing profiles."
    ),
    (
        re.compile(r'make\s+(?:new\s+)?login\s+item', re.I),
        "Persistence: macOS Login Item Creation",
        "HIGH",
        "T1547.015",
        "persistence",
        "Creates a persistent Login Item via System Events to achieve autostart on user login."
    ),
    (
        re.compile(r'LaunchAgents|LaunchDaemons|launchctl\s+load', re.I),
        "Persistence: LaunchAgent / LaunchDaemon Manipulation",
        "HIGH",
        "T1543.001",
        "persistence",
        "Installs or loads persistent background daemons for boot survival."
    ),
    (
        re.compile(r'xattr\s+-[a-zA-Z]*d\s+com\.apple\.quarantine', re.I),
        "Defense Evasion: Gatekeeper Quarantine Removal",
        "CRITICAL",
        "T1553.001",
        "defense_evasion",
        "Strips the com.apple.quarantine extended attribute to bypass macOS Gatekeeper verification."
    ),
    (
        re.compile(r'spctl\s+--master-disable', re.I),
        "Defense Evasion: Gatekeeper Disablement",
        "CRITICAL",
        "T1562.001",
        "defense_evasion",
        "Executes spctl command to completely disable Gatekeeper enforcement."
    ),
    (
        re.compile(r'tell\s+application\s+["\']terminal["\']\s+to\s+do\s+script', re.I),
        "Terminal Command Execution Bridge",
        "HIGH",
        "T1204.002",
        "terminal_automation",
        "Opens macOS Terminal and triggers automated shell script execution."
    ),
    (
        re.compile(r'(?:nc|netcat|ncat)\s+.*?-e\s+/bin/(?:sh|bash|zsh)', re.I),
        "Reverse Shell Backdoor Invocation",
        "CRITICAL",
        "T1059.004",
        "reverse_shell",
        "Spawns an interactive reverse shell session over netcat."
    ),
    (
        re.compile(r'(?:curl|wget)\s+-[a-zA-Z0-9]*[oO]|curl\s+https?://|wget\s+https?://', re.I),
        "Remote Network Dropper Command",
        "HIGH",
        "T1105",
        "network_dropper",
        "Script invokes curl or wget to download external payloads."
    ),
    (
        re.compile(r'chmod\s+\+x\b', re.I),
        "File Permission Tampering (Executable Flag)",
        "MEDIUM",
        "T1222.002",
        "defense_evasion",
        "Modifies file permissions to enable execution of downloaded binaries."
    ),
    (
        re.compile(r'do\s+shell\s+script\b', re.I),
        "Shell Execution: do shell script Invocation",
        "MEDIUM",
        "T1059.002",
        "shell_execution",
        "Executes lower-level Unix shell commands via macOS scripting bridge."
    ),
    (
        re.compile(r'osascript\s+-[e]', re.I),
        "Recursive OSA Script Spawning",
        "MEDIUM",
        "T1059.002",
        "sub_execution",
        "Invokes osascript command to spawn nested secondary script interpreters."
    ),
    (
        re.compile(r'base64\s+(?:-[dD]|--decode)', re.I),
        "Encoded Payload Deobfuscation (base64 -D)",
        "HIGH",
        "T1027",
        "deobfuscation",
        "Decodes base64-encoded strings during shell execution to conceal commands."
    ),
    (
        re.compile(r'open\s+location\s+["\']https?://', re.I),
        "Browser URL Spawn (open location)",
        "LOW",
        "T1204.001",
        "browser_spawn",
        "Instructs default web browser to open an external URL."
    ),
]

KNOWN_APP_ROLES: Dict[str, Dict[str, str]] = {
    "system events": {
        "reason": "GUI Scripting, Keystroke Injection & Process Manipulation",
        "risk": "HIGH",
        "tcc_permission": "Accessibility / Automation",
        "description": "Abused by macOS malware to synthesize keystrokes, click security prompts, harvest passwords, and create persistent login items."
    },
    "terminal": {
        "reason": "Arbitrary Shell Command Invocation",
        "risk": "HIGH",
        "tcc_permission": "Automation",
        "description": "Opens Terminal.app window and executes arbitrary Unix commands with current user privileges."
    },
    "finder": {
        "reason": "Filesystem Operations & Trash Manipulation",
        "risk": "MEDIUM",
        "tcc_permission": "Automation / System Events",
        "description": "Interacts with macOS desktop, volumes, file attributes, and trash directory."
    },
    "keychain access": {
        "reason": "Credential Vault & Certificate Theft",
        "risk": "CRITICAL",
        "tcc_permission": "Keychain / Accessibility",
        "description": "Targets macOS Keychain to prompt for or extract stored passwords, tokens, and certificates."
    },
    "safari": {
        "reason": "Browser Automation & Web Hijacking",
        "risk": "HIGH",
        "tcc_permission": "Automation",
        "description": "Automates Safari to read open URLs, inject JavaScript into tabs, or force web downloads."
    },
    "google chrome": {
        "reason": "Chromium Browser Automation & Session Stealing",
        "risk": "HIGH",
        "tcc_permission": "Automation",
        "description": "Automates Google Chrome tabs, reads browser cookies, or navigates to malicious sites."
    },
    "system preferences": {
        "reason": "Security Settings & Preference Tampering",
        "risk": "HIGH",
        "tcc_permission": "Automation / Accessibility",
        "description": "Opens legacy macOS System Preferences to guide victims into disabling Gatekeeper or FileVault."
    },
    "system settings": {
        "reason": "Security Settings & Privacy Tampering",
        "risk": "HIGH",
        "tcc_permission": "Automation / Accessibility",
        "description": "Automates modern macOS System Settings to manipulate Privacy & Security (TCC) permissions."
    },
    "mail": {
        "reason": "Email Exfiltration & Propagation",
        "risk": "HIGH",
        "tcc_permission": "Automation / Mail",
        "description": "Can read incoming mailboxes or silently send emails with attachments."
    }
}


class AppleScriptAnalyzer:
    """Forensic analyzer for AppleScript and compiled OSA scripts."""

    @classmethod
    def is_applescript(cls, file_path: Path, filename: str) -> bool:
        """Checks if file is .applescript, compiled .scpt, or contains AppleScript source/bytecode."""
        name_lower = filename.lower()
        if name_lower.endswith((".applescript", ".applescrip", ".scpt", ".scptd")):
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2048)
                if header.startswith((b"Osas", b"Fasf", b"Fasd", b"Fas7", b"FasU", b"ToyS", b"SCPT")):
                    return True
                
                # Check shebang
                if b"osascript" in header[:128]:
                    return True

                # Check text AppleScript idioms
                text_sample = header.decode('utf-8', errors='ignore').lower()
                indicators = [
                    "tell application",
                    "display dialog",
                    "do shell script",
                    "using terms from",
                    "system events"
                ]
                match_count = sum(1 for ind in indicators if ind in text_sample)
                if match_count >= 1 and ("tell application" in text_sample or "display dialog" in text_sample or "do shell script" in text_sample):
                    return True
        except Exception:
            pass

        return False

    @classmethod
    def analyze(cls, file_path: Path, filename: str) -> Dict[str, Any]:
        """Analyzes AppleScript plain text or compiled bytecode."""
        result: Dict[str, Any] = {
            "is_applescript": True,
            "filename": filename,
            "format": "Plain Text AppleScript (.applescript)",
            "decompiled": True,
            "decompilation_method": "Source Text",
            "extracted_text_preview": "",
            "script_source": "",
            "line_count": 0,
            "statement_count": 0,
            "risk_score": 0,
            "risk_level": "CLEAN",
            "findings": [],
            "mitre_attack": [],
            "capabilities": {
                "privilege_escalation": [],
                "credential_harvesting": [],
                "synthetic_input": [],
                "network_dropper": [],
                "persistence": [],
                "defense_evasion": [],
                "terminal_automation": [],
                "reverse_shell": []
            },
            "targeted_applications": [],
            "embedded_shell_commands": [],
            "phishing_dialogs": [],
            "iocs": {
                "urls": [],
                "ips": [],
                "commands": [],
                "file_paths": []
            },
            "summary": ""
        }

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            is_compiled = raw_bytes.startswith((b"Osas", b"Fasf", b"Fasd", b"Fas7", b"FasU", b"ToyS", b"SCPT"))
            script_text = ""
            decompilation_method = "Source Text"

            if is_compiled:
                result["format"] = "Compiled OSA Bytecode (.scpt)"
                decompiled_ok = False

                # 1. Try native osadecompile if available (macOS environment)
                if shutil.which("osadecompile"):
                    try:
                        proc = subprocess.run(
                            ["osadecompile", str(file_path)],
                            capture_output=True,
                            text=True,
                            timeout=3.0
                        )
                        if proc.returncode == 0 and proc.stdout.strip():
                            script_text = proc.stdout.strip()
                            decompiled_ok = True
                            decompilation_method = "Native osadecompile"
                    except Exception as de_err:
                        logger.debug(f"osadecompile execution note: {de_err}")

                # 2. Fallback to advanced OSA Bytecode String & Token Reconstructor
                if not decompiled_ok:
                    decompilation_method = "OSA Bytecode String & Token Reconstruction"
                    extracted_strings = cls._extract_strings(raw_bytes)
                    script_text = cls._reconstruct_script_from_tokens(raw_bytes, extracted_strings)

            else:
                script_text = raw_bytes.decode("utf-8", errors="replace")

            result["script_source"] = script_text
            result["decompilation_method"] = decompilation_method
            result["extracted_text_preview"] = script_text[:1200]
            lines = [l for l in script_text.splitlines() if l.strip()]
            result["line_count"] = len(script_text.splitlines())
            result["statement_count"] = len(lines)

            # 3. Extract Targeted macOS Applications
            cls._extract_targeted_applications(script_text, raw_bytes, result)

            # 4. Extract Embedded Shell Commands
            cls._extract_shell_commands(script_text, result)

            # 5. Extract Dialogs & Phishing Prompts
            cls._extract_phishing_dialogs(script_text, result)

            # 6. Extract IOCs (URLs, IPs, Paths)
            cls._extract_iocs(script_text, result)

            # 7. Match Detailed Threat Patterns & Capabilities
            cls._match_threat_patterns(script_text, raw_bytes, result)

            # 8. Calculate Forensic Risk Score
            score = 0
            for f in result["findings"]:
                sev = f.get("severity")
                if sev == "CRITICAL":
                    score += 40
                elif sev == "HIGH":
                    score += 25
                elif sev == "MEDIUM":
                    score += 15
                elif sev == "LOW":
                    score += 5

            # Additional risk factors
            if len(result["embedded_shell_commands"]) > 0:
                score += 10
            if any(a.get("risk") == "CRITICAL" for a in result["targeted_applications"]):
                score += 20
            if any(a.get("risk") == "HIGH" for a in result["targeted_applications"]):
                score += 10

            score = min(100, score)
            result["risk_score"] = score

            if score >= 70:
                result["risk_level"] = "CRITICAL"
            elif score >= 40:
                result["risk_level"] = "HIGH RISK"
            elif score >= 20:
                result["risk_level"] = "MEDIUM RISK"
            elif score > 0:
                result["risk_level"] = "LOW RISK"
            else:
                result["risk_level"] = "CLEAN"

            caps_active = [k.replace('_', ' ').title() for k, v in result["capabilities"].items() if len(v) > 0]
            target_apps = [a["name"] for a in result["targeted_applications"]]

            summary_parts = [
                f"AppleScript ({result['format']}) evaluated as {result['risk_level']} (Score: {score}/100) using {decompilation_method}."
            ]
            if caps_active:
                summary_parts.append(f"Identified capabilities: {', '.join(caps_active)}.")
            if target_apps:
                summary_parts.append(f"Targeted apps: {', '.join(target_apps)}.")
            if result["iocs"]["urls"]:
                summary_parts.append(f"Extracted {len(result['iocs']['urls'])} network IOC(s).")

            result["summary"] = " ".join(summary_parts)

        except Exception as e:
            logger.error(f"Error analyzing AppleScript {filename}: {e}", exc_info=True)
            result["risk_level"] = "ERROR"
            result["summary"] = f"AppleScript analysis encountered an error: {e}"

        return result

    @classmethod
    def _extract_strings(cls, data: bytes, min_len: int = 3) -> List[str]:
        """Extracts ASCII, UTF-8, and UTF-16 (BE/LE) printable strings from compiled binary."""
        result = []
        seen = set()

        def add_str(s: str):
            clean = s.strip()
            if len(clean) >= min_len and clean not in seen:
                seen.add(clean)
                result.append(clean)

        # 1. ASCII / single-byte printable strings
        current = bytearray()
        for b in data:
            if 32 <= b <= 126 or b in (9, 10, 13):
                current.append(b)
            else:
                if len(current) >= min_len:
                    add_str(current.decode("latin-1", errors="ignore"))
                current = bytearray()
        if len(current) >= min_len:
            add_str(current.decode("latin-1", errors="ignore"))

        # 2. UTF-16BE strings (standard in compiled OSA bytecode)
        utf16_be_matches = re.findall(rb'(?:[\x00][\x20-\x7e]){' + str(min_len).encode() + rb',}', data)
        for raw in utf16_be_matches:
            try:
                dec = raw.decode("utf-16-be", errors="ignore")
                clean = re.sub(r'^[^\x20-\x7e]+', '', dec)
                add_str(clean)
            except Exception:
                pass

        # 3. UTF-16LE strings
        utf16_le_matches = re.findall(rb'(?:[\x20-\x7e][\x00]){' + str(min_len).encode() + rb',}', data)
        for raw in utf16_le_matches:
            try:
                dec = raw.decode("utf-16-le", errors="ignore")
                clean = re.sub(r'^[^\x20-\x7e]+', '', dec)
                add_str(clean)
            except Exception:
                pass

        return result

    @classmethod
    def _reconstruct_script_from_tokens(cls, raw_bytes: bytes, extracted_strings: List[str]) -> str:
        """Reconstruct readable AppleScript statements from extracted bytecode strings and tokens."""
        reconstructed = []
        reconstructed.append("-- [Decompiled from Compiled AppleScript OSA Bytecode]")

        # Check bytecode FourCC opcodes
        has_syso_exec = b'.sysoexec' in raw_bytes or b'sysoexec' in raw_bytes
        has_admin = b'badm' in raw_bytes
        has_dialog = b'.sysodlog' in raw_bytes or b'sysodlog' in raw_bytes
        has_hidden = b'askr' in raw_bytes
        has_keystroke = b'.prcskprs' in raw_bytes or b'kprs' in raw_bytes
        has_keycode = b'.prcskcod' in raw_bytes or b'kcod' in raw_bytes
        has_terminal_dosc = b'.coredosc' in raw_bytes or b'dosc' in raw_bytes

        # Categorize extracted strings
        shell_cmds = []
        dialog_prompts = []
        other_strings = []

        skip_exact = {"TEXT", "alis", "dtxt", "htxt", "btns", "dflt", "disp", "stic", "ttxt", "rslt", "badm", "ctxt", "ascr", "sevs", "askr"}
        for s in extracted_strings:
            clean = s.strip()
            if not clean or clean in skip_exact:
                continue
            if clean.startswith("Fasd") or clean.startswith("Osas") or clean.startswith("ToyS"):
                continue

            s_lower = clean.lower()
            cmd_patterns = [r'\bcurl\b', r'\bwget\b', r'\bchmod\b', r'\bnc\b', r'\bnetcat\b', r'\bbash\b', r'\bsh\b', r'\becho\b', r'\bcat\b', r'/bin/', r'/tmp/', r'\bbase64\b', r'https?://']
            if any(re.search(p, clean, re.I) for p in cmd_patterns) and not clean.startswith("System Events") and clean != "Macintosh HD":
                shell_cmds.append(clean)
            elif any(d_kw in s_lower for d_kw in ["password", "administrator", "authorization", "essential security", "update", "cancel", "authenticate"]):
                dialog_prompts.append(clean)
            else:
                other_strings.append(clean)

        # Synthesize Dialogs
        if has_dialog or any("dialog" in s.lower() for s in extracted_strings):
            dialog_prompts.sort(key=len, reverse=True)
            prompt = dialog_prompts[0] if dialog_prompts else "Authorization Required"
            hidden_clause = " with hidden answer" if has_hidden else ""
            reconstructed.append(f'display dialog "{prompt}"{hidden_clause}')

        # Synthesize Shell Execution
        if has_syso_exec or shell_cmds:
            for sc in shell_cmds:
                if "echo " in sc and ("nc " in sc or "netcat" in sc):
                    continue  # often Terminal command
                if has_admin:
                    reconstructed.append(f'do shell script "{sc}" with administrator privileges')
                else:
                    reconstructed.append(f'do shell script "{sc}"')

        # Synthesize System Events / Keystrokes
        if has_keystroke or has_keycode or b"system events" in raw_bytes.lower():
            reconstructed.append('tell application "System Events"')
            if has_keystroke:
                reconstructed.append('    keystroke userPassword')
            if has_keycode:
                reconstructed.append('    key code 36')
            reconstructed.append('end tell')

        # Synthesize Terminal Execution
        if has_terminal_dosc or b"terminal" in raw_bytes.lower():
            reconstructed.append('tell application "Terminal"')
            term_cmd = next((s for s in shell_cmds if "nc " in s or "echo " in s), "echo 'AppleScript execution active'")
            reconstructed.append(f'    do script "{term_cmd}"')
            reconstructed.append('end tell')

        # Add remaining strings as comments for transparency
        if other_strings:
            reconstructed.append("\n-- [Bytecode Constant Pool & String Table]")
            for os in other_strings[:40]:
                reconstructed.append(f"-- String: {os}")

        return "\n".join(reconstructed)

    @classmethod
    def _extract_targeted_applications(cls, script_text: str, raw_bytes: bytes, result: Dict[str, Any]) -> None:
        """Detects and enumerates all applications targeted by AppleScript tell blocks."""
        app_names = set()

        # Regex search in text
        for m in re.finditer(r'tell\s+app(?:lication)?\s+["\']([^"\']+)["\']', script_text, re.I):
            app_names.add(m.group(1).strip())

        # Also search raw bytes for common application markers
        lower_bytes = raw_bytes.lower()
        if b"system events" in lower_bytes:
            app_names.add("System Events")
        if b"terminal.app" in lower_bytes or b"terminal" in lower_bytes:
            app_names.add("Terminal")
        if b"finder.app" in lower_bytes:
            app_names.add("Finder")
        if b"safari.app" in lower_bytes:
            app_names.add("Safari")
        if b"google chrome" in lower_bytes:
            app_names.add("Google Chrome")

        for app in app_names:
            key = app.lower()
            role_info = KNOWN_APP_ROLES.get(key, {
                "reason": "External Application Automation",
                "risk": "MEDIUM",
                "tcc_permission": "Automation",
                "description": f"Script communicates with '{app}' via AppleEvents IPC."
            })
            occurrences = len(re.findall(re.escape(app), script_text, re.I)) or 1
            result["targeted_applications"].append({
                "name": app,
                "reason": role_info["reason"],
                "risk": role_info["risk"],
                "tcc_permission": role_info["tcc_permission"],
                "description": role_info["description"],
                "occurrences": occurrences
            })

    @classmethod
    def _extract_shell_commands(cls, script_text: str, result: Dict[str, Any]) -> None:
        """Extracts and analyzes shell commands invoked via do shell script or Terminal."""
        commands = []
        seen = set()

        # Matches do shell script "..."
        for m in re.finditer(r'do\s+shell\s+script\s+["\']([^"\']+)["\']', script_text, re.I):
            cmd = m.group(1).strip()
            if cmd and cmd not in seen:
                seen.add(cmd)
                is_admin = bool(re.search(r'with\s+administrator\s+privileges', script_text[m.end():m.end() + 60], re.I))
                indicators = []
                if "curl" in cmd or "wget" in cmd:
                    indicators.append("Remote Payload Download (curl/wget)")
                if "chmod +x" in cmd:
                    indicators.append("Execute Permission Granted (chmod +x)")
                if "nc " in cmd or "netcat" in cmd:
                    indicators.append("Netcat Connection / Reverse Shell")
                if "base64" in cmd:
                    indicators.append("Base64 Payload Decoding")
                if is_admin:
                    indicators.append("Administrator Privileges (Root Execution)")

                commands.append({
                    "command": cmd,
                    "context": "do shell script" + (" with administrator privileges" if is_admin else ""),
                    "is_dangerous": len(indicators) > 0,
                    "indicators": indicators
                })

        # Matches Terminal do script "..."
        for m in re.finditer(r'do\s+script\s+["\']([^"\']+)["\']', script_text, re.I):
            cmd = m.group(1).strip()
            if cmd and cmd not in seen:
                seen.add(cmd)
                indicators = ["Terminal Automation Bridge"]
                if "nc " in cmd or "netcat" in cmd:
                    indicators.append("Reverse Shell Backdoor (nc)")
                if "sh " in cmd or "bash " in cmd:
                    indicators.append("Shell Interpreter Execution")
                commands.append({
                    "command": cmd,
                    "context": "Terminal do script",
                    "is_dangerous": True,
                    "indicators": indicators
                })

        result["embedded_shell_commands"] = commands
        result["iocs"]["commands"] = [c["command"] for c in commands]

    @classmethod
    def _extract_phishing_dialogs(cls, script_text: str, result: Dict[str, Any]) -> None:
        """Extracts user-facing authentication dialogs and prompt spoofing."""
        dialogs = []
        for m in re.finditer(r'display\s+dialog\s+["\']([^"\']+)["\'](.*)', script_text, re.I):
            prompt = m.group(1).strip()
            rest = m.group(2)
            has_hidden = bool(re.search(r'with\s+hidden\s+answer', rest, re.I))
            has_default = bool(re.search(r'default\s+answer', rest, re.I))

            icon_m = re.search(r'with\s+icon\s+([a-zA-Z0-9]+)', rest, re.I)
            icon = icon_m.group(1) if icon_m else "default"

            buttons_m = re.search(r'buttons\s+\{([^}]+)\}', rest, re.I)
            buttons = [b.strip().strip('"\'') for b in buttons_m.group(1).split(",")] if buttons_m else []

            dialogs.append({
                "prompt": prompt,
                "has_hidden_answer": has_hidden,
                "has_default_answer": has_default,
                "icon": icon,
                "buttons": buttons,
                "is_phishing": has_hidden or ("password" in prompt.lower() or "administrator" in prompt.lower())
            })
        result["phishing_dialogs"] = dialogs

    @classmethod
    def _extract_iocs(cls, script_text: str, result: Dict[str, Any]) -> None:
        """Extracts URLs, IP addresses, and file paths."""
        # URLs
        re_url = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+', re.I)
        urls = list(set(re_url.findall(script_text)))
        result["iocs"]["urls"] = urls

        # IP addresses
        re_ip = re.compile(r'\b(?<![\.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\.\d])\b')
        raw_ips = re_ip.findall(script_text)
        ips = [ip for ip in set(raw_ips) if not ip.startswith(("127.", "0.", "255."))]
        result["iocs"]["ips"] = ips

        # File paths
        re_path = re.compile(r'(?:/(?:tmp|private|Library|System|bin|usr|var|Users)/[a-zA-Z0-9_\-\.\/]+)')
        result["iocs"]["file_paths"] = list(set(re_path.findall(script_text)))

    @classmethod
    def _match_threat_patterns(cls, script_text: str, raw_bytes: bytes, result: Dict[str, Any]) -> None:
        """Matches AppleScript threat patterns and categorizes capabilities."""
        seen_mitre = set()
        matched_titles = set()

        for pattern, title, severity, mitre, cap_cat, desc in APPLESCRIPT_THREAT_PATTERNS:
            matches = list(pattern.finditer(script_text))
            if matches:
                matched_titles.add(title)
                snippet = matches[0].group(0)[:140].replace('\n', ' ').strip()
                result["findings"].append({
                    "title": title,
                    "severity": severity,
                    "mitre": mitre,
                    "category": cap_cat,
                    "description": desc,
                    "snippet": snippet,
                    "count": len(matches)
                })

                if mitre not in seen_mitre:
                    seen_mitre.add(mitre)
                    result["mitre_attack"].append({
                        "technique_id": mitre,
                        "name": title
                    })

                if cap_cat in result["capabilities"]:
                    result["capabilities"][cap_cat].append({
                        "title": title,
                        "snippet": snippet,
                        "severity": severity
                    })

        # Bytecode FourCC fallback verification
        bytecode_checks = [
            (
                b'badm' in raw_bytes and (b'.sysoexec' in raw_bytes or b'sysoexec' in raw_bytes),
                "Privilege Escalation: Administrator Privileges Request",
                "CRITICAL",
                "T1548.001",
                "privilege_escalation",
                "Compiled script requests root/administrator execution (badm + sysoexec opcodes).",
                "OSA Bytecode Opcode: syso/exec + badm"
            ),
            (
                b'askr' in raw_bytes and (b'.sysodlog' in raw_bytes or b'sysodlog' in raw_bytes),
                "Credential Harvesting: Hidden Answer Password Dialog",
                "CRITICAL",
                "T1056.002",
                "credential_harvesting",
                "Compiled script renders hidden-answer authentication dialog (askr + sysodlog opcodes).",
                "OSA Bytecode Opcode: sysodlog + askr"
            ),
            (
                b'.prcskprs' in raw_bytes or b'kprs' in raw_bytes,
                "Synthetic Keystroke Injection",
                "CRITICAL",
                "T1056.001",
                "synthetic_input",
                "Compiled script issues synthetic keystrokes via System Events (kprs opcode).",
                "OSA Bytecode Opcode: prcs/kprs"
            ),
            (
                b'.coredosc' in raw_bytes or b'dosc' in raw_bytes,
                "Terminal Command Execution Bridge",
                "HIGH",
                "T1059.002",
                "terminal_automation",
                "Compiled script automates Terminal.app to execute secondary shell payloads.",
                "OSA Bytecode Opcode: core/dosc"
            )
        ]

        for cond, title, severity, mitre, cap_cat, desc, snippet in bytecode_checks:
            if cond and title not in matched_titles:
                matched_titles.add(title)
                result["findings"].append({
                    "title": title,
                    "severity": severity,
                    "mitre": mitre,
                    "category": cap_cat,
                    "description": desc,
                    "snippet": snippet,
                    "count": 1
                })
                if mitre not in seen_mitre:
                    seen_mitre.add(mitre)
                    result["mitre_attack"].append({
                        "technique_id": mitre,
                        "name": title
                    })
                if cap_cat in result["capabilities"]:
                    result["capabilities"][cap_cat].append({
                        "title": title,
                        "snippet": snippet,
                        "severity": severity
                    })
