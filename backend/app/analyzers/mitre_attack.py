"""
MITRE ATT&CK Mapping & Attribution Engine.
Maps static file findings, behavioral indicators, YARA rules, and extracted capabilities
to MITRE ATT&CK Tactics and Techniques.
"""

from typing import List, Dict, Any, Optional

TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

class MitreAttackMapper:
    """Evaluates findings, analysis data, and format structures to map to MITRE ATT&CK."""

    @staticmethod
    def map_all(findings: List[Any], analysis_data: Dict[str, Any], category: str) -> List[Dict[str, Any]]:
        techniques: Dict[str, Dict[str, Any]] = {}

        def add_technique(
            tech_id: str,
            name: str,
            tactic_id: str,
            description: str,
            severity: str,
            evidence: str
        ):
            if tech_id not in techniques:
                techniques[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": name,
                    "tactic_id": tactic_id,
                    "tactic_name": TACTIC_NAMES.get(tactic_id, "Execution"),
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                    "description": description,
                    "severity": severity,
                    "evidence": [evidence]
                }
            else:
                if evidence not in techniques[tech_id]["evidence"]:
                    techniques[tech_id]["evidence"].append(evidence)
                # Escalate severity if higher
                sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if sev_order.get(severity.upper(), 0) > sev_order.get(techniques[tech_id]["severity"].upper(), 0):
                    techniques[tech_id]["severity"] = severity

        # 1. Analyze findings titles and descriptions
        for f in findings:
            title = getattr(f, "title", "") if hasattr(f, "title") else f.get("title", "")
            desc = getattr(f, "description", "") if hasattr(f, "description") else f.get("description", "")
            sev = getattr(f, "severity", "medium") if hasattr(f, "severity") else f.get("severity", "medium")
            sev_norm = sev.upper() if isinstance(sev, str) else "MEDIUM"
            text = f"{title} {desc}".lower()

            # Initial Access
            if "phish" in text or "spf" in text or "dkim" in text or "dmarc" in text:
                add_technique(
                    "T1566.001", "Spearphishing Attachment", "TA0001",
                    "Email indicators or untrusted document attachments suggest phishing delivery.",
                    sev_norm, title
                )

            # MIME Spoofing
            if "mime type confusion" in text or "extension mismatch" in text or "masquerad" in text:
                add_technique(
                    "T1036", "Masquerading", "TA0005",
                    "File extension or MIME signature was masked to disguise the real payload type.",
                    sev_norm, title
                )

            # Macros & Script Execution
            if "vba macro" in text or "autoopen" in text or "workbook_open" in text or "xlm macro" in text:
                add_technique(
                    "T1059.005", "Visual Basic", "TA0002",
                    "Visual Basic for Applications (VBA) or Excel 4.0 XLM macro code execution detected.",
                    sev_norm, title
                )
                add_technique(
                    "T1204.002", "User Execution: Malicious File", "TA0002",
                    "Relies on a user opening the weaponized document to trigger payload execution.",
                    sev_norm, title
                )

            # WScript / VBScript indicators
            if "wscript.shell" in text or "wscript" in text or "xmlhttp" in text or "shell.run" in text or "executestatement" in text or "executeglobal" in text:
                add_technique(
                    "T1059.005", "Visual Basic", "TA0002",
                    "VBScript / Windows Script Host (WSH) execution indicators detected.",
                    sev_norm, title
                )
                add_technique(
                    "T1071.001", "Application Layer Protocol: Web Protocols", "TA0011",
                    "Script uses HTTP/HTTPS-based communication (XMLHTTP, WinHTTP) for C2 or download.",
                    sev_norm, title
                )

            # RTF Weaponized Exploitation Vectors
            if "rtf weaponized" in text or "exploitation vector" in text or ("rtf" in text and "exploit" in text):
                add_technique(
                    "T1203", "Exploitation for Client Execution", "TA0002",
                    "RTF document contains weaponized exploitation vectors (e.g. Equation Editor, MSHTML, OLE autolink).",
                    "HIGH", title
                )
                add_technique(
                    "T1566.001", "Spearphishing Attachment", "TA0001",
                    "Weaponized RTF documents are a common spearphishing delivery mechanism.",
                    "HIGH", title
                )
                add_technique(
                    "T1204.002", "User Execution: Malicious File", "TA0002",
                    "Exploit payload requires user to open the RTF document to trigger execution.",
                    "HIGH", title
                )

            # Remote Template Injection
            if "remote template" in text or "attachedtemplate" in text or "template injection" in text:
                add_technique(
                    "T1221", "Template Injection", "TA0005",
                    "Document references external template hosted on a remote server to bypass perimeter defenses.",
                    "HIGH", title
                )
                add_technique(
                    "T1137.001", "Office Application Startup: Office Template Macros", "TA0003",
                    "Alters or injects Office templates for persistent execution.",
                    "HIGH", title
                )

            # DDE formulas
            if "dde" in text or "dynamic data exchange" in text:
                add_technique(
                    "T1218", "System Binary Proxy Execution", "TA0002",
                    "Dynamic Data Exchange (DDE) formula used to execute system commands through Office applications.",
                    "HIGH", title
                )

            # Exploitation for Client Execution (Equation Editor, etc.)
            if "equation editor" in text or "cve-2017-11882" in text or "cve-2018-0802" in text or "cve-2021-40444" in text:
                add_technique(
                    "T1203", "Exploitation for Client Execution", "TA0002",
                    "Exploits vulnerabilities in client applications (e.g. Equation Editor memory corruption) to achieve code execution.",
                    "CRITICAL", title
                )

            # PDF JavaScript & Launch
            if "javascript" in text and category == "pdf":
                add_technique(
                    "T1059.007", "JavaScript", "TA0002",
                    "Embedded PDF JavaScript scripts detected.",
                    sev_norm, title
                )
            if "/launch" in text or "launch action" in text:
                add_technique(
                    "T1204.002", "User Execution: Malicious File", "TA0002",
                    "PDF /Launch action triggers external process invocation.",
                    "HIGH", title
                )

            # Embedded Payloads
            if "embedded payload" in text or "nested payload" in text or "ole10native" in text or "embedded files" in text:
                add_technique(
                    "T1027.009", "Embedded Payloads", "TA0005",
                    "Nested executable or archive payloads embedded inside document or container structures.",
                    sev_norm, title
                )

            # Software Packing / High Entropy
            if "packer" in text or "high entropy" in text or "packed" in text or "upx" in text:
                add_technique(
                    "T1027.002", "Software Packing", "TA0005",
                    "Sections or binary streams exhibit packing or compression to hinder static analysis.",
                    sev_norm, title
                )

            # Obfuscation
            if "obfuscation" in text or "encodedcommand" in text or "base64" in text or "xor" in text:
                add_technique(
                    "T1027", "Obfuscated Files or Information", "TA0005",
                    "Payload contains obfuscated, encoded, or encrypted segments.",
                    sev_norm, title
                )
                add_technique(
                    "T1140", "Deobfuscate/Decode Files or Information", "TA0005",
                    "Employs runtime decoding routines (e.g. Base64, XOR, certutil) to reveal payloads.",
                    sev_norm, title
                )

            # Anti-Debugging & Evasion
            if "anti-debugging" in text or "isdebuggerpresent" in text:
                add_technique(
                    "T1622", "Debugger Evasion", "TA0005",
                    "Employs API checks or timing routines to detect debuggers and alter execution.",
                    "HIGH", title
                )
            if "anti-vm" in text or "sandbox evasion" in text or "virtualbox" in text or "vmware" in text:
                add_technique(
                    "T1497.001", "Virtualization/Sandbox Evasion: System Checks", "TA0005",
                    "Inspects CPU, RAM, disk, or driver artifacts to detect and evade virtualized sandbox environments.",
                    "HIGH", title
                )
            if "sleep" in text and ("evasion" in text or "delay" in text or "timing" in text):
                add_technique(
                    "T1497.003", "Virtualization/Sandbox Evasion: Time Based Evasion", "TA0005",
                    "Executes prolonged sleep delays to exhaust automated sandbox analysis timeouts.",
                    "MEDIUM", title
                )

            # Process Injection
            if "injection" in text or "virtualalloc" in text or "createremotethread" in text:
                add_technique(
                    "T1055", "Process Injection", "TA0004",
                    "Calls memory allocation and thread manipulation APIs consistent with process injection.",
                    "HIGH", title
                )

            # HTML Smuggling
            if "html smuggling" in text or "data:text/html" in text or "blob(" in text:
                add_technique(
                    "T1027.006", "HTML Smuggling", "TA0005",
                    "Employs HTML5/JavaScript data URIs or Blobs to assemble malicious payloads client-side.",
                    "HIGH", title
                )

            # Ingress Tool Transfer / Download Cradles
            if "download cradle" in text or "downloadstring" in text or "certutil" in text or "bitsadmin" in text:
                add_technique(
                    "T1105", "Ingress Tool Transfer", "TA0011",
                    "Downloads external malicious tools or payloads from remote command-and-control servers.",
                    sev_norm, title
                )

            # Web Shell
            if "web shell" in text or "webshell" in text or ("php" in text and "eval" in text):
                add_technique(
                    "T1505.003", "Server Software Component: Web Shell", "TA0003",
                    "Web shell backdoor scripts allowing remote arbitrary command execution.",
                    "CRITICAL", title
                )

            # DLP / Leaked Secrets / Credentials in Files
            if "dlp" in text or "credential" in text or "private key" in text or "aws access key" in text or "api key" in text:
                if "private key" in text:
                    add_technique(
                        "T1552.004", "Unsecured Credentials: Private Keys", "TA0006",
                        "Unencrypted cryptographic private key blocks detected in file content.",
                        "CRITICAL", title
                    )
                else:
                    add_technique(
                        "T1552.001", "Unsecured Credentials: Credentials In Files", "TA0006",
                        "Hardcoded credentials, cloud API tokens, or secrets discovered in file structure.",
                        sev_norm, title
                    )

            # Anti-Forensics / Timestomping
            if "timestomp" in text or "creation date posterior" in text or "future timestamp" in text:
                add_technique(
                    "T1070.006", "Indicator Removal: Timestomp", "TA0005",
                    "File timestamps appear forged, reversed, or manipulated to evade forensic timeline reconstruction.",
                    "HIGH", title
                )

            # Phishing Links
            if "deceptive phishing link" in text or "spearphishing link" in text or ("deceptive" in text and "link" in text):
                add_technique(
                    "T1566.002", "Phishing: Spearphishing Link", "TA0001",
                    "Hyperlinks visually masquerade as trusted brands but redirect to malicious external infrastructure.",
                    "CRITICAL", title
                )

            # Obfuscation & Deobfuscation (T1027)
            if "deobfuscat" in text or "xor" in text or "base64" in text or "obfuscat" in text:
                add_technique(
                    "T1027", "Obfuscated Files or Information", "TA0005",
                    "Payload employs cryptographic encryption, XOR encoding, or multi-layer Base64 obfuscation to evade static inspection.",
                    sev_norm, title
                )

            # Client Software Exploitation (T1203)
            if "follina" in text or "msdt" in text or "cve-2022-30190" in text or "cve-2021-40444" in text or "cve-2017-11882" in text or "equation editor" in text:
                add_technique(
                    "T1203", "Exploitation for Client Execution", "TA0002",
                    "Exploitation of vulnerabilities in client software (Office, Equation Editor, MSDT) to execute arbitrary code.",
                    "CRITICAL", title
                )

        # 2. Inspect Office Specific Data
        office_data = analysis_data.get("office", {})
        if office_data.get("vba_stomping", {}).get("is_stomped"):
            add_technique(
                "T1027.009", "Embedded Payloads", "TA0005",
                "VBA Stomping detected: compiled P-code exists without matching source code.",
                "HIGH", "VBA Stomping discrepancy detected"
            )
            add_technique(
                "T1059.005", "Visual Basic", "TA0002",
                "VBA Stomping executes P-code directly in the Microsoft Office runtime.",
                "HIGH", "VBA Stomping compiled execution"
            )

        if office_data.get("xlm_macros", {}).get("has_xlm_macros"):
            add_technique(
                "T1059.005", "Visual Basic", "TA0002",
                "Legacy Excel 4.0 (XLM) macro sheet formulas detected.",
                "HIGH", "Excel 4.0 XLM Macro Sheet"
            )

        if office_data.get("remote_templates"):
            for rt in office_data.get("remote_templates", []):
                add_technique(
                    "T1221", "Template Injection", "TA0005",
                    f"External relationship points to remote template: {rt.get('target', '')}",
                    "HIGH", f"Template Target: {rt.get('target', '')}"
                )

        # 3. Inspect Executable Specific Data
        exec_data = analysis_data.get("executable", {})
        if exec_data.get("anti_analysis", {}).get("anti_debugging"):
            add_technique(
                "T1622", "Debugger Evasion", "TA0005",
                "Binary references Win32 anti-debugging APIs.",
                "HIGH", ", ".join(exec_data["anti_analysis"]["anti_debugging"][:4])
            )
        if exec_data.get("anti_analysis", {}).get("anti_vm"):
            add_technique(
                "T1497.001", "Virtualization/Sandbox Evasion: System Checks", "TA0005",
                "Binary references anti-VM or sandbox fingerprinting APIs.",
                "HIGH", ", ".join(exec_data["anti_analysis"]["anti_vm"][:4])
            )
        if exec_data.get("disassembly", {}).get("suspicious_patterns"):
            for pat in exec_data["disassembly"]["suspicious_patterns"]:
                add_technique(
                    "T1055", "Process Injection", "TA0004",
                    f"Entry point instructions indicate shellcode or injection prologue: {pat}",
                    "HIGH", pat
                )

        # ELF-specific mitigations (No NX, No PIE, Stripped)
        elf_mitigations = exec_data.get("elf_mitigations", {})
        if elf_mitigations:
            missing = elf_mitigations.get("missing_mitigations", [])
            if any("nx" in m.lower() or "executable stack" in m.lower() for m in missing):
                add_technique(
                    "T1059.004", "Unix Shell", "TA0002",
                    "ELF binary has an executable stack (No NX), enabling shellcode execution directly on the stack.",
                    "HIGH", "Executable Stack (PT_GNU_STACK flags=RWX)"
                )
                add_technique(
                    "T1600", "Weaken Encryption", "TA0005",
                    "Absence of NX/DEP protection weakens memory-based exploit mitigations.",
                    "HIGH", "No-eXecute (NX) bit disabled on stack segment"
                )
            if any("pie" in m.lower() for m in missing):
                add_technique(
                    "T1574.006", "Dynamic Linker Hijacking", "TA0004",
                    "Non-PIE ELF binary loads at a fixed, predictable base address, aiding ROP/ret2libc attacks.",
                    "MEDIUM", "Non-PIE ELF (ET_EXEC) — fixed base address"
                )
            if any("strip" in m.lower() for m in missing):
                add_technique(
                    "T1027.008", "Stripped Payloads", "TA0005",
                    "ELF binary has no symbol table (stripped), hindering reverse engineering and forensic attribution.",
                    "MEDIUM", "Stripped ELF — no section headers / symbol table"
                )


        script_data = analysis_data.get("script", {})
        # Use raw_script_type (normalized internal key) for comparisons; fall back to display name
        script_type = script_data.get("raw_script_type", script_data.get("script_type", "")).lower()
        if script_type in ["powershell", "ps1"]:
            add_technique(
                "T1059.001", "PowerShell", "TA0002",
                "PowerShell command or script execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"PowerShell Script ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )
        elif script_type in ["vbscript", "vbs", "vba", "wsf", "hta"]:
            add_technique(
                "T1059.005", "Visual Basic", "TA0002",
                "VBScript or Windows Script Host execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"VBS/WSH Script ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )
        elif script_type in ["shell", "bash", "sh"]:
            add_technique(
                "T1059.004", "Unix Shell", "TA0002",
                "Unix/Linux shell script execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"Shell Script ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )
        elif script_type in ["javascript", "js"]:
            add_technique(
                "T1059.007", "JavaScript", "TA0002",
                "JavaScript or JScript execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"JavaScript ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )
        elif script_type in ["php"]:
            add_technique(
                "T1059.006", "Python/PHP/Perl", "TA0002",
                "PHP script execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"PHP Script ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )
            if script_data.get("is_webshell"):
                add_technique(
                    "T1505.003", "Server Software Component: Web Shell", "TA0003",
                    "PHP file contains backdoor and remote code execution functions consistent with a Web Shell.",
                    "CRITICAL", "PHP Web Shell Signature"
                )
        elif script_type in ["batch", "cmd"]:
            add_technique(
                "T1059.003", "Windows Command Shell", "TA0002",
                "Windows Batch/CMD script execution detected.",
                "HIGH" if script_data.get("risk_score", 0) > 40 else "LOW",
                f"Batch Script ({script_data.get('suspicious_count', 0)} suspicious elements)"
            )

        if script_data.get("has_lolbins"):
            add_technique(
                "T1218", "System Binary Proxy Execution", "TA0002",
                "Invokes Living-off-the-Land Binaries (LOLBins) to proxy execution.",
                "HIGH", ", ".join(script_data.get("lolbin_matches", [])[:4])
            )

        # 5. Inspect Email Specific Data
        email_data = analysis_data.get("email", {})
        if email_data.get("homoglyphs", {}).get("has_homoglyphs"):
            add_technique(
                "T1036", "Masquerading", "TA0005",
                "Sender domain utilizes Unicode homoglyphs or Punycode to impersonate a legitimate brand.",
                "HIGH", "Punycode / Homoglyph lookalike domain"
            )
        if email_data.get("display_name_deception", {}).get("is_deceptive"):
            add_technique(
                "T1036", "Masquerading", "TA0005",
                "Display name contains an email address or VIP title differing from the authentic sender.",
                "HIGH", "Display Name Spoofing"
            )
        if email_data.get("html_smuggling", {}).get("has_smuggling"):
            add_technique(
                "T1027.006", "HTML Smuggling", "TA0005",
                "Email body contains HTML smuggling scripts or Base64 data URIs.",
                "HIGH", "HTML Smuggling payload"
            )

        # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        result = list(techniques.values())
        result.sort(key=lambda x: (sev_rank.get(x["severity"].upper(), 5), x["tactic_id"], x["technique_id"]))
        return result

    @staticmethod
    def generate_navigator_layer(techniques: List[Dict[str, Any]], filename: str) -> Dict[str, Any]:
        """
        Generate a MITRE ATT&CK Navigator v4.5 JSON layer.
        Can be directly opened and viewed in https://mitre-attack.github.io/attack-navigator/
        """
        technique_entries = []
        for t in techniques:
            sev = t.get("severity", "MEDIUM").upper()
            score = 100 if sev == "CRITICAL" else (75 if sev == "HIGH" else (50 if sev == "MEDIUM" else 25))
            color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else ("#eab308" if sev == "MEDIUM" else "#3b82f6"))
            tactic_slug = t.get("tactic_name", "execution").lower().replace(" ", "-")

            technique_entries.append({
                "techniqueID": t.get("technique_id"),
                "tactic": tactic_slug,
                "score": score,
                "color": color,
                "comment": "; ".join(t.get("evidence", [])) if t.get("evidence") else t.get("description", ""),
                "enabled": True,
                "metadata": [
                    {"name": "Severity", "value": sev},
                    {"name": "Technique Name", "value": t.get("technique_name", "")}
                ]
            })

        return {
            "name": f"FileSanitizer - {filename}",
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK Matrix coverage generated by FileSanitizer deep security triage for '{filename}'.",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Office 365"]
            },
            "sorting": 3,
            "techniques": technique_entries,
            "gradient": {
                "colors": ["#fef08a", "#f97316", "#ef4444"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {"label": "Critical Risk Technique", "color": "#ef4444"},
                {"label": "High Risk Technique", "color": "#f97316"},
                {"label": "Medium Risk Technique", "color": "#eab308"}
            ]
        }

