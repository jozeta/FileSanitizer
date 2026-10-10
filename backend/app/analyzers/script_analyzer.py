"""
Script and Command-Line Triage Analyzer.
Performs in-depth static analysis of script files:
- PowerShell (.ps1, .psm1)
- VBScript / VBA / WSF / HTA (.vbs, .vba, .wsf, .hta)
- Shell Scripts (.sh, .bash, .zsh)
- JavaScript (.js, .jse)
- PHP (.php, .phtml)
- Windows Batch / Command (.bat, .cmd)

Detects suspicious functions, obfuscation, encoding, LOLBins, web shells, and extracts URLs.
"""

import re
import math
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger

SUSPICIOUS_PATTERNS = {
    "powershell": [
        ("Invoke-Expression / IEX", r"(?i)\b(invoke-expression|iex)\b", "critical", "Direct execution of dynamic or downloaded string/command"),
        ("ScriptBlock Dynamic Compilation", r"(?i)\[scriptblock\]::create\s*\(", "critical", "Dynamic script block compilation from raw string"),
        ("Download Cradle (WebClient)", r"(?i)\b(downloadstring|downloadfile|downloaddata)\b", "critical", "WebClient download cradle to fetch remote payloads"),
        ("Encoded Command Flag", r"(?i)(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}", "high", "Base64-encoded command-line payload execution"),
        ("Base64 String Conversion", r"(?i)\[System\.Convert\]::FromBase64String\s*\(", "high", "Direct programmatic Base64 payload decoding"),
        ("GZip Stream Decompression", r"(?i)\[System\.IO\.Compression\.GzipStream\]|\[System\.IO\.Compression\.DeflateStream\]", "high", "Compressed payload decompression cradle"),
        ("Execution Policy Bypass", r"(?i)(-executionpolicy\s+bypass|-ep\s+bypass)", "medium", "Explicit bypass of PowerShell script execution policy"),
        ("Hidden / Silent Window", r"(?i)(-windowstyle\s+hidden|-w\s+1|-w\s+hidden|-noni|-noninteractive)", "medium", "Suppresses PowerShell console window for stealth"),
        ("Memory Injection / Win32 API", r"(?i)\[ref\]\.assembly\.gettype|\b(virtualalloc|writeprocessmemory|createremotethread|virtualprotect|rtlmovememory)\b", "critical", "In-memory shellcode execution and reflection API injection"),
        ("AMSI Bypass / Defender Evasion", r"(?i)\b(amsiutils|amsiinitfailed|amsiscanbuffer|set-mppreference\s+-disablerealtime|disablescriptscanning)\b", "critical", "Antimalware Scan Interface (AMSI) or Windows Defender bypass and patching"),
        ("Script Block Logging Tampering", r"(?i)(enablescriptblocklogging\s*=\s*0|enablescriptblockinvocationlogging\s*=\s*0)", "critical", "Disables PowerShell operational script block logging"),
        ("Inline C# Compilation (Add-Type)", r"(?i)\badd-type\s+(-typedefinition|-memberdefinition)\b", "high", "Compiles inline C# source code to execute native .NET or Win32 APIs"),
        ("Assembly Dynamic Load", r"(?i)\[reflection\.assembly\]::load\w*\s*\(", "high", "Dynamically loads .NET assembly binary bytes directly into process memory"),
        ("Alternate Data Streams (ADS)", r"(?i)(-(stream|path)\s+.*?:\w+|:\$data|:zone\.identifier)", "high", "Accesses NTFS Alternate Data Streams (ADS) to conceal secondary payloads"),
        ("Interactive Reverse Shell", r"(?i)system\.net\.sockets\.tcpclient|\bgetstream\(\).*?(streamreader|streamwriter)", "critical", "Creates raw TCP socket pipeline piping commands to shell (Reverse Shell)"),
        ("Reconnaissance & Enumeration", r"(?i)\b(get-process|get-service|get-wmiobject|get-ciminstance|whoami(\.exe)?|net\s+user|net\s+group|systeminfo|ipconfig|route\s+print)\b", "medium", "System discovery, reconnaissance, and domain enumeration commands"),
        ("WMI / Remote Execution", r"(?i)\b(invoke-wmimethod|wmic\s+process|enter-pssession|invoke-command\s+-computername)\b", "high", "WMI or WinRM remote process execution across network hosts"),
        ("Registry Persistence / Startup", r"(?i)(currentversion\\run|currentversion\\runonce|new-itemproperty\s+.*?-propertytype|register-scheduledtask)", "high", "Establishes automated persistence in Windows Registry or Task Scheduler"),
        ("Credential Access / Mimikatz", r"(?i)\b(mimikatz|invoke-mimikatz|comsvcs\.dll.*?minidump|lsass\.exe|get-credential|vaultcli)\b", "critical", "Attempts credential harvesting, LSASS memory dumping, or password extraction"),
        ("String Reversal Obfuscation", r"(?i)\[array\]::reverse\s*\(|-join\s*\$\w+\[-1\.\.", "medium", "Reverses string characters to evade static pattern matchers"),
        ("Format Operator Obfuscation", r"[\"'](\{\d+\})+[\"']\s*-f\s+", "medium", "PowerShell composite formatting operator used to assemble split keyword strings"),
        ("Web Requests", r"(?i)\b(invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer)\b", "medium", "Outbound HTTP/BITS request invocation to transfer network data"),
    ],
    "vbscript": [
        ("WScript.Shell Spawning", r"(?i)createobject\s*\(\s*[\"\']wscript\.shell[\"\']\s*\)", "high", "Spawns interactive shell for process execution"),
        ("Shell.Run / Exec", r"(?i)\.(run|exec)\s*\(?", "high", "Executes command line or binary payload"),
        ("ADODB.Stream Dropper", r"(?i)createobject\s*\(\s*[\"\']adodb\.stream[\"\']\s*\)", "high", "Drops binary file streams to disk"),
        ("XMLHTTP Web Request", r"(?i)createobject\s*\(\s*[\"\'](msxml2\.(server)?xmlhttp|winhttp\.winhttprequest\.5\.1)[\"\']\s*\)", "high", "Outbound HTTP request to download payload"),
        ("WMI / Winmgmt Execution", r"(?i)getobject\s*\(\s*[\"\']winmgmts:", "high", "WMI interaction to query system or spawn processes"),
        ("Dynamic Execution", r"(?i)\b(execute|eval)\s*\(", "high", "Dynamic evaluation of obfuscated VBScript code"),
        ("Chr() String Obfuscation", r"(?i)(chr\s*\(\s*\d+\s*\)\s*&\s*){3,}", "medium", "Heavily concatenated Chr() character strings to evade string search"),
    ],
    "hta": [
        ("MSHTA Execution Host", r"(?i)\bmshta(\.exe)?\b", "critical", "Invokes Microsoft HTML Application host (MSHTA LOLBin)"),
        ("ActiveX Shell Spawning", r"(?i)(new\s+ActiveXObject\s*\(\s*[\"']WScript\.Shell[\"']|CreateObject\s*\(\s*[\"']WScript\.Shell[\"'])", "critical", "Spawns interactive command shell via WScript.Shell ActiveX"),
        ("ActiveX FileSystemObject", r"(?i)(new\s+ActiveXObject|CreateObject)\s*\(\s*[\"']Scripting\.FileSystemObject[\"']", "high", "Accesses host file system via Scripting.FileSystemObject ActiveX"),
        ("ActiveX ADODB Dropper", r"(?i)(new\s+ActiveXObject|CreateObject)\s*\(\s*[\"']ADODB\.Stream[\"']", "high", "Drops binary files to disk via ADODB.Stream"),
        ("Stealth WindowState", r"(?i)windowstate\s*=\s*[\"'](minimize|hidden)[\"']", "critical", "HTA configured to launch minimized or hidden for stealth"),
        ("Auto-Close on Execution", r"(?i)\bwindow\.close\s*\(", "medium", "Closes HTA window immediately after staging payload"),
        ("Dynamic Code Evaluation", r"(?i)\b(eval|execute|executeglobal)\s*\(", "high", "Dynamic evaluation of obfuscated code"),
    ],
    "shell": [
        ("Pipe to Shell (curl|bash)", r"(?i)(curl|wget)\s+[^|;]+?\|\s*(ba)?sh", "critical", "Piping untrusted remote script directly to shell interpreter"),
        ("Interactive Reverse Shell", r"(?i)(/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+|nc\s+(-e|/bin/sh)|mkfifo\s+/tmp/)", "critical", "Reverse shell connection to remote command-and-control server"),
        ("Base64 Pipe Execution", r"(?i)base64\s+(-d|--decode)\s*\|\s*(ba)?sh", "high", "Decoding and executing base64 payload"),
        ("Persistence / Cron Injection", r"(?i)(crontab\s+-l|/etc/cron\.(d|daily|hourly)|systemctl\s+enable)", "high", "Automated persistence via system scheduler or cron"),
        ("Stealth / Anti-Forensics", r"(?i)(unset\s+histfile|history\s+-c|export\s+histsize=0)", "medium", "Disables shell history logging to evade detection"),
        ("Permission Escalation", r"(?i)chmod\s+(\+x|777|755)\s+", "medium", "Grants execute permissions to downloaded files"),
    ],
    "javascript": [
        ("ActiveX Spawning", r"(?i)new\s+ActiveXObject\s*\(\s*[\"\'](WScript\.Shell|Scripting\.FileSystemObject)[\"\']\s*\)", "critical", "Windows Script Host ActiveX object execution via JScript"),
        ("NodeJS Child Process", r"(?i)require\s*\(\s*[\"\']child_process[\"\']\s*\)\.(exec|spawn)", "critical", "Spawns external operating system command from JavaScript"),
        ("Keystroke Logging Listener", r"(?i)(?:addEventListener|attachEvent)\s*\(\s*[\"\']key(?:down|press|up)[\"\']", "critical", "Keystroke logger capturing input events"),
        ("Session Token Access", r"(?i)document\.cookie\b", "high", "Direct access to document.cookie authentication tokens"),
        ("Password Field Interception", r"(?i)input\[type=[\"\']password[\"\']\]", "critical", "Targeting password input credentials in DOM"),
        ("JSFuck / Hieroglyphic Obfuscation", r"(\[\]\+\[\]|\!\+\[\]|\(\!\[\]\+\[\]\)){3,}", "high", "Heavy JSFuck character obfuscation"),
        ("Obfuscator.io / Mangled Identifiers", r"\b_0x[a-f0-9]{4,6}\b", "high", "Obfuscator.io hexadecimal identifier mangling and string array rotation"),
        ("Browser Fingerprinting Telemetry", r"(?i)\b(todataurl|getcontext\([\"']webgl|audiocontext|oscillatornode|navigator\.webdriver)\b", "medium", "Canvas, WebGL, or Audio browser environment fingerprinting"),
        ("Web / Service Worker Creation", r"(?i)(new\s+Worker\s*\(|navigator\.serviceWorker\.register)", "medium", "Spawns background service worker or web worker thread"),
        ("WebAssembly Module Instantiation", r"(?i)\bWebAssembly\.(instantiate|compile)\b", "medium", "Compiles or instantiates compiled WebAssembly binary payload"),
        ("CSS Exfiltration / Keylogger", r"(?i)input\[value\^=.*?\]\s*\{[^}]*background(-image)?\s*:\s*url\(", "critical", "CSS injection keylogger exfiltrating typed form values via background URLs"),
        ("eval() Execution", r"(?i)\beval\s*\(", "medium", "Dynamic execution of string code (common in minifiers, verify payload)"),
        ("Function Constructor", r"(?i)new\s+Function\s*\(", "medium", "Dynamic function generator from string arguments"),
        ("String.fromCharCode Obfuscation", r"(?i)(String\.fromCharCode\s*\(\s*(\d+\s*,\s*){3,}\d+\s*\))", "medium", "Decodes character codes to bypass keyword filters"),
    ],

    "python": [
        ("Reverse Shell / Socket Connection", r"(?i)\bsocket\.socket\b.*?connect\s*\(", "critical", "Low-level socket creation connecting outbound (potential reverse shell)"),
        ("Subprocess Command Execution", r"(?i)subprocess\.(Popen|call|run|check_output)\s*\(", "critical", "Spawns host operating system process"),
        ("Dynamic Code Evaluation", r"(?i)\b(exec|eval|compile)\s*\(", "high", "Dynamic evaluation of string code payload"),
        ("Pickle / Marshal Deserialization", r"(?i)\b(pickle\.loads?|marshal\.loads?)\s*\(", "critical", "Insecure deserialization leading to remote code execution"),
        ("Ctypes / Memory Access", r"(?i)\bctypes\.(windll|cdll)\b", "high", "Direct memory or native C library invocation"),
    ],
    "php": [
        ("Web Shell Execution", r"(?i)\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(", "critical", "Executes operating system shell commands from PHP"),
        ("Dynamic Code Evaluation", r"(?i)\b(eval|assert)\s*\(", "critical", "Direct evaluation of dynamic string payload"),
        ("Preg Replace /e Modifier", r"(?i)preg_replace\s*\(\s*[\"\'].*?\/e[\"\']", "critical", "Deprecated preg_replace /e switch executing replacement as PHP code"),
        ("Base64 POST/GET Backdoor", r"(?i)base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "critical", "Receives base64-encoded backdoor commands from HTTP request parameters"),
        ("Decompression Deobfuscation", r"(?i)\b(gzinflate|gzuncompress|str_rot13)\s*\(", "high", "Decompresses multi-layered obfuscated PHP web shells"),
        ("File Creation / Dropper", r"(?i)\b(file_put_contents|fwrite|fputs)\s*\(", "medium", "Writes downloaded payload or dropper file to web root"),
    ],
    "batch": [
        ("Certutil Downloader / Decoder", r"(?i)certutil(\.exe)?\s+(-urlcache|-split|-decode)", "critical", "Uses certutil LOLBin to download remote files or decode Base64 payloads"),
        ("Bitsadmin Transfer", r"(?i)bitsadmin(\.exe)?\s+/transfer", "high", "Uses BITS background file transfer service to download payloads"),
        ("PowerShell Invocation", r"(?i)powershell(\.exe)?\s+(-e|-enc|-nop|-w\s+hidden)", "high", "Batch file launches obfuscated PowerShell command"),
        ("LOLBin Proxy Execution", r"(?i)\b(rundll32|regsvr32|mshta|cscript|wscript)(\.exe)?\b", "high", "Invokes Living-off-the-Land Binaries to bypass application control"),
        ("Variable Obfuscation", r"(%[a-zA-Z0-9_]+%){4,}", "medium", "High density of environment variable concatenations to break string signatures"),
    ],
}

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

class ScriptAnalyzer(BaseAnalyzer):
    """Analyzes scripts, command files, and web shells for malicious behaviors."""

    @property
    def name(self) -> str:
        return "ScriptAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        name_lower = filename.lower()

        # Detect script language
        script_type = "unknown"
        if name_lower.endswith(".hta"):
            script_type = "hta"
        elif name_lower.endswith((".ps1", ".psm1", ".psd1")):
            script_type = "powershell"
        elif name_lower.endswith((".vbs", ".vbe", ".vba", ".wsf")):
            script_type = "vbscript"
        elif name_lower.endswith((".sh", ".bash", ".zsh")):
            script_type = "shell"
        elif name_lower.endswith((".js", ".jse")):
            script_type = "javascript"
        elif name_lower.endswith((".php", ".phtml", ".php4", ".php5", ".php7", ".phps")):
            script_type = "php"
        elif name_lower.endswith((".bat", ".cmd")):
            script_type = "batch"

        try:
            content_bytes = file_path.read_bytes()
            content = content_bytes.decode("utf-8", errors="ignore")
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                findings=[Finding(
                    category="script",
                    severity="high",
                    title="Script Read Error",
                    description=f"Could not read script contents: {str(e)}",
                    details={}
                )],
                data={}
            )

        # Fallback script type detection from shebang / header
        if script_type == "unknown":
            first_header = content[:500].lower()
            if "<hta:application" in first_header or ("<html" in first_header and any(kw in content.lower() for kw in ["wscript.shell", "activexobject", "vbscript"])):
                script_type = "hta"
            elif first_header.startswith("#!/bin/bash") or first_header.startswith("#!/bin/sh"):
                script_type = "shell"
            elif "<?php" in first_header:
                script_type = "php"
            elif first_header.startswith("@echo off"):
                script_type = "batch"
            elif "wscript" in first_header or "dim " in first_header:
                script_type = "vbscript"

        # Entropy calculation
        entropy = calculate_shannon_entropy(content)

        # Pattern scanning
        detected_patterns = []
        patterns_to_test = []
        if script_type == "hta":
            patterns_to_test.extend(SUSPICIOUS_PATTERNS.get("hta", []))
            patterns_to_test.extend(SUSPICIOUS_PATTERNS.get("vbscript", []))
            patterns_to_test.extend(SUSPICIOUS_PATTERNS.get("javascript", []))
        elif script_type in SUSPICIOUS_PATTERNS:
            patterns_to_test.extend(SUSPICIOUS_PATTERNS[script_type])

        # Also test general LOLBins & Base64 decoding across all scripts
        patterns_to_test.append(("Log4Shell JNDI Lookup (CVE-2021-44228)", r"(?i)\$\{(?:jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):|\$\{[^}]+\})", "critical", "Log4j JNDI remote code execution exploit string (CVE-2021-44228)"))
        patterns_to_test.append(("Spring4Shell ClassLoader Exploit (CVE-2022-22965)", r"(?i)class\.module\.classLoader", "critical", "Spring Framework data binding classloader RCE exploit string (CVE-2022-22965)"))
        patterns_to_test.append(("Text4Shell Remote Code Execution (CVE-2022-42889)", r"(?i)\$\{(?:script|dns|url):", "critical", "Apache Commons Text dynamic interpolation RCE string (CVE-2022-42889)"))
        patterns_to_test.append(("Generic Base64 Decode", r"(?i)(frombase64string|base64_decode|base64\s+-d)", "medium", "Base64 decoding function detected"))

        lines = content.splitlines()
        matched_lines = []
        is_webshell = False
        has_lolbins = False
        lolbin_matches = []

        for pat_name, regex, severity, description in patterns_to_test:
            matches = list(re.finditer(regex, content))
            if matches:
                if "Web Shell" in pat_name or "Backdoor" in pat_name:
                    is_webshell = True
                if "LOLBin" in pat_name:
                    has_lolbins = True
                    for m in matches:
                        lolbin_matches.append(m.group(0))

                line_numbers = []
                for m in matches[:5]:
                    # Find line number
                    start = m.start()
                    line_no = content.count("\n", 0, start) + 1
                    line_numbers.append(line_no)
                    matched_lines.append({
                        "line": line_no,
                        "pattern": pat_name,
                        "match": m.group(0)[:80],
                        "severity": severity
                    })

                detected_patterns.append({
                    "name": pat_name,
                    "severity": severity,
                    "count": len(matches),
                    "description": description,
                    "sample_lines": line_numbers[:5]
                })

                findings.append(Finding(
                    category="script",
                    severity=severity,
                    title=f"Suspicious Script Function: {pat_name}",
                    description=f"{description} (found {len(matches)} occurrence{'s' if len(matches) > 1 else ''} in {script_type.upper()} script, e.g. line {line_numbers[0] if line_numbers else '?'}).",
                    details={"pattern": pat_name, "count": len(matches), "lines": line_numbers}
                ))

        # Obfuscation & Base64 Blocks Extraction
        b64_blocks = []
        extracted_urls: List[str] = []
        try:
            from app.analyzers.deobfuscator import Deobfuscator
            raw_b64_list = Deobfuscator.scan_for_base64_blocks(content)
            for b64_item in raw_b64_list:
                enc_preview = b64_item.get("encoded", "")
                enc_full = b64_item.get("encoded_full", enc_preview)
                dec = b64_item.get("decoded", "")
                encoding = b64_item.get("encoding", "UTF-8")
                is_binary = b64_item.get("is_binary", False)

                b64_blocks.append({
                    "encoded": enc_preview,
                    "encoded_full": enc_full,
                    "decoded_preview": dec[:140].strip(),
                    "encoding": encoding,
                    "length": len(enc_full)
                })

                # Check if decoded payload contains dangerous execution commands
                is_critical = is_binary or any(kw in dec.lower() for kw in [
                    "invoke-expression", "iex", "downloadstring", "downloadfile", "webclient",
                    "virtualalloc", "writeprocessmemory", "createremotethread", "amsiutils",
                    "cmd.exe", "powershell", "wscript.shell", "/bin/sh", "curl", "wget", "nc "
                ])

                findings.append(Finding(
                    category="deobfuscation",
                    severity="critical" if is_critical else "high",
                    title=f"Identified & Decoded Base64 String ({encoding})",
                    description=(
                        f"Found Base64 string '{enc_preview}'. "
                        f"Decoded content reveals ({encoding}): {dec[:200]}"
                    ),
                    details={
                        "encoded_string": enc_full,
                        "encoded_preview": enc_preview,
                        "decoded_plaintext": dec,
                        "encoding": encoding,
                        "byte_length": b64_item.get("bytes_len", len(dec)),
                        "extracted_urls": b64_item.get("extracted_urls", []),
                        "extracted_ips": b64_item.get("extracted_ips", [])
                    }
                ))

                for u in b64_item.get("extracted_urls", []):
                    if u not in extracted_urls:
                        extracted_urls.append(u)
        except Exception as b64_err:
            logger.debug(f"Base64 scanner note: {b64_err}")

        # Extract URLs
        url_matches = list(re.findall(r"https?://[a-zA-Z0-9\.\-_~:/?#\[\]@!$&'()*+,;=%]+", content))
        for u in url_matches:
            if u not in extracted_urls:
                extracted_urls.append(u)
        extracted_urls = sorted(list(set(extracted_urls)))

        # Calculate script risk score
        risk_score = 0
        for pat in detected_patterns:
            sev = pat["severity"]
            if sev == "critical":
                risk_score += 35
            elif sev == "high":
                risk_score += 20
            elif sev == "medium":
                risk_score += 10
        if entropy > 5.8:
            risk_score += 15
        if b64_blocks:
            risk_score += 15
        risk_score = min(100, risk_score)

        hta_details = None
        if script_type == "hta":
            hta_details = self._analyze_hta(content, filename, findings, extracted_urls)

        display_names = {
            "hta": "HTML Application (.hta)",
            "powershell": "PowerShell Script (.ps1)",
            "vbscript": "VBScript / WSH (.vbs)",
            "shell": "Unix Shell Script (.sh)",
            "javascript": "JavaScript (.js)",
            "python": "Python Script (.py)",
            "php": "PHP Script (.php)",
            "batch": "Windows Batch Script (.bat/.cmd)",
            "unknown": "Generic Script"
        }

        if not findings:
            findings.append(Finding(
                category="script",
                severity="informational",
                title=f"{display_names.get(script_type, 'Script')} Code Clean",
                description=f"Static heuristic triage completed on {len(lines)} lines of code. No malicious APIs, reverse shells, or evasion patterns detected."
            ))

        # Categorized Dangerous APIs & Functions
        dangerous_apis = []
        DANGEROUS_API_CATALOG = [
            ("Process Execution & Shell Spawning", "cmd.exe / powershell / wscript.shell", r"(?i)\b(cmd(\.exe)?|powershell(\.exe)?|wscript\.shell|shellexecute|subprocess|child_process|system\s*\(|exec\s*\(|shell_exec|popen)\b", "high", "Spawns interactive operating system shell or child process"),
            ("Network & Outbound Exfiltration", "curl / wget / WebClient / Sockets", r"(?i)\b(curl|wget|net\.webclient|invoke-webrequest|invoke-restmethod|msxml2\.xmlhttp|winhttp|socket\.socket|/dev/tcp/)\b", "high", "Initiates remote network connections or file downloads"),
            ("Persistence & Task Scheduling", "Cron / Registry Run / Task Scheduler", r"(?i)\b(schtasks|crontab|systemctl|currentversion\\run|software\\microsoft\\windows\\currentversion)\b", "high", "Configures recurring startup persistence hooks"),
            ("Credential Access & Spying", "Credentials / Cookies / Keyloggers", r"(?i)\b(document\.cookie|getasynckeystate|mimikatz|lsass|/etc/shadow|key(?:down|press))\b", "critical", "Intersects credentials, authentication cookies, or keystrokes"),
            ("Defense Evasion & Tampering", "AMSI Bypass / History Clearing / Sleep", r"(?i)\b(amsiutils|amsiinitfailed|unset\s+histfile|history\s+-c|start-sleep|wscript\.sleep)\b", "critical", "Disables system defenses, evades logging, or halts sandbox evaluation"),
        ]

        for cat_name, api_title, reg, sev, desc in DANGEROUS_API_CATALOG:
            m_list = list(re.finditer(reg, content))
            if m_list:
                line_hits = []
                for m in m_list[:3]:
                    line_no = content.count("\n", 0, m.start()) + 1
                    line_hits.append(line_no)
                dangerous_apis.append({
                    "category": cat_name,
                    "api_title": api_title,
                    "severity": sev,
                    "description": desc,
                    "count": len(m_list),
                    "matched_sample": m_list[0].group(0)[:60],
                    "lines": line_hits
                })

        # Specific extraction and decoding of PowerShell -EncodedCommand (UTF-16LE / UTF-8)
        encoded_commands = []
        enc_cmd_matches = list(re.finditer(r"(?i)(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})", content))
        for em in enc_cmd_matches:
            raw_b64 = em.group(1)
            try:
                dec_bytes = base64.b64decode(raw_b64)
                # Try UTF-16LE first (PowerShell standard)
                decoded_text = dec_bytes.decode('utf-16le', errors='ignore').strip()
                if not decoded_text or sum(1 for c in decoded_text if c.isprintable()) < len(decoded_text) * 0.7:
                    decoded_text = dec_bytes.decode('utf-8', errors='ignore').strip()

                if decoded_text:
                    encoded_commands.append({
                        "raw_encoded": raw_b64,
                        "decoded": decoded_text,
                        "length": len(decoded_text)
                    })
                    findings.append(Finding(
                        category="powershell",
                        severity="critical",
                        title="Decoded Hidden PowerShell -EncodedCommand Payload",
                        description=f"Extracted and unmasked Base64 command payload: {decoded_text[:200]}",
                        details={"raw_encoded": raw_b64, "decoded_command": decoded_text}
                    ))
            except Exception as dec_err:
                logger.debug(f"EncodedCommand decode error: {dec_err}")

        powershell_forensics = None
        if script_type == "powershell" or any("PowerShell" in p["name"] or "Invoke" in p["name"] for p in detected_patterns):
            powershell_forensics = {
                "encoded_commands": encoded_commands,
                "dangerous_cmdlets": [p for p in detected_patterns if any(kw in p["name"] for kw in ["Invoke-Expression", "ScriptBlock", "Download Cradle", "Inline C#", "Reverse Shell"])],
                "evasion_tactics": [p for p in detected_patterns if any(kw in p["name"] for kw in ["AMSI", "Defender", "Logging", "Bypass", "Hidden", "Obfuscation", "Reversal", "Format Operator"])],
                "recon_commands": [p for p in detected_patterns if "Reconnaissance" in p["name"] or "WMI" in p["name"]],
                "persistence": [p for p in detected_patterns if "Persistence" in p["name"] or "Registry" in p["name"]],
                "credential_dumping": [p for p in detected_patterns if "Credential" in p["name"] or "Mimikatz" in p["name"]],
                "alternate_data_streams": [p for p in detected_patterns if "Alternate Data Streams" in p["name"]],
            }

        web_forensics = None
        if script_type in ["javascript", "hta"] or "<script" in content.lower():
            web_forensics = {
                "obfuscation": [p for p in detected_patterns if any(kw in p["name"] for kw in ["JSFuck", "Obfuscator", "fromCharCode", "eval"])],
                "fingerprinting": [p for p in detected_patterns if "Fingerprinting" in p["name"]],
                "background_workers": [p for p in detected_patterns if "Worker" in p["name"] or "WebAssembly" in p["name"]],
                "credential_theft": [p for p in detected_patterns if "Password" in p["name"] or "Cookie" in p["name"] or "Keystroke" in p["name"] or "CSS" in p["name"]],
            }

        code_modules_list = [{
            "name": f"{filename} (Full Source)",
            "code": content[:100000]
        }]
        for idx, ec in enumerate(encoded_commands):
            code_modules_list.append({
                "name": f"Decoded -EncodedCommand #{idx+1}",
                "code": ec["decoded"]
            })
        if hta_details:
            for idx, vb in enumerate(hta_details.get("script_blocks", {}).get("vbscript_snippets", [])):
                code_modules_list.append({
                    "name": f"VBScript Block #{idx+1} (Line {vb['start_line']})",
                    "code": vb["code"]
                })
            for idx, js in enumerate(hta_details.get("script_blocks", {}).get("javascript_snippets", [])):
                code_modules_list.append({
                    "name": f"JavaScript Block #{idx+1} (Line {js['start_line']})",
                    "code": js["code"]
                })

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data={
                "script_type": display_names.get(script_type, script_type.capitalize()),
                "raw_script_type": script_type,
                "entropy": entropy,
                "lines_count": len(lines),
                "characters_count": len(content),
                "detected_patterns": detected_patterns,
                "dangerous_apis": dangerous_apis,
                "matched_lines": matched_lines[:50],
                "b64_blocks": b64_blocks[:10],
                "urls": extracted_urls,
                "risk_score": risk_score,
                "is_webshell": is_webshell,
                "has_lolbins": has_lolbins,
                "lolbin_matches": lolbin_matches,
                "code_modules": code_modules_list,
                "hta_details": hta_details,
                "powershell_forensics": powershell_forensics,
                "web_forensics": web_forensics
            }
        )

    def _analyze_hta(self, content: str, filename: str, findings: List[Finding], extracted_urls: List[str]) -> Dict[str, Any]:
        """Deep inspection of HTML Application (HTA) files: HTML, CSS, VBScript, and JavaScript."""
        hta_info = {
            "is_hta": True,
            "application_tag": {},
            "windowstate": "normal",
            "is_stealth_window": False,
            "html_structure": {
                "has_forms": False,
                "has_passwords": False,
                "iframes": [],
                "external_resources": [],
            },
            "css_analysis": {
                "style_blocks_count": 0,
                "has_hidden_elements": False,
                "hidden_techniques": []
            },
            "script_blocks": {
                "vbscript_count": 0,
                "javascript_count": 0,
                "inline_handlers_count": 0,
                "vbscript_snippets": [],
                "javascript_snippets": [],
                "inline_handlers": []
            },
            "activex_objects": [],
            "lolbins_invoked": []
        }

        # 1. Parse <hta:application ...> tag
        app_match = re.search(r"<hta:application\s+([^>]+)>", content, re.IGNORECASE)
        if app_match:
            raw_attrs = app_match.group(1)
            attrs = dict(re.findall(r'(\w+)\s*=\s*["\']([^"\']*)["\']', raw_attrs, re.IGNORECASE))
            hta_info["application_tag"] = attrs

            ws = attrs.get("windowstate", attrs.get("WINDOWSTATE", "normal")).lower()
            hta_info["windowstate"] = ws
            sit = attrs.get("showintaskbar", attrs.get("SHOWINTASKBAR", "yes")).lower()

            if ws in ["minimize", "hidden"] or sit == "no":
                hta_info["is_stealth_window"] = True
                findings.append(Finding(
                    category="hta",
                    severity="critical",
                    title="Stealth HTA Window Execution",
                    description=(
                        f"HTA configuration enforces stealth execution: "
                        f"windowState='{ws}', showInTaskbar='{sit}'. "
                        "This suppresses visual console/window indicators to silently execute scripts."
                    ),
                    details={"attributes": attrs}
                ))

        # 2. CSS Analysis (style tags and inline style attributes)
        style_blocks = re.findall(r"<style[^>]*>(.*?)</style>", content, re.DOTALL | re.IGNORECASE)
        hta_info["css_analysis"]["style_blocks_count"] = len(style_blocks)

        all_css = " ".join(style_blocks) + " " + " ".join(re.findall(r'style\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE))
        all_css_lower = all_css.lower()

        hidden_techs = []
        if re.search(r"display\s*:\s*none", all_css_lower):
            hidden_techs.append("display: none (hidden DOM elements)")
        if re.search(r"visibility\s*:\s*hidden", all_css_lower):
            hidden_techs.append("visibility: hidden (invisible DOM elements)")
        if re.search(r"opacity\s*:\s*0(\.0+)?\b", all_css_lower):
            hidden_techs.append("opacity: 0 (zero-opacity cloaking)")
        if re.search(r"(top|left|right|bottom)\s*:\s*-[0-9]{3,}", all_css_lower):
            hidden_techs.append("off-screen negative coordinates (viewport ejection)")
        if re.search(r"(width|height)\s*:\s*0(px)?", all_css_lower):
            hidden_techs.append("zero-dimension bounds (0px width/height)")

        if hidden_techs:
            hta_info["css_analysis"]["has_hidden_elements"] = True
            hta_info["css_analysis"]["hidden_techniques"] = hidden_techs
            findings.append(Finding(
                category="hta",
                severity="high",
                title=f"CSS Cloaking & Hidden Elements Detected ({len(hidden_techs)} techniques)",
                description=f"HTA contains CSS rules designed to conceal elements from victim display: {', '.join(hidden_techs)}.",
                details={"techniques": hidden_techs}
            ))

        # 3. HTML DOM Structure & External Resources
        iframes = re.findall(r'<iframe[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        hta_info["html_structure"]["iframes"] = iframes
        for ifr in iframes:
            if ifr.startswith(("http://", "https://", "//")):
                extracted_urls.append(ifr)
                findings.append(Finding(
                    category="network",
                    severity="critical",
                    title="Remote iFrame Injection in HTA",
                    description=f"HTA loads remote iframe content from untrusted origin: '{ifr}'.",
                    details={"url": ifr}
                ))

        forms = re.findall(r'<form[^>]*\saction\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        hta_info["html_structure"]["has_forms"] = bool(forms)
        for act in forms:
            if act.startswith(("http://", "https://")):
                extracted_urls.append(act)

        has_pwd = bool(re.search(r'<input[^>]*type\s*=\s*["\']password["\']', content, re.IGNORECASE))
        hta_info["html_structure"]["has_passwords"] = has_pwd
        if has_pwd and forms:
            findings.append(Finding(
                category="phishing",
                severity="high",
                title="Credential Phishing Form Template Detected",
                description="HTA embeds HTML forms with password input fields targeting user credentials.",
                details={"action": forms[0] if forms else ""}
            ))

        # External asset links
        ext_scripts = re.findall(r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        ext_links = re.findall(r'<link[^>]*\shref\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        for asset in ext_scripts + ext_links:
            if asset.startswith(("http://", "https://")):
                extracted_urls.append(asset)
                hta_info["html_structure"]["external_resources"].append(asset)

        # 4. Embedded Script Blocks (VBScript vs JavaScript)
        script_matches = list(re.finditer(r'<script([^>]*)>(.*?)</script>', content, re.DOTALL | re.IGNORECASE))
        for sm in script_matches:
            tag_attrs = sm.group(1).lower()
            code_body = sm.group(2).strip()
            if not code_body:
                continue

            is_vbs = "vbscript" in tag_attrs or "vbs" in tag_attrs
            start_line = content.count("\n", 0, sm.start()) + 1
            code_lines = len(code_body.splitlines())

            if is_vbs:
                hta_info["script_blocks"]["vbscript_count"] += 1
                hta_info["script_blocks"]["vbscript_snippets"].append({
                    "start_line": start_line,
                    "lines_count": code_lines,
                    "preview": code_body[:300],
                    "code": code_body
                })
            else:
                hta_info["script_blocks"]["javascript_count"] += 1
                hta_info["script_blocks"]["javascript_snippets"].append({
                    "start_line": start_line,
                    "lines_count": code_lines,
                    "preview": code_body[:300],
                    "code": code_body
                })

        # 5. Inline Event Handlers
        inline_handlers = re.findall(r'\s(on[a-z]{3,15})\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        for ev, code_snippet in inline_handlers:
            hta_info["script_blocks"]["inline_handlers_count"] += 1
            hta_info["script_blocks"]["inline_handlers"].append({
                "event": ev,
                "handler": code_snippet[:150]
            })
            if any(kw in code_snippet.lower() for kw in ["eval", "exec", "activexobject", "createobject", "run", "wscript"]):
                findings.append(Finding(
                    category="active_content",
                    severity="critical",
                    title=f"Direct Execution in HTML Event Handler ({ev})",
                    description=f"HTML tag executes script payload immediately upon DOM trigger '{ev}': {code_snippet[:100]}",
                    details={"event": ev, "snippet": code_snippet}
                ))

        # 6. Detect ActiveX Objects & LOLBins
        activex_matches = list(set(re.findall(r'(?:ActiveXObject|CreateObject)\s*\(\s*["\']([^"\']+)["\']', content, re.IGNORECASE)))
        hta_info["activex_objects"] = activex_matches
        if activex_matches:
            findings.append(Finding(
                category="active_content",
                severity="critical",
                title=f"Dangerous ActiveX Objects Instantiated ({len(activex_matches)} classes)",
                description=f"HTA instantiates high-privilege Windows Script Host ActiveX objects: {', '.join(activex_matches)}.",
                details={"activex_classes": activex_matches}
            ))

        lolbins = list(set(re.findall(r'\b(powershell(?:\.exe)?|cmd(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?)\b', content, re.IGNORECASE)))
        hta_info["lolbins_invoked"] = lolbins
        if lolbins:
            findings.append(Finding(
                category="execution",
                severity="critical",
                title=f"Living-off-the-Land Binaries (LOLBins) Invoked ({len(lolbins)} binaries)",
                description=f"HTA spawns Windows system executables commonly leveraged for proxy execution and payload delivery: {', '.join(lolbins)}.",
                details={"binaries": lolbins}
            ))

        return hta_info
