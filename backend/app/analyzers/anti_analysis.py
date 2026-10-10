"""
Anti-Analysis & Evasion Behavior Analyzer.
Detects defense evasion, anti-debugging, anti-VM/hypervisor detection,
sandbox sleep acceleration, and environment guardrailing across
binaries (PE, ELF, Mach-O), scripts (PowerShell, VBScript, Batch, Bash, JS, Python, AppleScript),
Office documents (VBA Macros, XLM 4.0), PDF JavaScript, Windows Event Logs (EVTX), and LNK shortcuts.
"""

import re
from typing import Dict, Any, List, Optional
from app.analyzers.base import Finding


class AntiAnalysisDetector:
    """
    Comprehensive multi-format scanner for anti-analysis, anti-debugging, anti-VM,
    and sandbox evasion techniques (MITRE ATT&CK T1497, T1622, T1027, T1562, T1070).
    """

    @classmethod
    def scan_all(
        cls,
        category: str,
        filename: str,
        file_bytes: bytes,
        binary_info: Optional[Dict[str, Any]] = None,
        script_triage: Optional[Dict[str, Any]] = None,
        office_info: Optional[Dict[str, Any]] = None,
        pdf_info: Optional[Dict[str, Any]] = None,
        evtx_info: Optional[Dict[str, Any]] = None,
        lnk_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        techniques: List[Dict[str, Any]] = []

        # 1. Binary checks (PE / ELF / Mach-O)
        if binary_info or category in ["executable", "binary"] or filename.lower().endswith((".exe", ".dll", ".sys", ".elf", ".bin")):
            cls._scan_binary(binary_info or {}, file_bytes, techniques)

        # 2. Script checks (PowerShell, VBScript, Batch, Shell, JS, PHP, Python, AppleScript)
        if script_triage or category in ["script", "applescript"] or filename.lower().endswith((".ps1", ".vbs", ".bat", ".sh", ".js", ".php", ".py", ".applescript", ".scpt")):
            cls._scan_script(script_triage or {}, file_bytes, techniques)

        # 3. Office VBA / XLM checks
        if office_info or category == "office" or filename.lower().endswith((".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".rtf", ".dotm")):
            cls._scan_office(office_info or {}, file_bytes, techniques)

        # 4. PDF checks
        if pdf_info or category == "pdf" or filename.lower().endswith(".pdf"):
            cls._scan_pdf(pdf_info or {}, file_bytes, techniques)

        # 5. Windows Event Logs (EVTX audit tampering)
        if evtx_info or category == "evtx" or filename.lower().endswith(".evtx"):
            cls._scan_evtx(evtx_info or {}, file_bytes, techniques)

        # 6. LNK shortcut delay execution
        if lnk_info or category == "lnk" or filename.lower().endswith(".lnk"):
            cls._scan_lnk(lnk_info or {}, file_bytes, techniques)

        # 7. Raw file bytes fallback check
        text_content = file_bytes[:1000000].decode("latin-1", errors="ignore")
        cls._scan_text_heuristics(text_content, techniques)

        # Deduplicate techniques by name
        unique_techs = []
        seen = set()
        for t in techniques:
            if t["name"] not in seen:
                seen.add(t["name"])
                unique_techs.append(t)

        has_evasion = len(unique_techs) > 0
        severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        highest_sev = "low"
        for t in unique_techs:
            if severity_rank.get(t["severity"], 0) > severity_rank.get(highest_sev, 0):
                highest_sev = t["severity"]

        confidence = "HIGH" if len(unique_techs) >= 2 else ("MEDIUM" if len(unique_techs) == 1 else "NONE")

        summary = (
            f"Identified {len(unique_techs)} anti-analysis and defense evasion technique(s) "
            f"across code structures, environment guardrails, and anti-debugging triggers."
            if has_evasion
            else "No prominent anti-analysis or sandbox evasion behaviors identified."
        )

        # Group by evasion category
        category_breakdown: Dict[str, int] = {}
        for t in unique_techs:
            c = t.get("category", "General Evasion")
            category_breakdown[c] = category_breakdown.get(c, 0) + 1

        return {
            "evasion_detected": has_evasion,
            "confidence": confidence,
            "highest_severity": highest_sev if has_evasion else "info",
            "techniques_count": len(unique_techs),
            "category_breakdown": category_breakdown,
            "techniques": unique_techs,
            "summary": summary
        }

    @classmethod
    def _scan_binary(cls, binary_info: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        imports = binary_info.get("imports", {})
        all_funcs = []
        for dll, funcs in imports.items():
            if isinstance(funcs, list):
                for f in funcs:
                    if isinstance(f, dict):
                        all_funcs.append(f.get("name", ""))
                    elif isinstance(f, str):
                        all_funcs.append(f)

        func_set = set(all_funcs)
        raw_text = file_bytes[:1000000].decode("latin-1", errors="ignore")

        # 1. Anti-debugging Win32 APIs
        anti_debug_apis = [
            ("IsDebuggerPresent", "Queries PEB.BeingDebugged flag via standard Win32 API.", "high", "T1622"),
            ("CheckRemoteDebuggerPresent", "Checks whether target process is monitored by remote kernel/user debugger.", "high", "T1622"),
            ("NtQueryInformationProcess", "Queries ProcessDebugPort (0x07) or ProcessDebugFlags to detect attached debuggers.", "critical", "T1622"),
            ("ZwQueryInformationProcess", "Native system call querying ProcessDebugPort (0x07) to detect attached debuggers.", "critical", "T1622"),
            ("NtSetInformationThread", "Calls ThreadHideFromDebugger (0x11) to detach debuggers and terminate on debug events.", "critical", "T1622"),
            ("ZwSetInformationThread", "Native system call detaching debugger via ThreadHideFromDebugger (0x11).", "critical", "T1622"),
            ("OutputDebugStringA", "Uses OutputDebugString and GetLastError trick to detect debugger presence.", "medium", "T1622"),
            ("OutputDebugStringW", "Uses OutputDebugString and GetLastError trick to detect debugger presence.", "medium", "T1622"),
            ("GetThreadContext", "Inspects hardware breakpoint registers DR0-DR7 in debug registers.", "critical", "T1622"),
            ("SetThreadContext", "Overwrites hardware breakpoints or manipulates context registers.", "critical", "T1622"),
            ("AddVectoredExceptionHandler", "Registers Vectored Exception Handler (VEH) to hijack INT3 / single-step exceptions before debugger.", "high", "T1622"),
            ("FindWindowA", "Checks for OllyDbg, x64dbg, or IDA Pro debugger window class names.", "medium", "T1497.001"),
            ("FindWindowW", "Checks for debugger and reverse-engineering window class names.", "medium", "T1497.001"),
        ]

        for api_name, desc, sev, mitre_id in anti_debug_apis:
            if api_name in func_set or api_name in raw_text:
                techniques.append({
                    "category": "Anti-Debugging",
                    "name": f"Win32 API: {api_name}",
                    "description": desc,
                    "severity": sev,
                    "evidence": f"Imported API or symbol: {api_name}",
                    "mitre_id": mitre_id
                })

        # 2. Anti-VM & Hypervisor checks
        anti_vm_apis = [
            ("GetSystemInfo", "Checks CPU core count (< 2 cores indicates virtual sandbox).", "medium", "T1497"),
            ("GlobalMemoryStatusEx", "Checks total physical RAM size (< 4 GB indicates sandbox VM).", "medium", "T1497"),
            ("GetCursorPos", "Monitors mouse movement to verify interactive human presence before detonation.", "high", "T1497.001"),
            ("GetAsyncKeyState", "Monitors user keypresses to delay execution until human activity is verified.", "high", "T1497.001"),
            ("SetupDiGetClassDevsA", "Enumerates hardware device trees checking for VMware or VirtualBox PCI device IDs.", "high", "T1497.001"),
            ("SetupDiGetClassDevsW", "Enumerates hardware device trees checking for VM peripheral vendor IDs.", "high", "T1497.001"),
        ]

        for api_name, desc, sev, mitre_id in anti_vm_apis:
            if api_name in func_set:
                techniques.append({
                    "category": "Anti-VM / Sandbox Guardrail",
                    "name": f"Environment Check: {api_name}",
                    "description": desc,
                    "severity": sev,
                    "evidence": f"Imported API: {api_name}",
                    "mitre_id": mitre_id
                })

        # 3. Timing & Sleep Evasion
        timing_apis = [
            ("GetTickCount", "Checks system uptime or calculates delta around Sleep to detect sandbox fast-forwarding.", "medium", "T1497.003"),
            ("GetTickCount64", "Monitors high-resolution tick counts to detect time acceleration hooks.", "medium", "T1497.003"),
            ("QueryPerformanceCounter", "High-precision timer used to detect debugging latency or sleep warping.", "medium", "T1497.003"),
            ("timeGetTime", "Multimedia timer API used for sleep acceleration detection.", "medium", "T1497.003"),
            ("SleepEx", "Alertable sleep used to evade rudimentary sleep hook skips.", "medium", "T1497.003"),
        ]

        for api_name, desc, sev, mitre_id in timing_apis:
            if api_name in func_set:
                techniques.append({
                    "category": "Sandbox Sleep Evasion",
                    "name": f"Timing / Sleep Delta Check: {api_name}",
                    "description": desc,
                    "severity": sev,
                    "evidence": f"Imported API: {api_name}",
                    "mitre_id": mitre_id
                })

        # 4. Disassembly instructions check (PEB access, RDTSC, Direct Syscalls)
        disasm = binary_info.get("disassembly", {})
        susp_patterns = disasm.get("suspicious_patterns", [])
        instructions = disasm.get("instructions", [])

        for pat in susp_patterns:
            if "PEB Access" in pat:
                techniques.append({
                    "category": "Anti-Debugging",
                    "name": "Direct PEB (Process Environment Block) Query",
                    "description": "Direct memory access to fs:[30h] or gs:[60h] reading BeingDebugged, NtGlobalFlag, or ProcessHeap flags.",
                    "severity": "critical",
                    "evidence": pat,
                    "mitre_id": "T1622"
                })
            elif "Syscall" in pat:
                techniques.append({
                    "category": "Defense Evasion",
                    "name": "Direct Syscall Invocation (EDR Bypass)",
                    "description": "Direct kernel transition bypassing user-mode API monitoring hooks in ntdll.dll.",
                    "severity": "critical",
                    "evidence": pat,
                    "mitre_id": "T1027"
                })

        # RDTSC instruction scanning
        for inst in instructions:
            mnem = (inst.get("mnemonic") or "").lower()
            if mnem in ["rdtsc", "rdtscp"]:
                techniques.append({
                    "category": "Sandbox Sleep Evasion",
                    "name": f"RDTSC Time-Delta Instruction ({inst.get('address')})",
                    "description": "Executes raw CPU Read Time-Stamp Counter instruction to detect single-stepping latency or sandbox hypervisor hooks.",
                    "severity": "high",
                    "evidence": f"{inst.get('address')}: {inst.get('mnemonic')} {inst.get('op_str', '')}",
                    "mitre_id": "T1497.003"
                })
                break

        # 5. Linux ELF checks
        if "elf_mitigations" in binary_info or binary_info.get("format", "").startswith("Linux"):
            if b"ptrace" in file_bytes:
                techniques.append({
                    "category": "Anti-Debugging",
                    "name": "Linux ptrace(PTRACE_TRACEME)",
                    "description": "Calls ptrace to attach to itself; if a debugger is already attached, ptrace fails with -1.",
                    "severity": "critical",
                    "evidence": "ptrace symbol / string in ELF binary",
                    "mitre_id": "T1622"
                })
            if b"/proc/self/status" in file_bytes and b"TracerPid" in file_bytes:
                techniques.append({
                    "category": "Anti-Debugging",
                    "name": "Linux TracerPid Inspection (/proc/self/status)",
                    "description": "Parses /proc/self/status looking for non-zero TracerPid to detect GDB, LLDB, or strace.",
                    "severity": "critical",
                    "evidence": "/proc/self/status and TracerPid string markers",
                    "mitre_id": "T1622"
                })
            if b"/proc/self/wchan" in file_bytes or b"sys_ptrace" in file_bytes:
                techniques.append({
                    "category": "Anti-Debugging",
                    "name": "Linux Kernel Wait Channel Check (/proc/self/wchan)",
                    "description": "Inspects kernel wait channel to detect if execution thread is waiting in sys_ptrace.",
                    "severity": "critical",
                    "evidence": "/proc/self/wchan marker",
                    "mitre_id": "T1622"
                })

    @classmethod
    def _scan_script(cls, script_triage: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        text = file_bytes.decode("utf-8", errors="ignore")

        # 1. PowerShell Debugger Detection
        if re.search(r"(?i)\[System\.Diagnostics\.Debugger\]::IsAttached", text):
            techniques.append({
                "category": "Anti-Debugging",
                "name": "PowerShell [Debugger]::IsAttached Query",
                "description": "Queries .NET runtime diagnostic debugger interface to determine if managed debugger is attached.",
                "severity": "critical",
                "evidence": "[System.Diagnostics.Debugger]::IsAttached",
                "mitre_id": "T1622"
            })

        # 2. AMSI Memory Patching & Evasion
        if re.search(r"(?i)\b(amsiutils|amsiinitfailed|amsiscanbuffer)\b", text):
            techniques.append({
                "category": "Defense Evasion",
                "name": "PowerShell AMSI Memory Patching (Antimalware Bypass)",
                "description": "Overwrites AmsiScanBuffer in memory or flips amsiInitFailed to true to silently suppress antivirus inspection.",
                "severity": "critical",
                "evidence": "amsiutils / amsiinitfailed memory reference",
                "mitre_id": "T1562.001"
            })

        # 3. ETW (Event Tracing for Windows) Patching
        if re.search(r"(?i)\b(etweventwrite|nttraceevent|etwenable)\b", text):
            techniques.append({
                "category": "Defense Evasion",
                "name": "ETW (Event Tracing for Windows) Patching",
                "description": "Patches EtwEventWrite in ntdll.dll with RET opcode to blind SIEM agents and endpoint telemetry sensors.",
                "severity": "critical",
                "evidence": "EtwEventWrite / NtTraceEvent patch string",
                "mitre_id": "T1562.001"
            })

        # 4. JavaScript debugger statement
        if re.search(r"(?i)\bdebugger\s*;", text):
            techniques.append({
                "category": "Anti-Debugging",
                "name": "JavaScript debugger Statement",
                "description": "Triggers automated breakpoint pausing execution in developer tools / headless debuggers.",
                "severity": "high",
                "evidence": "debugger; statement in JavaScript",
                "mitre_id": "T1622"
            })

        # 5. Sandbox Sleep Evasion
        sleep_match = re.search(r"(?i)\b(start-sleep\s+(-s(econds)?\s+)?(\d+)|wscript\.sleep\s+(\d+)|timeout\s+(/t\s+)?(\d+)|sleep\s+(\d+)|ping\s+127\.0\.0\.1\s+-n\s+(\d+))\b", text)
        if sleep_match:
            val = int(sleep_match.group(4) or sleep_match.group(5) or sleep_match.group(7) or sleep_match.group(8) or sleep_match.group(9) or 0)
            if val >= 30:
                techniques.append({
                    "category": "Sandbox Sleep Evasion",
                    "name": f"Extended Sleep Pause ({val}s)",
                    "description": f"Delays execution for {val} seconds to exceed standard automated sandbox run timeouts.",
                    "severity": "high",
                    "evidence": sleep_match.group(0),
                    "mitre_id": "T1497.003"
                })

        # 6. Anti-VM Hardware & Environment Guardrails
        wmi_vm_match = re.search(r"(?i)(win32_computersystem|win32_bios|win32_baseboard|win32_processor|win32_logicaldisk|win32_physicalmemory).*?(vbox|vmware|virtualbox|qemu|kvm|hyper-v|capacity|numberofcores|size)", text)
        if wmi_vm_match:
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "WMI Hardware / Hypervisor Guardrail Check",
                "description": "Queries WMI system hardware tables checking for VirtualBox, VMware, QEMU, RAM size, or CPU core constraints.",
                "severity": "critical",
                "evidence": wmi_vm_match.group(0)[:80],
                "mitre_id": "T1497.001"
            })

        # 7. Domain Join & Human Activity checks
        if re.search(r"(?i)(partofdomain|userdnsdomain|cursor\]::position)", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Domain Join or Mouse Movement Guardrail",
                "description": "Verifies host belongs to an Active Directory corporate domain or measures mouse cursor delta before running.",
                "severity": "high",
                "evidence": "PartOfDomain / USERDNSDOMAIN / Cursor position query",
                "mitre_id": "T1497.001"
            })

        # 8. AppleScript VM checks
        if re.search(r"(?i)(sysctl\s+-n\s+hw\.model|ioreg\s+-l.*?IOPlatformExpertDevice)", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "macOS / AppleScript Hardware Model Verification",
                "description": "Executes sysctl or ioreg checking for VMware, VirtualBox, or QEMU macOS emulation strings.",
                "severity": "critical",
                "evidence": "sysctl / ioreg hardware inspection command",
                "mitre_id": "T1497.001"
            })

    @classmethod
    def _scan_office(cls, office_info: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        text = file_bytes.decode("latin-1", errors="ignore")

        # 1. VBA Stomping
        stomping = office_info.get("vba_stomping", {})
        if stomping.get("is_stomped"):
            techniques.append({
                "category": "Defense Evasion",
                "name": "VBA Stomping / Source Code Purging",
                "description": "Compiled P-code bytecode exists while compressed source code is cleared or mismatched.",
                "severity": "critical",
                "evidence": "VBA performance cache mismatch (olevba)",
                "mitre_id": "T1027"
            })

        # 2. Win32 API Debugger Declarations in VBA
        if re.search(r"(?i)\bdeclare\s+(ptrsafe\s+)?function\s+(isdebuggerpresent|checkremotedebuggerpresent|gettickcount|getcursorpos)\b", text):
            matched_api = re.findall(r"(?i)\b(isdebuggerpresent|checkremotedebuggerpresent|gettickcount|getcursorpos)\b", text)
            techniques.append({
                "category": "Anti-Debugging",
                "name": f"VBA Native Win32 API Declaration ({', '.join(set(matched_api))})",
                "description": "Macro declares kernel32/user32 anti-debugging or timing verification APIs via PtrSafe declarations.",
                "severity": "critical",
                "evidence": f"Declared API: {', '.join(set(matched_api))}",
                "mitre_id": "T1622"
            })

        # 3. Macro Application.Wait / Sleep Delay
        if re.search(r"(?i)\bapplication\.wait\b|\bstart-sleep\b|\bsleep\s+\d{4,}\b", text):
            techniques.append({
                "category": "Sandbox Sleep Evasion",
                "name": "VBA Application.Wait / Sleep Delay Loop",
                "description": "Halts macro execution for prolonged periods or spins DoEvents loops to outrun sandbox evaluation limits.",
                "severity": "medium",
                "evidence": "Application.Wait or Win32 Sleep in macro",
                "mitre_id": "T1497.003"
            })

        # 4. Office Environment Guardrails (Recent Files, Screen Resolution, Printers)
        if re.search(r"(?i)application\.recentfiles\.count\s*<\s*\d+", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Office RecentFiles History Guardrail",
                "description": "Checks Application.RecentFiles.Count to terminate if running in a fresh, unpopulated automated sandbox.",
                "severity": "high",
                "evidence": "Application.RecentFiles.Count check",
                "mitre_id": "T1497.001"
            })

        if re.search(r"(?i)(getsystemmetrics\(0\)|sm_cxscreen|application\.activeprinter)", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Display Resolution or Active Printer Verification",
                "description": "Validates screen resolution exceeds 1024px or checks for configured physical printers.",
                "severity": "high",
                "evidence": "GetSystemMetrics / ActivePrinter check",
                "mitre_id": "T1497.001"
            })

        # 5. Excel 4.0 (XLM) Macro Evasion
        if re.search(r"(?i)(get\.workspace\(1\)|get\.window\(7\)|=exec\(.*?timeout)", text):
            techniques.append({
                "category": "Defense Evasion",
                "name": "Excel 4.0 (XLM) Environment & Timing Inspection",
                "description": "Legacy XLM macro queries workspace environment parameters or launches timeout subprocesses to evade detection.",
                "severity": "high",
                "evidence": "GET.WORKSPACE / GET.WINDOW / EXEC timeout formula",
                "mitre_id": "T1027"
            })

    @classmethod
    def _scan_pdf(cls, pdf_info: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        text = file_bytes.decode("latin-1", errors="ignore")

        # 1. Acrobat Viewer Version & Platform Guardrail
        if re.search(r"(?i)(app\.viewerversion|app\.platform)", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Acrobat Version / Platform Guardrail",
                "description": "PDF JavaScript queries app.viewerVersion or app.platform to only detonate on targeted reader versions.",
                "severity": "high",
                "evidence": "app.viewerVersion / app.platform in PDF JS stream",
                "mitre_id": "T1497"
            })

        # 2. PDF JS Timing & Sleep Delay Loop
        if re.search(r"(?i)(new\s+date\(\)\.gettime\(\).*?while|for.*?new\s+date\(\))", text):
            techniques.append({
                "category": "Sandbox Sleep Evasion",
                "name": "PDF JavaScript Date-Math Delay Loop",
                "description": "Uses new Date().getTime() in a busy loop to stall execution until the sandbox timeout expires.",
                "severity": "high",
                "evidence": "Date().getTime() busy-wait delay loop in PDF JavaScript",
                "mitre_id": "T1497.003"
            })

        # 3. PDF Plugin Enumeration
        if re.search(r"(?i)app\.plugins", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Acrobat Reader Plugin Enumeration",
                "description": "Enumerates installed PDF reader plugins to detect security instrumentation or missing standard modules.",
                "severity": "medium",
                "evidence": "app.plugIns in PDF JS stream",
                "mitre_id": "T1497.001"
            })

    @classmethod
    def _scan_evtx(cls, evtx_info: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        records = evtx_info.get("records", [])
        raw_text = file_bytes[:1000000].decode("latin-1", errors="ignore")

        # 1. Audit Log Cleared (Event 1102 / 104)
        has_1102 = any(r.get("event_id") == 1102 for r in records) or "1102" in raw_text and "Audit Log Cleared" in raw_text
        has_104 = any(r.get("event_id") == 104 for r in records) or "104" in raw_text and "Log file was cleared" in raw_text

        if has_1102 or has_104:
            techniques.append({
                "category": "Defense Evasion",
                "name": "Security / System Audit Log Purge (Event 1102 / 104)",
                "description": "Identified explicit event record indicating security event log was cleared by an administrator or attacker.",
                "severity": "critical",
                "evidence": "Event ID 1102 (The audit log was cleared) or Event ID 104",
                "mitre_id": "T1070.001"
            })

        # 2. System Time Changed / Timestomping (Event 4616)
        has_4616 = any(r.get("event_id") == 4616 for r in records) or "4616" in raw_text and "system time was changed" in raw_text
        if has_4616:
            techniques.append({
                "category": "Anti-Forensics / Timestomping",
                "name": "Host System Time Tampering (Event 4616)",
                "description": "The system clock was modified manually or via command-line, an indicator of temporal evasion or timestomping.",
                "severity": "high",
                "evidence": "Event ID 4616 (The system time was changed)",
                "mitre_id": "T1070.006"
            })

        # 3. Event Log Service Tampered / Stopped (Event 7040 / 7036)
        has_eventlog_stop = any(
            (r.get("event_id") in [7040, 7036] and "eventlog" in str(r.get("description", "")).lower())
            for r in records
        )
        if has_eventlog_stop or ("EventLog" in raw_text and "stopped" in raw_text):
            techniques.append({
                "category": "Defense Evasion",
                "name": "Windows Event Log Service Disabled / Stopped (Event 7040/7036)",
                "description": "The EventLog service was set to disabled or stopped to suppress event indexing.",
                "severity": "critical",
                "evidence": "Event ID 7040/7036 targeting Windows Event Log service",
                "mitre_id": "T1562.002"
            })

    @classmethod
    def _scan_lnk(cls, lnk_info: Dict[str, Any], file_bytes: bytes, techniques: List[Dict[str, Any]]):
        cmd = str(lnk_info.get("command_line_arguments", "")) or ""
        raw_text = file_bytes.decode("latin-1", errors="ignore")

        if re.search(r"(?i)\b(timeout\s+/t\s+\d+|ping\s+127\.0\.0\.1\s+-n\s+\d+|start-sleep)\b", cmd + " " + raw_text):
            techniques.append({
                "category": "Sandbox Sleep Evasion",
                "name": "LNK Shortcut Delayed Execution Argument",
                "description": "LNK target command line chains timeout, ping localhost, or Start-Sleep to delay payload execution.",
                "severity": "high",
                "evidence": "timeout / ping delay loop inside LNK argument string",
                "mitre_id": "T1497.003"
            })

    @classmethod
    def _scan_text_heuristics(cls, text: str, techniques: List[Dict[str, Any]]):
        # 1. Locale / Language Guardrails (Russian/CIS keyboard layout evasion)
        if re.search(r"(?i)\b(00000419|ru-ru|getkeyboardlayout.*?0x0419)\b", text):
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": "Geographic / Language Guardrail (CIS / Russian Locale)",
                "description": "Checks system keyboard layout for Russian/Cyrillic (0x0419) and terminates to avoid domestic law enforcement.",
                "severity": "high",
                "evidence": "Locale identifier 0x0419 / ru-RU detected",
                "mitre_id": "T1497"
            })

        # 2. Reverse Engineering & Security Analysis Process Detection
        vm_procs = re.findall(r"(?i)\b(wireshark|fiddler|procmon|x64dbg|x32dbg|ollydbg|ida|ida64|ghidra|vmtoolsd|vboxservice|processhacker|pestudio)\.exe\b", text)
        if vm_procs:
            techniques.append({
                "category": "Security Tool Detection",
                "name": f"Security Analysis Process Detection ({', '.join(set(vm_procs))})",
                "description": "Target checks running processes for reverse-engineering tools, network sniffers, or debuggers.",
                "severity": "critical",
                "evidence": f"Monitored tool processes: {', '.join(set(vm_procs))}",
                "mitre_id": "T1497.001"
            })

        # 3. Sandbox Usernames & Virtual Hardware Artifacts
        sandbox_artifacts = re.findall(r"(?i)\b(MALTEST|TEQUILA|JOHN-PC|SANDBOX|VIRUS|MALWARE|CURRENTUSER|VBOX_HARDDISK|VMware_Virtual_S)\b", text)
        if sandbox_artifacts:
            techniques.append({
                "category": "Anti-VM / Sandbox Guardrail",
                "name": f"Known Sandbox Artifact Signatures ({', '.join(set(sandbox_artifacts))})",
                "description": "String checks targeting default virtual disk models, sandbox hostnames, or automated lab user accounts.",
                "severity": "high",
                "evidence": f"Matched artifact strings: {', '.join(set(sandbox_artifacts))}",
                "mitre_id": "T1497.001"
            })
