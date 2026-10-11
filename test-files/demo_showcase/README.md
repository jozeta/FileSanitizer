# FileSanitizer Demo Showcase Suite

This directory contains **26 premier demonstration files** — exactly one curated file per supported file format. Each artifact is selected to demonstrate FileSanitizer's deep forensic inspection, static analysis, threat triage, and visual reporting capabilities.

---

## Showcase Catalog (One File Per Format)

| Format | Showcase File | Vulnerabilities & Threats Demonstrated | FileSanitizer Features Highlighted |
| :--- | :--- | :--- | :--- |
| **PDF** | `demo_fontmatrix_breakout.pdf` | CVE-2024-4367 (PDF.js FontMatrix RCE), embedded JavaScript, autorun `/OpenAction` | Didier Stevens PDFiD token badges, clickable raw stream inspector, object stream viewer |
| **Word (Macro)** | `demo_vba_weaponized_macro.docm` | VBA stomping, WMI Win32_Process, AutoExec execution trigger, encoded download cradle | VBA code decompilation, P-code discrepancy analysis, suspicious API call highlights |
| **Word (OOXML)** | `demo_office_document.docx` | External relationships, embedded OLE package references, suspicious external target | OOXML package dissection, relationship graph, embedded part extractor |
| **Excel** | `demo_financial_spreadsheets.xlsx` | Dynamic Data Exchange (DDE), formula injection (`=cmd\|'/c calc'!A1`), hidden sheets | Formula risk scoring, hidden sheet alerts, CSV/DDE formula sanitization preview |
| **PowerPoint** | `demo_stealth_presentation.pptm` | Mouse-over action traps (`ppactionhover`), slide click triggers, hidden presentation slides | Presentation slide layout analysis, hover/click trigger inspection, embedded VBA |
| **Rich Text (RTF)** | `demo_weaponized_exploit.rtf` | Microsoft Equation Editor CVE-2017-11882, MonikerLink CVE-2024-21413, embedded PE payload | OLE Object Carver, CLSID mapping, carved payload hashing & analysis |
| **Windows Logs** | `demo_endpoint_sysmon.evtx` | Sysmon Process Create (1), Network Connect (3), Image Load (7), Process Access (10) | Multi-Host Swimlanes, Parent-Child Process Tree, MITRE ATT&CK technique mapping |
| **Network PCAP** | `demo_network_attack.pcap` | DNS tunneling/exfiltration, HTTP POST C2 beaconing, cleartext credentials, file exfil | Flow timeline, stream reassembly, protocol breakdown, carved payload analyzer |
| **Outlook Email** | `demo_phishing_invoice.msg` | Urgent invoice phishing lure, dangerous macro attachment, spoofed authentication | OLE Compound file parsing, SPF/DKIM/DMARC badges, transit hop latency graph |
| **MIME Email** | `demo_credential_phishing.eml` | Microsoft 365 credential harvester, hidden 1x1 tracking pixel, base64 MIME HTML | Header anomaly scoring, tracking pixel detection, decoded HTML body preview |
| **Archive** | `demo_multi_payload_archive.zip` | WinRAR extension spoofing CVE-2023-38831, Zip Slip traversal (`../../`), compression bomb | Archive tree explorer, Zip Slip traversal alert, compression ratio monitoring |
| **Windows Executable** | `demo_advanced_implant.exe` | Suspicious PE imports (`VirtualAlloc`, `WriteProcessMemory`), high entropy, API hashing | PE header analyzer, section entropy heatmap, Ghidra decompilation, call graph |
| **Linux Executable** | `demo_linux_rootkit.elf` | 64-bit ELF headers, dynamic symbol imports (`ptrace`, `mprotect`), suspicious syscalls | ELF header inspection, dynamic symbol table, disassembly view, checksec security flags |
| **Windows Shortcut** | `demo_stealth_shortcut.lnk` | LOLBin PowerShell execution, Base64 cradle, icon spoofing, MotW bypass CVE-2024-38217 | MS-SHLLINK parser, command-line deobfuscator, icon mismatch alert, TrackerDataBlock |
| **Image (Forensics)**| `demo_geotagged_forensics.jpg`| GPS EXIF metadata, camera serials, concealed overlay polyglot data | Interactive OpenStreetMap/Nominatim reverse geocoding, EXIF metadata table |
| **Vector Graphics** | `demo_active_vector.svg` | ImageTragick CVE-2016-3714, XML External Entity (XXE), inline JavaScript (`onload`) | XML structure sanitizer, active script removal preview, XXE payload alert |
| **PowerShell** | `demo_amsi_bypass_cradle.ps1` | In-memory AMSI patch (`amsiInitFailed`), reflection, WebClient download cradle | Script AST parser, AMSI bypass signature detection, deobfuscated payload view |
| **Batch Script** | `demo_lolbin_stager.bat` | CertUtil `-urlcache` download LOLBin, `-decode` payload staging, hidden cmd execution | Living-off-the-Land binary detection, staged payload extraction |
| **POSIX Shell** | `demo_reverse_shell.sh` | Interactive `/dev/tcp` reverse shell, cron persistence installation, history scrubbing | Shell command tokenizer, reverse shell pattern matching, persistence heuristics |
| **PHP Backdoor** | `demo_backdoor_webshell.php` | Obfuscated webshell, `eval(base64_decode())`, system command execution parameters | PHP parser, dynamic evaluation alert, base64 string deobfuscation |
| **Java Archive** | `demo_trojan_archive.jar` | Dangerous manifest `Main-Class`, embedded bytecode with `Runtime.getRuntime().exec` | JAR manifest inspector, class file list, decompiled bytecode preview |
| **Browser Extension**| `demo_malicious_extension.crx`| Chromium CRX3 package, `<all_urls>` permission abuse, background interception worker | Manifest v3 validator, high-risk permission breakdown, background script triage |
| **AppleScript** | `demo_macos_dropper.scpt` | Compiled AppleScript OSA binary, `do shell script` curl download and execution | OSA component decompiler, shell invocation extraction |
| **VBScript** | `demo_wscript_dropper.vbs` | `WScript.Shell`, MSXML2.XMLHTTP payload download, Temp directory executable staging | VBScript analyzer, HTTP request detection, file drop heuristics |
| **Spreadsheet CSV** | `demo_formula_injection.csv` | Formula injection / DDE command execution (`=cmd\|'/c calc'!A1`) | Formula risk analyzer, dangerous leading character sanitizer preview |
| **Web Document** | `demo_phishing_login.html` | Fake login lure, hidden credential harvesting iframe, cross-domain form submission | HTML DOM analyzer, iframe overlay detector, form action destination verification |

---

## Recommended Live Demo Walkthrough

### 1. The Weaponized Document & Exploit Analysis
- **Upload**: `demo_fontmatrix_breakout.pdf` or `demo_vba_weaponized_macro.docm`.
- **Observe**:
  - Immediate high-severity threat alert and risk score calculation.
  - Interactive **Didier Stevens PDFiD Tokens** modal — click on any token (`/JavaScript`, `/OpenAction`) to inspect raw streams and decompiled JavaScript.
  - In `demo_vba_weaponized_macro.docm`, review the decompiled VBA code and view detected API calls (`Shell`, `CreateProcess`, `WMI`).

### 2. Binary Forensics & Reverse Engineering
- **Upload**: `demo_advanced_implant.exe` or `demo_linux_rootkit.elf`.
- **Observe**:
  - Interactive **Section Entropy Heatmap** visually flagging packed/encrypted payloads.
  - Imported symbol risk breakdown, checksec exploit mitigation flags (DEP/NX, ASLR, SafeSEH).
  - Pure-client or backend-generated **Ghidra Decompilation & Function Call Graph**.

### 3. Endpoint & Network Correlation
- **Upload**: `demo_endpoint_sysmon.evtx` and `demo_network_attack.pcap`.
- **Observe**:
  - The **Multi-Host Swimlanes** detailing process execution and network activity across systems.
  - Parent-child process tree reconstruction tracking malicious stagers spawning PowerShell.
  - Full packet flow reassembly and DNS query extraction in the PCAP analyzer.

### 4. Forensic Metadata & Geocoding
- **Upload**: `demo_geotagged_forensics.jpg`.
- **Observe**:
  - Extraction of GPS latitude, longitude, altitude, and timestamp metadata.
  - Embedded **Nominatim / OpenStreetMap** interactive map visualizing the exact location where the media was captured.
