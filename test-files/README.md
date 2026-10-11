# FileSanitizer Test Files Suite

This repository directory contains curated test files, forensic attack artifacts, and vulnerability benchmarks specifically crafted to exercise FileSanitizer's security analyzers, Content Disarm & Reconstruction (CDR) engines, threat graph correlation, and antivirus pipelines.

---

## Directory Organization

```
test-files/
├── demo_showcase/              # 🌟 26 PREMIER FILES (One per supported format for demos)
├── correlated_investigation/   # 🔗 7 SYNCHRONIZED ARTIFACTS ("Operation CobaltShadow" APT campaign)
├── malicious_pdf/              # 📄 Specialized Malicious PDF test suite (jonaslejon/malicious-pdf)
├── ultimate_files/             # 🔬 Comprehensive cross-format vulnerability & detection corpus
└── [unit-test fixtures]        # 🧪 Core fixtures retained for automated test suites
```

---

## 1. Demo Showcase Suite (`test-files/demo_showcase/`)

Contains **exactly 26 curated demonstration files** — one per supported file format — showcasing FileSanitizer's forensic analysis, static code decompilation, threat intelligence, and CDR capabilities:

| Format | Showcase File | Primary Feature & Vulnerability Highlight |
| :--- | :--- | :--- |
| **PDF** | `demo_fontmatrix_breakout.pdf` | CVE-2024-4367 PDF.js RCE, Didier Stevens PDFiD badges, clickable raw stream inspector |
| **Word Macro** | `demo_vba_weaponized_macro.docm` | VBA stomping, WMI process execution, auto-exec macros, P-code discrepancy |
| **Word OOXML** | `demo_office_document.docx` | OpenXML relationship inspection, embedded OLE packages, metadata sanitization |
| **Excel** | `demo_financial_spreadsheets.xlsx` | Dynamic Data Exchange (DDE), formula injection (`=cmd\|'/c calc'!A1`), hidden sheets |
| **PowerPoint** | `demo_stealth_presentation.pptm` | Mouse-over action triggers (`ppactionhover`), slide click traps, hidden slides |
| **Rich Text (RTF)** | `demo_weaponized_exploit.rtf` | Microsoft Equation Editor CVE-2017-11882, MonikerLink CVE-2024-21413, carved PE payload |
| **Windows Logs** | `demo_endpoint_sysmon.evtx` | Multi-Host Swimlanes, parent-child process tree, Sysmon 1/3/7/10/11, MITRE ATT&CK |
| **Network PCAP** | `demo_network_attack.pcap` | DNS tunneling/exfiltration, HTTP POST C2 beaconing, packet stream reassembly |
| **Outlook Email** | `demo_phishing_invoice.msg` | Pure-Python OLE Compound File parsing, SPF/DKIM/DMARC badges, transit hop timeline |
| **MIME Email** | `demo_credential_phishing.eml` | Microsoft 365 credential harvester, hidden 1x1 tracking pixel, base64 MIME body |
| **Archive** | `demo_multi_payload_archive.zip` | WinRAR extension spoofing CVE-2023-38831, Zip Slip traversal (`../../`), compression bomb |
| **Windows Executable** | `demo_advanced_implant.exe` | PE section entropy heatmap, API hashing detection, Ghidra decompilation, call graph |
| **Linux Executable** | `demo_linux_rootkit.elf` | 64-bit ELF headers, dynamic symbol imports (`ptrace`, `mprotect`), checksec flags |
| **Windows Shortcut** | `demo_stealth_shortcut.lnk` | LOLBin PowerShell execution, Base64 cradle, icon spoofing, MotW bypass CVE-2024-38217 |
| **Image Forensics** | `demo_geotagged_forensics.jpg` | Forensic GPS EXIF metadata, OpenStreetMap/Nominatim interactive reverse geocoding map |
| **Vector Graphics** | `demo_active_vector.svg` | ImageTragick CVE-2016-3714, XML External Entity (XXE), inline JavaScript (`onload`) |
| **PowerShell** | `demo_amsi_bypass_cradle.ps1` | In-memory AMSI patch (`amsiInitFailed`), reflection, WebClient download cradle |
| **Batch Script** | `demo_lolbin_stager.bat` | CertUtil `-urlcache` download LOLBin, `-decode` payload staging, background execution |
| **POSIX Shell** | `demo_reverse_shell.sh` | Interactive `/dev/tcp` reverse shell, cron persistence installation, history scrubbing |
| **PHP Backdoor** | `demo_backdoor_webshell.php` | Obfuscated webshell, `eval(base64_decode())`, system command execution parameters |
| **Java Archive** | `demo_trojan_archive.jar` | JAR manifest inspection, decompiled Java bytecode analysis, `ProcessBuilder` execution |
| **Browser Extension** | `demo_malicious_extension.crx` | Chromium CRX3 package, `<all_urls>` permission abuse, background worker analysis |
| **AppleScript** | `demo_macos_dropper.scpt` | Compiled AppleScript OSA binary, `do shell script` curl download and execution |
| **VBScript** | `demo_wscript_dropper.vbs` | `WScript.Shell`, MSXML2.XMLHTTP payload download, Temp directory executable staging |
| **Spreadsheet CSV** | `demo_formula_injection.csv` | Formula injection / DDE command execution (`=cmd\|'/c calc'!A1`), CSV sanitization |
| **Web Document** | `demo_phishing_login.html` | Credential phishing form, hidden iframe overlay, cross-domain form submission |

See [`test-files/demo_showcase/README.md`](demo_showcase/README.md) for full walkthrough instructions.

---

## 2. Correlated Investigation Suite (`test-files/correlated_investigation/`)

Contains **7 synchronized forensic artifacts** modeling an APT intrusion campaign titled **"Operation CobaltShadow"**:

1. `01_phishing_email.msg` — Initial phishing lure with fake invoice and malicious macro attachment.
2. `02_weaponized_document.docm` — Weaponized Word document executing AutoOpen PowerShell cradle.
3. `03_c2_implant_beacon.exe` — CobaltStrike beacon implant payload (**SHA-256**: `b002241f...`).
4. `04_endpoint_workstation_hostA.evtx` — Windows Event Log from victim Workstation `WKSTN-FIN-01` (`10.0.4.15`).
5. `05_endpoint_domain_controller_hostB.evtx` — Windows Event Log from Domain Controller `DC-PROD-01` (`10.0.4.50`).
6. `06_network_traffic_capture.pcap` — Wire traffic capture showing DNS, HTTP download, TLS C2, and SMB lateral movement.
7. `07_exfiltrated_archive.zip` — Exfiltrated confidential payroll archive (**SHA-256**: `2f38219c...`).

When uploaded or analyzed together, FileSanitizer's **Multi-Host Swimlanes**, **Forensic Super-Timeline**, and **Threat Graph** visually connect all events across network, endpoint, and identity layers.

See [`test-files/correlated_investigation/README.md`](correlated_investigation/README.md) for the complete attack scenario narrative, IOC tables, and demonstration steps.

---

## 3. Automated Test Suite Fixtures

The following files are strictly retained in the root of `test-files/` as required dependencies for the automated pytest suite (`backend/tests/`):
- `clean_document.pdf`
- `office_vba_macro_template_injection.docm`
- `clean_office_document.docx`
- `image_gps_exif_metadata.jpg`
- `word_macro_with_google_links.docm`
- `pdf_autorun_javascript_sunet_link.pdf`
- `pdf_with_image_containing_sunet_url.pdf`
