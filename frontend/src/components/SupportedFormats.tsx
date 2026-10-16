import React, { useState } from 'react';
import { 
  FileCheck2, 
  Image as ImageIcon, 
  FileText, 
  FileCode, 
  Archive, 
  FileSpreadsheet, 
  ShieldCheck, 
  Wrench, 
  Search, 
  ArrowRight, 
  ShieldAlert, 
  Sparkles,
  Mail,
  Binary,
  Cpu,
  Puzzle,
  Terminal,
  Globe,
  Activity,
  Link as LinkIcon,
  Smartphone,
  Coffee
} from 'lucide-react';

interface SupportedFormatsProps {
  onGoToSanitizer: () => void;
}

export const SupportedFormats: React.FC<SupportedFormatsProps> = ({ onGoToSanitizer }) => {
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const analysisEngines = [
    { name: "Didier Stevens oledump.py", desc: "Deep OLE stream hierarchy & XLM macro sheet analysis" },
    { name: "slimm609/checksec v3", desc: "Binary exploit mitigations (Canary, ASLR, DEP, RELRO, CFG)" },
    { name: "pefile, pyelftools & Mach-O", desc: "Native executable structural decomposition & import analysis" },
    { name: "python-evtx Engine", desc: "Windows Event Log binary chunk parsing & MITRE ATT&CK mapping" },
    { name: "ClamAV Multi-Engine", desc: "Core engine + SecuriteInfo & Sanesecurity community feeds" },
    { name: "CISA KEV & FIRST EPSS", desc: "Known Exploited Vulnerabilities & Exploit Prediction scoring" },
    { name: "YARA Rules Engine", desc: "Office DDE, XLM Macros, LOLBins, & CVE pattern rules" },
    { name: "CIRCL Hashlookup & NSRL", desc: "Trusted operating system benign hash verification" },
    { name: "ThreatFox & AbuseIPDB", desc: "Malware payload hashes, C2 indicators & IP reputation" },
    { name: "Wayback Machine & Archive", desc: "Historical snapshot exploration & domain time-series tracking" },
    { name: "BGPView & Team Cymru", desc: "Autonomous System (ASN) prefix routing & BGP path discovery" },
    { name: "VirusTotal & URLhaus", desc: "Multi-scanner file hashes and malicious host reputation" },
  ];

  const formatCategories = [
    {
      id: "email",
      category: "Email Messages & Mailboxes",
      icon: Mail,
      iconColor: "text-indigo-600 bg-indigo-50 border-indigo-200",
      extensions: [".eml", ".msg", ".mbox"],
      description: "Internet message RFC 822/5322 containers and Microsoft Outlook Compound File (.msg) objects harboring tracking beacons, phishing links, or payload attachments.",
      threats: [
        "Phishing & Credential Theft Forms", 
        "Display Name & Header Spoofing", 
        "Zero-Pixel Invisible Web Beacons", 
        "Dangerous Executable & Script Droppers", 
        "Macro-Enabled Office Containers", 
        "SPF / DKIM / DMARC Authentication Failures"
      ],
      checks: [
        "Received-SPF authentication validation headers and SPF failure detection",
        "DKIM cryptographic signature verification status and spoofing indicators",
        "Sender Display Name spoofing (mismatched display names vs. envelope addresses)",
        "Mismatched From address domain vs. Reply-To destination domain routing",
        "Hidden 1x1 zero-pixel tracking beacons and CSS hidden image telemetry",
        "Active executable HTML elements (<script>, <form>, <iframe>, <object>, <embed>)",
        "Dangerous executable attachment extensions (.exe, .scr, .vbs, .ps1, .bat, .cmd, .js)",
        "Macro-enabled Office attachment containers (.docm, .xlsm, .pptm, .dotm)",
        "Direct Microsoft Outlook Compound File (.msg) OLE stream inspection via olefile",
        "Embedded hyperlink extraction with VirusTotal, URLhaus, and urlscan.io cross-checks"
      ],
      sanitizations: [
        "Decompose and disarm into clean, sanitized Plain Text or secure HTML",
        "Strip all 1x1 tracking pixels, hidden web beacons, and external telemetry URLs",
        "Neutralize active HTML code (<script>, dynamic forms, interactive iframes)",
        "Extract, quarantine, and isolate all file attachments into triage storage",
        "Defang clickable URLs and display explicit threat warning banners"
      ]
    },
    {
      id: "executables",
      category: "Executable Binaries & Libraries",
      icon: Binary,
      iconColor: "text-violet-600 bg-violet-50 border-violet-200",
      extensions: [".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".bin"],
      description: "Compiled native binary executables across Windows (PE/COFF), Linux (ELF), and macOS (Mach-O) analyzed for malware implants, unpackers, and suspicious system API imports.",
      threats: [
        "Ransomware & Trojan Droppers",
        "Living-off-the-Land (LOLBins) Execution",
        "UPX & Custom Anti-Analysis Packers",
        "Process Injection & Memory Hooking",
        "Unsigned or Invalid Authenticode Signatures",
        "Dynamic Syscall Evasion (ptrace / memfd_create)"
      ],
      checks: [
        "Windows PE parsing via pefile (COFF Headers, Optional Header, Subsystem, Target Architecture)",
        "Linux ELF inspection via pyelftools (ELF Headers, PT_LOAD segments, DT_NEEDED shared libraries)",
        "macOS Mach-O parsing (Fat binary multi-architecture slices, LC_LOAD_DYLIB, Code Signatures)",
        "Binary exploit mitigations audit via checksec v3 (Stack Canary, NX / DEP, ASLR / PIE, Full/Partial RELRO, Fortify Source, SafeSEH, CFG)",
        "Shannon section entropy calculation (detects UPX, Themida, and encrypted payloads)",
        "Suspicious API import heuristic matching (VirtualAlloc, WriteProcessMemory, CreateRemoteThread)",
        "Linux dynamic execution indicators (ptrace anti-debugging, memfd_create fileless execution)",
        "Authenticode digital signature verification (checks for signed vs. unsigned executables)",
        "Living-off-the-Land (LOLBins) YARA rule detection (CertUtil, PowerShell, MSBuild, Bitsadmin)",
        "CIRCL Hashlookup NSRL database lookup (identifies known-good operating system files)",
        "ThreatFox & VirusTotal malware reputation queries against SHA-256 and MD5 hashes"
      ],
      sanitizations: [
        "Executable Disarmament: nullifies executable entry point and clears PE optional header",
        "Generates comprehensive Forensic Triage PDF Dossier detailing headers, sections, and imports",
        "Extracts benign strings, decompiled resource metadata, and safe triage summary"
      ]
    },
    {
      id: "office",
      category: "Microsoft Office Documents",
      icon: FileSpreadsheet,
      iconColor: "text-amber-600 bg-amber-50 border-amber-200",
      extensions: [".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".rtf", ".odt", ".ods", ".odp"],
      description: "Word processing, spreadsheet, and presentation documents inspected with Didier Stevens oledump.py for macro streams, Excel 4.0 XLM formulas, and external injection.",
      threats: [
        "VBA Macro Droppers / Ransomware", 
        "Excel 4.0 (XLM) Macro Sheet Hijacking",
        "Dynamic Data Exchange (DDE) Exploits",
        "Remote Template Injection Attacks", 
        "ActiveX Remote Code Execution", 
        "Tracked Change Information Leakage"
      ],
      checks: [
        "Didier Stevens oledump stream analysis (identifies VBA macro indicators M/m, stream sizes)",
        "Excel 4.0 (XLM) macro sheet detection and auto-execute formulas (Auto_Open / CALL / EXEC)",
        "Dynamic Data Exchange (DDE) remote process execution fields and links",
        "Visual Basic for Applications (VBA) macro binary streams (vbaProject.bin)",
        "ActiveX controls and embedded OLE storage objects",
        "Remote template injection (attachedTemplate relationships in .rels)",
        "External relationships and remote web resource references",
        "Tracked changes (revisions, deletions, insertions, author timestamps)",
        "Internal author comments, reviewer remarks, and unresolved notes",
        "Core metadata (dc:creator, cp:lastModifiedBy, dc:title, dc:description, cp:keywords)",
        "Hyperlinks and URLs embedded in document text or relationship targets"
      ],
      sanitizations: [
        "Purge all VBA macro binary streams (vbaProject.bin) without executing them",
        "Strip Excel 4.0 (XLM) macro sheets and neutralize DDE formulas",
        "Strip embedded ActiveX controls and OLE storage objects",
        "Neutralize external relationships and remote attached template targets",
        "Scrub personal author and modifier metadata from docProps/core.xml",
        "Permanently delete tracked revisions and internal reviewer comments",
        "Downgrade macroEnabled container types (.docm/.xlsm) to standard safe formats (.docx/.xlsx)"
      ]
    },
    {
      id: "pdf",
      category: "PDF Documents",
      icon: FileText,
      iconColor: "text-rose-600 bg-rose-50 border-rose-200",
      extensions: [".pdf", ".pdfa"],
      description: "Portable Document Format documents are complex multi-stream containers that can harbor active scripting, file attachments, and remote trigger actions.",
      threats: ["Embedded Heap-Spray Exploits", "Automatic Command Execution (/Launch)", "Phishing via JavaScript Popups", "Credential-Stealing Dynamic Forms"],
      checks: [
        "Document catalog metadata (Author, Title, Subject, Creator, Producer, Dates)",
        "Active JavaScript actions (embedded /JS objects and document scripts)",
        "/Launch actions and automatic /OpenAction triggers",
        "Embedded file attachments and secondary document payloads (/EmbeddedFiles, /EF)",
        "Interactive AcroForms and dynamic XML Forms Architecture (XFA)",
        "External hyperlinks, URI stream actions, and remote document references",
        "Embedded rich media objects (screen annotations, movie clips, 3D streams)",
        "Multiple incremental updates (revision history masking shadow attacks)",
        "Password protection, encryption markers, and exploit structural tokens"
      ],
      sanitizations: [
        "Strip document author, title, producer, and modification timestamps",
        "Purge active JavaScript streams and automated /OpenAction hooks",
        "Eradicate /Launch actions capable of executing local programs",
        "Permanently remove embedded file attachments and secondary files",
        "Flatten interactive AcroForms and dynamic XFA form structures",
        "Neutralize and strip external hyperlinks and /URI actions",
        "Maximum Rasterization CDR: renders every page to an image and compiles a completely fresh PDF"
      ]
    },
    {
      id: "images",
      category: "Images & Photographs",
      icon: ImageIcon,
      iconColor: "text-blue-600 bg-blue-50 border-blue-200",
      extensions: [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif"],
      description: "Standard digital imagery and photographs frequently leak device fingerprints, exact physical location, and embedded tracking pixels.",
      threats: [
        "Physical Geolocation Stalking", 
        "Hardware Device Fingerprinting", 
        "Hidden Steganographic Payloads", 
        "Embedded Tracking Beacons",
        "AI Deepfakes & Synthetic Media Impersonation"
      ],
      checks: [
        "EXIF metadata (Camera Make, Model, Body Serial Number, Lens Model, Software)",
        "GPS geographic coordinates (Latitude, Longitude, Altitude, Geodetic Datum)",
        "AI Image Provenance & C2PA Content Credentials inspection (Coalition for Content Provenance)",
        "IPTC digitalSourceType trainedAlgorithmicMedia and claim generator metadata (DALL-E, Firefly)",
        "Stable Diffusion, Midjourney, and NovelAI prompt & model hyperparameter extraction",
        "Physical camera hardware tag verification vs synthetic software generation markers",
        "Error Level Analysis (ELA) for image compression disparity and local modification",
        "Author, photographer, artist, and copyright attribution tags",
        "Creation, camera shutter, and software digitization timestamps",
        "Embedded text comments, annotation chunks, and caption packets",
        "XMP (Extensible Metadata Platform) and IPTC core photo structures",
        "Embedded thumbnails, preview icons, and auxiliary image streams",
        "Embedded URLs within EXIF string headers or comment chunks",
        "Optical Character Recognition (OCR) text discovery for screenshots and scanned documents",
        "QR Code and 2D barcode payload extraction and malicious URL triage",
        "ICC color profiles and alpha channel transparency masks"
      ],
      sanitizations: [
        "Strip all EXIF, XMP, IPTC, and comment metadata packets",
        "Remove GPS geographic location coordinates permanently",
        "Eradicate photographer, artist, and copyright tags",
        "Strip creation and digitization timestamps",
        "Re-encode raw pixel data (purges slack space, hidden payloads, and synthetic markers)",
        "Lossless format conversion (Convert to PNG or JPG)",
        "Flatten image: composite transparency channels onto a pure white background"
      ]
    },
    {
      id: "archives",
      category: "Compressed Archives",
      icon: Archive,
      iconColor: "text-purple-600 bg-purple-50 border-purple-200",
      extensions: [".zip", ".jar", ".7z", ".tar", ".gz", ".tgz"],
      description: "Compressed packages and Java archives (.jar) analyzed for directory traversal, decompression bombs, Main-Class droppers, and dangerous APIs.",
      threats: [
        "Path Traversal Arbitrary File Overwrite",
        "Zip Bombs / Decompression Denial of Service",
        "Executable Droppers (.exe, .ps1, .bat)",
        "Dangerous Java Applet / JAR Droppers (all-permissions)",
        "Hidden Nested Archives"
      ],
      checks: [
        "Directory traversal filenames (../../etc/passwd, ..\\windows\\system32)",
        "Java Archive (.jar) manifest inspection (Main-Class, all-permissions) and bytecode execution API scanning (ProcessBuilder, Runtime.exec, URLClassLoader, Unsafe)",
        "Executable and script members (.exe, .dll, .bat, .cmd, .ps1, .vbs, .sh, .py)",
        "Excessive compression ratios / zip bombs (>100:1 ratio against uncompressed size)",
        "Recursive nested archives exceeding extraction limits",
        "Encrypted and password-protected member files",
        "Absolute file paths and symbolic link targets"
      ],
      sanitizations: [
        "Filter and exclude directory traversal filenames",
        "Purge executable binaries, installer scripts, and PowerShell droppers",
        "Enforce strict decompression limits on member sizes and recursion depth",
        "Reconstruct clean, standardized ZIP archive containing only safe data files"
      ]
    },
    {
      id: "web",
      category: "Vector Graphics & Active Web",
      icon: FileCode,
      iconColor: "text-emerald-600 bg-emerald-50 border-emerald-200",
      extensions: [".svg", ".html", ".htm"],
      description: "Markup documents executed directly by web browsers, making them vectors for cross-site scripting (XSS), credential phishing, and tracking.",
      threats: ["Browser DOM Cross-Site Scripting (XSS)", "Credential Harvesting Phishing Forms", "Zero-Pixel Tracking Beacons", "Malicious Meta Refresh Redirects"],
      checks: [
        "Executable <script> elements and client-side JavaScript payloads",
        "Inline DOM event handlers (onload, onerror, onclick, onmouseover, onsubmit)",
        "javascript: and data: pseudo-protocol URIs in anchors and xlink targets",
        "Credential phishing forms (<form action=...> and submit buttons)",
        "External tracking beacons, remote images, and analytics scripts",
        "Embedded iframes (<iframe src=...> mirroring external portals)",
        "Meta refresh redirects (<meta http-equiv=\"refresh\">) and external links"
      ],
      sanitizations: [
        "Strip all <script> tags and executable JavaScript code",
        "Remove inline DOM event handlers (onload, onerror, etc.)",
        "Neutralize and decompose credential forms and form fields",
        "Strip embedded iframes and third-party tracking beacons",
        "Rasterize SVG directly to clean, inert PNG or JPEG raster image (Safest CDR)"
      ]
    },
    {
      id: "data",
      category: "Plain Text, Scripts & Tabular Data",
      icon: FileCheck2,
      iconColor: "text-slate-600 bg-slate-100 border-slate-200",
      extensions: [".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".py", ".sh", ".ps1"],
      description: "Source code, shell scripts, and structured tabular data susceptible to formula injection (DDE), encoding attacks, or embedded remote dropper links.",
      threats: [
        "CSV Formula Execution / DDE Injection", 
        "Arbitrary Command Execution (=cmd|...)", 
        "Shell & PowerShell Downloader Payloads",
        "Encoding Confusables & BOM Tricks", 
        "Phishing URLs in Data Columns"
      ],
      checks: [
        "CSV Formula / Dynamic Data Exchange (DDE) prefixes (=cmd|..., +powershell..., @SUM...)",
        "Character encoding identification (UTF-8, UTF-16LE, UTF-16BE) and BOM presence",
        "Suspicious shell command strings, PowerShell execution arguments, and downloader URLs",
        "XML External Entity (XXE) expansion indicators and entity bombs",
        "Embedded URLs and external web links"
      ],
      sanitizations: [
        "Escape dangerous spreadsheet formula execution prefixes with safe leading single quote (')",
        "Normalize character encoding to standard UTF-8",
        "Strip dangerous Byte Order Mark (BOM) bytes"
      ]
    },
    {
      id: "extensions",
      category: "Browser Extensions & Store Packages",
      icon: Puzzle,
      iconColor: "text-indigo-600 bg-indigo-50 border-indigo-200",
      extensions: [".crx", ".zip"],
      description: "Chrome and Microsoft Edge extension packages (.crx / unpacked .zip) inspected for excessive permissions, background surveillance, and malicious JavaScript telemetry.",
      threats: [
        "Broad Web Hijacking (<all_urls> / *://*/*)",
        "Credential & Session Cookie Harvesting",
        "Persistent Background Surveillance Workers",
        "Weak Content Security Policy (unsafe-eval)",
        "Hidden Keystroke Logging & DOM Exfiltration"
      ],
      checks: [
        "CRX2 and CRX3 header verification, public key extraction, and signature validation",
        "Manifest V2 & V3 permission risk audit (webRequestBlocking, cookies, debugger, proxy)",
        "Broad host scope identification (<all_urls>, *://*/*, http://*/*)",
        "Content Security Policy (CSP) parsing (unsafe-eval, unsafe-inline, remote script origins)",
        "Background service workers and persistent script execution inspection",
        "Content script match rules and DOM injection points",
        "Static JavaScript AST & regex heuristics (eval, new Function, keydown listeners, sendBeacon)"
      ],
      sanitizations: [
        "Package Disarmament: generates isolated, sanitized manifest with elevated permissions stripped",
        "Comprehensive Extension Forensic Triage dossier with permission risk weights and heuristic warnings",
        "Deobfuscation and static reporting of high-risk background scripts and injected content scripts"
      ]
    },
    {
      id: "applescript",
      category: "macOS AppleScript & Applications",
      icon: Terminal,
      iconColor: "text-sky-600 bg-sky-50 border-sky-200",
      extensions: [".applescript", ".scpt", ".app"],
      description: "macOS Open Scripting Architecture (OSA) source and compiled bytecode scripts, as well as .app application bundles analyzed for privilege escalation and phishing triggers.",
      threats: [
        "Root Privilege Escalation (with administrator privileges)",
        "Fake System Password Dialog Phishing",
        "Background Keystroke Logging (System Events)",
        "Stealthy Shell Command Droppers (do shell script)",
        "Unsigned Mach-O Application Bundles"
      ],
      checks: [
        "OSA header identification for compiled bytecode scripts (.scpt) and plain text source (.applescript)",
        "Heuristic detection of 'with administrator privileges' root escalation requests",
        "Credential harvesting prompts ('display dialog with hidden answer')",
        "Keystroke and accessibility interception ('tell application \"System Events\" to keystroke')",
        "Embedded network IOC extraction (curl/wget download cradles inside do shell script)",
        "macOS .app bundle Info.plist entitlement auditing and Mach-O binary triage"
      ],
      sanitizations: [
        "Defangs privilege escalation hooks and credential prompt calls",
        "Generates clean, sanitized vector PDF review dossier of the script logic",
        "Quarantines remote download URLs and marks non-executable permissions (0o644)"
      ]
    },
    {
      id: "network",
      category: "Domain/IP & Host Intelligence",
      icon: Globe,
      iconColor: "text-blue-600 bg-blue-50 border-blue-200",
      extensions: ["Domains (e.g. folksam.se)", "IPv4 / IPv6 Addresses", "Hostnames & URLs"],
      description: "Deep infrastructure, host discovery, and domain intelligence profiling combining authoritative DNS, BGP/ASN routing, passive web exposure, CISA KEV/EPSS correlation, and sandboxed screenshots.",
      threats: [
        "Active C2 Communication & Malicious Hosting",
        "CISA KEV Known Exploited Frameworks & CMS",
        "Punycode & Homoglyph Lookalike Impersonation",
        "Unprotected Web Exposure (robots.txt, .well-known, sitemaps)",
        "Spoofed Reverse DNS / Mail Server Impersonation",
        "Shared Infrastructure & Malicious Neighboring Domains"
      ],
      checks: [
        "Complete DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, PTR)",
        "Forward-Confirmed Reverse DNS (FCrDNS) verification for mail and server hosts",
        "BGP Routing & ASN intelligence (announced prefix, origin ASN, RIR registration, ISP type)",
        "Passive Web Exposure harvesting (robots.txt disallow rules, sitemap.xml endpoints, .well-known/ PKI)",
        "CISA KEV & FIRST EPSS vulnerability correlation for fingerprinted web servers, frameworks, and CMS",
        "Reverse Nameserver (Reverse-NS) and Reverse Mail Server (Reverse-MX) shared infrastructure pivots",
        "Collapsible CDN & DDoS infrastructure filtering (Baffin Bay, Cloudflare, Akamai) isolating true affiliates",
        "Typosquatting & lookalike domain generator (bitsquatting, homoglyphs, omissions, hyphenations)",
        "Reverse tracking & analytics pivots (Google Analytics UA/G-, Tag Manager GTM-, AdSense pub-)",
        "Wayback Machine / Internet Archive historical snapshot query and first-seen/last-seen tracking",
        "Investigation snapshot comparison and time-series delta change tracking",
        "Live sandboxed headless browser rendering and high-resolution screenshot preview"
      ],
      sanitizations: [
        "Pure infrastructure intelligence: CDR file sanitization is safely bypassed for network targets",
        "Defangs all hostile target URLs and links across forensic incident response dossiers",
        "Exports structured intelligence dossiers in JSON, CSV, and formatted forensic reports",
        "Enables one-click IOC quick-enrichment across all file analysis jobs (PCAP, EVTX, Email, etc.)"
      ]
    },
    {
      id: "evtx",
      category: "Windows Event Logs (EVTX)",
      icon: Activity,
      iconColor: "text-emerald-600 bg-emerald-50 border-emerald-200",
      extensions: [".evtx"],
      description: "Windows XML Event Log binary files parsed with python-evtx, reconstructing multi-log chronological incident timelines, MITRE ATT&CK techniques, and privilege escalation.",
      threats: [
        "Pass-the-Hash & NTLM Relay Logons (Event 4624)",
        "Kerberoasting & Ticket Granting Attacks (Event 4769)",
        "Brute-Force & Password Spraying (Event 4625)",
        "Event Log Clearing & Defense Evasion (Event 1102 / 104)",
        "Malicious Service & Scheduled Task Installs (Event 7045 / 4698)",
        "LSASS Memory Access & Dumping (Sysmon Event 10)"
      ],
      checks: [
        "Binary XML chunk validation & parsing via python-evtx",
        "MITRE ATT&CK technique classification across 100+ Windows Security, System, and Sysmon Event IDs",
        "Multi-log chronological timeline correlation across multiple EVTX files in unified incident workspace",
        "Brute-force burst heuristic analysis (detects high-frequency failed logon bursts within tight time windows)",
        "Privilege escalation token audit (SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege assignments)",
        "Lateral movement indicators (Type 3 network logons, PsExec service installation 7045, WinRM connections)",
        "Suspicious parent-child process tree analysis (Office documents spawning cmd.exe or powershell.exe)",
        "PowerShell script block logging analysis (Event 4104 obfuscated script blocks and download cradles)",
        "Account lockout event tracking (Event 4740) and user privilege change audits (Events 4728/4732)",
        "One-click IOC quick-enrichment pivot for extracted domains, IPv4 addresses, and executable hashes"
      ],
      sanitizations: [
        "Redact and mask sensitive internal usernames, domains, and security identifier (SID) strings",
        "Anonymize private internal IP addresses (RFC 1918 subnets) and computer hostnames",
        "Generate forensic timeline summary dossier and export sanitized JSON/CSV datasets"
      ]
    },
    {
      id: "lnk",
      category: "Windows Shell Links & Shortcuts (LNK)",
      icon: LinkIcon,
      iconColor: "text-amber-600 bg-amber-50 border-amber-200",
      extensions: [".lnk"],
      description: "Windows Shell Link shortcut binary containers analyzed for command-line injection, living-off-the-land binaries (LOLBins), UNC path credential harvesting, and forensic metadata.",
      threats: [
        "Remote PowerShell & CMD Payload Execution",
        "Living-off-the-Land (LOLBins) Hijacking (mshta, rundll32, certutil)",
        "Hidden & Minimized Window Evasion (SW_HIDE)",
        "UNC Path NTLM Credential Theft (\\\\malicious-smb\\share)",
        "Deceptive Icon Camouflage (PDF/Word icon on script)"
      ],
      checks: [
        "Shell Link Header analysis (LinkFlags, FileAttributes, Creation/Access/Write timestamps)",
        "Target file path extraction and command-line arguments parsing (-enc, -w hidden, download cradles)",
        "Working directory and relative path target resolution",
        "Embedded icon location parsing and icon index spoofing detection (e.g. imageres.dll/shell32.dll disguise)",
        "Volume metadata extraction (DriveType: FIXED, REMOTE, REMOVABLE, and VolumeSerialNumber)",
        "Network share UNC path detection (targets attempting remote SMB outbound authentication)",
        "Environmental variable string expansion (%APPDATA%, %TEMP%, %COMSPEC%)",
        "Creator machine forensic metadata: MAC address from link UUID/GUID and NetBIOS computer hostname",
        "Suspicious LOLBin executable target matching (powershell.exe, cmd.exe, wscript.exe, mshta.exe)"
      ],
      sanitizations: [
        "Neutralize and strip dangerous command-line arguments and payload parameters",
        "Disarm target executable links and strip UNC network share references to prevent NTLM leaks",
        "Generate forensic triage dossier and export clean, text-based shortcut attribute report"
      ]
    },
    {
      id: "pcap",
      category: "Network Packet Captures (PCAP / PCAPNG)",
      icon: Activity,
      iconColor: "text-indigo-600 bg-indigo-50 border-indigo-200",
      extensions: [".pcap", ".pcapng", ".cap"],
      description: "Network packet capture traces dissected for protocol conversations, unencrypted credentials, TLS Server Name Indications (SNI), DNS queries, and malicious payloads.",
      threats: [
        "Plaintext Credential Theft (HTTP Basic Auth, FTP, Telnet)",
        "Malware Command-and-Control (C2) Communication",
        "Data Exfiltration & Covert Channel Transfers",
        "High-Entropy DGA & Dynamic DNS Telemetry",
        "Unencrypted Dangerous Executable/Script Downloads"
      ],
      checks: [
        "Deep packet inspection of Ethernet, IPv4, IPv6, TCP, UDP, and ICMP frames",
        "Application protocol dissection: HTTP, TLS/HTTPS, DNS, FTP, SSH, SMTP",
        "TLS Client Hello parsing for Server Name Indication (SNI) host extraction",
        "DNS question and answer decoding with DGA and suspicious TLD heuristics",
        "Cleartext credential scanner for HTTP basic auth and FTP USER/PASS commands",
        "Flow conversation aggregation with byte volumes, packet counts, and durations",
        "Transferred file payload extraction and dangerous extension verification"
      ],
      sanitizations: [
        "Anonymize internal IP subnet ranges and device MAC addresses",
        "Scrub cleartext passwords and authentication bearer tokens",
        "Strip dangerous executable payload transfers from PCAP packet data stream"
      ]
    },
    {
      id: "apk",
      category: "Android Mobile Apps & Dalvik Executables",
      icon: Smartphone,
      iconColor: "text-emerald-600 bg-emerald-50 border-emerald-200",
      extensions: [".apk", ".aab", ".xapk", ".dex"],
      description: "Android package archives and Dalvik executable bytecode evaluated for spyware, banking trojans, dangerous permission abuse, and component attack surfaces.",
      threats: [
        "Premium SMS & Banking 2FA OTP Interception",
        "Background Audio Surveillance & Camera Snooping",
        "Accessibility Service & Screen Overlay Abuse",
        "Exported Components & Unauthorized IPC Invocation",
        "Debuggable Keystore & Cleartext HTTP Vulnerabilities",
        "Dynamic Bytecode DEX Loading & Shell Spawning"
      ],
      checks: [
        "Pure-Python Android Binary XML (AXML) decoding of AndroidManifest.xml",
        "Dangerous permission matrix evaluation mapped to MITRE ATT&CK for Mobile",
        "Component attack surface auditing (Exported Activities, Services, Receivers, Providers)",
        "DEX Bytecode string pools, reflection, su/Runtime.exec, and SMS telephony APIs",
        "Cryptographic X.509 code signing certificate verification and debug keystore detection",
        "Native ELF library architecture cataloging (lib/arm64-v8a, armeabi-v7a, x86_64)",
        "Embedded secondary executable asset and payload extraction"
      ],
      sanitizations: [
        "Disarm active bytecode and compile forensic dossier into safe Vector PDF review report",
        "Strip dangerous permissions (SMS, Camera, Microphone, Overlay, Device Admin)",
        "Neutralize android:debuggable and cleartext HTTP flags",
        "Defang hardcoded C2 URLs and remote network telemetry endpoints"
      ]
    },
    {
      id: "java",
      category: "Java Files & JVM Bytecode",
      icon: Coffee,
      iconColor: "text-amber-600 bg-amber-50 border-amber-200",
      extensions: [".java", ".class", ".jar"],
      description: "Java source code (.java), compiled bytecode (.class), and Java archive (.jar/.war) packages audited for JVM exploitation vectors, Java Agents, and cross-platform RATs.",
      threats: [
        "Remote JNDI Directory Lookup (Log4Shell / RCE)",
        "Unmanaged Memory Manipulation (sun.misc.Unsafe)",
        "Java Instrumentation Agent In-Memory Hooks (Premain-Class)",
        "Insecure Object Deserialization (ysoserial gadget chains)",
        "Dynamic Class Loading (URLClassLoader / Method.invoke)",
        "Cross-Platform Java Remote Access Trojans (jRAT, Adwind)"
      ],
      checks: [
        "AST static security parsing of Java source files for shell execution and unmanaged memory",
        "Compiled .class binary Constant Pool inspection and dangerous method reference resolution",
        "Java version compatibility decoding from major/minor versions (Java 1.1 to Java 23)",
        "JAR manifest triage for standalone Main-Class, Premain Java Agent hooks, and all-permissions",
        "Contained bytecode scanning for OS shell execution (Runtime.exec, ProcessBuilder)",
        "Cataloging embedded native operating system libraries (.dll, .so, .dylib)",
        "Structural signature matching against known Java RAT malware families"
      ],
      sanitizations: [
        "Neutralize OS shell spawning and unmanaged memory pointers in source code",
        "Defang embedded URLs and network socket connections",
        "Enforce non-executable file permissions (0o644)",
        "Convert Java code and bytecode into static, non-executable Vector PDF dossier"
      ]
    }
  ];

  const filteredCategories = formatCategories.filter(cat => {
    const matchesCategory = activeCategory === 'all' || cat.id === activeCategory;
    const matchesSearch = searchTerm.trim() === '' || 
      cat.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cat.extensions.some(ext => ext.toLowerCase().includes(searchTerm.toLowerCase())) ||
      cat.checks.some(c => c.toLowerCase().includes(searchTerm.toLowerCase())) ||
      cat.threats.some(t => t.toLowerCase().includes(searchTerm.toLowerCase()));

    return matchesCategory && matchesSearch;
  });

  return (
    <div className="max-w-[80rem] mx-auto py-10 px-4 sm:px-6 lg:px-8 space-y-10">
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full text-xs font-mono text-slate-700 border border-slate-200">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>Complete Multi-Engine Format Inspection Matrix</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
          Supported Files & Security Checks
        </h1>
        <p className="text-base sm:text-lg text-slate-600 leading-relaxed">
          Explore the exact security indicators, active threats, and Content Disarm & Reconstruction 
          transformations applied to each file format.
        </p>
      </div>

      {/* Integrated Analysis Engines Bar */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 rounded-2xl p-6 text-white shadow-md">
        <div className="flex items-center gap-2 mb-3 text-xs font-bold uppercase tracking-wider text-blue-300">
          <Cpu className="w-4 h-4 text-blue-400" />
          <span>Integrated Security Engines & Threat Intelligence Services</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {analysisEngines.map((engine, idx) => (
            <div key={idx} className="bg-white/10 hover:bg-white/15 backdrop-blur-xs rounded-xl p-3 border border-white/10 transition-colors">
              <p className="text-xs font-bold text-white flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                {engine.name}
              </p>
              <p className="text-[11px] text-slate-300 mt-1 leading-snug">{engine.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          {/* Category Tabs */}
          <div className="flex flex-wrap gap-1.5 w-full sm:w-auto">
            <button
              onClick={() => setActiveCategory('all')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                activeCategory === 'all'
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              All Formats ({formatCategories.length})
            </button>
            {formatCategories.map(c => {
              const shortLabels: Record<string, string> = {
                email: 'Email',
                executables: 'Executables',
                office: 'Office',
                pdf: 'PDF',
                images: 'Images',
                archives: 'Archives',
                web: 'Web & SVG',
                data: 'Scripts & Data',
                extensions: 'Extensions',
                applescript: 'AppleScript',
                network: 'Domain/IP',
                evtx: 'EVTX Logs',
                lnk: 'LNK Shortcuts',
                pcap: 'PCAP Traces',
              };
              return (
                <button
                  key={c.id}
                  onClick={() => setActiveCategory(c.id)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                    activeCategory === c.id
                      ? 'bg-slate-900 text-white shadow-sm'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {shortLabels[c.id] || c.category.split(' ')[0]}
                </button>
              );
            })}
          </div>

          {/* Search Input */}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search checks, threats, ext..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
            />
          </div>
        </div>
      </div>

      {/* Format Cards */}
      <div className="space-y-6">
        {filteredCategories.length === 0 ? (
          <div className="text-center py-12 bg-white border border-slate-200 rounded-3xl p-8">
            <p className="text-sm text-slate-500">No formats match your search query "{searchTerm}".</p>
            <button
              onClick={() => { setActiveCategory('all'); setSearchTerm(''); }}
              className="mt-3 text-xs text-blue-600 font-semibold hover:underline cursor-pointer"
            >
              Reset filters
            </button>
          </div>
        ) : (
          filteredCategories.map((c) => {
            const Icon = c.icon;
            return (
              <div 
                key={c.id}
                className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-6 hover:border-slate-300 transition-all"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-5">
                  <div className="flex items-center gap-3">
                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center border shadow-xs ${c.iconColor}`}>
                      <Icon className="w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-slate-900">{c.category}</h3>
                      <p className="text-xs text-slate-500">{c.description}</p>
                    </div>
                  </div>

                  {/* Extension Badges */}
                  <div className="flex flex-wrap gap-1.5 items-center">
                    {c.extensions.map((ext) => (
                      <span 
                        key={ext}
                        className="px-2 py-0.5 bg-slate-100 text-slate-700 text-xs font-mono font-medium rounded-lg border border-slate-200"
                      >
                        {ext}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Mitigated Threats */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                    <span>Key Threat Vectors Disarmed</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {c.threats.map((threat, idx) => (
                      <span 
                        key={idx}
                        className="px-2.5 py-1 bg-amber-50/70 border border-amber-200/80 text-amber-800 text-xs font-medium rounded-full"
                      >
                        {threat}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Two Column Grid: Security Checks vs Sanitization Options */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
                  {/* Checks Column */}
                  <div className="bg-slate-50 border border-slate-100 rounded-2xl p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      <span>Security & Integrity Analysis ({c.checks.length})</span>
                    </div>
                    <ul className="space-y-2">
                      {c.checks.map((chk, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-xs text-slate-600 font-normal leading-relaxed">
                          <span className="text-emerald-500 font-bold mt-0.5">•</span>
                          <span>{chk}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Sanitization Column */}
                  <div className="bg-blue-50/40 border border-blue-100 rounded-2xl p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                      <Wrench className="w-4 h-4 text-blue-600" />
                      <span>Content Disarm & Reconstruction ({c.sanitizations.length})</span>
                    </div>
                    <ul className="space-y-2">
                      {c.sanitizations.map((san, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-xs text-slate-700 font-normal leading-relaxed">
                          <span className="text-blue-500 font-bold mt-0.5">•</span>
                          <span>{san}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* CTA Footer */}
      <div className="text-center pt-4">
        <button
          onClick={onGoToSanitizer}
          className="px-6 py-3 bg-slate-900 hover:bg-blue-600 text-white font-medium text-sm rounded-xl shadow-sm transition-all inline-flex items-center gap-2 cursor-pointer"
        >
          <span>Return to File Sanitizer</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
