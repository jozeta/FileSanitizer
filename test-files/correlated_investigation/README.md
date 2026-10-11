# Correlated Investigation Suite: "Operation CobaltShadow"

This directory contains **7 synchronized forensic artifacts** modeling an Advanced Persistent Threat (APT) multi-stage intrusion campaign titled **"Operation CobaltShadow"**. 

All 7 artifacts share exact **cryptographic hashes**, **microsecond timestamps**, **C2 IP addresses**, **domain infrastructure**, **internal hostnames**, and **compromised credentials**, designed specifically to showcase FileSanitizer's **Threat Graph**, **Multi-Host Swimlanes**, and **Forensic Super-Timeline**.

---

## Intrusion Storyline & Artifact Map

```mermaid
flowchart TD
    Email["01_phishing_email.msg<br/>(Invoice Phish from billing@invoicing-services.net)"]
    Doc["02_weaponized_document.docm<br/>(VBA AutoOpen Macro + WebClient Cradle)"]
    Implant["03_c2_implant_beacon.exe<br/>(SHA-256: b002241f... / MD5: 4ffdc2a3...)"]
    HostA["04_endpoint_workstation_hostA.evtx<br/>(WKSTN-FIN-01: 10.0.4.15 - User: jdoe)"]
    HostB["05_endpoint_domain_controller_hostB.evtx<br/>(DC-PROD-01: 10.0.4.50 - Lateral Movement)"]
    Network["06_network_traffic_capture.pcap<br/>(HTTP Payload Download, TLS C2, Exfiltration)"]
    Exfil["07_exfiltrated_archive.zip<br/>(SHA-256: 2f38219c... - Confidential Payroll Data)"]

    Email -->|Carved Attachment| Doc
    Doc -->|PowerShell Cradle Downloads| Implant
    Implant -->|Process Spawn & Sysmon Logs| HostA
    HostA -->|Network Traffic Recorded| Network
    HostA -->|LogonType 3 & SMB Lateral Movement| HostB
    HostA -->|7-Zip Staged Upload| Exfil
    Network -->|Carved POST Upload| Exfil
```

---

## Artifact Catalog & Shared Indicators

| Artifact | File Type | Key Indicators & Role in Scenario |
| :--- | :--- | :--- |
| `01_phishing_email.msg` | Outlook MSG | **Delivery Vector**: Phishing lure with subject *"Overdue Invoice #INV-2026-994"*. Transit headers identify hop `185.220.101.45` and carrying attachment `02_weaponized_document.docm`. |
| `02_weaponized_document.docm` | Word Macro | **Initial Access**: Macro executes `AutoOpen()`, spawning hidden PowerShell cradle connecting to `http://evil-payloads-delivery.org/beacon_updater.exe`. |
| `03_c2_implant_beacon.exe` | Windows PE | **C2 Implant**: Deterministic CobaltStrike beacon implant.<br/>• **SHA-256**: `b002241ff8da0fd372dc9736bf2e4be970fb89792d6df5fac28de3eaa5b4f982`<br/>• **MD5**: `4ffdc2a3c88a8396fdf1367eec6d2a8b` |
| `04_endpoint_workstation_hostA.evtx` | Windows Event Log | **Host A Telemetry** (`WKSTN-FIN-01`, `10.0.4.15`):<br/>• Sysmon Event 11: File creation of `beacon_updater.exe` (SHA-256 matching `b002241f...`).<br/>• Event 4688: Process tree `WINWORD.EXE` → `powershell.exe` → `beacon_updater.exe`.<br/>• Sysmon Event 3: Network beacon connection to `185.220.101.45:443`.<br/>• 7-Zip process creating exfiltration archive `financial_q3_confidential.zip`. |
| `05_endpoint_domain_controller_hostB.evtx` | Windows Event Log | **Host B Telemetry** (`DC-PROD-01`, `10.0.4.50`):<br/>• Event 4624 (LogonType 3 Network Logon) from source `10.0.4.15` as user `svc_admin`.<br/>• Event 4672: Special privilege escalation (`SeDebugPrivilege`).<br/>• Event 5140 & 5145: Administrative network share access (`\\DC-PROD-01\ADMIN$`).<br/>• Event 7045: Remote service creation `WindowsDefendUpdateSvc` executing `beacon_updater.exe` (SHA-256 matching `b002241f...`).<br/>• Event 1102: Audit log clearing anti-forensics attempt. |
| `06_network_traffic_capture.pcap` | Network PCAP | **Network Wire Traffic** (`10.0.4.0/24` subnet):<br/>• DNS query resolving `evil-payloads-delivery.org` to `185.220.101.45`.<br/>• HTTP GET `/beacon_updater.exe` delivering implant (SHA-256 matching `b002241f...`).<br/>• TLS encrypted C2 sessions to `185.220.101.45:443`.<br/>• SMB2 Tree Connect and Session Setup from `10.0.4.15` to `10.0.4.50`.<br/>• HTTP POST multipart upload of `financial_q3_confidential.zip` to `91.240.118.72:8080`. |
| `07_exfiltrated_archive.zip` | ZIP Archive | **Stolen Data**: Confidential employee payroll and domain credential dumps.<br/>• **SHA-256**: `2f38219c4605e94329c4b2dfd086b0af17e0c131b0d2edf30416d8d0ec3c2bf0`<br/>• **MD5**: `4c35089de860e4b79f9c3adbd5c1f41f` |

---

## Cross-Artifact Bindings & Indicators

```
Target Infrastructure:
├── Host A (Workstation):        10.0.4.15  (WKSTN-FIN-01.target.local)
├── Host B (Domain Controller):  10.0.4.50  (DC-PROD-01.target.local)
├── Default Gateway:             10.0.4.1   (00:50:56:EE:99:88)
└── Target User Accounts:        TARGET\jdoe (Victim), TARGET\svc_admin (Compromised Service)

Adversary Infrastructure:
├── C2 Delivery & Callback IP:   185.220.101.45:443
├── C2 Domain:                   evil-payloads-delivery.org, c2.evil-payloads-delivery.org
├── Reverse Shell Listener:      194.26.29.112:4444
├── Exfiltration Dropzone IP:    91.240.118.72:8080 (dropzone-secure-exfil.com)
└── Harvested Credentials:       TARGET\svc_admin / P@ssw0rd2026!Summer#

Deterministic Payload Hashes:
├── beacon_updater.exe:
│   ├── SHA-256: b002241ff8da0fd372dc9736bf2e4be970fb89792d6df5fac28de3eaa5b4f982
│   └── MD5:     4ffdc2a3c88a8396fdf1367eec6d2a8b
└── financial_q3_confidential.zip:
    ├── SHA-256: 2f38219c4605e94329c4b2dfd086b0af17e0c131b0d2edf30416d8d0ec3c2bf0
    └── MD5:     4c35089de860e4b79f9c3adbd5c1f41f
```

---

## FileSanitizer Multi-Artifact Correlation Demonstration

When these artifacts are analyzed together or viewed in the Fleet & Cross-File Correlation views:

1. **Multi-Host Swimlanes**:
   - The swimlanes automatically align Host A (`WKSTN-FIN-01`) and Host B (`DC-PROD-01`).
   - Observers can visually track the lateral pivot at `10:00:45Z` when `WKSTN-FIN-01` initiates an SMB network logon to `DC-PROD-01`, installs the remote service, and executes the second stage implant.

2. **Forensic Super-Timeline**:
   - Blends packet captures, endpoint Sysmon events, Windows Security audit trails, and email transit hops into a single, microsecond-accurate chronology spanning from initial phish arrival (`09:59:30Z`) through to data exfiltration and log wiping (`10:01:30Z`).

3. **Threat Graph & IOC Correlation Engine**:
   - Shared nodes for SHA-256 `b002241f...`, IP `185.220.101.45`, IP `10.0.4.15`, and user `svc_admin` visually tie all 7 files together into an interconnected attack cluster.
