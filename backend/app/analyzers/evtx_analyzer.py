"""
Forensic Windows Event Log (.EVTX and ZIP archive) Analyzer.
Dissects Windows Event Logs (.evtx) and ZIP archives containing event logs:
- Pure-Python binary EVTX chunk / record parsing with fallback
- Comprehensive Incident Response (IR) threat vector extraction:
  * Anti-Forensics (Event 1102/104 log clearing)
  * Ransomware & Storage Tampering (Shadow copy deletion, Defender disabled)
  * Privilege Escalation & Account Manipulation (4672, 4720, 4728, 4732)
  * Brute Force & Password Spraying (4625 bursts)
  * Process Creation & LOLBins (4688, Sysmon 1)
  * PowerShell Script Block Logging (4104)
  * Persistence via Services (7045) and Scheduled Tasks (4698)
  * Network Communications (Sysmon 3)
- Interactive Forensic Event Timeline with configurable Event IDs from Settings.
"""

import base64
import os
import re
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from collections import Counter

from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
from app.core.logging_config import logger
from app.core.settings_store import settings_store

# Sensitive & Monitored Event Catalog for Windows IR
EVENT_CATALOG = {
    1: {"name": "Sysmon Process Creation", "category": "Process Execution", "severity": "info", "description": "Sysmon detected new process execution with full command line, hashes, and parent process", "curated": False},
    2: {"name": "Sysmon File Creation Time Changed", "category": "Defense Evasion", "severity": "high", "description": "Sysmon detected timestomping on file creation time", "curated": False},
    3: {"name": "Sysmon Network Connection", "category": "Network Communication", "severity": "info", "description": "Sysmon logged outbound or inbound TCP/UDP network connection", "curated": False},
    4: {"name": "Sysmon Service State Change", "category": "System", "severity": "info", "description": "Sysmon service state change", "curated": False},
    5: {"name": "Sysmon Process Terminated", "category": "Process Execution", "severity": "info", "description": "Sysmon process terminated", "curated": False},
    6: {"name": "Sysmon Driver Loaded", "category": "Privilege Escalation", "severity": "high", "description": "Sysmon detected a kernel driver loaded into system space (potential rootkit)", "curated": False},
    7: {"name": "Sysmon Image Loaded", "category": "Process Execution", "severity": "info", "description": "Sysmon detected DLL image loaded into process memory (potential DLL hijacking)", "curated": False},
    8: {"name": "Sysmon CreateRemoteThread", "category": "Process Execution", "severity": "critical", "description": "Sysmon detected remote thread created in another process (Process Injection / Shellcode)", "curated": False},
    9: {"name": "Sysmon RawAccessRead", "category": "Credential Access", "severity": "high", "description": "Sysmon detected raw disk access (potential Volume Shadow Copy or NTDS.dit theft)", "curated": False},
    10: {"name": "Sysmon ProcessAccess", "category": "Credential Access", "severity": "critical", "description": "Sysmon detected process handle opened to another process (LSASS memory dump / Mimikatz)", "curated": False},
    11: {"name": "Sysmon File Created", "category": "File System", "severity": "info", "description": "Sysmon detected file creation on disk", "curated": False},
    12: {"name": "Sysmon Registry Object Created / Deleted", "category": "Persistence / Registry", "severity": "info", "description": "Sysmon detected creation or deletion of registry keys and objects", "curated": True},
    13: {"name": "Sysmon Registry Value Set", "category": "Persistence / Registry", "severity": "medium", "description": "Sysmon detected registry value modification (Run keys, services, persistence)", "curated": True},
    14: {"name": "Sysmon Registry Key / Value Renamed", "category": "Defense Evasion", "severity": "info", "description": "Sysmon detected renaming of registry keys or values", "curated": True},
    15: {"name": "Sysmon Alternate Data Stream Created", "category": "Defense Evasion", "severity": "medium", "description": "Sysmon detected file creation in Alternate Data Stream (ADS) with hash calculation (Zone.Identifier bypass)", "curated": True},
    16: {"name": "Sysmon Configuration Changed", "category": "Anti-Forensics", "severity": "medium", "description": "Sysmon filter configuration was modified or reloaded", "curated": True},
    17: {"name": "Sysmon Named Pipe Created", "category": "Lateral Movement", "severity": "medium", "description": "Sysmon detected creation of a named pipe (Cobalt Strike, PsExec, RPC lateral movement)", "curated": True},
    18: {"name": "Sysmon Named Pipe Connected", "category": "Lateral Movement", "severity": "info", "description": "Sysmon detected connection established to a named pipe", "curated": True},
    19: {"name": "Sysmon WmiEvent (Filter Activity)", "category": "Persistence / WMI", "severity": "high", "description": "Sysmon detected WMI event filter registration (WMI persistence)", "curated": True},
    20: {"name": "Sysmon WmiEvent (Consumer Activity)", "category": "Persistence / WMI", "severity": "high", "description": "Sysmon detected WMI event consumer registration (CommandLineEventConsumer persistence)", "curated": True},
    21: {"name": "Sysmon WmiEvent (FilterToConsumer Binding)", "category": "Persistence / WMI", "severity": "high", "description": "Sysmon detected WMI event consumer bound to filter (active WMI subscription)", "curated": True},
    22: {"name": "Sysmon DNS Query Logged", "category": "Network Communication", "severity": "info", "description": "Sysmon logged outbound DNS query name, result, and initiating process ID", "curated": True},
    23: {"name": "Sysmon File Delete Archived", "category": "Anti-Forensics", "severity": "medium", "description": "Sysmon detected file deletion and saved copy in Archive directory (ransomware / wiper tracking)", "curated": True},
    24: {"name": "Sysmon Clipboard Content Changed", "category": "Discovery / Reconnaissance", "severity": "info", "description": "Sysmon monitored clipboard modification and captured copied content/hashes", "curated": False},
    25: {"name": "Sysmon Process Tampering", "category": "Defense Evasion", "severity": "critical", "description": "Sysmon detected process tampering (Process Hollowing, Herpaderping, Doppelganging)", "curated": True},
    26: {"name": "Sysmon File Delete Detected", "category": "Anti-Forensics", "severity": "info", "description": "Sysmon logged file deletion event without archiving", "curated": False},
    27: {"name": "Sysmon Block Executable Creation", "category": "Execution Control", "severity": "high", "description": "Sysmon blocked writing of executable file binary to disk", "curated": True},
    28: {"name": "Sysmon Block File Shredding", "category": "Anti-Forensics", "severity": "high", "description": "Sysmon blocked shredding or wipe attempt on target file", "curated": True},
    29: {"name": "Sysmon Executable File Detected", "category": "Execution Control", "severity": "medium", "description": "Sysmon detected creation of executable binary on target filesystem", "curated": True},
    41: {"name": "Kernel-Power System Crash", "category": "System Lifecycle", "severity": "high", "description": "System rebooted without cleanly shutting down first (Kernel-Power crash)", "curated": False},
    42: {"name": "System Entering Sleep", "category": "System Lifecycle", "severity": "info", "description": "The computer is entering low-power sleep state", "curated": False},
    59: {"name": "BITS Transfer Job Created", "category": "Network / BITS", "severity": "medium", "description": "A BITS transfer job was created (potential background C2 downloader / LOLBin)", "curated": False},
    60: {"name": "BITS Transfer Context Modified", "category": "Network / BITS", "severity": "info", "description": "A BITS transfer job context or properties were modified", "curated": False},
    61: {"name": "BITS Transfer Job Completed", "category": "Network / BITS", "severity": "medium", "description": "A BITS transfer job completed downloading or uploading payload files", "curated": False},
    91: {"name": "WinRM Connection Received", "category": "Lateral Movement / WinRM", "severity": "info", "description": "WinRM service received an inbound remote management connection", "curated": False},
    100: {"name": "Task Scheduler Task Started", "category": "Persistence / Task", "severity": "info", "description": "Task Scheduler started an instance of a scheduled task", "curated": False},
    102: {"name": "Task Scheduler Task Failed", "category": "Persistence / Task", "severity": "medium", "description": "Task Scheduler failed to start scheduled task", "curated": False},
    104: {"name": "Log File Cleared", "category": "Anti-Forensics", "severity": "critical", "description": "The Windows System or Application event log file was cleared", "curated": False},
    106: {"name": "Scheduled Task Registered", "category": "Persistence / Task", "severity": "medium", "description": "Task Scheduler registered a new scheduled task", "curated": False},
    107: {"name": "Task Scheduler Task Triggered", "category": "Persistence / Task", "severity": "info", "description": "Task Scheduler triggered a scheduled task based on time or event trigger", "curated": False},
    110: {"name": "Task Scheduler Task Instance Launched", "category": "Persistence / Task", "severity": "info", "description": "Task Scheduler launched an action instance for a scheduled task", "curated": False},
    140: {"name": "Task Scheduler Task Updated", "category": "Persistence / Task", "severity": "medium", "description": "Task Scheduler updated the registration or settings of an existing task", "curated": False},
    141: {"name": "Task Scheduler Task Deleted", "category": "Persistence / Task", "severity": "medium", "description": "Task Scheduler deleted a scheduled task", "curated": False},
    161: {"name": "WinRM User Authenticated", "category": "Lateral Movement / WinRM", "severity": "high", "description": "User authenticated for remote WinRM / PowerShell Remoting session", "curated": False},
    168: {"name": "WinRM Remote Session Created", "category": "Lateral Movement / WinRM", "severity": "high", "description": "A remote WinRM management session / PowerShell shell was established", "curated": False},
    200: {"name": "Scheduled Task Executed", "category": "Task Execution", "severity": "info", "description": "Task Scheduler launched an action for a scheduled task", "curated": False},
    201: {"name": "Scheduled Task Completed", "category": "Task Execution", "severity": "info", "description": "Task Scheduler completed task action", "curated": False},
    307: {"name": "Document Printed", "category": "Print Spooler", "severity": "info", "description": "Print Spooler successfully printed a document", "curated": False},
    311: {"name": "Task Scheduler Action Executed", "category": "Persistence / Task", "severity": "info", "description": "Task Scheduler executed a custom process or handler action for a task", "curated": False},
    400: {"name": "PowerShell Engine Started", "category": "Script Execution", "severity": "info", "description": "PowerShell engine lifecycle started", "curated": False},
    403: {"name": "PowerShell Engine Stopped", "category": "Script Execution", "severity": "info", "description": "PowerShell engine has stopped execution", "curated": False},
    600: {"name": "PowerShell Provider Started", "category": "Script Execution", "severity": "info", "description": "PowerShell provider lifecycle started", "curated": False},
    800: {"name": "Print Driver Added", "category": "Print Spooler", "severity": "medium", "description": "Print Spooler added a printer driver", "curated": False},
    801: {"name": "Print Driver Updated", "category": "Print Spooler", "severity": "high", "description": "Print Spooler updated a printer driver (potential PrintNightmare exploit)", "curated": False},
    805: {"name": "Print Rendering Failure", "category": "Print Spooler", "severity": "info", "description": "Print Spooler rendering failure", "curated": False},
    808: {"name": "Print Driver Load Failed (PrintNightmare)", "category": "Print Spooler", "severity": "high", "description": "Print Spooler failed to load driver (potential PrintNightmare CVE-2021-34527 exploitation)", "curated": False},
    1000: {"name": "Defender Scan Started", "category": "Antivirus", "severity": "info", "description": "Microsoft Defender Antivirus scan started", "curated": False},
    1001: {"name": "System Crash / BugCheck (BSOD)", "category": "System Lifecycle", "severity": "high", "description": "Operating system crashed or encountered fatal BugCheck blue screen (potential kernel exploit)", "curated": False},
    1002: {"name": "Defender Scan Stopped", "category": "Antivirus", "severity": "info", "description": "Microsoft Defender Antivirus scan was stopped", "curated": False},
    1005: {"name": "Defender Action Failed", "category": "Antivirus", "severity": "high", "description": "Microsoft Defender failed to perform remediation action on detected malware", "curated": False},
    1006: {"name": "Defender Malware in Memory/File", "category": "Antivirus", "severity": "critical", "description": "Microsoft Defender detected active malware in memory or disk", "curated": False},
    1008: {"name": "Defender Signature Update Failed", "category": "Antivirus", "severity": "medium", "description": "Microsoft Defender failed to apply signature update", "curated": False},
    1033: {"name": "Application Installed", "category": "Software Installation", "severity": "info", "description": "Windows Installer completed software installation", "curated": False},
    1074: {"name": "System Shutdown/Restart Initiated", "category": "System Lifecycle", "severity": "info", "description": "A process or user initiated system shutdown or restart", "curated": False},
    1076: {"name": "Unexpected Shutdown Reason Supplied", "category": "System Lifecycle", "severity": "info", "description": "User supplied reason code for previous unexpected system shutdown/reboot", "curated": False},
    1100: {"name": "Event Logging Service Shutdown", "category": "Anti-Forensics", "severity": "critical", "description": "The Windows Event Logging Service was shut down", "curated": False},
    1102: {"name": "Audit Log Cleared", "category": "Anti-Forensics", "severity": "critical", "description": "The Windows Security audit log was cleared by an administrator or threat actor", "curated": False},
    1116: {"name": "Defender Malware Detected", "category": "Malware Detection", "severity": "critical", "description": "Microsoft Defender Antivirus detected active malware or suspicious threat", "curated": False},
    1117: {"name": "Defender Malware Action Taken", "category": "Malware Detection", "severity": "high", "description": "Microsoft Defender Antivirus took action to remediate or quarantine threat", "curated": False},
    1118: {"name": "Defender Quick Scan Completed", "category": "Malware Detection", "severity": "info", "description": "Microsoft Defender completed a scheduled quick scan", "curated": False},
    1119: {"name": "Defender Full Scan Completed", "category": "Malware Detection", "severity": "info", "description": "Microsoft Defender completed a scheduled full scan", "curated": False},
    1149: {"name": "RDP Authentication Succeeded", "category": "Remote Desktop", "severity": "medium", "description": "Remote Desktop Services: User authentication succeeded", "curated": False},
    2000: {"name": "Defender Signatures Updated", "category": "Antivirus", "severity": "info", "description": "Microsoft Defender virus signatures updated successfully", "curated": False},
    2001: {"name": "Defender Signature Update Failed", "category": "Antivirus", "severity": "medium", "description": "Microsoft Defender failed to update antivirus definitions", "curated": False},
    3006: {"name": "DNS Query Response Received", "category": "DNS / Network", "severity": "info", "description": "DNS Client received a DNS resolution response for a domain", "curated": False},
    3008: {"name": "DNS Query Timed Out", "category": "DNS / Network", "severity": "info", "description": "DNS query request timed out without receiving authoritative answer", "curated": False},
    3010: {"name": "DNS Query Failed", "category": "DNS / Network", "severity": "info", "description": "DNS query failed with error response code (NXDOMAIN / SERVFAIL)", "curated": False},
    3018: {"name": "DNS Query Sent to Name Server", "category": "DNS / Network", "severity": "info", "description": "DNS query request sent across network to configured resolver", "curated": False},
    3076: {"name": "WDAC Image Load Block Audited", "category": "Code Integrity / WDAC", "severity": "high", "description": "Code Integrity determined that a process tried to load an unsigned driver or binary (Audit mode)", "curated": False},
    3077: {"name": "WDAC Image Load Blocked", "category": "Code Integrity / WDAC", "severity": "critical", "description": "Code Integrity blocked an unsigned driver or binary from loading (Enforced)", "curated": False},
    3089: {"name": "WDAC Signature Verification Details", "category": "Code Integrity / WDAC", "severity": "info", "description": "Code Integrity verified image signature details during binary execution", "curated": False},
    4100: {"name": "PowerShell Script Block Error", "category": "PowerShell", "severity": "medium", "description": "PowerShell logged a script block execution failure or parser error", "curated": False},
    4103: {"name": "PowerShell Pipeline Execution", "category": "Script Execution", "severity": "info", "description": "PowerShell Module logging recorded command execution", "curated": False},
    4104: {"name": "PowerShell Script Block Execution", "category": "Script Execution", "severity": "medium", "description": "PowerShell Script Block Logging captured code execution blocks", "curated": False},
    4105: {"name": "PowerShell Pipeline Execution Started", "category": "PowerShell", "severity": "info", "description": "PowerShell started executing a command pipeline or script", "curated": False},
    4106: {"name": "PowerShell Pipeline Execution Completed", "category": "PowerShell", "severity": "info", "description": "PowerShell completed execution of command pipeline or script", "curated": False},
    4608: {"name": "Windows is Starting Up", "category": "System Lifecycle", "severity": "info", "description": "Local Security Authority (LSA) subsystem has initialized and Windows kernel is starting up", "curated": False},
    4609: {"name": "Windows is Shutting Down", "category": "System Lifecycle", "severity": "info", "description": "Local Security Authority (LSA) subsystem has initiated system shutdown sequence", "curated": False},
    4610: {"name": "Authentication Package Loaded", "category": "Logon / Authentication", "severity": "low", "description": "Local Security Authority loaded an authentication package into memory", "curated": False},
    4611: {"name": "Trusted Logon Process Registered", "category": "Logon / Authentication", "severity": "low", "description": "A trusted logon process registered with Local Security Authority", "curated": False},
    4612: {"name": "Internal Resources Allocated for Audit Messages", "category": "System", "severity": "info", "description": "Internal memory resources were allocated for queuing security audit messages", "curated": False},
    4614: {"name": "Notification Package Loaded", "category": "Logon / Authentication", "severity": "medium", "description": "Security Accounts Manager (SAM) loaded a password notification package (persistence vector)", "curated": True},
    4616: {"name": "System Time Changed", "category": "Anti-Forensics", "severity": "medium", "description": "System clock/time was modified (potential timestomping or event log manipulation)", "curated": True},
    4624: {"name": "Successful Logon", "category": "Logon / Authentication", "severity": "info", "description": "An account successfully logged on to the host", "curated": False},
    4625: {"name": "Failed Logon", "category": "Logon / Authentication", "severity": "medium", "description": "An account failed to log on (potential brute force or wrong credentials)", "curated": False},
    4627: {"name": "Group Membership Information", "category": "Logon / Authentication", "severity": "info", "description": "Detailed group membership and SID information populated during user logon", "curated": False},
    4634: {"name": "Account Logoff", "category": "Logon / Authentication", "severity": "info", "description": "An account was logged off", "curated": False},
    4647: {"name": "User-Initiated Logoff", "category": "Logon / Authentication", "severity": "info", "description": "User initiated logoff", "curated": False},
    4648: {"name": "Logon with Explicit Credentials", "category": "Logon / Authentication", "severity": "medium", "description": "A logon was attempted using explicit credentials (RunAs / secondary credentials)", "curated": False},
    4649: {"name": "Replay Attack Detected", "category": "Kerberos / Identity", "severity": "critical", "description": "Kerberos replay attack was detected by domain controller", "curated": False},
    4656: {"name": "Handle to Object Requested", "category": "Object Access", "severity": "info", "description": "A handle to an object was requested", "curated": False},
    4657: {"name": "Registry Value Modified", "category": "Object Access", "severity": "info", "description": "A registry value was modified", "curated": False},
    4658: {"name": "Handle to Object Closed", "category": "Object Access", "severity": "info", "description": "The handle to an object was closed", "curated": False},
    4659: {"name": "Object Handle Requested with Intent to Delete", "category": "Object Access", "severity": "low", "description": "Handle to an object was requested with intent to delete the file or registry entry", "curated": False},
    4660: {"name": "Object Deleted", "category": "Object Access", "severity": "info", "description": "An object was deleted", "curated": False},
    4661: {"name": "Handle to Object Requested (SAM/LSA)", "category": "Credential Access", "severity": "high", "description": "A handle was requested to an object (SAM database, LSA secrets, or domain object)", "curated": False},
    4662: {"name": "Operation Performed on AD Object", "category": "Active Directory", "severity": "info", "description": "An operation was performed on an Active Directory object (DCSync / DS-Replication-Get-Changes)", "curated": False},
    4663: {"name": "Object Access Attempt", "category": "File System", "severity": "info", "description": "An attempt was made to access a protected file system or registry object", "curated": False},
    4664: {"name": "Hard Link Creation Attempt", "category": "Object Access", "severity": "low", "description": "An attempt was made to create a filesystem hard link", "curated": False},
    4670: {"name": "Permissions on Object Changed", "category": "Object Access", "severity": "medium", "description": "Discretionary Access Control List (DACL) or security permissions on an object were changed", "curated": True},
    4672: {"name": "Special Privileges Assigned", "category": "Privilege Escalation", "severity": "high", "description": "Special administrative privileges assigned to new logon session (SeDebugPrivilege, etc.)", "curated": False},
    4673: {"name": "Sensitive Privilege Service Called", "category": "Privilege Escalation", "severity": "medium", "description": "A privileged service was called by a user process", "curated": False},
    4674: {"name": "Operation Attempted on Privileged Object", "category": "Privilege Escalation", "severity": "medium", "description": "An operation was attempted on a privileged object", "curated": False},
    4675: {"name": "SIDs Were Filtered", "category": "Logon / Authentication", "severity": "info", "description": "Security identifiers were filtered during forest trust authentication", "curated": False},
    4688: {"name": "Process Creation", "category": "Process Execution", "severity": "info", "description": "A new process has been created by parent process", "curated": False},
    4689: {"name": "Process Terminated", "category": "Process Execution", "severity": "info", "description": "A process has exited or was terminated", "curated": False},
    4690: {"name": "Handle Duplication Attempted", "category": "Object Access", "severity": "info", "description": "An attempt was made to duplicate a handle to an object", "curated": False},
    4691: {"name": "Indirect Object Access Requested", "category": "Object Access", "severity": "info", "description": "Indirect access to an object was requested", "curated": False},
    4697: {"name": "Service Installed in System", "category": "Persistence / Service", "severity": "high", "description": "A service was installed in the system", "curated": False},
    4698: {"name": "Scheduled Task Created", "category": "Persistence / Task", "severity": "high", "description": "A scheduled task was created on the system", "curated": False},
    4699: {"name": "Scheduled Task Deleted", "category": "Persistence / Task", "severity": "medium", "description": "A scheduled task was deleted", "curated": False},
    4700: {"name": "Scheduled Task Enabled", "category": "Persistence / Task", "severity": "info", "description": "A scheduled task was enabled", "curated": False},
    4701: {"name": "Scheduled Task Disabled", "category": "Persistence / Task", "severity": "medium", "description": "A scheduled task was disabled", "curated": False},
    4702: {"name": "Scheduled Task Updated", "category": "Persistence / Task", "severity": "medium", "description": "A scheduled task was updated", "curated": False},
    4703: {"name": "Token Right Adjusted", "category": "Privilege Escalation", "severity": "medium", "description": "Privilege rights on a user access token were enabled or disabled", "curated": True},
    4704: {"name": "User Right Assigned", "category": "Privilege Escalation", "severity": "high", "description": "A user right or security privilege was assigned to an account (e.g. SeDebugPrivilege)", "curated": False},
    4705: {"name": "User Right Removed", "category": "Privilege Escalation", "severity": "medium", "description": "A user right or security privilege was removed from an account", "curated": False},
    4706: {"name": "Trust Created to Domain", "category": "Active Directory", "severity": "high", "description": "A new domain trust relationship was established", "curated": False},
    4707: {"name": "Trust Removed from Domain", "category": "Active Directory", "severity": "medium", "description": "A domain trust relationship was removed", "curated": False},
    4713: {"name": "Kerberos Policy Changed", "category": "Active Directory", "severity": "high", "description": "Kerberos ticket expiration or encryption policy was modified", "curated": False},
    4714: {"name": "Encrypted Data Recovery Policy Changed", "category": "Policy & Auditing", "severity": "medium", "description": "Encrypted data recovery policy for BitLocker / EFS was changed", "curated": False},
    4715: {"name": "Audit Policy on Object Changed", "category": "Policy & Auditing", "severity": "low", "description": "SACL / audit policy on a specific object was modified", "curated": False},
    4716: {"name": "Trusted Domain Information Modified", "category": "Active Directory", "severity": "medium", "description": "Trusted domain configuration was modified", "curated": False},
    4717: {"name": "System Security Access Granted", "category": "Privilege Escalation", "severity": "high", "description": "System security access was granted to an account", "curated": False},
    4718: {"name": "System Security Access Removed", "category": "Privilege Escalation", "severity": "medium", "description": "System security access was revoked from an account", "curated": False},
    4719: {"name": "System Audit Policy Changed", "category": "Policy & Auditing", "severity": "high", "description": "System audit policy was altered (potential defense evasion to suppress logging)", "curated": False},
    4720: {"name": "User Account Created", "category": "Account Manipulation", "severity": "high", "description": "A user account was created on the system or domain", "curated": False},
    4722: {"name": "User Account Enabled", "category": "Account Manipulation", "severity": "medium", "description": "A user account was enabled", "curated": False},
    4723: {"name": "Password Change Attempt", "category": "Active Directory", "severity": "info", "description": "An attempt was made to change an account's password", "curated": False},
    4724: {"name": "Password Reset Attempt", "category": "Account Manipulation", "severity": "high", "description": "An attempt was made to reset an account's password", "curated": False},
    4725: {"name": "User Account Disabled", "category": "Active Directory", "severity": "medium", "description": "A user account was disabled in Active Directory / local system", "curated": False},
    4726: {"name": "User Account Deleted", "category": "Account Manipulation", "severity": "medium", "description": "A user account was deleted", "curated": False},
    4727: {"name": "Security-Enabled Global Group Created", "category": "Account Manipulation", "severity": "low", "description": "A new security-enabled global group was created in Active Directory / SAM", "curated": False},
    4728: {"name": "Member Added to Global Security Group", "category": "Privilege Escalation", "severity": "high", "description": "A member was added to a security-enabled global group (e.g. Domain Admins)", "curated": False},
    4729: {"name": "Member Removed from Global Group", "category": "Active Directory", "severity": "medium", "description": "A member was removed from a security-enabled global group", "curated": False},
    4730: {"name": "Security-Enabled Global Group Deleted", "category": "Account Manipulation", "severity": "low", "description": "A security-enabled global group was deleted", "curated": False},
    4731: {"name": "Security-Enabled Local Group Created", "category": "Account Manipulation", "severity": "low", "description": "A security-enabled local group was created", "curated": False},
    4732: {"name": "Member Added to Local Security Group", "category": "Privilege Escalation", "severity": "critical", "description": "A member was added to a security-enabled local group (e.g. Administrators)", "curated": False},
    4733: {"name": "Member Removed from Local Group", "category": "Active Directory", "severity": "medium", "description": "A member was removed from a security-enabled local group", "curated": False},
    4734: {"name": "Security-Enabled Local Group Deleted", "category": "Account Manipulation", "severity": "low", "description": "A security-enabled local group was deleted", "curated": False},
    4735: {"name": "Security-Enabled Local Group Changed", "category": "Account Manipulation", "severity": "low", "description": "Properties or name of a security-enabled local group were changed", "curated": False},
    4737: {"name": "Security-Enabled Global Group Changed", "category": "Account Manipulation", "severity": "low", "description": "Properties or name of a security-enabled global group were changed", "curated": False},
    4738: {"name": "User Account Modified", "category": "Account Manipulation", "severity": "medium", "description": "A user account was modified", "curated": False},
    4739: {"name": "Domain Policy Was Changed", "category": "Policy & Auditing", "severity": "high", "description": "Domain security policy (password length, lockout threshold, Kerberos) was changed", "curated": True},
    4740: {"name": "User Account Locked Out", "category": "Logon / Authentication", "severity": "medium", "description": "A user account was locked out after exceeding failed logon attempts (brute-force indicator)", "curated": True},
    4741: {"name": "Computer Account Created", "category": "Active Directory", "severity": "medium", "description": "A computer account was created in Active Directory", "curated": False},
    4742: {"name": "Computer Account Changed", "category": "Active Directory", "severity": "medium", "description": "A computer account was altered in Active Directory", "curated": False},
    4743: {"name": "Computer Account Deleted", "category": "Active Directory", "severity": "medium", "description": "A computer account was deleted from Active Directory", "curated": False},
    4744: {"name": "Local Group Created", "category": "Account Manipulation", "severity": "info", "description": "A local group was created on the system", "curated": False},
    4745: {"name": "Local Group Modified", "category": "Account Manipulation", "severity": "info", "description": "A local group was modified on the system", "curated": False},
    4746: {"name": "Local Group Deleted", "category": "Account Manipulation", "severity": "info", "description": "A local group was deleted from the system", "curated": False},
    4751: {"name": "Security-Disabled Global Group Created", "category": "Active Directory", "severity": "info", "description": "A distribution or security-disabled global group was created", "curated": False},
    4752: {"name": "Security-Disabled Global Group Modified", "category": "Active Directory", "severity": "info", "description": "A distribution or security-disabled global group was modified", "curated": False},
    4753: {"name": "Security-Disabled Global Group Deleted", "category": "Active Directory", "severity": "info", "description": "A distribution or security-disabled global group was deleted", "curated": False},
    4754: {"name": "Security-Enabled Universal Group Created", "category": "Account Manipulation", "severity": "low", "description": "A security-enabled universal group was created in AD", "curated": False},
    4755: {"name": "Universal Security Group Modified", "category": "Active Directory", "severity": "medium", "description": "A security-enabled universal group was modified", "curated": False},
    4756: {"name": "Member Added to Universal Security Group", "category": "Privilege Escalation", "severity": "high", "description": "A member was added to a security-enabled universal group (Enterprise Admins)", "curated": False},
    4757: {"name": "Member Removed from Universal Group", "category": "Active Directory", "severity": "medium", "description": "A member was removed from a security-enabled universal group", "curated": False},
    4758: {"name": "Security-Enabled Universal Group Deleted", "category": "Account Manipulation", "severity": "low", "description": "A security-enabled universal group was deleted from AD", "curated": False},
    4764: {"name": "Group Type Changed", "category": "Active Directory", "severity": "medium", "description": "A group's type was changed between security and distribution group", "curated": False},
    4765: {"name": "SID History Added to Account", "category": "Privilege Escalation", "severity": "critical", "description": "SID history was added to an account (Golden Ticket / persistence vector)", "curated": False},
    4766: {"name": "Attempt to Add SID History Failed", "category": "Privilege Escalation", "severity": "high", "description": "An attempt to add SID history to an account failed", "curated": False},
    4767: {"name": "User Account Unlocked", "category": "Account Manipulation", "severity": "info", "description": "A locked-out user account was unlocked by an administrator", "curated": False},
    4768: {"name": "Kerberos TGT Request", "category": "Kerberos / Identity", "severity": "info", "description": "A Kerberos authentication ticket (TGT) was requested", "curated": False},
    4769: {"name": "Kerberos Service Ticket", "category": "Kerberos / Identity", "severity": "medium", "description": "A Kerberos service ticket was requested (Kerberoasting vector)", "curated": False},
    4770: {"name": "Kerberos Ticket Renewed", "category": "Kerberos / Identity", "severity": "info", "description": "A Kerberos ticket-granting ticket (TGT) was renewed", "curated": False},
    4771: {"name": "Kerberos Pre-Authentication Failed", "category": "Kerberos / Identity", "severity": "medium", "description": "Kerberos pre-authentication failed (potential password spray or AS-REP roasting)", "curated": False},
    4772: {"name": "Kerberos Ticket Request Failed", "category": "Kerberos / Identity", "severity": "medium", "description": "A Kerberos authentication ticket request failed", "curated": False},
    4774: {"name": "Account Mapped for Logon", "category": "Logon / Authentication", "severity": "info", "description": "An account was mapped for logon authentication", "curated": False},
    4775: {"name": "Could Not Map Account for Logon", "category": "Logon / Authentication", "severity": "low", "description": "An account could not be mapped for logon authentication", "curated": False},
    4776: {"name": "NTLM Authentication Attempt", "category": "Logon / Authentication", "severity": "info", "description": "The domain controller validated account credentials via NTLM", "curated": False},
    4777: {"name": "Domain Controller Failed to Validate Credentials", "category": "Logon / Authentication", "severity": "medium", "description": "The domain controller failed to validate credentials for an account", "curated": False},
    4778: {"name": "RDP Session Reconnected", "category": "Remote Desktop", "severity": "info", "description": "An existing Remote Desktop Protocol session was reconnected", "curated": False},
    4779: {"name": "RDP Session Disconnected", "category": "Remote Desktop", "severity": "info", "description": "A Remote Desktop Protocol session was disconnected", "curated": False},
    4780: {"name": "ACL Set on Protected Admin Account (AdminSDHolder)", "category": "Privilege Escalation", "severity": "high", "description": "Access control list was updated on an administrative account by the AdminSDHolder background task", "curated": True},
    4781: {"name": "Account Name Changed", "category": "Account Manipulation", "severity": "medium", "description": "The name of a user or computer account was renamed", "curated": False},
    4782: {"name": "Password Hash of Account Accessed", "category": "Credential Access", "severity": "high", "description": "The password hash display API was invoked to access account secrets", "curated": True},
    4793: {"name": "Password Policy Checking API Called", "category": "Credential Access", "severity": "low", "description": "Password policy validation API was invoked", "curated": False},
    4794: {"name": "DSRM Administrator Password Set", "category": "Active Directory", "severity": "critical", "description": "An attempt was made to set the Directory Services Restore Mode administrator password", "curated": False},
    4797: {"name": "Query for Blank Password Accounts", "category": "Credential Access", "severity": "medium", "description": "An attempt was made to query accounts with blank passwords", "curated": True},
    4798: {"name": "Local Group Membership Enumerated", "category": "Discovery / Reconnaissance", "severity": "low", "description": "A user's local group membership was enumerated (Discovery / BloodHound)", "curated": False},
    4799: {"name": "Security-Enabled Group Enumerated", "category": "Discovery / Reconnaissance", "severity": "low", "description": "A security-enabled local group membership was enumerated (Reconnaissance)", "curated": False},
    4800: {"name": "Workstation Locked", "category": "Logon / Authentication", "severity": "info", "description": "The workstation screen was locked", "curated": False},
    4801: {"name": "Workstation Unlocked", "category": "Logon / Authentication", "severity": "info", "description": "The workstation screen was unlocked", "curated": False},
    4802: {"name": "Screen Saver Invoked", "category": "System", "severity": "info", "description": "The screen saver was invoked by the operating system", "curated": False},
    4803: {"name": "Screen Saver Dismissed", "category": "System", "severity": "info", "description": "The screen saver was dismissed by user interaction", "curated": False},
    4817: {"name": "Auditing Settings on Object Changed", "category": "Policy & Auditing", "severity": "low", "description": "Auditing settings on an Active Directory or filesystem object were changed", "curated": False},
    4820: {"name": "Kerberos TGT Denied Device Restriction", "category": "Kerberos / Identity", "severity": "low", "description": "Kerberos TGT denied because the device does not meet authentication policy restrictions", "curated": False},
    4825: {"name": "RDP Connection Denied by Policy", "category": "Remote Desktop", "severity": "medium", "description": "A Remote Desktop user access attempt was denied by system policy", "curated": False},
    4826: {"name": "Boot Configuration Data Loaded", "category": "System Lifecycle", "severity": "info", "description": "Boot Configuration Data (BCD) was loaded during operating system startup", "curated": False},
    4864: {"name": "Kerberos End-to-End Namespace Conflict", "category": "Kerberos / Identity", "severity": "low", "description": "Kerberos end-to-end forest trust detected namespace collision", "curated": False},
    4876: {"name": "Certificate Services Backup Started", "category": "Certificate Services", "severity": "info", "description": "Certificate Services backup started", "curated": False},
    4877: {"name": "Certificate Services Backup Completed", "category": "Certificate Services", "severity": "info", "description": "Certificate Services backup completed", "curated": False},
    4878: {"name": "Certificate Services Restore Started", "category": "Certificate Services", "severity": "info", "description": "Certificate Services restore started", "curated": False},
    4879: {"name": "Certificate Services Restore Completed", "category": "Certificate Services", "severity": "info", "description": "Certificate Services restore completed", "curated": False},
    4882: {"name": "Certificate Services Security Permissions Changed", "category": "Certificate Services", "severity": "high", "description": "Security permissions on the Certificate Authority (ADCS) were modified (ESC7 vulnerability)", "curated": True},
    4885: {"name": "Certificate Services Data Recovery Agent Changed", "category": "Certificate Services", "severity": "medium", "description": "ADCS data recovery agent certificate was replaced", "curated": False},
    4886: {"name": "Certificate Request Approved", "category": "Certificate Services", "severity": "info", "description": "Certificate Services approved a certificate request", "curated": False},
    4887: {"name": "Certificate Issued", "category": "Certificate Services", "severity": "info", "description": "Certificate Services issued a certificate (potential ADCS ESC1-ESC8 abuse)", "curated": False},
    4888: {"name": "Certificate Request Denied", "category": "Certificate Services", "severity": "info", "description": "Certificate Services denied a certificate request", "curated": False},
    4889: {"name": "Certificate Services Request Set to Pending", "category": "Certificate Services", "severity": "info", "description": "ADCS marked a certificate enrollment request as pending administrative approval", "curated": False},
    4890: {"name": "Certificate Services Settings Changed", "category": "Certificate Services", "severity": "low", "description": "Configuration manager settings for Active Directory Certificate Services were modified", "curated": False},
    4891: {"name": "Certificate Services Config Entry Changed", "category": "Certificate Services", "severity": "low", "description": "A registry configuration entry for Certificate Services was modified", "curated": False},
    4892: {"name": "Certificate Services Property Changed", "category": "Certificate Services", "severity": "low", "description": "A CA property or extension parameter was updated", "curated": False},
    4895: {"name": "CA Certificate Published to Active Directory", "category": "Certificate Services", "severity": "low", "description": "Certificate Services published a CA certificate to Active Directory Domain Services", "curated": False},
    4896: {"name": "Rows Deleted from CA Database", "category": "Anti-Forensics", "severity": "high", "description": "One or more certificate issuance or revocation rows were purged from CA database", "curated": True},
    4897: {"name": "Certificate Services Role Separation Enabled", "category": "Certificate Services", "severity": "low", "description": "Role separation security enforcement was enabled on the CA", "curated": False},
    4898: {"name": "Certificate Template Loaded", "category": "Certificate Services", "severity": "info", "description": "Certificate Services loaded an X.509 certificate template into memory", "curated": False},
    4902: {"name": "Per-User Audit Policy Table Created", "category": "Policy & Auditing", "severity": "low", "description": "A per-user security audit policy table was initialized", "curated": False},
    4904: {"name": "Security Event Source Registered", "category": "Policy & Auditing", "severity": "medium", "description": "An attempt was made to register a new security event source provider", "curated": False},
    4905: {"name": "Security Event Source Unregistered", "category": "Policy & Auditing", "severity": "medium", "description": "An attempt was made to unregister a security event source provider", "curated": False},
    4906: {"name": "CrashOnAuditFail Value Changed", "category": "Anti-Forensics", "severity": "high", "description": "CrashOnAuditFail registry key was modified (system halting on audit failure disabled)", "curated": True},
    4907: {"name": "Auditing Settings on Object Changed", "category": "Policy & Auditing", "severity": "low", "description": "Object audit SACL settings were modified", "curated": False},
    4908: {"name": "Special Groups Logon Table Modified", "category": "Privilege Escalation", "severity": "high", "description": "Special Groups logon tracking table was modified", "curated": True},
    4912: {"name": "Per-User Audit Policy Table Modified", "category": "Policy & Auditing", "severity": "medium", "description": "Per-user audit policy entries were modified", "curated": False},
    4928: {"name": "AD Replica Source Context Established", "category": "Active Directory", "severity": "low", "description": "Active Directory replica source naming context was established", "curated": False},
    4929: {"name": "AD Replica Source Context Removed", "category": "Active Directory", "severity": "low", "description": "Active Directory replica source naming context was removed", "curated": False},
    4930: {"name": "AD Replica Source Context Modified", "category": "Active Directory", "severity": "low", "description": "Active Directory replica source naming context was modified", "curated": False},
    4931: {"name": "AD Destination Context Modified", "category": "Active Directory", "severity": "low", "description": "Active Directory destination naming context was modified", "curated": False},
    4932: {"name": "AD Replication Sync Begun", "category": "Active Directory", "severity": "info", "description": "Active Directory naming context synchronization begun", "curated": False},
    4933: {"name": "AD Replication Sync Ended", "category": "Active Directory", "severity": "info", "description": "Active Directory naming context synchronization completed", "curated": False},
    4934: {"name": "AD Replica Object Attributes Replicated", "category": "Active Directory", "severity": "info", "description": "Attributes of an AD replica object were replicated across domain controllers", "curated": False},
    4935: {"name": "AD Replication Failure Begins", "category": "Active Directory", "severity": "medium", "description": "Active Directory replication failure condition started", "curated": False},
    4936: {"name": "AD Replication Failure Ends", "category": "Active Directory", "severity": "info", "description": "Active Directory replication failure condition resolved", "curated": False},
    4937: {"name": "Lingering Object Removed from Replica", "category": "Active Directory", "severity": "low", "description": "A lingering tombstone object was removed from an Active Directory replica", "curated": False},
    4944: {"name": "Firewall Rule Active on Startup", "category": "Firewall / WFP", "severity": "info", "description": "A Windows Firewall rule was active when the Windows Firewall service started", "curated": False},
    4945: {"name": "Rule Listed on Firewall Startup", "category": "Firewall / WFP", "severity": "info", "description": "A rule was listed when Windows Firewall started", "curated": False},
    4946: {"name": "Rule Added to Firewall Exception List", "category": "Firewall / WFP", "severity": "medium", "description": "A new port/application rule was added to the Windows Firewall exception list", "curated": True},
    4947: {"name": "Rule Modified in Firewall Exception List", "category": "Firewall / WFP", "severity": "medium", "description": "A rule in the Windows Firewall exception list was modified", "curated": True},
    4948: {"name": "Rule Deleted from Firewall Exception List", "category": "Firewall / WFP", "severity": "medium", "description": "A rule was removed from the Windows Firewall exception list", "curated": True},
    4950: {"name": "Windows Firewall Setting Changed", "category": "Firewall / WFP", "severity": "medium", "description": "A global Windows Firewall setting (state, inbound/outbound action) was modified", "curated": True},
    4951: {"name": "Firewall Rule Ignored (Version Conflict)", "category": "Firewall / WFP", "severity": "low", "description": "Windows Firewall rule ignored due to unrecognized major version", "curated": False},
    4952: {"name": "Firewall Rule Minor Version Ignored", "category": "Firewall / WFP", "severity": "low", "description": "Parts of firewall rule ignored due to unrecognized minor version", "curated": False},
    4953: {"name": "Firewall Rule Parse Error", "category": "Firewall / WFP", "severity": "low", "description": "Firewall rule ignored because it could not be parsed", "curated": False},
    4954: {"name": "Firewall Group Policy Restored", "category": "Firewall / WFP", "severity": "info", "description": "Windows Firewall Group Policy settings were restored", "curated": False},
    4956: {"name": "Active Firewall Profile Changed", "category": "Firewall / WFP", "severity": "medium", "description": "Active Windows Firewall profile switched (Domain, Private, or Public profile)", "curated": True},
    4957: {"name": "Firewall Rule Not Applied", "category": "Firewall / WFP", "severity": "low", "description": "Windows Firewall did not apply rule", "curated": False},
    4958: {"name": "Firewall Rule Not Applied (Unconfigured)", "category": "Firewall / WFP", "severity": "low", "description": "Windows Firewall did not apply rule because item is not configured", "curated": False},
    4964: {"name": "Special Group Assigned to Logon", "category": "Privilege Escalation", "severity": "high", "description": "A special administrative group was assigned to a new logon session", "curated": False},
    5000: {"name": "Defender Real-Time Enabled", "category": "Antivirus", "severity": "info", "description": "Microsoft Defender Antivirus real-time protection was enabled", "curated": False},
    5001: {"name": "Defender Real-Time Protection Disabled", "category": "Defense Evasion", "severity": "critical", "description": "Microsoft Defender Antivirus real-time protection was disabled", "curated": False},
    5004: {"name": "Defender Configuration Changed", "category": "Defense Evasion", "severity": "high", "description": "Microsoft Defender Antivirus configuration settings were modified", "curated": False},
    5007: {"name": "Defender Configuration Tampered", "category": "Defense Evasion", "severity": "critical", "description": "Microsoft Defender Antivirus configuration was tampered with or modified", "curated": False},
    5024: {"name": "Windows Firewall Service Started", "category": "Policy & Firewall", "severity": "info", "description": "The Windows Firewall service has started successfully", "curated": False},
    5025: {"name": "Windows Firewall Service Stopped", "category": "Policy & Firewall", "severity": "high", "description": "The Windows Firewall service has been stopped", "curated": False},
    5031: {"name": "Windows Firewall Blocked Application", "category": "Policy & Firewall", "severity": "medium", "description": "Windows Firewall blocked an application from accepting incoming network traffic", "curated": False},
    5038: {"name": "Code Integrity Hash Invalid", "category": "Defense Evasion", "severity": "high", "description": "Code integrity determined that the image hash of a file is not valid (unsigned or tampered binary)", "curated": True},
    5058: {"name": "Key File Operation", "category": "Cryptographic Services", "severity": "info", "description": "Cryptographic service provider performed an operation on a key file", "curated": False},
    5059: {"name": "Key Migration Operation", "category": "Cryptographic Services", "severity": "info", "description": "Cryptographic key migration operation was performed", "curated": False},
    5061: {"name": "Cryptographic Operation", "category": "Cryptographic Services", "severity": "info", "description": "A cryptographic operation (key generation, signature, encryption) was logged", "curated": False},
    5136: {"name": "Directory Service Object Modified", "category": "Active Directory", "severity": "medium", "description": "A directory service object (user, computer, GPO, ACL) was modified in Active Directory", "curated": True},
    5137: {"name": "Directory Service Object Created", "category": "Active Directory", "severity": "low", "description": "A directory service object was created in Active Directory", "curated": False},
    5138: {"name": "Directory Service Object Undeleted", "category": "Active Directory", "severity": "low", "description": "A directory service object was restored/undeleted from the AD Recycle Bin", "curated": False},
    5139: {"name": "Directory Service Object Moved", "category": "Active Directory", "severity": "low", "description": "A directory service object was moved to another organizational unit (OU)", "curated": False},
    5140: {"name": "Network Share Object Accessed", "category": "Lateral Movement", "severity": "low", "description": "A network share object was accessed (SMB lateral movement connection)", "curated": False},
    5141: {"name": "Directory Service Object Deleted", "category": "Active Directory", "severity": "medium", "description": "A directory service object was deleted from Active Directory", "curated": False},
    5142: {"name": "Network Share Added", "category": "Lateral Movement", "severity": "high", "description": "A new network share object was added to the host", "curated": False},
    5143: {"name": "Network Share Modified", "category": "Lateral Movement / Shares", "severity": "medium", "description": "A network share configuration or security descriptor was modified", "curated": False},
    5144: {"name": "Network Share Deleted", "category": "Lateral Movement", "severity": "medium", "description": "A network share object was deleted from the host", "curated": False},
    5145: {"name": "Network Share Detailed Access Check", "category": "Lateral Movement", "severity": "medium", "description": "A network share was checked to see whether client has desired access rights (SMB file copying/staging)", "curated": False},
    5156: {"name": "Firewall Connection Allowed", "category": "Network Communication", "severity": "info", "description": "The Windows Filtering Platform permitted an inbound or outbound network connection", "curated": False},
    5158: {"name": "WFP Bind to Local Port", "category": "Network Communication", "severity": "info", "description": "The Windows Filtering Platform permitted binding to a local port", "curated": False},
    5376: {"name": "Credential Manager Credentials Backed Up", "category": "Credential Access", "severity": "medium", "description": "Credentials stored in Windows Credential Manager were backed up", "curated": True},
    5377: {"name": "Credential Manager Credentials Restored", "category": "Credential Access", "severity": "medium", "description": "Credentials in Windows Credential Manager were restored from backup", "curated": False},
    5378: {"name": "Requested Credentials Read from Credential Manager", "category": "Credential Access", "severity": "medium", "description": "Stored credentials were read from Windows Credential Manager", "curated": True},
    5379: {"name": "Credential Manager Read", "category": "Credential Access", "severity": "medium", "description": "Credentials were read from Windows Credential Manager", "curated": False},
    5440: {"name": "WFP Callout Present on Startup", "category": "Firewall / WFP", "severity": "info", "description": "A Windows Filtering Platform callout driver was present when Base Filtering Engine started", "curated": False},
    5447: {"name": "WFP Filter Changed", "category": "Policy & Firewall", "severity": "info", "description": "A Windows Filtering Platform (WFP) network packet filter was changed", "curated": False},
    6005: {"name": "Event Log Service Started (System Boot)", "category": "System Lifecycle", "severity": "info", "description": "The Windows Event Log service was started (host booted up)", "curated": False},
    6006: {"name": "Event Log Service Stopped (Clean Shutdown)", "category": "System Lifecycle", "severity": "info", "description": "The Windows Event Log service was stopped (clean host shutdown)", "curated": False},
    6008: {"name": "Unexpected System Shutdown", "category": "System Lifecycle", "severity": "high", "description": "The previous system shutdown was unexpected (crash, blue screen, power loss)", "curated": False},
    6009: {"name": "Operating System Version at Boot", "category": "System Lifecycle", "severity": "info", "description": "Windows kernel build, version, and architecture detected during operating system boot", "curated": False},
    6013: {"name": "System Uptime", "category": "System Lifecycle", "severity": "info", "description": "System uptime reported in seconds", "curated": False},
    6272: {"name": "Network Policy Server Granted Access", "category": "RADIUS / Network", "severity": "info", "description": "Network Policy Server (NPS) granted full network access to client", "curated": False},
    6273: {"name": "Network Policy Server Denied Access", "category": "RADIUS / Network", "severity": "medium", "description": "Network Policy Server (NPS) denied network access to client (failed 802.1X/VPN auth)", "curated": True},
    6274: {"name": "Network Policy Server Discarded Request", "category": "RADIUS / Network", "severity": "low", "description": "NPS discarded authentication request", "curated": False},
    6278: {"name": "Network Policy Server Full Access Granted", "category": "RADIUS / Network", "severity": "info", "description": "Network Policy Server granted full access to client without quarantine restrictions", "curated": False},
    6416: {"name": "New External Device Recognized", "category": "USB / Device Control", "severity": "medium", "description": "A new external device (USB flash drive, external disk, peripheral) was recognized by system", "curated": True},
    6419: {"name": "Device Disabling Request Made", "category": "USB / Device Control", "severity": "low", "description": "A request was made to disable a Plug and Play hardware device", "curated": False},
    6420: {"name": "Device Was Disabled", "category": "USB / Device Control", "severity": "low", "description": "A Plug and Play hardware device was disabled", "curated": False},
    6421: {"name": "Device Enabling Request Made", "category": "USB / Device Control", "severity": "low", "description": "A request was made to enable a Plug and Play hardware device", "curated": False},
    6422: {"name": "Device Was Enabled", "category": "USB / Device Control", "severity": "low", "description": "A Plug and Play hardware device was enabled", "curated": False},
    6423: {"name": "Device Installation Forbidden by Policy", "category": "USB / Device Control", "severity": "medium", "description": "Installation of external device was blocked by system group policy", "curated": True},
    6424: {"name": "Device Installation Permitted by Policy", "category": "USB / Device Control", "severity": "low", "description": "Installation of device was permitted after prior policy exclusion", "curated": False},
    7000: {"name": "Service Failed to Start", "category": "Services", "severity": "medium", "description": "Service Control Manager failed to start a service", "curated": False},
    7001: {"name": "Service Logon Failure", "category": "Services", "severity": "medium", "description": "Service failed to log on due to logon failure (bad account credentials)", "curated": True},
    7009: {"name": "Service Timeout During Connect", "category": "Services", "severity": "low", "description": "Service Control Manager timed out waiting for service to connect", "curated": False},
    7022: {"name": "Service Hung on Starting", "category": "Services", "severity": "medium", "description": "A service hung during startup initialization", "curated": False},
    7023: {"name": "Service Terminated with Error", "category": "Services", "severity": "medium", "description": "A service terminated with a fatal win32 error", "curated": False},
    7024: {"name": "Service Terminated with Service-Specific Error", "category": "Services", "severity": "medium", "description": "A service terminated with a service-specific exit code", "curated": False},
    7026: {"name": "Boot-Start Driver Failed to Load", "category": "Services / Drivers", "severity": "medium", "description": "One or more boot-start or system-start drivers failed to load", "curated": False},
    7030: {"name": "Service Marked as Interactive", "category": "Services", "severity": "low", "description": "A service was configured to interact with the desktop", "curated": False},
    7031: {"name": "Service Crashed Unexpectedly", "category": "Services", "severity": "medium", "description": "A service terminated unexpectedly and SCM executed failure actions", "curated": True},
    7032: {"name": "SCM Took Recovery Action", "category": "Services", "severity": "medium", "description": "Service Control Manager took recovery action after service failure", "curated": False},
    7034: {"name": "Service Terminated Unexpectedly", "category": "Services", "severity": "medium", "description": "A service terminated unexpectedly (crash, kill, or malicious evasion)", "curated": True},
    7036: {"name": "Service State Changed", "category": "System", "severity": "info", "description": "A Windows service transitioned to stopped or running state", "curated": False},
    7040: {"name": "Service Start Type Changed", "category": "Persistence / Service", "severity": "medium", "description": "A Windows service start type was modified (e.g. disabled to manual/automatic)", "curated": False},
    7045: {"name": "New Service Installed", "category": "Persistence / Service", "severity": "high", "description": "A new Windows service was installed in the system", "curated": False},
    8001: {"name": "AppLocker Policy Applied", "category": "AppLocker / Execution Control", "severity": "info", "description": "AppLocker policy was applied successfully to the computer", "curated": False},
    8002: {"name": "AppLocker Executable Allowed", "category": "AppLocker / Execution Control", "severity": "info", "description": "AppLocker policy allowed binary executable (.exe, .dll) to run", "curated": False},
    8003: {"name": "AppLocker Executable Audited (Would Block)", "category": "AppLocker / Execution Control", "severity": "high", "description": "AppLocker policy audited executable that would be blocked in enforce mode", "curated": False},
    8004: {"name": "AppLocker Executable Prevented", "category": "AppLocker / Execution Control", "severity": "critical", "description": "AppLocker policy blocked unauthorized binary executable from running", "curated": False},
    8005: {"name": "AppLocker Script or MSI Allowed", "category": "AppLocker / Execution Control", "severity": "info", "description": "AppLocker policy allowed script (.ps1, .vbs, .bat) or MSI installer", "curated": False},
    8006: {"name": "AppLocker Script Audited (Would Block)", "category": "AppLocker / Execution Control", "severity": "high", "description": "AppLocker policy audited script or installer that would be blocked in enforce mode", "curated": False},
    8007: {"name": "AppLocker Script or MSI Prevented", "category": "AppLocker / Execution Control", "severity": "critical", "description": "AppLocker blocked unauthorized script or MSI installer from executing", "curated": False},
    11707: {"name": "Application Installed Successfully", "category": "Software Installation", "severity": "info", "description": "Windows Installer installed an application successfully", "curated": False},
    20001: {"name": "Device Driver Install Started", "category": "System / Drivers", "severity": "info", "description": "Device driver installation process started", "curated": False},
    20003: {"name": "Device Driver Install Completed", "category": "System / Drivers", "severity": "info", "description": "Device driver installation completed successfully", "curated": False},
}

LOLBINS_LIST = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "cscript.exe", "wscript.exe", "wmic.exe",
    "schtasks.exe", "vssadmin.exe", "bcdedit.exe", "wbadmin.exe", "net.exe", "net1.exe",
    "whoami.exe", "nltest.exe", "klist.exe", "tasklist.exe", "sc.exe"
]

RANSOMWARE_CMD_PATTERNS = [
    r"(?i)\bvssadmin(\.exe)?\s+delete\s+shadows",
    r"(?i)\bwmic(\.exe)?\s+shadowcopy\s+delete",
    r"(?i)\bwbadmin(\.exe)?\s+delete\s+catalog",
    r"(?i)\bbcdedit(\.exe)?\s+.*?bootstatuspolicy\s+ignoreallfailures",
    r"(?i)\bbcdedit(\.exe)?\s+.*?recoveryenabled\s+no",
    r"(?i)\bwbadmin(\.exe)?\s+delete\s+systemstatebackup",
]

# Pre-compiled high-performance regex patterns for XML parsing (800x faster than ElementTree on large EVTX)
RE_EVENT_ID = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
RE_TIME = re.compile(r'SystemTime=[\'"]([^\'"]+)[\'"]')
RE_COMPUTER = re.compile(r'<Computer>([^<]+)</Computer>')
RE_CHANNEL = re.compile(r'<Channel>([^<]+)</Channel>')
RE_LEVEL = re.compile(r'<Level>(\d+)</Level>')
RE_DATA = re.compile(r'<Data(?:\s+Name=[\'"]([^\'"]+)[\'"])?>([^<]*)</Data>')


def decode_powershell_command(cmd_str: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Detects PowerShell encoded commands (-enc, -encodedcommand, -e, -ec, /enc, etc.)
    or FromBase64String payloads and decodes them into readable UTF-16LE / UTF-8 plain text.
    """
    if not cmd_str or len(cmd_str) < 10:
        return None

    patterns = [
        r'(?i)(?:-|\/)(?:enc(?:odedcommand)?|e(?:c)?)\s+["\']?([A-Za-z0-9+/=]{10,})["\']?',
        r'(?i)(?:FromBase64String|frombase64string)\s*\(\s*["\']([A-Za-z0-9+/=]{10,})["\']\s*\)',
        r'(?i)(?:-encodedcommand)\s+([A-Za-z0-9+/=]{10,})',
    ]

    for pat in patterns:
        m = re.search(pat, cmd_str)
        if m:
            b64_candidate = m.group(1).strip()
            pad_len = len(b64_candidate) % 4
            if pad_len != 0:
                b64_candidate += '=' * (4 - pad_len)
            try:
                raw_bytes = base64.b64decode(b64_candidate)
                decoded_text = ""
                # PowerShell EncodedCommand is standard Windows Unicode (UTF-16LE)
                try:
                    decoded_text = raw_bytes.decode('utf-16le')
                except Exception:
                    try:
                        decoded_text = raw_bytes.decode('utf-8')
                    except Exception:
                        decoded_text = raw_bytes.decode('latin-1', errors='replace')

                clean_text = "".join(ch for ch in decoded_text if ch.isprintable() or ch in '\r\n\t ')
                if len(clean_text) >= 3 and len(clean_text) >= len(decoded_text) * 0.6:
                    lowered = clean_text.lower()
                    indicators = []
                    for kw in [
                        "downloadstring", "downloadfile", "invoke-expression", "iex",
                        "amsiutils", "bypass", "webclient", "bitstransfer", "virtualalloc",
                        "rundll32", "net.webclient", "start-process", "hidden",
                        "noninteractive", "mimikatz", "invoke-mimikatz", "sharphound",
                        "invoke-webrequest", "iwr", "scriptblock", "system.net"
                    ]:
                        if kw in lowered:
                            indicators.append(kw)
                    return {
                        "raw_encoded": m.group(1),
                        "decoded": clean_text.strip(),
                        "indicators": indicators,
                        "tokens_found": indicators,
                        "suspicious_tokens": indicators,
                        "is_suspicious": len(indicators) > 0 or any(bad in lowered for bad in ["http://", "https://", "ftp://", ".exe", ".dll", ".ps1"])
                    }
            except Exception:
                continue
    return None


def deobfuscate_command(cmd_str: Optional[str]) -> Dict[str, Any]:
    """
    Automatic normalization of cmd.exe and PowerShell obfuscation techniques (Eventlog Item 6):
    - Caret escaping: c^m^d^.^e^x^e -> cmd.exe
    - Backtick insertion: I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n -> Invoke-Expression
    - String concatenation: ('down'+'load'+'string') -> ('downloadstring')
    - Environment variable slicing / expansion (%COMSPEC:~0,1%)
    - Recursive Base64 decoding (-enc, -encodedcommand, FromBase64String)
    - Security keyword tagging (IEX, DownloadString, Mimikatz, AMSI bypass, etc.)
    """
    if not cmd_str:
        return {
            "raw_command": "",
            "deobfuscated_command": "",
            "is_obfuscated": False,
            "obfuscation_types": [],
            "flagged_tokens": [],
            "steps": []
        }

    current = cmd_str
    types: List[str] = []
    steps: List[Dict[str, Any]] = []

    # 1. Caret stripping (cmd.exe escape character)
    if "^" in current and not current.startswith("^"):
        cleaned_caret = current.replace("^", "")
        if cleaned_caret != current:
            types.append("Caret Escaping (^)")
            current = cleaned_caret
            steps.append({"step": len(steps) + 1, "type": "Caret Stripping (^)", "output": current})

    # 2. Backtick removal (PowerShell escape character)
    if "`" in current:
        cleaned_tick = current.replace("`", "")
        if cleaned_tick != current:
            types.append("PowerShell Backticks (`)")
            current = cleaned_tick
            steps.append({"step": len(steps) + 1, "type": "Backtick Removal (`)", "output": current})

    # 3. String concatenation merging ('a' + 'b' -> 'ab')
    if "+" in current:
        c_sub = re.sub(r"(['\"])\s*\+\s*\1", "", current)
        if c_sub != current:
            types.append("String Concatenation (+)")
            current = c_sub
            steps.append({"step": len(steps) + 1, "type": "String Concatenation Merging", "output": current})

    # 4. Environment variable slice replacement (%COMSPEC:~0,1% etc.)
    comspec_m = re.findall(r'%[A-Za-z0-9_]+:[~0-9,]+%', current)
    if comspec_m:
        types.append("Environment Variable Slicing")
        for cm in comspec_m:
            if "COMSPEC" in cm.upper():
                current = current.replace(cm, "c")
            elif "PATH" in cm.upper():
                current = current.replace(cm, "")
        steps.append({"step": len(steps) + 1, "type": "Environment Variable Normalization", "output": current})

    # 5. Base64 Encoded Command Decoding
    ps_dec = decode_powershell_command(cmd_str)
    if ps_dec and ps_dec.get("decoded"):
        types.append("Base64 Encoded Payload")
        dec_body = ps_dec["decoded"]
        current = f"{current} [DECODED_B64: {dec_body}]"
        steps.append({"step": len(steps) + 1, "type": "Base64 Decoding", "output": dec_body})

    # Flagged Security Tokens
    SUSPICIOUS_KEYWORDS = [
        "downloadstring", "downloadfile", "invoke-expression", "iex",
        "amsiutils", "bypass", "webclient", "bitstransfer", "virtualalloc",
        "rundll32", "net.webclient", "start-process", "hidden",
        "noninteractive", "mimikatz", "invoke-mimikatz", "sharphound",
        "invoke-webrequest", "iwr", "scriptblock", "system.net",
        "vssadmin", "delete shadows", "wmic", "schtasks", "reg add",
        "net user", "whoami", "certutil", "urlcache", "powershell"
    ]
    low = current.lower()
    flagged = [kw for kw in SUSPICIOUS_KEYWORDS if kw in low]

    return {
        "raw_command": cmd_str,
        "deobfuscated_command": current,
        "is_obfuscated": len(types) > 0,
        "obfuscation_types": types,
        "flagged_tokens": flagged,
        "steps": steps
    }


def compile_template(template_node):
    """
    Compiles an EVTX TemplateNode AST once into a flat sequence of static string chunks
    and substitution slot indices. Reduces record rendering time by ~2000%.
    """
    import Evtx.Nodes as e_nodes
    from Evtx.Views import validate_name, escape_value

    parts: List[Tuple[bool, Any]] = []

    def rec(node):
        if isinstance(node, e_nodes.OpenStartElementNode):
            parts.append((False, '<' + node.tag_name()))
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    parts.append((False, ' ' + validate_name(child.attribute_name().string()) + '="'))
                    rec(child.attribute_value())
                    parts.append((False, '"'))
            parts.append((False, '>'))
            for child in node.children():
                rec(child)
            parts.append((False, '</' + validate_name(node.tag_name()) + '>\n'))
        elif isinstance(node, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
            parts.append((True, node.index()))
        elif isinstance(node, e_nodes.ValueNode):
            parts.append((False, escape_value(node.children()[0].string())))
        elif isinstance(node, e_nodes.CDataSectionNode):
            parts.append((False, '<![CDATA[' + escape_value(node.cdata()) + ']]>'))
        elif isinstance(node, e_nodes.EntityReferenceNode):
            parts.append((False, escape_value(node.entity_reference())))
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            parts.append((False, escape_value(node.processing_instruction_target())))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            parts.append((False, escape_value(node.string())))

    for c in template_node.children():
        rec(c)
    return parts


def fast_render_record(root_node, template_cache: Dict[Any, Any]) -> str:
    """
    Renders an Evtx.Record into XML in microseconds using pre-compiled template ASTs.
    """
    import Evtx.Nodes as e_nodes
    from Evtx.Views import escape_value, render_root_node

    try:
        tmpl = root_node.template()
        tmpl_key = (tmpl.offset(), tmpl.length())
        if tmpl_key not in template_cache:
            template_cache[tmpl_key] = compile_template(tmpl)
        compiled = template_cache[tmpl_key]

        subs = list(root_node.substitutions())
        parts: List[str] = []
        for is_sub, val in compiled:
            if not is_sub:
                parts.append(val)
            else:
                if val < len(subs):
                    s = subs[val]
                    if isinstance(s, e_nodes.BXmlTypeNode):
                        parts.append(render_root_node(s.root()))
                    else:
                        parts.append(escape_value(s.string()))
        return "".join(parts)
    except Exception:
        return ""


class EvtxAnalyzer(BaseAnalyzer):
    """Deep inspection of Windows XML Event Logs (.evtx) and ZIP archives containing logs."""

    @property
    def name(self) -> str:
        return "EvtxAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str, workspace: Optional[Any] = None, progress_callback: Optional[Callable[[int, str], None]] = None) -> AnalyzerResult:
        findings: List[Finding] = []
        parsed_files: List[Dict[str, Any]] = []
        all_records: List[Dict[str, Any]] = []

        # 1. Determine if single .evtx or a ZIP archive containing .evtx files
        temp_extracted_dir: Optional[str] = None
        temp_input_file: Optional[str] = None
        evtx_paths: List[Path] = []

        if isinstance(file_path, (bytes, bytearray)):
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1] or ".evtx")
            tf.write(file_path)
            tf.flush()
            tf.close()
            temp_input_file = tf.name
            target_file_path = Path(temp_input_file)
        else:
            target_file_path = Path(file_path)

        is_zip = False
        try:
            with open(target_file_path, "rb") as f:
                header = f.read(16)
            is_zip = header.startswith(b"PK\x03\x04")
        except Exception:
            pass

        if is_zip or filename.lower().endswith((".zip", ".zip64")):
            try:
                temp_extracted_dir = tempfile.mkdtemp(prefix="evtx_zip_")
                with zipfile.ZipFile(target_file_path, "r") as zf:
                    for name in zf.namelist():
                        if name.lower().endswith(".evtx") and not name.startswith("__MACOSX"):
                            target_out = Path(temp_extracted_dir) / Path(name).name
                            target_out.write_bytes(zf.read(name))
                            evtx_paths.append(target_out)
            except Exception as ze:
                logger.error(f"Error unpacking EVTX zip archive: {ze}")
                findings.append(Finding(
                    category="evtx",
                    severity="high",
                    title="Failed to Extract EVTX Archive",
                    description=f"Archive could not be unpacked to read Windows Event Logs: {ze}",
                    details={"error": str(ze)}
                ))
        else:
            evtx_paths.append(target_file_path)

        if not evtx_paths:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message="No valid .evtx log files found in input.",
                findings=findings,
                data={}
            )

        # 2. Parse each EVTX file using python-evtx with fast compiled template ASTs
        template_cache: Dict[Any, Any] = {}
        for log_path in evtx_paths:
            file_record_count = 0
            file_channels: Set[str] = set()
            file_name = filename if len(evtx_paths) == 1 else log_path.name

            try:
                import Evtx.Evtx as evtx
                with evtx.Evtx(str(log_path)) as log:
                    for record in log.records():
                        try:
                            root = record.root()
                            xml_content = fast_render_record(root, template_cache)
                            if not xml_content:
                                xml_content = record.xml()
                            rec_data = self._parse_event_xml(xml_content, file_name)
                            if rec_data:
                                all_records.append(rec_data)
                                file_record_count += 1
                                if rec_data.get("channel"):
                                    file_channels.add(rec_data["channel"])
                                if progress_callback and file_record_count % 1000 == 0:
                                    progress_callback(
                                        min(90, int(file_record_count / 700)),
                                        f"Parsing {file_name}: {file_record_count:,} records processed..."
                                    )
                        except Exception as rec_err:
                            logger.debug(f"EVTX record parse error in {file_name}: {rec_err}")
                            continue
            except Exception as log_err:
                logger.debug(f"Binary EVTX parse exception for {file_name}: {log_err}")

            # Fallback: check if the file contains XML event elements directly (e.g. exported events or non-standard chunks)
            if file_record_count == 0:
                try:
                    with open(log_path, "r", encoding="utf-8", errors="ignore") as xf:
                        raw_text = xf.read()
                    if "<Event" in raw_text:
                        event_blocks = re.findall(r"<Event[\s>].*?</Event>", raw_text, re.DOTALL | re.IGNORECASE)
                        for eb in event_blocks:
                            rec_data = self._parse_event_xml(eb, file_name)
                            if rec_data:
                                all_records.append(rec_data)
                                file_record_count += 1
                                if rec_data.get("channel"):
                                    file_channels.add(rec_data["channel"])
                except Exception as fb_err:
                    logger.debug(f"XML fallback parsing error: {fb_err}")

            if file_record_count > 0:
                parsed_files.append({
                    "filename": file_name,
                    "records_count": file_record_count,
                    "channels": list(file_channels),
                    "file_size": log_path.stat().st_size
                })
            else:
                logger.error(f"Failed to parse EVTX log {file_name}: 0 records extracted")
                findings.append(Finding(
                    category="evtx",
                    severity="medium",
                    title=f"Error Parsing Log File: {file_name}",
                    description=f"Could not read complete event records from {file_name}",
                    details={"filename": file_name}
                ))

        # Clean up temporary extracted directory if created
        if temp_extracted_dir and os.path.exists(temp_extracted_dir):
            try:
                import shutil
                shutil.rmtree(temp_extracted_dir, ignore_errors=True)
            except Exception:
                pass

        if not all_records:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=True,
                findings=findings,
                data={
                    "total_events": 0,
                    "parsed_files": parsed_files,
                    "message": "Zero records parsed from supplied Windows Event Log file(s)."
                }
            )

        # 3. Analyze and Aggregate Records
        if progress_callback:
            progress_callback(92, f"Correlating security events & lateral movement ({len(all_records):,} events)...")

        total_events = len(all_records)
        event_id_counts: Dict[int, int] = Counter(r["event_id"] for r in all_records if r.get("event_id"))
        unique_users: Set[str] = {r["user"] for r in all_records if r.get("user") and r["user"] not in ["-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]}
        unique_computers: Set[str] = {r["computer"] for r in all_records if r.get("computer")}
        unique_ips: Set[str] = {r["ip_address"] for r in all_records if r.get("ip_address") and r["ip_address"] not in ["-", "127.0.0.1", "::1"]}

        # Time range
        timestamps = [r["timestamp"] for r in all_records if r.get("timestamp")]
        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None

        # Threat Vectors & Heuristics
        anti_forensics_events: List[Dict[str, Any]] = []
        ransomware_events: List[Dict[str, Any]] = []
        privilege_escalation_events: List[Dict[str, Any]] = []
        brute_force_attempts: List[Dict[str, Any]] = []
        process_creation_events: List[Dict[str, Any]] = []
        script_block_events: List[Dict[str, Any]] = []
        service_events: List[Dict[str, Any]] = []
        scheduled_task_events: List[Dict[str, Any]] = []
        network_events: List[Dict[str, Any]] = []
        lateral_movement_events: List[Dict[str, Any]] = []
        usb_history_raw: List[Dict[str, Any]] = []
        file_access_raw: List[Dict[str, Any]] = []
        print_audit_raw: List[Dict[str, Any]] = []
        rdp_events_raw: List[Dict[str, Any]] = []
        deobfuscated_cmds_raw: List[Dict[str, Any]] = []

        failed_logons_by_user: Dict[str, int] = Counter()
        failed_logons_by_ip: Dict[str, int] = Counter()

        for rec in all_records:
            eid = rec.get("event_id")
            cmd = rec.get("command_line", "") or ""
            user = rec.get("user", "")
            ip = rec.get("ip_address", "")

            # Anti-Forensics: Event 1102 / 104
            if eid in [1102, 104]:
                rec["title"] = f"Event Log Cleared ({'Security 1102' if eid == 1102 else 'System 104'})"
                rec["description"] = f"Event audit log wiped by {user or 'Administrator'}"
                rec["severity"] = "critical"
                rec["threat_reason"] = "Audit log intentionally wiped (Anti-Forensics MITRE T1070.001)"
                anti_forensics_events.append(rec)

            # Ransomware: Shadow copy deletion or Defender disabling
            if eid == 5001:
                rec["title"] = "Windows Defender Antivirus Real-Time Protection Disabled"
                rec["description"] = "Defender protection was turned off by registry, group policy, or command"
                rec["severity"] = "critical"
                rec["threat_reason"] = "Microsoft Defender Real-Time Protection Disabled (Defense Evasion)"
                ransomware_events.append(rec)
            if cmd:
                for pat in RANSOMWARE_CMD_PATTERNS:
                    if re.search(pat, cmd):
                        rec["title"] = "Volume Shadow Copy / Backup Deletion Attempt"
                        rec["description"] = f"Command: {cmd[:90]}"
                        rec["severity"] = "critical"
                        rec["threat_reason"] = "Ransomware staging: Volume Shadow Copy or Recovery backup deletion"
                        ransomware_events.append(rec)
                        break

            # Privilege Escalation: 4672, 4720, 4728, 4732, 4756
            if eid in [4672, 4720, 4728, 4732, 4756]:
                name = EVENT_CATALOG.get(eid, {}).get("name", "Privilege Escalation Event")
                rec["title"] = name
                rec["description"] = rec.get("summary") or f"Privilege change: {name}"
                rec["severity"] = "critical" if eid in [4732, 4728, 4756] else "high"
                rec["threat_reason"] = f"Privilege change or account creation: {name}"
                privilege_escalation_events.append(rec)

            # Brute Force: 4625 Failed Logon
            if eid == 4625:
                rec["title"] = "Failed Logon Attempt"
                rec["description"] = f"Account: {user or 'Unknown'} from {ip or 'Local'}"
                rec["severity"] = "medium"
                rec["threat_reason"] = "Failed authentication attempt (potential brute-force or password spray)"
                brute_force_attempts.append(rec)
                if user and user != "-":
                    failed_logons_by_user[user] += 1
                if ip and ip not in ["-", "127.0.0.1", "::1"]:
                    failed_logons_by_ip[ip] += 1

            # Process Creation: 4688, Sysmon 1
            if eid in [4688, 1]:
                proc_name = rec.get("process_name", "") or ""
                proc_base = Path(proc_name).name if proc_name else "process"
                is_lolbin = any(proc_name.lower().endswith(lb) for lb in LOLBINS_LIST) or any(lb in cmd.lower() for lb in LOLBINS_LIST)
                rec["is_lolbin"] = is_lolbin
                rec["title"] = f"Executed: {proc_base}"
                rec["description"] = f"Process: {proc_name or 'N/A'}"
                rec["command_line"] = cmd
                rec["image"] = proc_name
                rec["severity"] = "high" if is_lolbin else "info"
                if is_lolbin:
                    rec["threat_reason"] = f"Execution of Living-Off-The-Land Binary ({proc_base})"
                process_creation_events.append(rec)

            # PowerShell Script Block Logging: 4104
            if eid == 4104:
                script_text = rec.get("script_text", "") or ""
                is_mal_ps = any(kw in script_text.lower() for kw in ["downloadstring", "invoke-expression", "iex", "amsiutils", "bypass", "virtualalloc"])
                rec["title"] = "PowerShell Script Block Execution"
                rec["description"] = (script_text[:120] + "...") if script_text else "Script block executed"
                rec["severity"] = "high" if is_mal_ps else "medium"
                if is_mal_ps:
                    rec["threat_reason"] = "Suspicious PowerShell primitive detected (download cradle, AMSI bypass, or API invocation)"
                script_block_events.append(rec)

            # Services: 7045, 4697
            if eid in [7045, 4697]:
                rec["title"] = f"Service Installed: {rec.get('service_name', 'Unknown')}"
                rec["description"] = f"Service '{rec.get('service_name')}' registered on host"
                rec["severity"] = "high"
                rec["threat_reason"] = "New Windows service registered (potential persistence mechanism)"
                service_events.append(rec)

            # Scheduled Tasks: 4698, 4699, 4702
            if eid in [4698, 4699, 4702]:
                rec["title"] = f"Scheduled Task Event ({eid})"
                rec["description"] = f"Task: {rec.get('task_name', 'Unknown')}"
                rec["severity"] = "high" if eid == 4698 else "medium"
                rec["threat_reason"] = "Scheduled task created or modified for persistence"
                scheduled_task_events.append(rec)

            # Lateral Movement & Network Shares: 5140, 5145
            if eid in [5140, 5145]:
                share = (rec.get("share_name") or rec.get("details", {}).get("ShareName") or "").strip()
                rel_target = (rec.get("relative_target_name") or rec.get("details", {}).get("RelativeTargetName") or "").strip()
                access_list = (rec.get("access_list") or rec.get("details", {}).get("AccessList") or "").strip()
                access_mask = (rec.get("access_mask") or rec.get("details", {}).get("AccessMask") or "").strip()

                is_admin_share = any(s in share.upper() for s in ["C$", "ADMIN$", "IPC$", "D$", "E$"])
                is_payload_ext = any(rel_target.lower().endswith(ext) for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".sys", ".scr", ".hta", ".bin"])
                is_suspicious_name = any(name in rel_target.lower() for name in ["wodcmdterm", "malwr", "psexec", "mimikatz", "cobalt", "beacon", "chisel"])
                is_write_access = any(w in access_list for w in ["%%1538", "%%1541", "WriteData", "AppendData"]) or ("0x00120089" in access_mask or "0x2" in access_mask)

                is_flagged_lateral = is_payload_ext or is_suspicious_name or (is_admin_share and is_write_access and rel_target != "\\")
                if is_flagged_lateral:
                    reason = f"Remote staging of payload '{rel_target}' via {share}" if is_payload_ext else f"Administrative share write to {share}\\{rel_target}"
                    rec["is_threat"] = True
                    rec["is_payload_drop"] = is_payload_ext or is_suspicious_name
                    rec["threat_reason"] = f"SMB Lateral Movement: {reason}"
                    rec["severity"] = "critical" if (is_payload_ext and is_admin_share) else "high"
                    rec["title"] = f"SMB Lateral Movement: {Path(rel_target).name if rel_target else share}"
                    rec["description"] = f"Remote staging via {share}\\{rel_target} from {ip or 'remote host'} by {user or 'account'}"
                    lateral_movement_events.append(rec)

            # Network: Sysmon 3, 5140, 5145, 5156
            if eid in [3, 5140, 5145, 5156]:
                network_events.append(rec)

            # Print Spooler: Event 307 (Eventlog Item 4)
            if eid == 307:
                doc = rec.get("details", {}).get("Param1") or rec.get("details", {}).get("DocumentName") or "Document"
                p_user = rec.get("details", {}).get("Param2") or rec.get("details", {}).get("UserName") or user or "Unknown"
                client_ws = rec.get("details", {}).get("Param3") or rec.get("details", {}).get("MachineName") or rec.get("computer") or "Unknown"
                printer = rec.get("details", {}).get("Param4") or rec.get("details", {}).get("PrinterName") or "Default Printer"
                port = rec.get("details", {}).get("Param5") or rec.get("details", {}).get("PortName") or ""
                try:
                    size_b = int(rec.get("details", {}).get("Param6") or rec.get("details", {}).get("Size") or 0)
                except Exception:
                    size_b = 0
                try:
                    pages = int(rec.get("details", {}).get("Param7") or rec.get("details", {}).get("Pages") or 1)
                except Exception:
                    pages = 1
                is_bulk = pages >= 50 or size_b >= 5000000
                is_sens = any(kw in doc.lower() for kw in ["confidential", "salary", "payroll", "financial", "secret", "dump", "db_", "database", "credential"])
                print_rec = {
                    "document_name": doc,
                    "pages": pages,
                    "size_bytes": size_b,
                    "printer": printer,
                    "port": port,
                    "user": p_user,
                    "client_machine": client_ws,
                    "timestamp": rec.get("timestamp"),
                    "is_bulk_print": is_bulk,
                    "is_sensitive": is_sens
                }
                print_audit_raw.append(print_rec)
                if is_bulk or is_sens:
                    rec["is_threat"] = True
                    rec["severity"] = "high"
                    rec["title"] = f"Bulk/Sensitive Document Printed: {doc}"
                    rec["description"] = f"Document '{doc}' ({pages} pages, {round(size_b/1024, 1)} KB) printed to {printer} by {p_user}"
                    rec["threat_reason"] = "Physical data theft indicator: Large volume or sensitive document printed"

            # Plugged-In Hardware & USB Forensic History: Events 6416, 2003, 2100, 2101, 2102, 1003, 1004, 20001 (Eventlog Item 2)
            if eid in [6416, 2003, 2100, 2101, 2102, 1003, 1004, 20001, 20003]:
                dtls = rec.get("details", {})
                d_name = dtls.get("DeviceDescription") or dtls.get("DeviceName") or dtls.get("DriverName") or dtls.get("FriendlyName") or "External Storage Device"
                hw_id = dtls.get("HardwareId") or dtls.get("InstanceId") or dtls.get("DeviceId") or str(dtls)
                drive_ltr = dtls.get("DriveName") or dtls.get("Volume") or ""
                if not drive_ltr:
                    m_d = re.search(r'\b([A-Za-z]:)\\?', str(dtls))
                    if m_d:
                        drive_ltr = m_d.group(1)
                m_sn = re.search(r'(?:VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[\\/]|#)([A-Za-z0-9_\-]{8,})', hw_id)
                sn = m_sn.group(1) if m_sn else dtls.get("SerialNumber", "SN-UNKNOWN")
                vendor_cand = "Generic / USB"
                if "Sandisk" in hw_id.title() or "Sandisk" in d_name.title():
                    vendor_cand = "SanDisk"
                elif "Kingston" in hw_id.title() or "Kingston" in d_name.title():
                    vendor_cand = "Kingston"
                elif "Samsung" in hw_id.title() or "Samsung" in d_name.title():
                    vendor_cand = "Samsung"
                elif "Crucial" in hw_id.title() or "Crucial" in d_name.title():
                    vendor_cand = "Crucial"

                usb_status = "Ejected" if eid in [2102, 1004] else "Mounted"
                usb_entry = {
                    "device_name": d_name,
                    "vendor": vendor_cand,
                    "serial_number": sn,
                    "drive_letter": drive_ltr or "N/A",
                    "status": usb_status,
                    "timestamp": rec.get("timestamp"),
                    "user": user or "Unknown",
                    "computer": rec.get("computer") or "Unknown",
                    "event_id": eid
                }
                usb_history_raw.append(usb_entry)

            # File & Document Access Audit: Events 4663, 5145, 5140 (Eventlog Item 3)
            if eid in [4663, 5145, 5140]:
                dtls = rec.get("details", {})
                obj_name = dtls.get("ObjectName") or rec.get("relative_target_name") or dtls.get("RelativeTargetName") or ""
                sh_name = rec.get("share_name") or dtls.get("ShareName") or ""
                full_fpath = f"{sh_name}\\{obj_name}" if sh_name and obj_name else (obj_name or sh_name)
                if full_fpath and full_fpath != "\\":
                    fname = Path(full_fpath.replace("\\", "/")).name or full_fpath
                    f_low = fname.lower()
                    if any(f_low.endswith(ext) for ext in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv", ".rtf"]):
                        f_cat = "Documents"
                    elif any(kw in f_low for kw in ["password", "secret", "credential", "id_rsa", ".key", ".pem", ".kdbx", ".pfx", "sam", "ntds"]):
                        f_cat = "Keys & Passwords"
                    elif any(f_low.endswith(ext) for ext in [".zip", ".rar", ".7z", ".tar", ".gz", ".iso"]):
                        f_cat = "Archives"
                    elif any(f_low.endswith(ext) for ext in [".py", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".c", ".cpp", ".cs"]):
                        f_cat = "Source Code"
                    elif any(f_low.endswith(ext) for ext in [".exe", ".dll", ".sys", ".scr", ".bin"]):
                        f_cat = "Executables"
                    else:
                        f_cat = "General File"

                    amask = rec.get("access_mask") or dtls.get("AccessMask") or ""
                    alist = rec.get("access_list") or dtls.get("AccessList") or ""
                    if any(w in alist for w in ["WriteData", "AppendData", "%%1538", "%%1541"]) or "0x2" in amask:
                        op = "Write / Modify"
                    elif "DELETE" in alist or "0x10000" in amask:
                        op = "Delete"
                    elif "Execute" in alist or "0x20" in amask:
                        op = "Execute"
                    else:
                        op = "Read"

                    is_adm_sh = any(s in sh_name.upper() for s in ["C$", "ADMIN$", "IPC$"])
                    file_access_raw.append({
                        "file_path": full_fpath,
                        "filename": fname,
                        "file_category": f_cat,
                        "operation": op,
                        "access_mask": amask,
                        "user": user or "Unknown",
                        "process": rec.get("process_name") or dtls.get("ProcessName") or "explorer.exe",
                        "computer": rec.get("computer") or "Unknown",
                        "timestamp": rec.get("timestamp"),
                        "is_admin_share": is_adm_sh,
                        "share_name": sh_name,
                        "is_sensitive": f_cat in ["Documents", "Keys & Passwords"] or is_adm_sh
                    })

            # Remote Desktop (RDP) Journey: Events 1149, 21, 22, 24, 25, 4778, 4779, 4624 (LogonType 10) (Eventlog Item 5)
            if eid in [1149, 21, 22, 24, 25, 4778, 4779] or (eid == 4624 and str(rec.get("logon_type")) == "10"):
                dtls = rec.get("details", {})
                r_user = dtls.get("Param1") or dtls.get("User") or user or "Unknown"
                r_host = dtls.get("Param2") or dtls.get("WorkstationName") or dtls.get("SourceNetworkAddress") or "Remote Client"
                r_ip = dtls.get("Param3") or rec.get("ip_address") or "Remote IP"
                r_status = (
                    "Authenticated" if eid == 1149
                    else "Active Session" if eid in [21, 22, 4624]
                    else "Disconnected" if eid in [24, 4779]
                    else "Reconnected" if eid in [25, 4778]
                    else "RDP Activity"
                )
                rdp_events_raw.append({
                    "user": r_user,
                    "client_ip": r_ip,
                    "client_name": r_host,
                    "target_host": rec.get("computer") or "Target Host",
                    "status": r_status,
                    "timestamp": rec.get("timestamp"),
                    "event_id": eid
                })

            # Command De-obfuscation Collection (Eventlog Item 6)
            deobf_data = rec.get("deobf_info") or deobfuscate_command(cmd or rec.get("script_text"))
            if deobf_data.get("is_obfuscated"):
                deobfuscated_cmds_raw.append({
                    "raw_command": deobf_data["raw_command"],
                    "deobfuscated_command": deobf_data["deobfuscated_command"],
                    "is_obfuscated": True,
                    "obfuscation_types": deobf_data["obfuscation_types"],
                    "flagged_tokens": deobf_data["flagged_tokens"],
                    "user": user or "Unknown",
                    "process": rec.get("process_name") or "powershell.exe",
                    "timestamp": rec.get("timestamp"),
                    "event_id": eid,
                    "steps": deobf_data.get("steps", [])
                })

        # Compile Desktop Session Storyline (Eventlog Item 1)
        desktop_storyline: List[Dict[str, Any]] = []
        for r in all_records:
            eid = r.get("event_id")
            ts = r.get("timestamp")
            u = r.get("user") or "Unknown"
            comp = r.get("computer") or "Host"
            dtls = r.get("details", {})

            if eid == 4624:
                ltype = str(r.get("logon_type") or dtls.get("LogonType") or "2")
                ltype_desc = "Interactive (Console)" if ltype == "2" else "RemoteInteractive (RDP)" if ltype == "10" else "Network (Share/SMB)" if ltype == "3" else f"Logon Type {ltype}"
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "logon",
                    "title": f"User Logon: {u}",
                    "description": f"User '{u}' initiated {ltype_desc} session on {comp}",
                    "user": u,
                    "computer": comp,
                    "severity": "info",
                    "icon": "key",
                    "event_ids": [4624],
                    "details": {"logon_type": ltype_desc, "ip": r.get("ip_address")}
                })
            elif eid in [6416, 2003, 2100, 1003]:
                d_name = dtls.get("DeviceDescription") or dtls.get("FriendlyName") or "USB Mass Storage Device"
                dr_ltr = dtls.get("DriveName") or dtls.get("Volume") or "External Drive"
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "usb",
                    "title": f"External Hardware Connected: {d_name}",
                    "description": f"Plugged in hardware '{d_name}' mounted as {dr_ltr} by {u}",
                    "user": u,
                    "computer": comp,
                    "severity": "medium",
                    "icon": "usb",
                    "event_ids": [eid],
                    "details": dtls
                })
            elif eid in [4663, 5145]:
                f_path = dtls.get("ObjectName") or r.get("relative_target_name") or dtls.get("RelativeTargetName") or ""
                if f_path and f_path != "\\" and any(f_path.lower().endswith(ext) for ext in [".doc", ".docx", ".xls", ".xlsx", ".pdf", ".key", ".kdbx", ".txt"]):
                    doc_leaf = Path(f_path.replace("\\", "/")).name
                    desktop_storyline.append({
                        "id": f"story_{len(desktop_storyline)+1}",
                        "timestamp": ts,
                        "category": "file_access",
                        "title": f"Sensitive Document Accessed: {doc_leaf}",
                        "description": f"User '{u}' opened/read file '{f_path}' using {r.get('process_name') or 'Explorer'}",
                        "user": u,
                        "computer": comp,
                        "severity": "medium",
                        "icon": "file",
                        "event_ids": [eid],
                        "details": {"file": f_path, "share": r.get("share_name")}
                    })
            elif eid in [4688, 1, 4104]:
                cmd = r.get("command_line") or r.get("script_text") or ""
                pname = Path(r.get("process_name") or "script").name
                is_evasive = r.get("deobf_info", {}).get("is_obfuscated") or r.get("is_lolbin") or "vssadmin" in cmd.lower()
                if is_evasive or eid == 4104:
                    desktop_storyline.append({
                        "id": f"story_{len(desktop_storyline)+1}",
                        "timestamp": ts,
                        "category": "execution",
                        "title": f"Evasive / Script Execution: {pname}",
                        "description": f"Executed command: {cmd[:110]}... (User: {u})",
                        "user": u,
                        "computer": comp,
                        "severity": "high" if is_evasive else "info",
                        "icon": "zap",
                        "event_ids": [eid],
                        "details": {"command": cmd, "deobfuscated": r.get("decoded_command")}
                    })
            elif eid == 307:
                doc = dtls.get("Param1") or dtls.get("DocumentName") or "Document"
                pages = dtls.get("Param7") or dtls.get("Pages") or "1"
                prt = dtls.get("Param4") or dtls.get("PrinterName") or "Printer"
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "printing",
                    "title": f"Document Printed: {doc}",
                    "description": f"User '{u}' printed {pages} page(s) of '{doc}' to '{prt}'",
                    "user": u,
                    "computer": comp,
                    "severity": "medium",
                    "icon": "printer",
                    "event_ids": [307],
                    "details": dtls
                })
            elif eid == 5001:
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "tampering",
                    "title": "Microsoft Defender Real-Time Protection Disabled",
                    "description": f"Antivirus defenses disabled on host {comp}",
                    "user": u,
                    "computer": comp,
                    "severity": "critical",
                    "icon": "shield-alert",
                    "event_ids": [5001],
                    "details": dtls
                })
            elif eid in [1102, 104]:
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "anti_forensics",
                    "title": f"Windows Event Log Purged ({'Security 1102' if eid == 1102 else 'System 104'})",
                    "description": f"Audit log wiped by user '{u}' to obscure attacker tracks",
                    "user": u,
                    "computer": comp,
                    "severity": "critical",
                    "icon": "trash",
                    "event_ids": [eid],
                    "details": dtls
                })
            elif eid in [4634, 1074]:
                desktop_storyline.append({
                    "id": f"story_{len(desktop_storyline)+1}",
                    "timestamp": ts,
                    "category": "logoff",
                    "title": f"Session Logoff / Shutdown: {u}",
                    "description": f"User session terminated or host shutdown on {comp}",
                    "user": u,
                    "computer": comp,
                    "severity": "info",
                    "icon": "lock",
                    "event_ids": [eid],
                    "details": dtls
                })

        desktop_storyline.sort(key=lambda s: s.get("timestamp") or "")

        # 4. Generate Security Findings
        # Finding: Anti-Forensics
        if anti_forensics_events:
            findings.append(Finding(
                category="anti_forensics",
                severity="critical",
                title=f"Windows Audit Event Log Cleared ({len(anti_forensics_events)} Occurrence{'s' if len(anti_forensics_events)>1 else ''})",
                description=(
                    "The Windows Security or System event log was deliberately purged (Event ID 1102 / 104). "
                    "This is a high-confidence indicator of attacker anti-forensics (MITRE ATT&CK T1070.001 - Clear Windows Event Logs) "
                    "to destroy evidence of lateral movement or persistence."
                ),
                details={"events": anti_forensics_events[:10]}
            ))

        # Finding: Lateral Movement & Remote File Staging (5145 / 5140)
        if lateral_movement_events:
            has_crit = any(r.get("severity") == "critical" or r.get("is_payload_drop") for r in lateral_movement_events)
            findings.append(Finding(
                category="lateral_movement",
                severity="critical" if has_crit else "high",
                title=f"SMB Lateral Movement & Remote Payload Staging ({len(lateral_movement_events)} Events)",
                description=(
                    "Identified administrative network share access and payload deployment across SMB shares (Event ID 5145/5140). "
                    "Detected transfer or staging of executable binaries/scripts (e.g. malwr.exe, wodCmdTerm.exe, batch files) over administrative shares (C$, ADMIN$). "
                    "This indicates active lateral movement or remote code deployment (MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares)."
                ),
                details={"events": lateral_movement_events[:15]}
            ))

        # Finding: Ransomware Indicators
        if ransomware_events:
            findings.append(Finding(
                category="ransomware",
                severity="critical",
                title=f"Ransomware Defense Tampering & Shadow Copy Deletion ({len(ransomware_events)} Events)",
                description=(
                    "Identified explicit commands or policy shifts associated with ransomware staging: "
                    "deletion of Volume Shadow Copies (vssadmin/wmic), disabling recovery boot options, "
                    "or disabling Microsoft Defender Real-Time Protection (Event ID 5001)."
                ),
                details={"events": ransomware_events[:10]}
            ))

        # Finding: Privilege Escalation
        admin_group_adds = [r for r in privilege_escalation_events if r.get("event_id") in [4728, 4732, 4756]]
        if admin_group_adds:
            findings.append(Finding(
                category="privilege_escalation",
                severity="critical",
                title=f"Accounts Added to Privileged Security Groups ({len(admin_group_adds)} Events)",
                description=(
                    "User accounts were added to administrative or high-privilege security groups (Event ID 4728/4732). "
                    "Investigate account identities and approving administrators to confirm legitimate change authorization."
                ),
                details={"events": admin_group_adds[:10]}
            ))

        new_accounts = [r for r in privilege_escalation_events if r.get("event_id") == 4720]
        if new_accounts:
            findings.append(Finding(
                category="account_manipulation",
                severity="high",
                title=f"New User Accounts Created on Host ({len(new_accounts)} Accounts)",
                description=(
                    "One or more user accounts were created (Event ID 4720). Common tactic for creating backdoor access."
                ),
                details={"events": new_accounts[:10]}
            ))

        # Finding: Brute Force Logons
        high_fail_users = {u: cnt for u, cnt in failed_logons_by_user.items() if cnt >= 5}
        high_fail_ips = {ip: cnt for ip, cnt in failed_logons_by_ip.items() if cnt >= 5}
        if high_fail_users or high_fail_ips:
            findings.append(Finding(
                category="authentication",
                severity="high",
                title=f"Logon Brute Force / Password Spraying Detected ({len(brute_force_attempts)} Failed Logons)",
                description=(
                    f"Concentrated burst of failed logon attempts (Event ID 4625). "
                    f"Target accounts: {list(high_fail_users.keys())[:5]}. "
                    f"Source IPs: {list(high_fail_ips.keys())[:5]}."
                ),
                details={"failed_by_user": high_fail_users, "failed_by_ip": high_fail_ips}
            ))

        # Finding: Dangerous PowerShell Script Blocks
        suspicious_scripts = []
        for s in script_block_events:
            text = s.get("script_text", "")
            if any(kw in text.lower() for kw in ["downloadstring", "invoke-expression", "iex", "amsiutils", "bypass", "virtualalloc"]):
                suspicious_scripts.append(s)

        if suspicious_scripts:
            findings.append(Finding(
                category="script",
                severity="high",
                title=f"Malicious PowerShell Script Block Detected ({len(suspicious_scripts)} Blocks)",
                description=(
                    "PowerShell Script Block Logging (Event ID 4104) recorded script text containing download cradles, "
                    "AMSI bypass routines, or memory injection primitives."
                ),
                details={"scripts": suspicious_scripts[:5]}
            ))

        # 5. Timeline Generation with User-Configured Event IDs and Severities from Settings
        configured_timeline_ids = getattr(settings_store, "get_evtx_timeline_event_ids", lambda: None)()
        if not configured_timeline_ids or not isinstance(configured_timeline_ids, list):
            configured_timeline_ids = [
                4624, 4625, 4672, 4648, 4688, 7045, 4697, 4698, 4699, 4702,
                4720, 4728, 4732, 4756, 1102, 104, 4104, 4103, 5001, 1116, 1117,
                1, 3, 7, 11, 13, 5140, 5145, 5156, 4768, 4769, 4776
            ]

        configured_set = set(configured_timeline_ids)
        configured_severity_rules = getattr(settings_store, "get_evtx_severity_rules", lambda: {})() or {}

        timeline_events = []
        for r in all_records:
            eid = r.get("event_id")
            cat_info = EVENT_CATALOG.get(eid, {
                "name": f"Event {eid}",
                "category": "System",
                "severity": "info",
                "description": "Windows System Event"
            })

            custom_sev = configured_severity_rules.get(str(eid))
            event_severity = custom_sev if custom_sev else r.get("severity") or cat_info.get("severity", "info")

            is_threat = (
                r.get("is_threat", False)
                or event_severity in ["critical", "high"]
                or eid in [1102, 104, 5001, 1116, 1117, 4728, 4732, 4756]
                or (eid == 4625 and failed_logons_by_user.get(r.get("user", ""), 0) >= 3)
                or r.get("is_lolbin", False)
                or bool(r.get("threat_reason"))
            )

            threat_reason = r.get("threat_reason")
            decoded_cmd = r.get("decoded_command")
            ps_info = r.get("ps_decoded_info") or {}

            if decoded_cmd:
                if ps_info.get("is_suspicious"):
                    is_threat = True
                    if event_severity not in ["critical"]:
                        event_severity = "high"
                    threat_reason = f"Decoded PowerShell EncodedCommand contains suspicious primitives ({', '.join(ps_info.get('indicators', [])) or 'obfuscated execution'})"
                elif not threat_reason:
                    threat_reason = "PowerShell -EncodedCommand execution detected and automatically decoded"

            if not threat_reason and is_threat:
                if eid in [1102, 104]:
                    threat_reason = "Audit or system event log was wiped (Anti-Forensics MITRE T1070.001)"
                elif eid == 5001:
                    threat_reason = "Microsoft Defender Real-Time Protection was disabled (Defense Evasion)"
                elif eid in [4728, 4732, 4756]:
                    threat_reason = "Account added to elevated administrative security group (Privilege Escalation)"
                elif eid == 7045:
                    threat_reason = f"New Windows service installed: {r.get('service_name', 'Unknown')}"
                elif eid == 4698:
                    threat_reason = f"New scheduled task created: {r.get('task_name', 'Unknown')}"
                elif eid == 4672:
                    threat_reason = "Administrative privileges assigned to logon session (SeDebugPrivilege)"
                elif eid == 4625:
                    threat_reason = "Authentication failure (potential password spray or brute force)"
                elif eid == 5145:
                    threat_reason = "Administrative share access check for lateral movement or remote staging"
                elif event_severity in ["critical", "high"]:
                    threat_reason = f"Classified as {event_severity.upper()} security event by administrator policy"

            item = {
                "timestamp": r.get("timestamp"),
                "event_id": eid,
                "event_name": cat_info["name"],
                "category": cat_info["category"],
                "severity": event_severity,
                "user": r.get("user") or "-",
                "computer": r.get("computer") or "-",
                "channel": r.get("channel") or "-",
                "summary": r.get("summary") or cat_info["description"],
                "command_line": r.get("command_line"),
                "decoded_command": decoded_cmd,
                "powershell_decoded": decoded_cmd,
                "ps_decoded_info": ps_info,
                "process_name": r.get("process_name"),
                "process_id": r.get("process_id"),
                "parent_process": r.get("parent_process"),
                "parent_process_id": r.get("parent_process_id"),
                "service_name": r.get("service_name"),
                "task_name": r.get("task_name"),
                "script_text": r.get("script_text"),
                "share_name": r.get("share_name") or r.get("details", {}).get("ShareName"),
                "relative_target_name": r.get("relative_target_name") or r.get("details", {}).get("RelativeTargetName"),
                "access_mask": r.get("access_mask") or r.get("details", {}).get("AccessMask"),
                "access_list": r.get("access_list") or r.get("details", {}).get("AccessList"),
                "ip_address": r.get("ip_address"),
                "ip_port": r.get("ip_port") or r.get("details", {}).get("IpPort"),
                "logon_type": r.get("logon_type") or r.get("details", {}).get("LogonType"),
                "status_code": r.get("status_code") or r.get("details", {}).get("Status"),
                "substatus_code": r.get("substatus_code") or r.get("details", {}).get("SubStatus"),
                "source_file": r.get("source_file"),
                "details": r.get("details", {}),
                "is_monitored": eid in configured_set,
                "is_threat": is_threat,
                "threat_reason": threat_reason,
            }
            timeline_events.append(item)

        # Prioritize all monitored security events and threat events in the timeline
        # 100% of detected threats are always preserved
        threats_list = [it for it in timeline_events if it.get("is_threat")]
        monitored_benign = [it for it in timeline_events if it.get("is_monitored") and not it.get("is_threat")]
        other_benign = [it for it in timeline_events if not it.get("is_monitored") and not it.get("is_threat")]
        
        # Keep 100% of threats, plus up to 5,000 monitored benign events and 2,000 other benign events for responsive browsing
        final_timeline = threats_list + monitored_benign[:5000] + other_benign[:2000]
        final_timeline.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        # Build clean Event ID statistics summary
        event_breakdown = []
        for eid, count in event_id_counts.most_common(50):
            info = EVENT_CATALOG.get(eid, {
                "name": f"Event {eid}",
                "category": "Other",
                "severity": "info",
                "description": "Standard Windows Event Record"
            })
            custom_sev = configured_severity_rules.get(str(eid))
            item_sev = custom_sev if custom_sev else info.get("severity", "info")
            event_breakdown.append({
                "event_id": eid,
                "name": info["name"],
                "category": info["category"],
                "severity": item_sev,
                "count": count,
                "description": info["description"],
                "in_timeline": eid in configured_set
            })

        if progress_callback:
            progress_callback(100, f"Forensic analysis complete ({len(final_timeline):,} timeline events indexed)")

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data={
                "total_records": total_events,
                "total_events": total_events,
                "files_parsed": [p.get("filename") for p in parsed_files],
                "time_range": {
                    "earliest": start_time,
                    "latest": end_time
                },
                "timeline": final_timeline,
                "timeline_events": final_timeline,
                "sensitive_event_counts": {
                    str(eid): count for eid, count in event_id_counts.items()
                    if eid in [4624, 4625, 4672, 4648, 4688, 7045, 4697, 4698, 4720, 4728, 4732, 1102, 104, 4104, 5001, 1, 3, 5140, 5145, 5156]
                },
                "event_id_distribution": {str(eid): count for eid, count in event_id_counts.items()},
                "threats": {
                    "anti_forensics": anti_forensics_events[:50],
                    "ransomware": ransomware_events[:50],
                    "privilege_escalation": privilege_escalation_events[:50],
                    "brute_force": brute_force_attempts[:50],
                    "lateral_movement": lateral_movement_events[:50],
                    "process_creation": process_creation_events[:50],
                    "powershell": script_block_events[:50],
                    "services_and_tasks": (service_events + scheduled_task_events)[:50],
                    "network_connections": network_events[:50]
                },
                "summary": {
                    "total_events": total_events,
                    "start_time": start_time,
                    "end_time": end_time,
                    "parsed_files": parsed_files,
                    "unique_users_count": len(unique_users),
                    "unique_computers_count": len(unique_computers),
                    "unique_ips_count": len(unique_ips),
                    "anti_forensics_count": len(anti_forensics_events),
                    "ransomware_indicators_count": len(ransomware_events),
                    "privilege_escalation_count": len(privilege_escalation_events),
                    "brute_force_count": len(brute_force_attempts),
                    "lateral_movement_count": len(lateral_movement_events),
                    "process_creations_count": len(process_creation_events),
                    "script_blocks_count": len(script_block_events)
                },
                "event_id_counts": event_breakdown,
                "configured_timeline_event_ids": list(configured_set),
                "threat_vectors": {
                    "anti_forensics": anti_forensics_events[:50],
                    "ransomware": ransomware_events[:50],
                    "privilege_escalation": privilege_escalation_events[:50],
                    "lateral_movement": lateral_movement_events[:50],
                    "brute_force": {
                        "total_failed": len(brute_force_attempts),
                        "top_failed_users": dict(failed_logons_by_user.most_common(10)),
                        "top_failed_ips": dict(failed_logons_by_ip.most_common(10)),
                        "sample_events": brute_force_attempts[:20]
                    },
                    "lolbins_executed": [p for p in process_creation_events if p.get("is_lolbin")][:50],
                    "script_blocks": script_block_events[:50],
                    "services_installed": service_events[:50],
                    "scheduled_tasks": scheduled_task_events[:50],
                    "network_connections": network_events[:50]
                },
                "unique_users": sorted(list(unique_users))[:50],
                "unique_computers": sorted(list(unique_computers)),
                "unique_ips": sorted(list(unique_ips))[:50],
                "desktop_storyline": desktop_storyline,
                "usb_history": usb_history_raw,
                "file_access_audit": file_access_raw,
                "print_audit": print_audit_raw,
                "rdp_sessions": rdp_events_raw,
                "deobfuscated_commands": deobfuscated_cmds_raw
            }
        )

    def _parse_event_xml(self, xml_str: str, filename: str) -> Optional[Dict[str, Any]]:
        """Extract structured fields from Windows Event XML representation using high-speed regex with ET fallback."""
        if not xml_str:
            return None

        try:
            m_eid = RE_EVENT_ID.search(xml_str)
            if not m_eid:
                return None
            event_id = int(m_eid.group(1))

            m_time = RE_TIME.search(xml_str)
            timestamp = m_time.group(1) if m_time else None

            m_comp = RE_COMPUTER.search(xml_str)
            computer = m_comp.group(1) if m_comp else None

            m_chan = RE_CHANNEL.search(xml_str)
            channel = m_chan.group(1) if m_chan else None

            m_lvl = RE_LEVEL.search(xml_str)
            level = int(m_lvl.group(1)) if m_lvl else 4

            event_data_dict: Dict[str, str] = {}
            for name_attr, val in RE_DATA.findall(xml_str):
                if name_attr:
                    event_data_dict[name_attr] = val
                elif val:
                    event_data_dict[f"Data_{len(event_data_dict)}"] = val

            if "<UserData" in xml_str and not event_data_dict:
                try:
                    clean_xml = re.sub(r'\sxmlns="[^"]+"', '', xml_str, count=1)
                    root = ET.fromstring(clean_xml)
                    user_data_node = root.find("UserData")
                    if user_data_node is not None:
                        for child in user_data_node:
                            for sub in child:
                                if sub.tag:
                                    event_data_dict[sub.tag] = sub.text or ""
                except Exception:
                    pass

            # Extract common IR attributes
            user = (
                event_data_dict.get("TargetUserName") or
                event_data_dict.get("SubjectUserName") or
                event_data_dict.get("User") or
                event_data_dict.get("AccountName") or
                event_data_dict.get("Param1") or
                None
            )

            ip = (
                event_data_dict.get("IpAddress") or
                event_data_dict.get("SourceIp") or
                event_data_dict.get("ClientAddress") or
                event_data_dict.get("DestinationIp") or
                event_data_dict.get("DestAddr") or
                None
            )

            cmd = (
                event_data_dict.get("CommandLine") or
                event_data_dict.get("ProcessCommandLine") or
                event_data_dict.get("ScriptBlockText") or
                None
            )

            process_name = (
                event_data_dict.get("NewProcessName") or
                event_data_dict.get("Image") or
                event_data_dict.get("ProcessName") or
                event_data_dict.get("SourceImage") or
                None
            )

            parent_process = (
                event_data_dict.get("ParentProcessName") or
                event_data_dict.get("ParentImage") or
                None
            )

            service_name = event_data_dict.get("ServiceName") or event_data_dict.get("ServiceName_0")
            task_name = event_data_dict.get("TaskName")
            share_name = event_data_dict.get("ShareName")
            relative_target_name = event_data_dict.get("RelativeTargetName")
            access_mask = event_data_dict.get("AccessMask")
            access_list = event_data_dict.get("AccessList")
            ip_port = event_data_dict.get("IpPort") or event_data_dict.get("SourcePort") or event_data_dict.get("DestinationPort") or event_data_dict.get("DestPort")
            logon_type = event_data_dict.get("LogonType")
            status_code = event_data_dict.get("Status")
            substatus_code = event_data_dict.get("SubStatus")
            process_id = event_data_dict.get("ProcessId") or event_data_dict.get("NewProcessId")
            parent_process_id = event_data_dict.get("ParentProcessId")

            # Formulate concise event summary
            summary = self._build_event_summary(event_id, event_data_dict, user, cmd, process_name, service_name, task_name)

            # Automatic Command De-obfuscation & PowerShell EncodedCommand decoding (Eventlog Item 6)
            deobf_info = deobfuscate_command(cmd or event_data_dict.get("ScriptBlockText"))
            ps_decoded_info = decode_powershell_command(cmd) or decode_powershell_command(event_data_dict.get("ScriptBlockText"))
            decoded_cmd = deobf_info.get("deobfuscated_command") if deobf_info.get("is_obfuscated") else (ps_decoded_info.get("decoded") if ps_decoded_info else None)

            return {
                "event_id": event_id,
                "timestamp": timestamp,
                "computer": computer,
                "channel": channel,
                "level": level,
                "user": user,
                "ip_address": ip,
                "ip_port": ip_port,
                "command_line": cmd,
                "decoded_command": decoded_cmd,
                "deobf_info": deobf_info,
                "powershell_decoded": decoded_cmd,
                "ps_decoded_info": ps_decoded_info,
                "process_name": process_name,
                "process_id": process_id,
                "parent_process": parent_process,
                "parent_process_id": parent_process_id,
                "service_name": service_name,
                "task_name": task_name,
                "share_name": share_name,
                "relative_target_name": relative_target_name,
                "access_mask": access_mask,
                "access_list": access_list,
                "logon_type": logon_type,
                "status_code": status_code,
                "substatus_code": substatus_code,
                "script_text": event_data_dict.get("ScriptBlockText"),
                "summary": summary,
                "source_file": filename,
                "details": event_data_dict
            }
        except Exception as e:
            logger.debug(f"XML parse error in event: {e}")
            return None

    def _build_event_summary(
        self,
        event_id: int,
        data: Dict[str, str],
        user: Optional[str],
        cmd: Optional[str],
        process: Optional[str],
        service: Optional[str],
        task: Optional[str]
    ) -> str:
        """Construct user-friendly one-line summary for event cards and timeline."""
        if event_id == 4624:
            logon_type = data.get("LogonType", "Unknown")
            type_desc = {
                "2": "Interactive", "3": "Network", "7": "Unlock",
                "9": "NewCredentials", "10": "RemoteDesktop/RDP", "11": "CachedInteractive"
            }.get(logon_type, f"Type {logon_type}")
            return f"Successful logon by {user or 'Unknown'} via {type_desc} from {data.get('IpAddress', 'Local host')}"

        if event_id == 4625:
            reason = data.get("Status", data.get("SubStatus", "Authentication failure"))
            return f"Failed logon attempt for account '{user or 'Unknown'}' from {data.get('IpAddress', 'Local host')} ({reason})"

        if event_id == 4672:
            return f"Special administrative privileges granted to {user or 'Account'}"

        if event_id in [4688, 1]:
            proc_base = Path(process).name if process else "process"
            cmd_preview = (cmd[:70] + "...") if cmd and len(cmd) > 70 else (cmd or "")
            return f"Created {proc_base} [{cmd_preview}]" if cmd_preview else f"Executed {proc_base}"

        if event_id == 4689:
            proc_base = Path(process).name if process else "process"
            return f"Process terminated: {proc_base}"

        if event_id == 7045:
            return f"New service installed: '{service or data.get('ServiceName', 'Unknown')}' ({data.get('ImagePath', '')[:60]})"

        if event_id == 4697:
            return f"Service installed in system: '{service or data.get('ServiceName', 'Unknown')}'"

        if event_id == 7036:
            return f"Service '{service or data.get('param1', 'service')}' entered {data.get('param2', 'new')} state"

        if event_id == 7040:
            return f"Service start type changed for '{service or data.get('param1', 'service')}'"

        if event_id == 4698:
            return f"New scheduled task created: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 4699:
            return f"Scheduled task deleted: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 4700:
            return f"Scheduled task enabled: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 4701:
            return f"Scheduled task disabled: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 4702:
            return f"Scheduled task updated: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 106:
            return f"Task Scheduler registered task: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 200:
            return f"Task Scheduler executed action for: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 201:
            return f"Task Scheduler completed action for: '{task or data.get('TaskName', 'Unknown')}'"

        if event_id == 4720:
            return f"New user account created: '{user or data.get('TargetUserName', 'Unknown')}'"

        if event_id == 4722:
            return f"User account enabled: '{user or data.get('TargetUserName', 'Unknown')}'"

        if event_id == 4724:
            return f"Password reset attempt for: '{user or data.get('TargetUserName', 'Unknown')}'"

        if event_id == 4726:
            return f"User account deleted: '{user or data.get('TargetUserName', 'Unknown')}'"

        if event_id == 4738:
            return f"User account modified: '{user or data.get('TargetUserName', 'Unknown')}'"

        if event_id in [4728, 4732, 4756]:
            group = data.get("TargetUserName", data.get("GroupName", "Privileged Group"))
            member = data.get("MemberName", data.get("SubjectUserName", "User"))
            return f"Member '{member}' added to security group '{group}'"

        if event_id == 4673:
            return f"Sensitive privilege service called by {user or 'User'} ({data.get('PrivilegeList', '')})"

        if event_id == 4674:
            return f"Operation attempted on privileged object by {user or 'User'}"

        if event_id == 4703:
            return f"Token privileges adjusted for {user or 'User'}"

        if event_id in [1102, 104]:
            return f"CRITICAL: Event log cleared by {user or 'Administrator'}"

        if event_id == 1100:
            return "CRITICAL: Windows Event Logging Service shutdown"

        if event_id == 4104:
            script_snip = (data.get("ScriptBlockText", "")[:80] + "...") if data.get("ScriptBlockText") else "PowerShell execution"
            return f"Script block: {script_snip}"

        if event_id == 4103:
            return f"PowerShell module execution by {user or 'User'}"

        if event_id == 5001:
            return "CRITICAL: Microsoft Defender Antivirus Real-time Protection Disabled"

        if event_id == 5007:
            return "CRITICAL: Microsoft Defender configuration tampered or modified"

        if event_id == 5004:
            return "Microsoft Defender configuration settings changed"

        if event_id in [1116, 1117]:
            threat_name = data.get("Threat Name", data.get("ThreatName", "Malware"))
            return f"CRITICAL Defender Malware Detection: '{threat_name}'"

        if event_id == 3:
            dest_ip = data.get("DestinationIp", "remote")
            dest_port = data.get("DestinationPort", "")
            return f"Network connection to {dest_ip}:{dest_port} by {Path(process).name if process else 'process'}"

        if event_id == 22:
            return f"DNS query for '{data.get('QueryName', 'domain')}' by {Path(process).name if process else 'process'}"

        if event_id == 8:
            return f"CRITICAL Sysmon CreateRemoteThread: {data.get('SourceImage', 'proc')} injected thread into {data.get('TargetImage', 'target')}"

        if event_id == 10:
            return f"CRITICAL Sysmon ProcessAccess: {data.get('SourceImage', 'proc')} opened handle to {data.get('TargetImage', 'target')}"

        if event_id == 25:
            return f"CRITICAL Sysmon Process Tampering detected on {data.get('Image', 'process')}"

        if event_id == 2:
            return f"Sysmon File Creation Time Changed (Timestomping) on {data.get('TargetFilename', 'file')}"

        if event_id == 6:
            return f"Sysmon Driver Loaded: {data.get('ImageLoaded', 'driver')}"

        if event_id == 9:
            return f"Sysmon RawAccessRead on {data.get('Device', 'device')}"

        if event_id in [17, 18]:
            return f"Sysmon Named Pipe {'Created' if event_id == 17 else 'Connected'}: {data.get('PipeName', 'pipe')}"

        if event_id == 5145:
            share = data.get("ShareName", "")
            target = data.get("RelativeTargetName", "")
            target_str = f"\\{target}" if target and target != "\\" else ""
            user_str = user or data.get("SubjectUserName", "User")
            ip_str = f" from {data.get('IpAddress', '')}" if data.get("IpAddress") else ""
            port_str = f":{data.get('IpPort')}" if data.get("IpPort") else ""
            access = data.get("AccessList", data.get("AccessMask", "")).strip().replace("\n", " ").replace("\t", " ")
            return f"SMB Share Access: {share}{target_str} by {user_str}{ip_str}{port_str} ({access[:40]})"

        if event_id == 5140:
            share = data.get("ShareName", "")
            user_str = user or data.get("SubjectUserName", "User")
            ip_str = f" from {data.get('IpAddress', '')}" if data.get("IpAddress") else ""
            return f"Network share accessed: {share} by {user_str}{ip_str}"

        if event_id == 5142:
            return f"Network share added: {data.get('ShareName', 'Share')}"

        if event_id == 5144:
            return f"Network share deleted: {data.get('ShareName', 'Share')}"

        if event_id == 5156:
            app = Path(data.get("Application", "")).name if data.get("Application") else "app"
            dest = f"{data.get('DestAddr', '')}:{data.get('DestPort', '')}"
            return f"WFP Allowed connection to {dest} by {app}"

        if event_id == 5158:
            return f"WFP bind to local port: {data.get('LocalPort', '')}"

        if event_id == 4648:
            target_user = data.get("TargetUserName", "Target")
            return f"Logon with explicit credentials for {target_user} by {user or 'User'}"

        if event_id == 4768:
            return f"Kerberos TGT requested for {data.get('TargetUserName', user or 'User')}"

        if event_id == 4769:
            service = data.get("ServiceName", "service")
            return f"Kerberos service ticket requested for '{service}' (TicketOptions: {data.get('TicketOptions', '')})"

        if event_id == 4771:
            return f"Kerberos pre-authentication failed for {user or data.get('TargetUserName', 'User')} (Error: {data.get('Status', '0x18')})"

        if event_id == 4776:
            return f"NTLM authentication validation for {data.get('TargetUserName', user or 'Account')} (Status: {data.get('Status', '')})"

        if event_id == 1149:
            client = data.get("Param2", data.get("IpAddress", "remote"))
            return f"RDP connection authenticated for {user or data.get('Param1', 'User')} from {client}"

        if event_id in [21, 24, 25]:
            act = "logon succeeded" if event_id == 21 else "disconnected" if event_id == 24 else "reconnected"
            return f"RDP session {act} for {user or 'User'}"

        info = EVENT_CATALOG.get(event_id)
        if info:
            return info["description"]

        return f"Event {event_id} on host"
