// Auto-generated comprehensive catalog of Windows Event IDs
export interface KnownEvtxEvent {
  id: number;
  name: string;
  category: string;
  desc: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  isCurated?: boolean;
}

export const KNOWN_EVTX_EVENTS: KnownEvtxEvent[] = [
  {
    "id": 1,
    "name": "Sysmon Process Creation",
    "category": "Process Execution",
    "desc": "Sysmon detected new process execution with full command line, hashes, and parent process",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 2,
    "name": "Sysmon File Creation Time Changed",
    "category": "Defense Evasion",
    "desc": "Sysmon detected timestomping on file creation time",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 3,
    "name": "Sysmon Network Connection",
    "category": "Network Communication",
    "desc": "Sysmon logged outbound or inbound TCP/UDP network connection",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4,
    "name": "Sysmon Service State Change",
    "category": "System",
    "desc": "Sysmon service state change",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5,
    "name": "Sysmon Process Terminated",
    "category": "Process Execution",
    "desc": "Sysmon process terminated",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6,
    "name": "Sysmon Driver Loaded",
    "category": "Privilege Escalation",
    "desc": "Sysmon detected a kernel driver loaded into system space (potential rootkit)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 7,
    "name": "Sysmon Image Loaded",
    "category": "Process Execution",
    "desc": "Sysmon detected DLL image loaded into process memory (potential DLL hijacking)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 8,
    "name": "Sysmon CreateRemoteThread",
    "category": "Process Execution",
    "desc": "Sysmon detected remote thread created in another process (Process Injection / Shellcode)",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 9,
    "name": "Sysmon RawAccessRead",
    "category": "Credential Access",
    "desc": "Sysmon detected raw disk access (potential Volume Shadow Copy or NTDS.dit theft)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 10,
    "name": "Sysmon ProcessAccess",
    "category": "Credential Access",
    "desc": "Sysmon detected process handle opened to another process (LSASS memory dump / Mimikatz)",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 11,
    "name": "Sysmon File Created",
    "category": "File System",
    "desc": "Sysmon detected file creation on disk",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 12,
    "name": "Sysmon Registry Object Created / Deleted",
    "category": "Persistence / Registry",
    "desc": "Sysmon detected creation or deletion of registry keys and objects",
    "severity": "info",
    "isCurated": true
  },
  {
    "id": 13,
    "name": "Sysmon Registry Value Set",
    "category": "Persistence / Registry",
    "desc": "Sysmon detected registry value modification (Run keys, services, persistence)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 14,
    "name": "Sysmon Registry Key / Value Renamed",
    "category": "Defense Evasion",
    "desc": "Sysmon detected renaming of registry keys or values",
    "severity": "info",
    "isCurated": true
  },
  {
    "id": 15,
    "name": "Sysmon Alternate Data Stream Created",
    "category": "Defense Evasion",
    "desc": "Sysmon detected file creation in Alternate Data Stream (ADS) with hash calculation (Zone.Identifier bypass)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 16,
    "name": "Sysmon Configuration Changed",
    "category": "Anti-Forensics",
    "desc": "Sysmon filter configuration was modified or reloaded",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 17,
    "name": "Sysmon Named Pipe Created",
    "category": "Lateral Movement",
    "desc": "Sysmon detected creation of a named pipe (Cobalt Strike, PsExec, RPC lateral movement)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 18,
    "name": "Sysmon Named Pipe Connected",
    "category": "Lateral Movement",
    "desc": "Sysmon detected connection established to a named pipe",
    "severity": "info",
    "isCurated": true
  },
  {
    "id": 19,
    "name": "Sysmon WmiEvent (Filter Activity)",
    "category": "Persistence / WMI",
    "desc": "Sysmon detected WMI event filter registration (WMI persistence)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 20,
    "name": "Sysmon WmiEvent (Consumer Activity)",
    "category": "Persistence / WMI",
    "desc": "Sysmon detected WMI event consumer registration (CommandLineEventConsumer persistence)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 21,
    "name": "Sysmon WmiEvent (FilterToConsumer Binding)",
    "category": "Persistence / WMI",
    "desc": "Sysmon detected WMI event consumer bound to filter (active WMI subscription)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 22,
    "name": "Sysmon DNS Query Logged",
    "category": "Network Communication",
    "desc": "Sysmon logged outbound DNS query name, result, and initiating process ID",
    "severity": "info",
    "isCurated": true
  },
  {
    "id": 23,
    "name": "Sysmon File Delete Archived",
    "category": "Anti-Forensics",
    "desc": "Sysmon detected file deletion and saved copy in Archive directory (ransomware / wiper tracking)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 24,
    "name": "Sysmon Clipboard Content Changed",
    "category": "Discovery / Reconnaissance",
    "desc": "Sysmon monitored clipboard modification and captured copied content/hashes",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 25,
    "name": "Sysmon Process Tampering",
    "category": "Defense Evasion",
    "desc": "Sysmon detected process tampering (Process Hollowing, Herpaderping, Doppelganging)",
    "severity": "critical",
    "isCurated": true
  },
  {
    "id": 26,
    "name": "Sysmon File Delete Detected",
    "category": "Anti-Forensics",
    "desc": "Sysmon logged file deletion event without archiving",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 27,
    "name": "Sysmon Block Executable Creation",
    "category": "Execution Control",
    "desc": "Sysmon blocked writing of executable file binary to disk",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 28,
    "name": "Sysmon Block File Shredding",
    "category": "Anti-Forensics",
    "desc": "Sysmon blocked shredding or wipe attempt on target file",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 29,
    "name": "Sysmon Executable File Detected",
    "category": "Execution Control",
    "desc": "Sysmon detected creation of executable binary on target filesystem",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 41,
    "name": "Kernel-Power System Crash",
    "category": "System Lifecycle",
    "desc": "System rebooted without cleanly shutting down first (Kernel-Power crash)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 42,
    "name": "System Entering Sleep",
    "category": "System Lifecycle",
    "desc": "The computer is entering low-power sleep state",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 59,
    "name": "BITS Transfer Job Created",
    "category": "Network / BITS",
    "desc": "A BITS transfer job was created (potential background C2 downloader / LOLBin)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 60,
    "name": "BITS Transfer Context Modified",
    "category": "Network / BITS",
    "desc": "A BITS transfer job context or properties were modified",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 61,
    "name": "BITS Transfer Job Completed",
    "category": "Network / BITS",
    "desc": "A BITS transfer job completed downloading or uploading payload files",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 91,
    "name": "WinRM Connection Received",
    "category": "Lateral Movement / WinRM",
    "desc": "WinRM service received an inbound remote management connection",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 100,
    "name": "Task Scheduler Task Started",
    "category": "Persistence / Task",
    "desc": "Task Scheduler started an instance of a scheduled task",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 102,
    "name": "Task Scheduler Task Failed",
    "category": "Persistence / Task",
    "desc": "Task Scheduler failed to start scheduled task",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 104,
    "name": "Log File Cleared",
    "category": "Anti-Forensics",
    "desc": "The Windows System or Application event log file was cleared",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 106,
    "name": "Scheduled Task Registered",
    "category": "Persistence / Task",
    "desc": "Task Scheduler registered a new scheduled task",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 107,
    "name": "Task Scheduler Task Triggered",
    "category": "Persistence / Task",
    "desc": "Task Scheduler triggered a scheduled task based on time or event trigger",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 110,
    "name": "Task Scheduler Task Instance Launched",
    "category": "Persistence / Task",
    "desc": "Task Scheduler launched an action instance for a scheduled task",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 140,
    "name": "Task Scheduler Task Updated",
    "category": "Persistence / Task",
    "desc": "Task Scheduler updated the registration or settings of an existing task",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 141,
    "name": "Task Scheduler Task Deleted",
    "category": "Persistence / Task",
    "desc": "Task Scheduler deleted a scheduled task",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 161,
    "name": "WinRM User Authenticated",
    "category": "Lateral Movement / WinRM",
    "desc": "User authenticated for remote WinRM / PowerShell Remoting session",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 168,
    "name": "WinRM Remote Session Created",
    "category": "Lateral Movement / WinRM",
    "desc": "A remote WinRM management session / PowerShell shell was established",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 200,
    "name": "Scheduled Task Executed",
    "category": "Task Execution",
    "desc": "Task Scheduler launched an action for a scheduled task",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 201,
    "name": "Scheduled Task Completed",
    "category": "Task Execution",
    "desc": "Task Scheduler completed task action",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 307,
    "name": "Document Printed",
    "category": "Print Spooler",
    "desc": "Print Spooler successfully printed a document",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 311,
    "name": "Task Scheduler Action Executed",
    "category": "Persistence / Task",
    "desc": "Task Scheduler executed a custom process or handler action for a task",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 400,
    "name": "PowerShell Engine Started",
    "category": "Script Execution",
    "desc": "PowerShell engine lifecycle started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 403,
    "name": "PowerShell Engine Stopped",
    "category": "Script Execution",
    "desc": "PowerShell engine has stopped execution",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 600,
    "name": "PowerShell Provider Started",
    "category": "Script Execution",
    "desc": "PowerShell provider lifecycle started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 800,
    "name": "Print Driver Added",
    "category": "Print Spooler",
    "desc": "Print Spooler added a printer driver",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 801,
    "name": "Print Driver Updated",
    "category": "Print Spooler",
    "desc": "Print Spooler updated a printer driver (potential PrintNightmare exploit)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 805,
    "name": "Print Rendering Failure",
    "category": "Print Spooler",
    "desc": "Print Spooler rendering failure",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 808,
    "name": "Print Driver Load Failed (PrintNightmare)",
    "category": "Print Spooler",
    "desc": "Print Spooler failed to load driver (potential PrintNightmare CVE-2021-34527 exploitation)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 1000,
    "name": "Defender Scan Started",
    "category": "Antivirus",
    "desc": "Microsoft Defender Antivirus scan started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1001,
    "name": "System Crash / BugCheck (BSOD)",
    "category": "System Lifecycle",
    "desc": "Operating system crashed or encountered fatal BugCheck blue screen (potential kernel exploit)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 1002,
    "name": "Defender Scan Stopped",
    "category": "Antivirus",
    "desc": "Microsoft Defender Antivirus scan was stopped",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1005,
    "name": "Defender Action Failed",
    "category": "Antivirus",
    "desc": "Microsoft Defender failed to perform remediation action on detected malware",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 1006,
    "name": "Defender Malware in Memory/File",
    "category": "Antivirus",
    "desc": "Microsoft Defender detected active malware in memory or disk",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 1008,
    "name": "Defender Signature Update Failed",
    "category": "Antivirus",
    "desc": "Microsoft Defender failed to apply signature update",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 1033,
    "name": "Application Installed",
    "category": "Software Installation",
    "desc": "Windows Installer completed software installation",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1074,
    "name": "System Shutdown/Restart Initiated",
    "category": "System Lifecycle",
    "desc": "A process or user initiated system shutdown or restart",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1076,
    "name": "Unexpected Shutdown Reason Supplied",
    "category": "System Lifecycle",
    "desc": "User supplied reason code for previous unexpected system shutdown/reboot",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1100,
    "name": "Event Logging Service Shutdown",
    "category": "Anti-Forensics",
    "desc": "The Windows Event Logging Service was shut down",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 1102,
    "name": "Audit Log Cleared",
    "category": "Anti-Forensics",
    "desc": "The Windows Security audit log was cleared by an administrator or threat actor",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 1116,
    "name": "Defender Malware Detected",
    "category": "Malware Detection",
    "desc": "Microsoft Defender Antivirus detected active malware or suspicious threat",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 1117,
    "name": "Defender Malware Action Taken",
    "category": "Malware Detection",
    "desc": "Microsoft Defender Antivirus took action to remediate or quarantine threat",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 1118,
    "name": "Defender Quick Scan Completed",
    "category": "Malware Detection",
    "desc": "Microsoft Defender completed a scheduled quick scan",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1119,
    "name": "Defender Full Scan Completed",
    "category": "Malware Detection",
    "desc": "Microsoft Defender completed a scheduled full scan",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 1149,
    "name": "RDP Authentication Succeeded",
    "category": "Remote Desktop",
    "desc": "Remote Desktop Services: User authentication succeeded",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 2000,
    "name": "Defender Signatures Updated",
    "category": "Antivirus",
    "desc": "Microsoft Defender virus signatures updated successfully",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 2001,
    "name": "Defender Signature Update Failed",
    "category": "Antivirus",
    "desc": "Microsoft Defender failed to update antivirus definitions",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 3006,
    "name": "DNS Query Response Received",
    "category": "DNS / Network",
    "desc": "DNS Client received a DNS resolution response for a domain",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 3008,
    "name": "DNS Query Timed Out",
    "category": "DNS / Network",
    "desc": "DNS query request timed out without receiving authoritative answer",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 3010,
    "name": "DNS Query Failed",
    "category": "DNS / Network",
    "desc": "DNS query failed with error response code (NXDOMAIN / SERVFAIL)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 3018,
    "name": "DNS Query Sent to Name Server",
    "category": "DNS / Network",
    "desc": "DNS query request sent across network to configured resolver",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 3076,
    "name": "WDAC Image Load Block Audited",
    "category": "Code Integrity / WDAC",
    "desc": "Code Integrity determined that a process tried to load an unsigned driver or binary (Audit mode)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 3077,
    "name": "WDAC Image Load Blocked",
    "category": "Code Integrity / WDAC",
    "desc": "Code Integrity blocked an unsigned driver or binary from loading (Enforced)",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 3089,
    "name": "WDAC Signature Verification Details",
    "category": "Code Integrity / WDAC",
    "desc": "Code Integrity verified image signature details during binary execution",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4100,
    "name": "PowerShell Script Block Error",
    "category": "PowerShell",
    "desc": "PowerShell logged a script block execution failure or parser error",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4103,
    "name": "PowerShell Pipeline Execution",
    "category": "Script Execution",
    "desc": "PowerShell Module logging recorded command execution",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4104,
    "name": "PowerShell Script Block Execution",
    "category": "Script Execution",
    "desc": "PowerShell Script Block Logging captured code execution blocks",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4105,
    "name": "PowerShell Pipeline Execution Started",
    "category": "PowerShell",
    "desc": "PowerShell started executing a command pipeline or script",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4106,
    "name": "PowerShell Pipeline Execution Completed",
    "category": "PowerShell",
    "desc": "PowerShell completed execution of command pipeline or script",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4608,
    "name": "Windows is Starting Up",
    "category": "System Lifecycle",
    "desc": "Local Security Authority (LSA) subsystem has initialized and Windows kernel is starting up",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4609,
    "name": "Windows is Shutting Down",
    "category": "System Lifecycle",
    "desc": "Local Security Authority (LSA) subsystem has initiated system shutdown sequence",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4610,
    "name": "Authentication Package Loaded",
    "category": "Logon / Authentication",
    "desc": "Local Security Authority loaded an authentication package into memory",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4611,
    "name": "Trusted Logon Process Registered",
    "category": "Logon / Authentication",
    "desc": "A trusted logon process registered with Local Security Authority",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4612,
    "name": "Internal Resources Allocated for Audit Messages",
    "category": "System",
    "desc": "Internal memory resources were allocated for queuing security audit messages",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4614,
    "name": "Notification Package Loaded",
    "category": "Logon / Authentication",
    "desc": "Security Accounts Manager (SAM) loaded a password notification package (persistence vector)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4616,
    "name": "System Time Changed",
    "category": "Anti-Forensics",
    "desc": "System clock/time was modified (potential timestomping or event log manipulation)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4624,
    "name": "Successful Logon",
    "category": "Logon / Authentication",
    "desc": "An account successfully logged on to the host",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4625,
    "name": "Failed Logon",
    "category": "Logon / Authentication",
    "desc": "An account failed to log on (potential brute force or wrong credentials)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4627,
    "name": "Group Membership Information",
    "category": "Logon / Authentication",
    "desc": "Detailed group membership and SID information populated during user logon",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4634,
    "name": "Account Logoff",
    "category": "Logon / Authentication",
    "desc": "An account was logged off",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4647,
    "name": "User-Initiated Logoff",
    "category": "Logon / Authentication",
    "desc": "User initiated logoff",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4648,
    "name": "Logon with Explicit Credentials",
    "category": "Logon / Authentication",
    "desc": "A logon was attempted using explicit credentials (RunAs / secondary credentials)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4649,
    "name": "Replay Attack Detected",
    "category": "Kerberos / Identity",
    "desc": "Kerberos replay attack was detected by domain controller",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 4656,
    "name": "Handle to Object Requested",
    "category": "Object Access",
    "desc": "A handle to an object was requested",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4657,
    "name": "Registry Value Modified",
    "category": "Object Access",
    "desc": "A registry value was modified",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4658,
    "name": "Handle to Object Closed",
    "category": "Object Access",
    "desc": "The handle to an object was closed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4659,
    "name": "Object Handle Requested with Intent to Delete",
    "category": "Object Access",
    "desc": "Handle to an object was requested with intent to delete the file or registry entry",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4660,
    "name": "Object Deleted",
    "category": "Object Access",
    "desc": "An object was deleted",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4661,
    "name": "Handle to Object Requested (SAM/LSA)",
    "category": "Credential Access",
    "desc": "A handle was requested to an object (SAM database, LSA secrets, or domain object)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4662,
    "name": "Operation Performed on AD Object",
    "category": "Active Directory",
    "desc": "An operation was performed on an Active Directory object (DCSync / DS-Replication-Get-Changes)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4663,
    "name": "Object Access Attempt",
    "category": "File System",
    "desc": "An attempt was made to access a protected file system or registry object",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4664,
    "name": "Hard Link Creation Attempt",
    "category": "Object Access",
    "desc": "An attempt was made to create a filesystem hard link",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4670,
    "name": "Permissions on Object Changed",
    "category": "Object Access",
    "desc": "Discretionary Access Control List (DACL) or security permissions on an object were changed",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4672,
    "name": "Special Privileges Assigned",
    "category": "Privilege Escalation",
    "desc": "Special administrative privileges assigned to new logon session (SeDebugPrivilege, etc.)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4673,
    "name": "Sensitive Privilege Service Called",
    "category": "Privilege Escalation",
    "desc": "A privileged service was called by a user process",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4674,
    "name": "Operation Attempted on Privileged Object",
    "category": "Privilege Escalation",
    "desc": "An operation was attempted on a privileged object",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4675,
    "name": "SIDs Were Filtered",
    "category": "Logon / Authentication",
    "desc": "Security identifiers were filtered during forest trust authentication",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4688,
    "name": "Process Creation",
    "category": "Process Execution",
    "desc": "A new process has been created by parent process",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4689,
    "name": "Process Terminated",
    "category": "Process Execution",
    "desc": "A process has exited or was terminated",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4690,
    "name": "Handle Duplication Attempted",
    "category": "Object Access",
    "desc": "An attempt was made to duplicate a handle to an object",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4691,
    "name": "Indirect Object Access Requested",
    "category": "Object Access",
    "desc": "Indirect access to an object was requested",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4697,
    "name": "Service Installed in System",
    "category": "Persistence / Service",
    "desc": "A service was installed in the system",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4698,
    "name": "Scheduled Task Created",
    "category": "Persistence / Task",
    "desc": "A scheduled task was created on the system",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4699,
    "name": "Scheduled Task Deleted",
    "category": "Persistence / Task",
    "desc": "A scheduled task was deleted",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4700,
    "name": "Scheduled Task Enabled",
    "category": "Persistence / Task",
    "desc": "A scheduled task was enabled",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4701,
    "name": "Scheduled Task Disabled",
    "category": "Persistence / Task",
    "desc": "A scheduled task was disabled",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4702,
    "name": "Scheduled Task Updated",
    "category": "Persistence / Task",
    "desc": "A scheduled task was updated",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4703,
    "name": "Token Right Adjusted",
    "category": "Privilege Escalation",
    "desc": "Privilege rights on a user access token were enabled or disabled",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4704,
    "name": "User Right Assigned",
    "category": "Privilege Escalation",
    "desc": "A user right or security privilege was assigned to an account (e.g. SeDebugPrivilege)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4705,
    "name": "User Right Removed",
    "category": "Privilege Escalation",
    "desc": "A user right or security privilege was removed from an account",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4706,
    "name": "Trust Created to Domain",
    "category": "Active Directory",
    "desc": "A new domain trust relationship was established",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4707,
    "name": "Trust Removed from Domain",
    "category": "Active Directory",
    "desc": "A domain trust relationship was removed",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4713,
    "name": "Kerberos Policy Changed",
    "category": "Active Directory",
    "desc": "Kerberos ticket expiration or encryption policy was modified",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4714,
    "name": "Encrypted Data Recovery Policy Changed",
    "category": "Policy & Auditing",
    "desc": "Encrypted data recovery policy for BitLocker / EFS was changed",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4715,
    "name": "Audit Policy on Object Changed",
    "category": "Policy & Auditing",
    "desc": "SACL / audit policy on a specific object was modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4716,
    "name": "Trusted Domain Information Modified",
    "category": "Active Directory",
    "desc": "Trusted domain configuration was modified",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4717,
    "name": "System Security Access Granted",
    "category": "Privilege Escalation",
    "desc": "System security access was granted to an account",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4718,
    "name": "System Security Access Removed",
    "category": "Privilege Escalation",
    "desc": "System security access was revoked from an account",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4719,
    "name": "System Audit Policy Changed",
    "category": "Policy & Auditing",
    "desc": "System audit policy was altered (potential defense evasion to suppress logging)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4720,
    "name": "User Account Created",
    "category": "Account Manipulation",
    "desc": "A user account was created on the system or domain",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4722,
    "name": "User Account Enabled",
    "category": "Account Manipulation",
    "desc": "A user account was enabled",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4723,
    "name": "Password Change Attempt",
    "category": "Active Directory",
    "desc": "An attempt was made to change an account's password",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4724,
    "name": "Password Reset Attempt",
    "category": "Account Manipulation",
    "desc": "An attempt was made to reset an account's password",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4725,
    "name": "User Account Disabled",
    "category": "Active Directory",
    "desc": "A user account was disabled in Active Directory / local system",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4726,
    "name": "User Account Deleted",
    "category": "Account Manipulation",
    "desc": "A user account was deleted",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4727,
    "name": "Security-Enabled Global Group Created",
    "category": "Account Manipulation",
    "desc": "A new security-enabled global group was created in Active Directory / SAM",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4728,
    "name": "Member Added to Global Security Group",
    "category": "Privilege Escalation",
    "desc": "A member was added to a security-enabled global group (e.g. Domain Admins)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4729,
    "name": "Member Removed from Global Group",
    "category": "Active Directory",
    "desc": "A member was removed from a security-enabled global group",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4730,
    "name": "Security-Enabled Global Group Deleted",
    "category": "Account Manipulation",
    "desc": "A security-enabled global group was deleted",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4731,
    "name": "Security-Enabled Local Group Created",
    "category": "Account Manipulation",
    "desc": "A security-enabled local group was created",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4732,
    "name": "Member Added to Local Security Group",
    "category": "Privilege Escalation",
    "desc": "A member was added to a security-enabled local group (e.g. Administrators)",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 4733,
    "name": "Member Removed from Local Group",
    "category": "Active Directory",
    "desc": "A member was removed from a security-enabled local group",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4734,
    "name": "Security-Enabled Local Group Deleted",
    "category": "Account Manipulation",
    "desc": "A security-enabled local group was deleted",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4735,
    "name": "Security-Enabled Local Group Changed",
    "category": "Account Manipulation",
    "desc": "Properties or name of a security-enabled local group were changed",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4737,
    "name": "Security-Enabled Global Group Changed",
    "category": "Account Manipulation",
    "desc": "Properties or name of a security-enabled global group were changed",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4738,
    "name": "User Account Modified",
    "category": "Account Manipulation",
    "desc": "A user account was modified",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4739,
    "name": "Domain Policy Was Changed",
    "category": "Policy & Auditing",
    "desc": "Domain security policy (password length, lockout threshold, Kerberos) was changed",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4740,
    "name": "User Account Locked Out",
    "category": "Logon / Authentication",
    "desc": "A user account was locked out after exceeding failed logon attempts (brute-force indicator)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4741,
    "name": "Computer Account Created",
    "category": "Active Directory",
    "desc": "A computer account was created in Active Directory",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4742,
    "name": "Computer Account Changed",
    "category": "Active Directory",
    "desc": "A computer account was altered in Active Directory",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4743,
    "name": "Computer Account Deleted",
    "category": "Active Directory",
    "desc": "A computer account was deleted from Active Directory",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4744,
    "name": "Local Group Created",
    "category": "Account Manipulation",
    "desc": "A local group was created on the system",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4745,
    "name": "Local Group Modified",
    "category": "Account Manipulation",
    "desc": "A local group was modified on the system",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4746,
    "name": "Local Group Deleted",
    "category": "Account Manipulation",
    "desc": "A local group was deleted from the system",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4751,
    "name": "Security-Disabled Global Group Created",
    "category": "Active Directory",
    "desc": "A distribution or security-disabled global group was created",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4752,
    "name": "Security-Disabled Global Group Modified",
    "category": "Active Directory",
    "desc": "A distribution or security-disabled global group was modified",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4753,
    "name": "Security-Disabled Global Group Deleted",
    "category": "Active Directory",
    "desc": "A distribution or security-disabled global group was deleted",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4754,
    "name": "Security-Enabled Universal Group Created",
    "category": "Account Manipulation",
    "desc": "A security-enabled universal group was created in AD",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4755,
    "name": "Universal Security Group Modified",
    "category": "Active Directory",
    "desc": "A security-enabled universal group was modified",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4756,
    "name": "Member Added to Universal Security Group",
    "category": "Privilege Escalation",
    "desc": "A member was added to a security-enabled universal group (Enterprise Admins)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4757,
    "name": "Member Removed from Universal Group",
    "category": "Active Directory",
    "desc": "A member was removed from a security-enabled universal group",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4758,
    "name": "Security-Enabled Universal Group Deleted",
    "category": "Account Manipulation",
    "desc": "A security-enabled universal group was deleted from AD",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4764,
    "name": "Group Type Changed",
    "category": "Active Directory",
    "desc": "A group's type was changed between security and distribution group",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4765,
    "name": "SID History Added to Account",
    "category": "Privilege Escalation",
    "desc": "SID history was added to an account (Golden Ticket / persistence vector)",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 4766,
    "name": "Attempt to Add SID History Failed",
    "category": "Privilege Escalation",
    "desc": "An attempt to add SID history to an account failed",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 4767,
    "name": "User Account Unlocked",
    "category": "Account Manipulation",
    "desc": "A locked-out user account was unlocked by an administrator",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4768,
    "name": "Kerberos TGT Request",
    "category": "Kerberos / Identity",
    "desc": "A Kerberos authentication ticket (TGT) was requested",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4769,
    "name": "Kerberos Service Ticket",
    "category": "Kerberos / Identity",
    "desc": "A Kerberos service ticket was requested (Kerberoasting vector)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4770,
    "name": "Kerberos Ticket Renewed",
    "category": "Kerberos / Identity",
    "desc": "A Kerberos ticket-granting ticket (TGT) was renewed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4771,
    "name": "Kerberos Pre-Authentication Failed",
    "category": "Kerberos / Identity",
    "desc": "Kerberos pre-authentication failed (potential password spray or AS-REP roasting)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4772,
    "name": "Kerberos Ticket Request Failed",
    "category": "Kerberos / Identity",
    "desc": "A Kerberos authentication ticket request failed",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4774,
    "name": "Account Mapped for Logon",
    "category": "Logon / Authentication",
    "desc": "An account was mapped for logon authentication",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4775,
    "name": "Could Not Map Account for Logon",
    "category": "Logon / Authentication",
    "desc": "An account could not be mapped for logon authentication",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4776,
    "name": "NTLM Authentication Attempt",
    "category": "Logon / Authentication",
    "desc": "The domain controller validated account credentials via NTLM",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4777,
    "name": "Domain Controller Failed to Validate Credentials",
    "category": "Logon / Authentication",
    "desc": "The domain controller failed to validate credentials for an account",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4778,
    "name": "RDP Session Reconnected",
    "category": "Remote Desktop",
    "desc": "An existing Remote Desktop Protocol session was reconnected",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4779,
    "name": "RDP Session Disconnected",
    "category": "Remote Desktop",
    "desc": "A Remote Desktop Protocol session was disconnected",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4780,
    "name": "ACL Set on Protected Admin Account (AdminSDHolder)",
    "category": "Privilege Escalation",
    "desc": "Access control list was updated on an administrative account by the AdminSDHolder background task",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4781,
    "name": "Account Name Changed",
    "category": "Account Manipulation",
    "desc": "The name of a user or computer account was renamed",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4782,
    "name": "Password Hash of Account Accessed",
    "category": "Credential Access",
    "desc": "The password hash display API was invoked to access account secrets",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4793,
    "name": "Password Policy Checking API Called",
    "category": "Credential Access",
    "desc": "Password policy validation API was invoked",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4794,
    "name": "DSRM Administrator Password Set",
    "category": "Active Directory",
    "desc": "An attempt was made to set the Directory Services Restore Mode administrator password",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 4797,
    "name": "Query for Blank Password Accounts",
    "category": "Credential Access",
    "desc": "An attempt was made to query accounts with blank passwords",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4798,
    "name": "Local Group Membership Enumerated",
    "category": "Discovery / Reconnaissance",
    "desc": "A user's local group membership was enumerated (Discovery / BloodHound)",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4799,
    "name": "Security-Enabled Group Enumerated",
    "category": "Discovery / Reconnaissance",
    "desc": "A security-enabled local group membership was enumerated (Reconnaissance)",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4800,
    "name": "Workstation Locked",
    "category": "Logon / Authentication",
    "desc": "The workstation screen was locked",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4801,
    "name": "Workstation Unlocked",
    "category": "Logon / Authentication",
    "desc": "The workstation screen was unlocked",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4802,
    "name": "Screen Saver Invoked",
    "category": "System",
    "desc": "The screen saver was invoked by the operating system",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4803,
    "name": "Screen Saver Dismissed",
    "category": "System",
    "desc": "The screen saver was dismissed by user interaction",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4817,
    "name": "Auditing Settings on Object Changed",
    "category": "Policy & Auditing",
    "desc": "Auditing settings on an Active Directory or filesystem object were changed",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4820,
    "name": "Kerberos TGT Denied Device Restriction",
    "category": "Kerberos / Identity",
    "desc": "Kerberos TGT denied because the device does not meet authentication policy restrictions",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4825,
    "name": "RDP Connection Denied by Policy",
    "category": "Remote Desktop",
    "desc": "A Remote Desktop user access attempt was denied by system policy",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4826,
    "name": "Boot Configuration Data Loaded",
    "category": "System Lifecycle",
    "desc": "Boot Configuration Data (BCD) was loaded during operating system startup",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4864,
    "name": "Kerberos End-to-End Namespace Conflict",
    "category": "Kerberos / Identity",
    "desc": "Kerberos end-to-end forest trust detected namespace collision",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4876,
    "name": "Certificate Services Backup Started",
    "category": "Certificate Services",
    "desc": "Certificate Services backup started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4877,
    "name": "Certificate Services Backup Completed",
    "category": "Certificate Services",
    "desc": "Certificate Services backup completed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4878,
    "name": "Certificate Services Restore Started",
    "category": "Certificate Services",
    "desc": "Certificate Services restore started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4879,
    "name": "Certificate Services Restore Completed",
    "category": "Certificate Services",
    "desc": "Certificate Services restore completed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4882,
    "name": "Certificate Services Security Permissions Changed",
    "category": "Certificate Services",
    "desc": "Security permissions on the Certificate Authority (ADCS) were modified (ESC7 vulnerability)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4885,
    "name": "Certificate Services Data Recovery Agent Changed",
    "category": "Certificate Services",
    "desc": "ADCS data recovery agent certificate was replaced",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4886,
    "name": "Certificate Request Approved",
    "category": "Certificate Services",
    "desc": "Certificate Services approved a certificate request",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4887,
    "name": "Certificate Issued",
    "category": "Certificate Services",
    "desc": "Certificate Services issued a certificate (potential ADCS ESC1-ESC8 abuse)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4888,
    "name": "Certificate Request Denied",
    "category": "Certificate Services",
    "desc": "Certificate Services denied a certificate request",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4889,
    "name": "Certificate Services Request Set to Pending",
    "category": "Certificate Services",
    "desc": "ADCS marked a certificate enrollment request as pending administrative approval",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4890,
    "name": "Certificate Services Settings Changed",
    "category": "Certificate Services",
    "desc": "Configuration manager settings for Active Directory Certificate Services were modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4891,
    "name": "Certificate Services Config Entry Changed",
    "category": "Certificate Services",
    "desc": "A registry configuration entry for Certificate Services was modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4892,
    "name": "Certificate Services Property Changed",
    "category": "Certificate Services",
    "desc": "A CA property or extension parameter was updated",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4895,
    "name": "CA Certificate Published to Active Directory",
    "category": "Certificate Services",
    "desc": "Certificate Services published a CA certificate to Active Directory Domain Services",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4896,
    "name": "Rows Deleted from CA Database",
    "category": "Anti-Forensics",
    "desc": "One or more certificate issuance or revocation rows were purged from CA database",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4897,
    "name": "Certificate Services Role Separation Enabled",
    "category": "Certificate Services",
    "desc": "Role separation security enforcement was enabled on the CA",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4898,
    "name": "Certificate Template Loaded",
    "category": "Certificate Services",
    "desc": "Certificate Services loaded an X.509 certificate template into memory",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4902,
    "name": "Per-User Audit Policy Table Created",
    "category": "Policy & Auditing",
    "desc": "A per-user security audit policy table was initialized",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4904,
    "name": "Security Event Source Registered",
    "category": "Policy & Auditing",
    "desc": "An attempt was made to register a new security event source provider",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4905,
    "name": "Security Event Source Unregistered",
    "category": "Policy & Auditing",
    "desc": "An attempt was made to unregister a security event source provider",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4906,
    "name": "CrashOnAuditFail Value Changed",
    "category": "Anti-Forensics",
    "desc": "CrashOnAuditFail registry key was modified (system halting on audit failure disabled)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4907,
    "name": "Auditing Settings on Object Changed",
    "category": "Policy & Auditing",
    "desc": "Object audit SACL settings were modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4908,
    "name": "Special Groups Logon Table Modified",
    "category": "Privilege Escalation",
    "desc": "Special Groups logon tracking table was modified",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 4912,
    "name": "Per-User Audit Policy Table Modified",
    "category": "Policy & Auditing",
    "desc": "Per-user audit policy entries were modified",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4928,
    "name": "AD Replica Source Context Established",
    "category": "Active Directory",
    "desc": "Active Directory replica source naming context was established",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4929,
    "name": "AD Replica Source Context Removed",
    "category": "Active Directory",
    "desc": "Active Directory replica source naming context was removed",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4930,
    "name": "AD Replica Source Context Modified",
    "category": "Active Directory",
    "desc": "Active Directory replica source naming context was modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4931,
    "name": "AD Destination Context Modified",
    "category": "Active Directory",
    "desc": "Active Directory destination naming context was modified",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4932,
    "name": "AD Replication Sync Begun",
    "category": "Active Directory",
    "desc": "Active Directory naming context synchronization begun",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4933,
    "name": "AD Replication Sync Ended",
    "category": "Active Directory",
    "desc": "Active Directory naming context synchronization completed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4934,
    "name": "AD Replica Object Attributes Replicated",
    "category": "Active Directory",
    "desc": "Attributes of an AD replica object were replicated across domain controllers",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4935,
    "name": "AD Replication Failure Begins",
    "category": "Active Directory",
    "desc": "Active Directory replication failure condition started",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 4936,
    "name": "AD Replication Failure Ends",
    "category": "Active Directory",
    "desc": "Active Directory replication failure condition resolved",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4937,
    "name": "Lingering Object Removed from Replica",
    "category": "Active Directory",
    "desc": "A lingering tombstone object was removed from an Active Directory replica",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4944,
    "name": "Firewall Rule Active on Startup",
    "category": "Firewall / WFP",
    "desc": "A Windows Firewall rule was active when the Windows Firewall service started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4945,
    "name": "Rule Listed on Firewall Startup",
    "category": "Firewall / WFP",
    "desc": "A rule was listed when Windows Firewall started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4946,
    "name": "Rule Added to Firewall Exception List",
    "category": "Firewall / WFP",
    "desc": "A new port/application rule was added to the Windows Firewall exception list",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4947,
    "name": "Rule Modified in Firewall Exception List",
    "category": "Firewall / WFP",
    "desc": "A rule in the Windows Firewall exception list was modified",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4948,
    "name": "Rule Deleted from Firewall Exception List",
    "category": "Firewall / WFP",
    "desc": "A rule was removed from the Windows Firewall exception list",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4950,
    "name": "Windows Firewall Setting Changed",
    "category": "Firewall / WFP",
    "desc": "A global Windows Firewall setting (state, inbound/outbound action) was modified",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4951,
    "name": "Firewall Rule Ignored (Version Conflict)",
    "category": "Firewall / WFP",
    "desc": "Windows Firewall rule ignored due to unrecognized major version",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4952,
    "name": "Firewall Rule Minor Version Ignored",
    "category": "Firewall / WFP",
    "desc": "Parts of firewall rule ignored due to unrecognized minor version",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4953,
    "name": "Firewall Rule Parse Error",
    "category": "Firewall / WFP",
    "desc": "Firewall rule ignored because it could not be parsed",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4954,
    "name": "Firewall Group Policy Restored",
    "category": "Firewall / WFP",
    "desc": "Windows Firewall Group Policy settings were restored",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 4956,
    "name": "Active Firewall Profile Changed",
    "category": "Firewall / WFP",
    "desc": "Active Windows Firewall profile switched (Domain, Private, or Public profile)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 4957,
    "name": "Firewall Rule Not Applied",
    "category": "Firewall / WFP",
    "desc": "Windows Firewall did not apply rule",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4958,
    "name": "Firewall Rule Not Applied (Unconfigured)",
    "category": "Firewall / WFP",
    "desc": "Windows Firewall did not apply rule because item is not configured",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 4964,
    "name": "Special Group Assigned to Logon",
    "category": "Privilege Escalation",
    "desc": "A special administrative group was assigned to a new logon session",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 5000,
    "name": "Defender Real-Time Enabled",
    "category": "Antivirus",
    "desc": "Microsoft Defender Antivirus real-time protection was enabled",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5001,
    "name": "Defender Real-Time Protection Disabled",
    "category": "Defense Evasion",
    "desc": "Microsoft Defender Antivirus real-time protection was disabled",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 5004,
    "name": "Defender Configuration Changed",
    "category": "Defense Evasion",
    "desc": "Microsoft Defender Antivirus configuration settings were modified",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 5007,
    "name": "Defender Configuration Tampered",
    "category": "Defense Evasion",
    "desc": "Microsoft Defender Antivirus configuration was tampered with or modified",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 5024,
    "name": "Windows Firewall Service Started",
    "category": "Policy & Firewall",
    "desc": "The Windows Firewall service has started successfully",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5025,
    "name": "Windows Firewall Service Stopped",
    "category": "Policy & Firewall",
    "desc": "The Windows Firewall service has been stopped",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 5031,
    "name": "Windows Firewall Blocked Application",
    "category": "Policy & Firewall",
    "desc": "Windows Firewall blocked an application from accepting incoming network traffic",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5038,
    "name": "Code Integrity Hash Invalid",
    "category": "Defense Evasion",
    "desc": "Code integrity determined that the image hash of a file is not valid (unsigned or tampered binary)",
    "severity": "high",
    "isCurated": true
  },
  {
    "id": 5058,
    "name": "Key File Operation",
    "category": "Cryptographic Services",
    "desc": "Cryptographic service provider performed an operation on a key file",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5059,
    "name": "Key Migration Operation",
    "category": "Cryptographic Services",
    "desc": "Cryptographic key migration operation was performed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5061,
    "name": "Cryptographic Operation",
    "category": "Cryptographic Services",
    "desc": "A cryptographic operation (key generation, signature, encryption) was logged",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5136,
    "name": "Directory Service Object Modified",
    "category": "Active Directory",
    "desc": "A directory service object (user, computer, GPO, ACL) was modified in Active Directory",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 5137,
    "name": "Directory Service Object Created",
    "category": "Active Directory",
    "desc": "A directory service object was created in Active Directory",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 5138,
    "name": "Directory Service Object Undeleted",
    "category": "Active Directory",
    "desc": "A directory service object was restored/undeleted from the AD Recycle Bin",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 5139,
    "name": "Directory Service Object Moved",
    "category": "Active Directory",
    "desc": "A directory service object was moved to another organizational unit (OU)",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 5140,
    "name": "Network Share Object Accessed",
    "category": "Lateral Movement",
    "desc": "A network share object was accessed (SMB lateral movement connection)",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 5141,
    "name": "Directory Service Object Deleted",
    "category": "Active Directory",
    "desc": "A directory service object was deleted from Active Directory",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5142,
    "name": "Network Share Added",
    "category": "Lateral Movement",
    "desc": "A new network share object was added to the host",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 5143,
    "name": "Network Share Modified",
    "category": "Lateral Movement / Shares",
    "desc": "A network share configuration or security descriptor was modified",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5144,
    "name": "Network Share Deleted",
    "category": "Lateral Movement",
    "desc": "A network share object was deleted from the host",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5145,
    "name": "Network Share Detailed Access Check",
    "category": "Lateral Movement",
    "desc": "A network share was checked to see whether client has desired access rights (SMB file copying/staging)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5156,
    "name": "Firewall Connection Allowed",
    "category": "Network Communication",
    "desc": "The Windows Filtering Platform permitted an inbound or outbound network connection",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5158,
    "name": "WFP Bind to Local Port",
    "category": "Network Communication",
    "desc": "The Windows Filtering Platform permitted binding to a local port",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5376,
    "name": "Credential Manager Credentials Backed Up",
    "category": "Credential Access",
    "desc": "Credentials stored in Windows Credential Manager were backed up",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 5377,
    "name": "Credential Manager Credentials Restored",
    "category": "Credential Access",
    "desc": "Credentials in Windows Credential Manager were restored from backup",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5378,
    "name": "Requested Credentials Read from Credential Manager",
    "category": "Credential Access",
    "desc": "Stored credentials were read from Windows Credential Manager",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 5379,
    "name": "Credential Manager Read",
    "category": "Credential Access",
    "desc": "Credentials were read from Windows Credential Manager",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 5440,
    "name": "WFP Callout Present on Startup",
    "category": "Firewall / WFP",
    "desc": "A Windows Filtering Platform callout driver was present when Base Filtering Engine started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 5447,
    "name": "WFP Filter Changed",
    "category": "Policy & Firewall",
    "desc": "A Windows Filtering Platform (WFP) network packet filter was changed",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6005,
    "name": "Event Log Service Started (System Boot)",
    "category": "System Lifecycle",
    "desc": "The Windows Event Log service was started (host booted up)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6006,
    "name": "Event Log Service Stopped (Clean Shutdown)",
    "category": "System Lifecycle",
    "desc": "The Windows Event Log service was stopped (clean host shutdown)",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6008,
    "name": "Unexpected System Shutdown",
    "category": "System Lifecycle",
    "desc": "The previous system shutdown was unexpected (crash, blue screen, power loss)",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 6009,
    "name": "Operating System Version at Boot",
    "category": "System Lifecycle",
    "desc": "Windows kernel build, version, and architecture detected during operating system boot",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6013,
    "name": "System Uptime",
    "category": "System Lifecycle",
    "desc": "System uptime reported in seconds",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6272,
    "name": "Network Policy Server Granted Access",
    "category": "RADIUS / Network",
    "desc": "Network Policy Server (NPS) granted full network access to client",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6273,
    "name": "Network Policy Server Denied Access",
    "category": "RADIUS / Network",
    "desc": "Network Policy Server (NPS) denied network access to client (failed 802.1X/VPN auth)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 6274,
    "name": "Network Policy Server Discarded Request",
    "category": "RADIUS / Network",
    "desc": "NPS discarded authentication request",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 6278,
    "name": "Network Policy Server Full Access Granted",
    "category": "RADIUS / Network",
    "desc": "Network Policy Server granted full access to client without quarantine restrictions",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 6416,
    "name": "New External Device Recognized",
    "category": "USB / Device Control",
    "desc": "A new external device (USB flash drive, external disk, peripheral) was recognized by system",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 6419,
    "name": "Device Disabling Request Made",
    "category": "USB / Device Control",
    "desc": "A request was made to disable a Plug and Play hardware device",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 6420,
    "name": "Device Was Disabled",
    "category": "USB / Device Control",
    "desc": "A Plug and Play hardware device was disabled",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 6421,
    "name": "Device Enabling Request Made",
    "category": "USB / Device Control",
    "desc": "A request was made to enable a Plug and Play hardware device",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 6422,
    "name": "Device Was Enabled",
    "category": "USB / Device Control",
    "desc": "A Plug and Play hardware device was enabled",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 6423,
    "name": "Device Installation Forbidden by Policy",
    "category": "USB / Device Control",
    "desc": "Installation of external device was blocked by system group policy",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 6424,
    "name": "Device Installation Permitted by Policy",
    "category": "USB / Device Control",
    "desc": "Installation of device was permitted after prior policy exclusion",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 7000,
    "name": "Service Failed to Start",
    "category": "Services",
    "desc": "Service Control Manager failed to start a service",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7001,
    "name": "Service Logon Failure",
    "category": "Services",
    "desc": "Service failed to log on due to logon failure (bad account credentials)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 7009,
    "name": "Service Timeout During Connect",
    "category": "Services",
    "desc": "Service Control Manager timed out waiting for service to connect",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 7022,
    "name": "Service Hung on Starting",
    "category": "Services",
    "desc": "A service hung during startup initialization",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7023,
    "name": "Service Terminated with Error",
    "category": "Services",
    "desc": "A service terminated with a fatal win32 error",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7024,
    "name": "Service Terminated with Service-Specific Error",
    "category": "Services",
    "desc": "A service terminated with a service-specific exit code",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7026,
    "name": "Boot-Start Driver Failed to Load",
    "category": "Services / Drivers",
    "desc": "One or more boot-start or system-start drivers failed to load",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7030,
    "name": "Service Marked as Interactive",
    "category": "Services",
    "desc": "A service was configured to interact with the desktop",
    "severity": "low",
    "isCurated": false
  },
  {
    "id": 7031,
    "name": "Service Crashed Unexpectedly",
    "category": "Services",
    "desc": "A service terminated unexpectedly and SCM executed failure actions",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 7032,
    "name": "SCM Took Recovery Action",
    "category": "Services",
    "desc": "Service Control Manager took recovery action after service failure",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7034,
    "name": "Service Terminated Unexpectedly",
    "category": "Services",
    "desc": "A service terminated unexpectedly (crash, kill, or malicious evasion)",
    "severity": "medium",
    "isCurated": true
  },
  {
    "id": 7036,
    "name": "Service State Changed",
    "category": "System",
    "desc": "A Windows service transitioned to stopped or running state",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 7040,
    "name": "Service Start Type Changed",
    "category": "Persistence / Service",
    "desc": "A Windows service start type was modified (e.g. disabled to manual/automatic)",
    "severity": "medium",
    "isCurated": false
  },
  {
    "id": 7045,
    "name": "New Service Installed",
    "category": "Persistence / Service",
    "desc": "A new Windows service was installed in the system",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 8001,
    "name": "AppLocker Policy Applied",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy was applied successfully to the computer",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 8002,
    "name": "AppLocker Executable Allowed",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy allowed binary executable (.exe, .dll) to run",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 8003,
    "name": "AppLocker Executable Audited (Would Block)",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy audited executable that would be blocked in enforce mode",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 8004,
    "name": "AppLocker Executable Prevented",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy blocked unauthorized binary executable from running",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 8005,
    "name": "AppLocker Script or MSI Allowed",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy allowed script (.ps1, .vbs, .bat) or MSI installer",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 8006,
    "name": "AppLocker Script Audited (Would Block)",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker policy audited script or installer that would be blocked in enforce mode",
    "severity": "high",
    "isCurated": false
  },
  {
    "id": 8007,
    "name": "AppLocker Script or MSI Prevented",
    "category": "AppLocker / Execution Control",
    "desc": "AppLocker blocked unauthorized script or MSI installer from executing",
    "severity": "critical",
    "isCurated": false
  },
  {
    "id": 11707,
    "name": "Application Installed Successfully",
    "category": "Software Installation",
    "desc": "Windows Installer installed an application successfully",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 20001,
    "name": "Device Driver Install Started",
    "category": "System / Drivers",
    "desc": "Device driver installation process started",
    "severity": "info",
    "isCurated": false
  },
  {
    "id": 20003,
    "name": "Device Driver Install Completed",
    "category": "System / Drivers",
    "desc": "Device driver installation completed successfully",
    "severity": "info",
    "isCurated": false
  }
];

export const CURATED_EVTX_EVENTS: KnownEvtxEvent[] = KNOWN_EVTX_EVENTS.filter((e) => e.isCurated);
export const EXTENDED_EVTX_EVENTS: KnownEvtxEvent[] = KNOWN_EVTX_EVENTS.filter((e) => !e.isCurated);
export const DEFAULT_EVTX_BASELINE_IDS: number[] = CURATED_EVTX_EVENTS.map((e) => e.id);

const EVENT_NAME_CACHE: Record<number, string> = {};
KNOWN_EVTX_EVENTS.forEach((e) => {
  EVENT_NAME_CACHE[e.id] = e.name;
});

export const getEventName = (id: number): string => {
  return EVENT_NAME_CACHE[id] || `Event ID ${id}`;
};

export const getEventDetails = (id: number): KnownEvtxEvent | undefined => {
  return KNOWN_EVTX_EVENTS.find((e) => e.id === id);
};
