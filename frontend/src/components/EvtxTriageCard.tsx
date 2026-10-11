import React, { useState, useMemo, useEffect } from 'react';
import {
  Clock,
  ShieldAlert,
  User,
  Monitor,
  Terminal,
  Search,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Zap,
  Activity,
  Lock,
  Skull,
  Calendar,
  Share2,
  Globe,
  Trash2,
  ShieldOff,
  Key,
  AlertTriangle,
  BarChart2,
  RefreshCw,
  BookOpen,
  Usb,
  FolderOpen,
  Printer,
  Radio,
  ExternalLink,
  Code2,
  Sparkles,
  CheckCircle2,
  X,
} from 'lucide-react';
import {
  EvtxInfo,
  EvtxThreatItem,
  EvtxTimelineEvent,
  AntiAnalysisInfo,
  EvtxDesktopStorylineItem,
  EvtxUsbDevice,
  EvtxFileAccessRecord,
  EvtxPrintRecord,
  EvtxRdpSession,
  EvtxDeobfuscatedCommand,
} from '../types';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import {
  formatTimestamp,
  formatBytes,
  getTimeDisplayConfig,
  setTimeDisplayConfig,
  TimeDisplayConfig,
} from '../utils/formatters';
import { ReferencedText } from './ReferencedFileLink';

interface EvtxTriageCardProps {
  evtxInfo?: EvtxInfo | null;
  filename: string;
  antiAnalysis?: AntiAnalysisInfo;
  workspaceJobs?: any[];
  onNavigateToPcap?: (pcapJobId?: string, targetIp?: string) => void;
  onSelectJob?: (newJobId: string) => void;
}

// Logon Type descriptive names
const LOGON_TYPE_NAMES: Record<string, string> = {
  '2': 'Interactive (Console Logon)',
  '3': 'Network (e.g. SMB / Share connection)',
  '4': 'Batch (Scheduled Script / Job)',
  '5': 'Service (Windows Service Startup)',
  '7': 'Unlock (Screen Unlocked)',
  '8': 'NetworkCleartext (Cleartext Credentials)',
  '9': 'NewCredentials (RunAs / Alternate Token)',
  '10': 'RemoteInteractive / RDP (Terminal Services)',
  '11': 'CachedInteractive (Domain Cached Creds)',
};

import { getEventName } from '../utils/knownEvtxEvents';

// PowerShell Base64 decoding helper (decodes Windows UTF-16LE with UTF-8 fallback)
export function decodePowerShellBase64(b64: string): string | null {
  try {
    const cleanB64 = b64.trim().replace(/\s+/g, '');
    const bin = atob(cleanB64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    // Windows PowerShell -EncodedCommand is UTF-16LE
    const decUtf16 = new TextDecoder('utf-16le').decode(bytes);
    if (decUtf16 && decUtf16.trim().length > 0 && !decUtf16.includes('\uFFFD')) {
      return decUtf16;
    }
    const decUtf8 = new TextDecoder('utf-8').decode(bytes);
    return decUtf8;
  } catch {
    return null;
  }
}

export function extractAndDecodePsCommand(cmd?: string): { decoded: string; rawB64: string; tokens_found: string[] } | null {
  if (!cmd) return null;
  const match = cmd.match(/(?:-encodedcommand|-enc|-e|-ec|\/enc)\s+([A-Za-z0-9+/=]{8,})/i);
  if (match && match[1]) {
    const decoded = decodePowerShellBase64(match[1]);
    if (decoded && decoded.trim().length > 0) {
      const lower = decoded.toLowerCase();
      const suspicious = [
        'downloadstring', 'downloaddata', 'downloadfile', 'invoke-expression', 'iex',
        'bypass', 'hidden', 'noninteractive', 'mimikatz', 'sharphound', 'amsiutils',
        'webrequest', 'curl', 'wget', 'certutil', 'bitstransfer', 'net user', 'rundll32'
      ];
      const tokens = suspicious.filter((t) => lower.includes(t));
      return { decoded: decoded.trim(), rawB64: match[1], tokens_found: tokens };
    }
  }
  return null;
}

// Safe severity badge styling
const getSeverityBadge = (sev?: string) => {
  const safeSev = (sev || 'info').toLowerCase();
  switch (safeSev) {
    case 'critical':
      return 'bg-rose-100 text-rose-800 border-rose-300';
    case 'high':
      return 'bg-orange-100 text-orange-800 border-orange-300';
    case 'medium':
      return 'bg-amber-100 text-amber-800 border-amber-300';
    case 'low':
      return 'bg-blue-100 text-blue-800 border-blue-300';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-300';
  }
};

// Custom Icon for Event Groups
const getEventIcon = (id: number) => {
  if (id === 1102 || id === 104) {
    return <Trash2 className="w-4 h-4 text-rose-600" />;
  }
  if (id === 5001) {
    return <ShieldOff className="w-4 h-4 text-rose-600" />;
  }
  if (id === 1116 || id === 1117) {
    return <Skull className="w-4 h-4 text-rose-500" />;
  }
  if (id === 4672 || id === 4728 || id === 4732 || id === 4756) {
    return <ShieldAlert className="w-4 h-4 text-orange-500" />;
  }
  if (id === 4720 || id === 4722 || id === 4724 || id === 4726) {
    return <User className="w-4 h-4 text-amber-600" />;
  }
  if (id === 4625) {
    return <Lock className="w-4 h-4 text-rose-500" />;
  }
  if (
    id === 4624 ||
    id === 4634 ||
    id === 4647 ||
    id === 4648 ||
    id === 4768 ||
    id === 4769 ||
    id === 4776
  ) {
    return <Key className="w-4 h-4 text-blue-500" />;
  }
  if (id === 4688 || id === 1 || id === 7) {
    return <Terminal className="w-4 h-4 text-emerald-500" />;
  }
  if (id === 4104 || id === 4103) {
    return <Zap className="w-4 h-4 text-cyan-500" />;
  }
  if (id === 7045 || id === 4697) {
    return <Activity className="w-4 h-4 text-purple-500" />;
  }
  if (id === 4698 || id === 4699 || id === 4700 || id === 4702) {
    return <Calendar className="w-4 h-4 text-indigo-500" />;
  }
  if (id === 5145 || id === 5140) {
    return <Share2 className="w-4 h-4 text-rose-500" />;
  }
  if (id === 3 || id === 5156) {
    return <Globe className="w-4 h-4 text-blue-500" />;
  }
  return <Clock className="w-4 h-4 text-slate-400" />;
};

// Fallback explanation for flagged events
const getWhyFlaggedExplanation = (ev: EvtxTimelineEvent): string => {
  const eid = ev.event_id;
  const sev = (ev.severity || 'info').toLowerCase();
  if (eid === 1102 || eid === 104) {
    return 'Security audit trail or system log was deliberately cleared (MITRE ATT&CK T1070.001 - Anti-Forensics to destroy intrusion evidence).';
  }
  if (eid === 5001) {
    return 'Microsoft Defender Antivirus Real-Time Protection was shut down (MITRE ATT&CK T1562.001 - Defense Evasion).';
  }
  if (eid === 4672) {
    return 'Elevated administrator privilege token granted to logon session (SeDebugPrivilege / SeTakeOwnershipPrivilege).';
  }
  if (eid === 4625) {
    return 'Authentication failure recorded. Repeated bursts indicate password spraying, brute force, or compromised service accounts.';
  }
  if (eid === 4728 || eid === 4732 || eid === 4756) {
    return 'Account added to sensitive privileged security group (e.g. Domain Admins, Local Administrators) - high risk privilege escalation.';
  }
  if (eid === 4720) {
    return 'New user account created on the host or active directory domain. Common mechanism for adversary backdoor persistence.';
  }
  if (eid === 7045 || eid === 4697) {
    return 'New Windows service registered on system. Adversaries install persistent services to establish survivable footholds.';
  }
  if (eid === 4698) {
    return 'New scheduled task created on the host for recurring code execution or reboot survivability.';
  }
  if (eid === 5145 || eid === 5140) {
    return 'Detailed access or file transfer check across SMB network shares (C$, ADMIN$). Classic vector for lateral movement payload delivery (PsExec, remote drops).';
  }
  if (eid === 4104) {
    return 'PowerShell script block executed on the host. Adversaries use PowerShell for discovery, cradles, and memory injection.';
  }
  if (eid === 4688 || eid === 1) {
    return 'Process creation with command line arguments. Living-off-the-land binaries (LOLBins) or scripting interpreters executed.';
  }
  if (sev === 'critical' || sev === 'high') {
    return `Security event classified as ${sev.toUpperCase()} severity under incident response monitoring policy.`;
  }
  return 'Flagged by forensic security heuristics as an unusual or high-risk activity indicator.';
};

export const EvtxTriageCard: React.FC<EvtxTriageCardProps> = ({
  evtxInfo,
  filename,
  antiAnalysis,
  workspaceJobs,
  onNavigateToPcap,
  onSelectJob,
}) => {
  if (!evtxInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-12 text-center shadow-sm">
        <RefreshCw className="w-8 h-8 text-indigo-600 animate-spin mx-auto mb-4" />
        <h3 className="text-base font-bold text-slate-800">Processing Windows Event Log Data</h3>
        <p className="text-xs text-slate-500 font-mono mt-1">Extracting security events, timelines, and threat vectors...</p>
      </div>
    );
  }

  const [activeTab, setActiveTab] = useState<
    | 'timeline'
    | 'storyline'
    | 'usb'
    | 'file_audit'
    | 'print_audit'
    | 'rdp'
    | 'deobfuscator'
    | 'threats'
    | 'entities'
    | 'lateral'
    | 'processes'
    | 'powershell'
    | 'logons'
    | 'persistence'
    | 'anti_analysis'
  >('timeline');
  const [fileAuditCategoryFilter, setFileAuditCategoryFilter] = useState<string>('all');
  const [fileAuditSearch, setFileAuditSearch] = useState<string>('');
  const [storylineCategoryFilter, setStorylineCategoryFilter] = useState<string>('all');
  const [selectedCorrelationEvent, setSelectedCorrelationEvent] = useState<any | null>(null);
  const [entitiesSubTab, setEntitiesSubTab] = useState<'all' | 'users' | 'computers' | 'ips' | 'shares' | 'processes'>('all');
  const [entitiesSearch, setEntitiesSearch] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedSourceFile, setSelectedSourceFile] = useState<string>('all');
  const [timeConfig, setTimeConfig] = useState<TimeDisplayConfig>(() => getTimeDisplayConfig());
  const [timelineMode, setTimelineMode] = useState<'monitored' | 'all'>('monitored');
  const [selectedTimeSlice, setSelectedTimeSlice] = useState<{
    start: number;
    end: number;
    label: string;
  } | null>(null);
  const [hoveredBin, setHoveredBin] = useState<any | null>(null);
  const [expandedEvents, setExpandedEvents] = useState<Record<number, boolean>>({});
  const [isAllExpanded, setIsAllExpanded] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/settings/time-display')
      .then((res) => res.json())
      .then((data) => {
        if (data && data.time_display) {
          setTimeDisplayConfig(data.time_display);
          setTimeConfig(data.time_display);
        } else if (data && data.format) {
          setTimeDisplayConfig(data);
          setTimeConfig(data);
        }
      })
      .catch(() => {});
  }, []);

  const toggleExpand = (idx: number) => {
    setExpandedEvents((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const toggleExpandAll = () => {
    const next = !isAllExpanded;
    setIsAllExpanded(next);
    const updated: Record<number, boolean> = {};
    if (next) {
      filteredTimeline.forEach((_, idx) => {
        updated[idx] = true;
      });
    }
    setExpandedEvents(updated);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const {
    total_records = 0,
    files_parsed = [],
    time_range = { earliest: null, latest: null },
    sensitive_event_counts = {},
    unique_users = [],
    unique_computers = [],
    unique_ips = [],
    threats = {
      anti_forensics: [],
      ransomware: [],
      privilege_escalation: [],
      brute_force: [],
      lateral_movement: [],
      process_creation: [],
      powershell: [],
      services_and_tasks: [],
      network_connections: [],
    },
    timeline = [],
    timeline_events = [],
    desktop_storyline = [],
    usb_history = [],
    file_access_audit = [],
    print_audit = [],
    rdp_sessions = [],
    deobfuscated_commands = [],
  } = evtxInfo || {};

  // Desktop Storyline memo with fallback derivation from timeline
  const desktopStoryline: EvtxDesktopStorylineItem[] = useMemo(() => {
    if (desktop_storyline && desktop_storyline.length > 0) {
      return desktop_storyline;
    }
    const derived: EvtxDesktopStorylineItem[] = [];
    const events = timeline_events && timeline_events.length > 0 ? timeline_events : timeline;
    for (const r of events || []) {
      const eid = r.event_id;
      const ts = r.timestamp || '';
      const u = r.user || 'Unknown';
      const comp = r.computer || 'Host';
      const dtls = r.details || {};
      if (eid === 4624) {
        derived.push({
          id: `story_${derived.length + 1}`,
          timestamp: ts,
          category: 'logon',
          title: `User Session Logon: ${u}`,
          description: `Interactive or network logon initialized on ${comp} (Logon Type ${r.logon_type || dtls.LogonType || '2'})`,
          user: u,
          computer: comp,
          severity: 'info',
          icon: 'user',
          event_ids: [eid],
          details: dtls
        });
      } else if (eid === 5001) {
        derived.push({
          id: `story_${derived.length + 1}`,
          timestamp: ts,
          category: 'defender_tampering',
          title: 'Windows Defender Real-Time Protection Disabled',
          description: 'Antivirus protection was shut down by administrative policy or command intervention',
          user: u,
          computer: comp,
          severity: 'critical',
          icon: 'shield-off',
          event_ids: [eid],
          details: dtls
        });
      } else if (eid === 1102 || eid === 104) {
        derived.push({
          id: `story_${derived.length + 1}`,
          timestamp: ts,
          category: 'log_cleared',
          title: 'Security Audit Log Cleared (Anti-Forensics)',
          description: `Event audit log purged by user '${u}' on ${comp} to remove forensic records`,
          user: u,
          computer: comp,
          severity: 'critical',
          icon: 'trash',
          event_ids: [eid],
          details: dtls
        });
      } else if (eid === 4634 || eid === 1074) {
        derived.push({
          id: `story_${derived.length + 1}`,
          timestamp: ts,
          category: 'logoff',
          title: `Session Logoff / Shutdown: ${u}`,
          description: `User session terminated or host shutdown on ${comp}`,
          user: u,
          computer: comp,
          severity: 'info',
          icon: 'lock',
          event_ids: [eid],
          details: dtls
        });
      }
    }
    derived.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    return derived;
  }, [desktop_storyline, timeline_events, timeline]);

  const filteredStoryline = useMemo(() => {
    if (storylineCategoryFilter === 'all') return desktopStoryline;
    return desktopStoryline.filter(s => s.category === storylineCategoryFilter);
  }, [desktopStoryline, storylineCategoryFilter]);

  const usbHistoryList: EvtxUsbDevice[] = useMemo(() => {
    return usb_history || [];
  }, [usb_history]);

  const fileAccessList: EvtxFileAccessRecord[] = useMemo(() => {
    return file_access_audit || [];
  }, [file_access_audit]);

  const filteredFileAccessAudit = useMemo(() => {
    let list = fileAccessList;
    if (fileAuditCategoryFilter !== 'all') {
      list = list.filter(f => f.file_category === fileAuditCategoryFilter);
    }
    if (fileAuditSearch.trim()) {
      const q = fileAuditSearch.toLowerCase();
      list = list.filter(f =>
        f.file_path.toLowerCase().includes(q) ||
        f.filename.toLowerCase().includes(q) ||
        f.user.toLowerCase().includes(q) ||
        f.process.toLowerCase().includes(q)
      );
    }
    return list;
  }, [fileAccessList, fileAuditCategoryFilter, fileAuditSearch]);

  const printAuditList: EvtxPrintRecord[] = useMemo(() => {
    return print_audit || [];
  }, [print_audit]);

  const rdpSessionsList: EvtxRdpSession[] = useMemo(() => {
    return rdp_sessions || [];
  }, [rdp_sessions]);

  const deobfuscatedCommandsList: EvtxDeobfuscatedCommand[] = useMemo(() => {
    return deobfuscated_commands || [];
  }, [deobfuscated_commands]);

  // Use timeline_events or timeline fallback
  const rawTimelineList: EvtxTimelineEvent[] = useMemo(() => {
    const list = timeline_events && timeline_events.length > 0 ? timeline_events : timeline;
    return list || [];
  }, [timeline_events, timeline]);

  // Extracted Forensic Entities (Accounts, Endpoints, IPs, Shares, Processes)
  const forensicEntities = useMemo(() => {
    const usersMap = new Map<string, {
      username: string;
      eventsCount: number;
      computers: Set<string>;
      logonTypes: Set<string>;
      ipAddresses: Set<string>;
      threatCount: number;
      sampleActions: string[];
      isPrivileged: boolean;
    }>();

    const computersMap = new Map<string, {
      hostname: string;
      eventsCount: number;
      users: Set<string>;
      sourceFiles: Set<string>;
      highestSeverity: string;
      ipAddresses: Set<string>;
    }>();

    const ipsMap = new Map<string, {
      ip: string;
      eventsCount: number;
      users: Set<string>;
      ports: Set<string>;
      computers: Set<string>;
      shares: Set<string>;
      highestSeverity: string;
    }>();

    const sharesMap = new Map<string, {
      shareName: string;
      eventsCount: number;
      clientIps: Set<string>;
      users: Set<string>;
      relativeTargets: Set<string>;
    }>();

    const processesMap = new Map<string, {
      processName: string;
      eventsCount: number;
      parentProcesses: Set<string>;
      users: Set<string>;
      commandLines: Set<string>;
      decodedCommands: Set<string>;
      isLolbin: boolean;
      highestSeverity: string;
    }>();

    const lolbinNames = [
      'powershell.exe', 'cmd.exe', 'certutil.exe', 'mshta.exe', 'wmic.exe',
      'rundll32.exe', 'regsvr32.exe', 'bitsadmin.exe', 'cscript.exe', 'wscript.exe',
      'psexec.exe', 'schtasks.exe', 'vssadmin.exe', 'sc.exe', 'net.exe', 'nltest.exe'
    ];

    unique_users.forEach((u) => {
      if (u && !usersMap.has(u)) {
        usersMap.set(u, {
          username: u,
          eventsCount: 0,
          computers: new Set(),
          logonTypes: new Set(),
          ipAddresses: new Set(),
          threatCount: 0,
          sampleActions: [],
          isPrivileged: u.toLowerCase().includes('admin') || u.toLowerCase().includes('system'),
        });
      }
    });

    unique_computers.forEach((c) => {
      if (c && !computersMap.has(c)) {
        computersMap.set(c, {
          hostname: c,
          eventsCount: 0,
          users: new Set(),
          sourceFiles: new Set(),
          highestSeverity: 'info',
          ipAddresses: new Set(),
        });
      }
    });

    unique_ips.forEach((ip) => {
      if (ip && !ipsMap.has(ip)) {
        ipsMap.set(ip, {
          ip,
          eventsCount: 0,
          users: new Set(),
          ports: new Set(),
          computers: new Set(),
          shares: new Set(),
          highestSeverity: 'info',
        });
      }
    });

    rawTimelineList.forEach((ev) => {
      const u = ev.user || ev.details?.TargetUserName || ev.details?.SubjectUserName;
      const c = ev.computer;
      const ip = ev.ip_address || ev.details?.IpAddress || ev.details?.SourceIp;
      const port = ev.ip_port || ev.details?.IpPort || ev.details?.SourcePort;
      const share = ev.share_name || ev.details?.ShareName;
      const relTarget = ev.relative_target_name || ev.details?.RelativeTargetName;
      const proc = ev.process_name || ev.details?.NewProcessName || ev.details?.Image;
      const parentProc = ev.parent_process || ev.details?.ParentProcessName;
      const cmd = ev.command_line || ev.details?.CommandLine;
      const decodedCmd = ev.decoded_command;
      const sev = (ev.severity || 'info').toLowerCase();
      const isThreat = ev.is_threat || ['critical', 'high'].includes(sev);

      if (u && u !== '-' && u !== 'N/A') {
        let uEntry = usersMap.get(u);
        if (!uEntry) {
          uEntry = {
            username: u,
            eventsCount: 0,
            computers: new Set(),
            logonTypes: new Set(),
            ipAddresses: new Set(),
            threatCount: 0,
            sampleActions: [],
            isPrivileged: u.toLowerCase().includes('admin') || u.toLowerCase().includes('system') || ev.event_id === 4672,
          };
          usersMap.set(u, uEntry);
        }
        uEntry.eventsCount += 1;
        if (c) uEntry.computers.add(c);
        if (ev.logon_type) uEntry.logonTypes.add(ev.logon_type);
        if (ip && ip !== '-' && ip !== '::1' && ip !== '127.0.0.1' && ip !== 'Local') uEntry.ipAddresses.add(ip);
        if (isThreat) uEntry.threatCount += 1;
        if (ev.event_id === 4672) uEntry.isPrivileged = true;
        if (uEntry.sampleActions.length < 3) {
          uEntry.sampleActions.push(`ID ${ev.event_id}: ${ev.summary || getEventName(ev.event_id)}`);
        }
      }

      if (c && c !== '-' && c !== 'N/A') {
        let cEntry = computersMap.get(c);
        if (!cEntry) {
          cEntry = {
            hostname: c,
            eventsCount: 0,
            users: new Set(),
            sourceFiles: new Set(),
            highestSeverity: 'info',
            ipAddresses: new Set(),
          };
          computersMap.set(c, cEntry);
        }
        cEntry.eventsCount += 1;
        if (u) cEntry.users.add(u);
        if (ev.source_file) cEntry.sourceFiles.add(ev.source_file);
        if (ip && ip !== '-' && ip !== '::1' && ip !== '127.0.0.1') cEntry.ipAddresses.add(ip);
        if (['critical', 'high'].includes(sev)) cEntry.highestSeverity = sev;
      }

      if (ip && ip !== '-' && ip !== '::1' && ip !== '127.0.0.1' && ip !== 'Local') {
        let ipEntry = ipsMap.get(ip);
        if (!ipEntry) {
          ipEntry = {
            ip,
            eventsCount: 0,
            users: new Set(),
            ports: new Set(),
            computers: new Set(),
            shares: new Set(),
            highestSeverity: 'info',
          };
          ipsMap.set(ip, ipEntry);
        }
        ipEntry.eventsCount += 1;
        if (u) ipEntry.users.add(u);
        if (port) ipEntry.ports.add(String(port));
        if (c) ipEntry.computers.add(c);
        if (share) ipEntry.shares.add(share);
        if (['critical', 'high'].includes(sev)) ipEntry.highestSeverity = sev;
      }

      if (share && share !== '-' && share !== 'N/A') {
        let sEntry = sharesMap.get(share);
        if (!sEntry) {
          sEntry = {
            shareName: share,
            eventsCount: 0,
            clientIps: new Set(),
            users: new Set(),
            relativeTargets: new Set(),
          };
          sharesMap.set(share, sEntry);
        }
        sEntry.eventsCount += 1;
        if (ip && ip !== '-' && ip !== 'Local') sEntry.clientIps.add(ip);
        if (u) sEntry.users.add(u);
        if (relTarget && relTarget !== '\\') sEntry.relativeTargets.add(relTarget);
      }

      if (proc && proc !== '-' && proc !== 'N/A') {
        const procBase = proc.split('\\').pop() || proc;
        let pEntry = processesMap.get(procBase);
        if (!pEntry) {
          pEntry = {
            processName: procBase,
            eventsCount: 0,
            parentProcesses: new Set(),
            users: new Set(),
            commandLines: new Set(),
            decodedCommands: new Set(),
            isLolbin: lolbinNames.includes(procBase.toLowerCase()),
            highestSeverity: 'info',
          };
          processesMap.set(procBase, pEntry);
        }
        pEntry.eventsCount += 1;
        if (parentProc) pEntry.parentProcesses.add(parentProc.split('\\').pop() || parentProc);
        if (u) pEntry.users.add(u);
        if (cmd) pEntry.commandLines.add(cmd);
        if (decodedCmd) pEntry.decodedCommands.add(decodedCmd);
        if (['critical', 'high'].includes(sev)) pEntry.highestSeverity = sev;
      }
    });

    return {
      users: Array.from(usersMap.values()).sort((a, b) => b.eventsCount - a.eventsCount),
      computers: Array.from(computersMap.values()).sort((a, b) => b.eventsCount - a.eventsCount),
      ips: Array.from(ipsMap.values()).sort((a, b) => b.eventsCount - a.eventsCount),
      shares: Array.from(sharesMap.values()).sort((a, b) => b.eventsCount - a.eventsCount),
      processes: Array.from(processesMap.values()).sort((a, b) => b.eventsCount - a.eventsCount),
    };
  }, [unique_users, unique_computers, unique_ips, rawTimelineList]);

  // Flattened threats list safely
  const allThreats = useMemo(() => {
    const list: EvtxThreatItem[] = [];
    Object.values(threats).forEach((tList) => {
      if (Array.isArray(tList)) {
        list.push(...tList);
      }
    });
    return list;
  }, [threats]);

  // Lateral movement list
  const lateralMovementList = useMemo(() => {
    if (threats.lateral_movement && threats.lateral_movement.length > 0) {
      return threats.lateral_movement;
    }
    return rawTimelineList.filter((ev) => ev.event_id === 5145 || ev.event_id === 5140);
  }, [threats.lateral_movement, rawTimelineList]);

  // Unique Event IDs in entire timeline for dropdown
  const eventIdsInTimeline = useMemo(() => {
    const s = new Set<number>();
    rawTimelineList.forEach((ev) => s.add(ev.event_id));
    return Array.from(s).sort((a, b) => a - b);
  }, [rawTimelineList]);

  // Time-based histogram binning for the distribution bar chart
  const { timeBins, maxBinCount } = useMemo(() => {
    const validWithTime = rawTimelineList
      .map((ev) => ({
        event: ev,
        time: ev.timestamp ? new Date(ev.timestamp).getTime() : NaN,
      }))
      .filter((item) => !isNaN(item.time))
      .sort((a, b) => a.time - b.time);

    if (validWithTime.length === 0) {
      return { timeBins: [], maxBinCount: 1 };
    }

    let minT = validWithTime[0].time;
    let maxT = validWithTime[validWithTime.length - 1].time;
    if (minT === maxT) {
      minT -= 30000;
      maxT += 30000;
    }

    const binCount = Math.min(32, Math.max(10, Math.floor(validWithTime.length / 25) || 12));
    const step = (maxT - minT) / binCount;

    const bins = [];
    for (let i = 0; i < binCount; i++) {
      const bStart = minT + i * step;
      const bEnd = minT + (i + 1) * step;
      const bEvents = validWithTime.filter(
        (p) => p.time >= bStart && (i === binCount - 1 ? p.time <= bEnd : p.time < bEnd)
      );

      const criticalCount = bEvents.filter(
        (p) => (p.event.severity || 'info').toLowerCase() === 'critical'
      ).length;
      const highCount = bEvents.filter(
        (p) => (p.event.severity || 'info').toLowerCase() === 'high'
      ).length;
      const mediumCount = bEvents.filter(
        (p) => (p.event.severity || 'info').toLowerCase() === 'medium'
      ).length;
      const threatCount = bEvents.filter(
        (p) =>
          p.event.is_threat ||
          ['critical', 'high'].includes((p.event.severity || 'info').toLowerCase())
      ).length;

      const eidMap: Record<number, number> = {};
      bEvents.forEach((p) => {
        eidMap[p.event.event_id] = (eidMap[p.event.event_id] || 0) + 1;
      });

      const label = `${new Date(bStart).toLocaleTimeString()} - ${new Date(
        bEnd
      ).toLocaleTimeString()}`;

      bins.push({
        idx: i,
        start: bStart,
        end: bEnd,
        label,
        count: bEvents.length,
        criticalCount,
        highCount,
        mediumCount,
        threatCount,
        eidMap,
      });
    }

    const maxCount = Math.max(...bins.map((b) => b.count), 1);
    return { timeBins: bins, maxBinCount: maxCount };
  }, [rawTimelineList]);

  // Filtered timeline based on all criteria
  const filteredTimeline = useMemo(() => {
    return rawTimelineList.filter((ev) => {
      // 1. Monitored vs All toggle
      if (timelineMode === 'monitored' && ev.is_monitored === false) {
        return false;
      }

      // 2. Source file filter (multi-evtx)
      if (selectedSourceFile !== 'all' && ev.source_file && ev.source_file !== selectedSourceFile) {
        return false;
      }

      // 3. Time slice filter from bar chart
      if (selectedTimeSlice && ev.timestamp) {
        const evTime = new Date(ev.timestamp).getTime();
        if (evTime < selectedTimeSlice.start || evTime > selectedTimeSlice.end) {
          return false;
        }
      }

      // 4. Event ID filter
      if (selectedEventId !== 'all' && String(ev.event_id) !== selectedEventId) {
        return false;
      }

      // 5. Severity filter
      if (
        selectedSeverity !== 'all' &&
        (ev.severity || 'info').toLowerCase() !== selectedSeverity.toLowerCase()
      ) {
        return false;
      }

      // 6. Search filter
      if (!searchFilter.trim()) return true;
      const q = searchFilter.toLowerCase();
      return (
        String(ev.event_id).includes(q) ||
        (ev.event_name && ev.event_name.toLowerCase().includes(q)) ||
        (ev.description && ev.description.toLowerCase().includes(q)) ||
        (ev.summary && ev.summary.toLowerCase().includes(q)) ||
        (ev.computer && ev.computer.toLowerCase().includes(q)) ||
        (ev.user && ev.user.toLowerCase().includes(q)) ||
        (ev.channel && ev.channel.toLowerCase().includes(q)) ||
        (ev.source_file && ev.source_file.toLowerCase().includes(q)) ||
        (ev.command_line && ev.command_line.toLowerCase().includes(q)) ||
        (ev.share_name && ev.share_name.toLowerCase().includes(q)) ||
        (ev.relative_target_name && ev.relative_target_name.toLowerCase().includes(q)) ||
        (ev.ip_address && ev.ip_address.toLowerCase().includes(q)) ||
        JSON.stringify(ev.details || {}).toLowerCase().includes(q)
      );
    });
  }, [
    rawTimelineList,
    timelineMode,
    selectedSourceFile,
    selectedTimeSlice,
    selectedEventId,
    selectedSeverity,
    searchFilter,
  ]);

  return (
    <div className="space-y-6">
      {/* Top Banner & Core Metrics */}
      <div className="p-6 bg-white text-slate-900 rounded-3xl shadow-sm border border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-blue-50 text-blue-700 border border-blue-200">
                Windows Event Log Forensics
              </span>
              {files_parsed.length > 1 && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-purple-50 text-purple-700 border border-purple-200 font-semibold">
                  {files_parsed.length} .evtx files parsed (Unified Timeline)
                </span>
              )}
            </div>
            <h3 className="text-xl font-bold font-mono tracking-tight text-slate-900 flex items-center gap-2">
              <Terminal className="w-5 h-5 text-indigo-600" />
              <span>{filename}</span>
            </h3>
            {time_range.earliest && time_range.latest && (
              <p className="text-xs text-slate-500 mt-1 flex items-center gap-2 font-mono">
                <Calendar className="w-3.5 h-3.5 text-slate-400" />
                <span>
                  {formatTimestamp(time_range.earliest, timeConfig)} —{' '}
                  {formatTimestamp(time_range.latest, timeConfig)}
                </span>
              </p>
            )}
          </div>

          <div className="flex items-center gap-3">
            {allThreats.length > 0 && (
              <div className="px-4 py-2 bg-rose-50 border border-rose-200 rounded-2xl flex items-center gap-2 text-rose-800 font-bold text-xs shadow-2xs">
                <Skull className="w-4 h-4 text-rose-600 animate-pulse" />
                <span>{allThreats.length} Threat Indicators Flagged</span>
              </div>
            )}
          </div>
        </div>

        {/* 5 Summary Counters */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-5 text-xs">
          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
              Total Log Records
            </span>
            <span className="text-2xl font-black font-mono text-slate-900">
              {total_records.toLocaleString()}
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
              Timeline Events
            </span>
            <span className="text-2xl font-black font-mono text-indigo-600">
              {rawTimelineList.length.toLocaleString()}
            </span>
          </div>

          <div
            onClick={() => {
              setEntitiesSubTab('users');
              setActiveTab('entities');
            }}
            className="p-3 bg-slate-50 hover:bg-amber-50/70 border border-slate-200/80 hover:border-amber-300 rounded-2xl transition-all cursor-pointer group"
            title="Click to view detailed Accounts and Users list"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">
                Accounts &amp; Users
              </span>
              <span className="text-[10px] text-amber-600 opacity-0 group-hover:opacity-100 font-bold transition-opacity">
                View →
              </span>
            </div>
            <span className="text-2xl font-black font-mono text-amber-700">
              {unique_users.length}
            </span>
            <span
              className="text-[10px] text-slate-400 block truncate mt-0.5"
              title={unique_users.join(', ')}
            >
              {unique_users.slice(0, 3).join(', ') || 'N/A'}
            </span>
          </div>

          <div
            onClick={() => {
              setEntitiesSubTab('computers');
              setActiveTab('entities');
            }}
            className="p-3 bg-slate-50 hover:bg-emerald-50/70 border border-slate-200/80 hover:border-emerald-300 rounded-2xl transition-all cursor-pointer group"
            title="Click to view detailed Endpoints list"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">
                Endpoints
              </span>
              <span className="text-[10px] text-emerald-600 opacity-0 group-hover:opacity-100 font-bold transition-opacity">
                View →
              </span>
            </div>
            <span className="text-2xl font-black font-mono text-emerald-700">
              {unique_computers.length}
            </span>
            <span
              className="text-[10px] text-slate-400 block truncate mt-0.5"
              title={unique_computers.join(', ')}
            >
              {unique_computers.slice(0, 2).join(', ') || 'N/A'}
            </span>
          </div>

          <div
            onClick={() => {
              setEntitiesSubTab('ips');
              setActiveTab('entities');
            }}
            className="p-3 bg-slate-50 hover:bg-purple-50/70 border border-slate-200/80 hover:border-purple-300 rounded-2xl transition-all cursor-pointer group"
            title="Click to view detailed IP Addresses and Network Indicators"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">
                Unique IP Addrs
              </span>
              <span className="text-[10px] text-purple-600 opacity-0 group-hover:opacity-100 font-bold transition-opacity">
                View →
              </span>
            </div>
            <span className="text-2xl font-black font-mono text-purple-700">
              {unique_ips.length}
            </span>
            <span
              className="text-[10px] text-slate-400 block truncate mt-0.5"
              title={unique_ips.join(', ')}
            >
              {unique_ips.slice(0, 2).join(', ') || 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* Sensitive Event IDs Quick-Filter Strip */}
      <div className="p-4 bg-white border border-slate-200 rounded-3xl shadow-xs">
        <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block mb-2.5">
          High-Value &amp; Sensitive Security Event IDs:
        </span>
        <div className="flex flex-wrap gap-2">
          {Object.entries(sensitive_event_counts).map(([eid, count]) => {
            const isSelected = selectedEventId === eid;
            return (
              <button
                key={eid}
                onClick={() => {
                  setSelectedEventId(isSelected ? 'all' : eid);
                  setActiveTab('timeline');
                }}
                className={`px-3 py-1.5 rounded-xl border text-xs font-mono font-bold flex items-center gap-2 transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600 text-white border-blue-700 shadow-sm'
                    : count > 0
                    ? 'bg-slate-50 hover:bg-slate-100 text-slate-800 border-slate-200'
                    : 'bg-slate-50/50 text-slate-400 border-slate-100'
                }`}
              >
                <span>Event {eid}</span>
                <span className="text-[10px] font-normal text-slate-500 truncate max-w-[130px]">
                  ({getEventName(Number(eid))})
                </span>
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                    isSelected
                      ? 'bg-white/20 text-white'
                      : count > 0
                      ? 'bg-indigo-100 text-indigo-800'
                      : 'bg-slate-200 text-slate-600'
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-7 shadow-xs">
        <div className="flex border-b border-slate-200 gap-2 mb-6 overflow-x-auto">
          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'timeline'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Forensic Event Timeline</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {filteredTimeline.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('threats')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'threats'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Threat Vector Findings</span>
            {allThreats.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-rose-100 text-rose-800 font-mono font-bold">
                {allThreats.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('storyline')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'storyline'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <BookOpen className="w-4 h-4 text-indigo-600" />
            <span>Desktop Storyline</span>
            {desktopStoryline.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-indigo-100 text-indigo-800 font-mono font-bold">
                {desktopStoryline.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('usb')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'usb'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Usb className="w-4 h-4 text-emerald-600" />
            <span>USB &amp; Hardware</span>
            {usbHistoryList.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-emerald-100 text-emerald-800 font-mono font-bold">
                {usbHistoryList.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('file_audit')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'file_audit'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FolderOpen className="w-4 h-4 text-amber-600" />
            <span>File &amp; Share Audit</span>
            {fileAccessList.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-amber-100 text-amber-800 font-mono font-bold">
                {fileAccessList.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('print_audit')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'print_audit'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Printer className="w-4 h-4 text-slate-700" />
            <span>Print Spooler</span>
            {printAuditList.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200 text-slate-800 font-mono font-bold">
                {printAuditList.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('rdp')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'rdp'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Radio className="w-4 h-4 text-purple-600" />
            <span>RDP Sessions</span>
            {rdpSessionsList.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-purple-100 text-purple-800 font-mono font-bold">
                {rdpSessionsList.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('deobfuscator')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'deobfuscator'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Code2 className="w-4 h-4 text-rose-600" />
            <span>Command De-obfuscator</span>
            {deobfuscatedCommandsList.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-rose-100 text-rose-800 font-mono font-bold">
                {deobfuscatedCommandsList.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('entities')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'entities'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <User className="w-4 h-4 text-amber-600" />
            <span>Endpoints, Accounts &amp; Indicators</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-amber-100 text-amber-800 font-mono font-bold">
              {unique_users.length + unique_computers.length + unique_ips.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('lateral')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'lateral'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Share2 className="w-4 h-4 text-rose-600" />
            <span>SMB Lateral Movement</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {lateralMovementList.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('processes')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'processes'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Zap className="w-4 h-4" />
            <span>Process Creation &amp; LOLBins</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {threats.process_creation?.length || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('powershell')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'powershell'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>PowerShell Script Blocks</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {threats.powershell?.length || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('logons')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'logons'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Logons &amp; Brute Force</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {threats.brute_force?.length || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('persistence')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'persistence'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Services &amp; Scheduled Tasks</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {threats.services_and_tasks?.length || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('anti_analysis')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'anti_analysis'
                ? 'bg-rose-50 text-rose-700 border-b-2 border-rose-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <span>Anti-Forensics &amp; Tampering</span>
            {Boolean(antiAnalysis?.techniques && antiAnalysis.techniques.length > 0) && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-rose-600 text-white font-mono font-bold">
                {antiAnalysis?.techniques.length}
              </span>
            )}
          </button>
        </div>

        {/* Tab 1: Forensic Timeline */}
        {activeTab === 'timeline' && (
          <div className="space-y-5">
            {/* Interactive Time Distribution Bar Chart */}
            {timeBins.length > 0 && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-3xl space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-indigo-600" />
                    <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Event Distribution Over Time
                    </span>
                    <span className="text-[11px] text-slate-500 font-medium">
                      (Horizontal: Time • Vertical: Event Count • Click bar to isolate period)
                    </span>
                  </div>

                  {selectedTimeSlice && (
                    <div className="flex items-center gap-2 self-start sm:self-auto">
                      <span className="px-2.5 py-1 text-xs font-bold bg-indigo-100 text-indigo-800 rounded-xl border border-indigo-200 flex items-center gap-1.5">
                        <span>Time Slice: {selectedTimeSlice.label}</span>
                        <button
                          onClick={() => setSelectedTimeSlice(null)}
                          className="text-indigo-400 hover:text-rose-600 cursor-pointer text-sm font-bold"
                          title="Clear time filter"
                        >
                          ✕
                        </button>
                      </span>
                    </div>
                  )}
                </div>

                {/* Histogram Bars Container */}
                <div className="relative pt-4 pb-2">
                  {/* Floating Popover on Hover */}
                  {hoveredBin && (
                    <div
                      className="absolute z-20 p-3 bg-white text-slate-800 rounded-xl shadow-xl border border-slate-200 text-xs space-y-1 pointer-events-none animate-modal-fade"
                      style={{
                        left: `${Math.min(
                          Math.max(10, (hoveredBin.idx / timeBins.length) * 100),
                          75
                        )}%`,
                        bottom: '105%',
                      }}
                    >
                      <div className="font-bold text-indigo-600 font-mono text-[11px]">
                        {hoveredBin.label}
                      </div>
                      <div className="text-slate-900 font-semibold">
                        Events: {hoveredBin.count.toLocaleString()}
                      </div>
                      {hoveredBin.threatCount > 0 && (
                        <div className="text-rose-600 font-bold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          <span>{hoveredBin.threatCount} Flagged Threat Events</span>
                        </div>
                      )}
                      <div className="pt-1 border-t border-slate-100 text-[10px] text-slate-600 font-mono">
                        Event IDs:{' '}
                        {Object.entries(hoveredBin.eidMap)
                          .slice(0, 3)
                          .map(([eid, cnt]) => `${eid} (${cnt})`)
                          .join(', ')}
                      </div>
                      <div className="text-[9px] text-slate-400 italic pt-0.5">
                        Click bar to isolate this time interval
                      </div>
                    </div>
                  )}

                  {/* The Bars */}
                  <div className="flex items-end gap-1.5 h-24 border-b border-slate-200 px-1">
                    {timeBins.map((bin) => {
                      const heightPercent = Math.max(8, (bin.count / maxBinCount) * 100);
                      const isSelected =
                        selectedTimeSlice && selectedTimeSlice.start === bin.start;
                      const hasCritical = bin.criticalCount > 0;
                      const hasHigh = bin.highCount > 0;
                      const hasMedium = bin.mediumCount > 0;

                      let barColor = 'bg-indigo-500 hover:bg-indigo-600';
                      if (hasCritical) barColor = 'bg-rose-500 hover:bg-rose-600';
                      else if (hasHigh) barColor = 'bg-orange-500 hover:bg-orange-600';
                      else if (hasMedium) barColor = 'bg-amber-500 hover:bg-amber-600';

                      return (
                        <button
                          key={bin.idx}
                          type="button"
                          onMouseEnter={() => setHoveredBin(bin)}
                          onMouseLeave={() => setHoveredBin(null)}
                          onClick={() => {
                            if (isSelected) {
                              setSelectedTimeSlice(null);
                            } else {
                              setSelectedTimeSlice({
                                start: bin.start,
                                end: bin.end,
                                label: bin.label,
                              });
                            }
                          }}
                          style={{ height: `${heightPercent}%` }}
                          className={`flex-1 rounded-t-md transition-all cursor-pointer relative group ${barColor} ${
                            isSelected
                              ? 'ring-2 ring-blue-600 ring-offset-2 scale-y-105 z-10'
                              : 'opacity-85 hover:opacity-100'
                          }`}
                          title={`${bin.label}: ${bin.count} events`}
                        />
                      );
                    })}
                  </div>

                  {/* Time Range Edge Labels */}
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 px-1">
                    <span>
                      {time_range.earliest ? formatTimestamp(time_range.earliest, timeConfig) : ''}
                    </span>
                    <span>
                      {time_range.latest ? formatTimestamp(time_range.latest, timeConfig) : ''}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Filter Bar & Scope Controls */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              {/* Search input */}
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search events, user, host, command line, share, payload..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-white border border-slate-200 rounded-xl text-xs focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-medium"
                />
              </div>

              {/* Scope Toggles: Monitored vs All */}
              <div className="flex items-center gap-2 flex-wrap">
                <div className="flex items-center bg-white border border-slate-200 rounded-xl p-0.5 text-xs font-semibold">
                  <button
                    type="button"
                    onClick={() => setTimelineMode('monitored')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      timelineMode === 'monitored'
                        ? 'bg-indigo-600 text-white shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Monitored IDs Only
                  </button>
                  <button
                    type="button"
                    onClick={() => setTimelineMode('all')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      timelineMode === 'all'
                        ? 'bg-indigo-600 text-white shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    All Records ({rawTimelineList.length})
                  </button>
                </div>

                {/* Source File Filter (when multi-log uploaded) */}
                {files_parsed.length > 1 && (
                  <select
                    value={selectedSourceFile}
                    onChange={(e) => setSelectedSourceFile(e.target.value)}
                    className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-xl text-xs font-medium text-slate-700"
                  >
                    <option value="all">All Sources ({files_parsed.length} files)</option>
                    {files_parsed.map((fName: string) => (
                      <option key={fName} value={fName}>
                        🪵 {fName}
                      </option>
                    ))}
                  </select>
                )}

                {/* Event ID filter */}
                <select
                  value={selectedEventId}
                  onChange={(e) => setSelectedEventId(e.target.value)}
                  className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-xl text-xs font-mono font-medium"
                >
                  <option value="all">All Event IDs ({eventIdsInTimeline.length})</option>
                  {eventIdsInTimeline.map((eid) => (
                    <option key={eid} value={String(eid)}>
                      Event {eid} ({getEventName(eid)})
                    </option>
                  ))}
                </select>

                {/* Severity filter */}
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-xl text-xs font-medium"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical / Malicious</option>
                  <option value="high">High / Dangerous</option>
                  <option value="medium">Medium / Suspicious</option>
                  <option value="low">Low</option>
                  <option value="info">Info / Benign</option>
                </select>

                {/* Time Display Controls Quick-Bar */}
                <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-xl px-2.5 py-1 text-xs">
                  <Clock className="w-3.5 h-3.5 text-indigo-600" />
                  <button
                    type="button"
                    onClick={() => {
                      const nextFmt = timeConfig.format === '24h' ? '12h' : '24h';
                      const updated = { ...timeConfig, format: nextFmt as '24h' | '12h' };
                      setTimeDisplayConfig(updated);
                      setTimeConfig(updated);
                    }}
                    className="font-mono font-bold text-slate-700 hover:text-indigo-600 cursor-pointer"
                    title="Toggle 24h / 12h time format"
                  >
                    {timeConfig.format.toUpperCase()}
                  </button>
                  <span className="text-slate-300">|</span>
                  <select
                    value={timeConfig.time_zone}
                    onChange={(e) => {
                      const updated = { ...timeConfig, time_zone: e.target.value };
                      setTimeDisplayConfig(updated);
                      setTimeConfig(updated);
                    }}
                    className="bg-transparent text-[11px] font-mono text-slate-700 focus:outline-none cursor-pointer"
                  >
                    <option value="UTC">UTC</option>
                    <option value="LOCAL">Local Time</option>
                    <option value="America/New_York">EST/EDT (New York)</option>
                    <option value="America/Chicago">CST/CDT (Chicago)</option>
                    <option value="America/Los_Angeles">PST/PDT (LA)</option>
                    <option value="Europe/London">GMT/BST (London)</option>
                    <option value="Europe/Berlin">CET/CEST (Berlin)</option>
                    <option value="Asia/Tokyo">JST (Tokyo)</option>
                    <option value="Asia/Singapore">SGT (Singapore)</option>
                  </select>
                </div>

                {/* Expand All / Collapse All Toggle */}
                {filteredTimeline.length > 0 && (
                  <button
                    type="button"
                    onClick={toggleExpandAll}
                    className="px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-xl text-xs font-semibold flex items-center gap-1 cursor-pointer transition-colors shadow-2xs"
                    title={isAllExpanded ? 'Collapse all timeline event details' : 'Expand all timeline event details'}
                  >
                    {isAllExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-indigo-600" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-indigo-600" />
                    )}
                    <span>{isAllExpanded ? 'Collapse All' : 'Expand All'}</span>
                  </button>
                )}

                {(searchFilter ||
                  selectedEventId !== 'all' ||
                  selectedSeverity !== 'all' ||
                  selectedTimeSlice ||
                  timelineMode !== 'monitored') && (
                  <button
                    onClick={() => {
                      setSearchFilter('');
                      setSelectedEventId('all');
                      setSelectedSeverity('all');
                      setSelectedTimeSlice(null);
                      setTimelineMode('monitored');
                    }}
                    className="px-2.5 py-1.5 text-xs text-blue-600 hover:text-blue-800 cursor-pointer font-semibold"
                  >
                    Reset Filters
                  </button>
                )}
              </div>
            </div>

            {/* Zero Events Alert with 1-Click "Switch to All Records" */}
            {filteredTimeline.length === 0 && rawTimelineList.length > 0 && timelineMode === 'monitored' && (
              <div className="p-6 text-center bg-indigo-50 border border-indigo-200 rounded-3xl space-y-3">
                <AlertTriangle className="w-8 h-8 text-indigo-600 mx-auto" />
                <h4 className="text-sm font-bold text-indigo-950">
                  0 Events match currently monitored Security Event IDs
                </h4>
                <p className="text-xs text-indigo-800 max-w-lg mx-auto">
                  This log contains {rawTimelineList.length} records whose Event IDs are not in your default monitored baseline. You can view all records immediately or add these Event IDs to monitoring in Settings.
                </p>
                <button
                  type="button"
                  onClick={() => setTimelineMode('all')}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold transition-colors cursor-pointer shadow-sm"
                >
                  Show All {rawTimelineList.length} Records in Timeline
                </button>
              </div>
            )}

            {/* Timeline Stream */}
            {filteredTimeline.length > 0 ? (
              <div className="relative pl-6 space-y-3.5 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                {filteredTimeline.map((ev, idx) => {
                  const isExpanded = expandedEvents[idx];
                  const safeSev = (ev.severity || 'info').toLowerCase();
                  const isThreat =
                    ev.is_threat ||
                    Boolean(ev.threat_reason) ||
                    ['critical', 'high'].includes(safeSev);

                  return (
                    <div
                      key={idx}
                      className={`relative p-4 bg-white hover:bg-slate-50/80 border rounded-2xl shadow-2xs transition-all ${
                        safeSev === 'critical'
                          ? 'border-rose-300 ring-1 ring-rose-500/20'
                          : safeSev === 'high'
                          ? 'border-orange-300 ring-1 ring-orange-500/20'
                          : safeSev === 'medium'
                          ? 'border-amber-200'
                          : 'border-slate-200/90'
                      }`}
                    >
                      {/* Left icon dot */}
                      <span className="absolute -left-6 top-4 p-1 rounded-full bg-white border border-slate-200 shadow-2xs">
                        {getEventIcon(ev.event_id)}
                      </span>

                      {/* Compact Header Line - Clicking toggles expansion */}
                      <div
                        onClick={() => toggleExpand(idx)}
                        className="flex items-center justify-between gap-3 cursor-pointer select-none"
                      >
                        <div className="flex items-center gap-2 flex-wrap min-w-0 flex-1">
                          <span className="px-2 py-0.5 bg-slate-100 text-slate-800 border border-slate-300 rounded-lg font-mono font-bold text-xs shrink-0">
                            ID {ev.event_id}
                          </span>
                          <span className="font-bold text-slate-900 text-xs sm:text-sm truncate">
                            — {ev.event_name || getEventName(ev.event_id)}
                          </span>
                          {ev.source_file && (
                            <span className="px-2 py-0.5 rounded-lg text-[10px] font-mono bg-purple-50 text-purple-700 border border-purple-200 shrink-0">
                              🪵 {ev.source_file}
                            </span>
                          )}
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border shrink-0 ${getSeverityBadge(
                              ev.severity
                            )}`}
                          >
                            {safeSev === 'critical'
                              ? 'CRITICAL / MALICIOUS'
                              : safeSev === 'high'
                              ? 'DANGEROUS / HIGH'
                              : safeSev === 'medium'
                              ? 'SUSPICIOUS / MEDIUM'
                              : safeSev.toUpperCase()}
                          </span>

                          {/* 1-line snippet of summary / user when collapsed */}
                          {!isExpanded && (
                            <span className="text-[11px] text-slate-500 truncate max-w-xs sm:max-w-md hidden md:inline ml-1 font-medium">
                              {ev.user ? `[${ev.user}] ` : ''}
                              {ev.process_name || ev.share_name || ev.summary || ev.description}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-2.5 shrink-0">
                          <span className="text-slate-400 font-mono text-[11px]">
                            {ev.timestamp ? formatTimestamp(ev.timestamp, timeConfig) : 'N/A'}
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleExpand(idx);
                            }}
                            className="px-2 py-0.5 rounded-lg text-slate-500 hover:text-indigo-600 hover:bg-slate-100 border border-transparent hover:border-slate-200 transition-colors cursor-pointer flex items-center gap-1 text-[11px] font-semibold"
                            title={isExpanded ? 'Collapse event details' : 'Expand event details'}
                          >
                            <span>{isExpanded ? 'Collapse' : 'Details'}</span>
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>

                      {/* Expandable Forensic Details Area */}
                      {isExpanded && (
                        <div className="mt-3 pt-3 border-t border-slate-100 space-y-3">
                          {/* Concise description / summary */}
                          <p className="text-xs text-slate-800 leading-relaxed font-semibold">
                            {ev.summary || ev.description}
                          </p>

                          {/* Security Threat Flagged Explanation Callout */}
                          {isThreat && (
                            <div className="p-3 rounded-xl border flex items-start gap-2.5 text-xs bg-amber-50/80 border-amber-200 text-amber-950">
                              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                              <div>
                                <span className="font-bold text-amber-900 block">
                                  Why this event is flagged:
                                </span>
                                <p className="mt-0.5 text-amber-900 leading-relaxed font-medium">
                                  {ev.threat_reason || getWhyFlaggedExplanation(ev)}
                                </p>
                              </div>
                            </div>
                          )}

                          {/* Decoded PowerShell Command (-EncodedCommand) Box */}
                          {(() => {
                            const psData =
                              ev.ps_decoded_info ||
                              (ev.decoded_command ? { decoded_command: ev.decoded_command } : null) ||
                              extractAndDecodePsCommand(ev.command_line || ev.script_text);
                            const decodedPayload = psData?.decoded_command || (psData as any)?.decoded;
                            if (!decodedPayload) return null;
                            const tokens: string[] = psData?.tokens_found || (psData as any)?.indicators || (psData as any)?.suspicious_tokens || [];

                            return (
                              <div className="p-3.5 bg-emerald-50/50 border border-emerald-300 rounded-xl space-y-2 text-xs">
                                <div className="flex items-center justify-between gap-2 flex-wrap">
                                  <div className="flex items-center gap-2">
                                    <span className="text-emerald-900 font-bold flex items-center gap-1.5">
                                      <span>🔓</span> Decoded PowerShell Command (-EncodedCommand)
                                    </span>
                                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 uppercase tracking-wider">
                                      De-obfuscated Payload
                                    </span>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(decodedPayload, `ps-${idx}`)}
                                    className="px-2 py-1 bg-white border border-emerald-200 hover:bg-emerald-50 rounded-lg text-emerald-800 text-[10px] font-semibold flex items-center gap-1 cursor-pointer shadow-2xs"
                                  >
                                    {copiedId === `ps-${idx}` ? (
                                      <Check className="w-3 h-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                    <span>Copy Script</span>
                                  </button>
                                </div>

                                {tokens.length > 0 && (
                                  <div className="flex items-center gap-1.5 flex-wrap text-[10px]">
                                    <span className="text-rose-700 font-bold">Suspicious Primitives Identified:</span>
                                    {tokens.map((tok: string) => (
                                      <span
                                        key={tok}
                                        className="px-1.5 py-0.5 bg-rose-100 text-rose-800 font-mono font-bold rounded"
                                      >
                                        {tok}
                                      </span>
                                    ))}
                                  </div>
                                )}

                                <pre className="p-3 bg-white border border-emerald-200 text-slate-800 rounded-lg font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all select-all max-h-60 overflow-y-auto">
                                  {decodedPayload}
                                </pre>
                              </div>
                            );
                          })()}

                          {/* Direct Extracted Event-Specific Properties Box */}
                          {/* 1. Network Share Access & Lateral Movement (5145, 5140) */}
                          {(ev.event_id === 5145 || ev.event_id === 5140) && (
                            <div className="p-3 bg-rose-50/50 border border-rose-200/80 rounded-xl text-xs space-y-1.5 font-mono">
                              <div className="flex items-center gap-1.5 text-rose-900 font-bold">
                                <Share2 className="w-3.5 h-3.5 text-rose-600" />
                                <span>SMB Network Share Detailed File Access</span>
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-700">
                                <div>
                                  <span className="text-slate-400">Share Name: </span>
                                  <strong className="text-slate-900">
                                    {ev.share_name || ev.details?.ShareName || 'N/A'}
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Target File / Relative: </span>
                                  <strong className="text-rose-700 break-all select-all">
                                    {ev.relative_target_name || ev.details?.RelativeTargetName || '\\'}
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Client Host: </span>
                                  <strong>
                                    {(ev.ip_address || ev.details?.IpAddress || 'Local')}:
                                    {(ev.ip_port || ev.details?.IpPort || '')}
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Access Mask: </span>
                                  <strong className="break-all">
                                    {ev.access_mask || ev.details?.AccessMask || 'N/A'}
                                  </strong>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* 2. Process Creation (4688, Sysmon 1) */}
                          {(ev.event_id === 4688 || ev.event_id === 1) && (
                            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1.5 font-mono">
                              <div className="flex items-center gap-1.5 text-slate-800 font-bold">
                                <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                                <span>Process Execution Details</span>
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px] text-slate-600">
                                <div>
                                  <span className="text-slate-400">Executable: </span>
                                  <strong className="text-slate-900 break-all">
                                    <ReferencedText
                                      text={ev.process_name || ev.details?.NewProcessName || ev.details?.Image || 'N/A'}
                                      workspaceJobs={workspaceJobs}
                                      onSelectJob={onSelectJob}
                                    />
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Parent Process: </span>
                                  <strong className="break-all">
                                    <ReferencedText
                                      text={ev.parent_process || ev.details?.ParentProcessName || 'N/A'}
                                      workspaceJobs={workspaceJobs}
                                      onSelectJob={onSelectJob}
                                    />
                                  </strong>
                                </div>
                              </div>
                              {(ev.command_line || ev.details?.CommandLine) && (
                                <div className="mt-1.5 p-2.5 bg-slate-100 text-slate-900 border border-slate-200 rounded-xl text-[11px] break-all select-all font-mono font-medium">
                                  <span className="text-slate-400 select-none mr-1">cmd:</span>
                                  <ReferencedText
                                    text={ev.command_line || ev.details?.CommandLine}
                                    workspaceJobs={workspaceJobs}
                                    onSelectJob={onSelectJob}
                                  />
                                </div>
                              )}
                            </div>
                          )}

                          {/* 3. Logons (4624, 4625) */}
                          {(ev.event_id === 4624 || ev.event_id === 4625) && (
                            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1.5 font-mono">
                              <div className="flex items-center gap-1.5 text-slate-800 font-bold">
                                <Key className="w-3.5 h-3.5 text-blue-600" />
                                <span>Authentication &amp; Session Diagnostics</span>
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px] text-slate-600">
                                <div>
                                  <span className="text-slate-400">Logon Type: </span>
                                  <strong>
                                    {LOGON_TYPE_NAMES[ev.logon_type || ev.details?.LogonType || ''] ||
                                      `Type ${ev.logon_type || ev.details?.LogonType || 'N/A'}`}
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Source Host: </span>
                                  <strong>
                                    {ev.ip_address || ev.details?.IpAddress || 'Local host'}
                                    {ev.ip_port ? `:${ev.ip_port}` : ''}
                                  </strong>
                                </div>
                                <div>
                                  <span className="text-slate-400">Target Account: </span>
                                  <strong>{ev.user || ev.details?.TargetUserName || 'Unknown'}</strong>
                                </div>
                                {(ev.status_code || ev.details?.Status) && (
                                  <div>
                                    <span className="text-slate-400">Status Code: </span>
                                    <strong className="text-rose-600">
                                      {ev.status_code || ev.details?.Status}
                                    </strong>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}

                          {/* 4. Services (7045, 4697) */}
                          {(ev.event_id === 7045 || ev.event_id === 4697) && (
                            <div className="p-3 bg-purple-50/60 border border-purple-200 rounded-xl text-xs space-y-1 font-mono">
                              <span className="text-purple-900 font-bold block">
                                Service: {ev.service_name || ev.details?.ServiceName || 'N/A'}
                              </span>
                              <div className="text-[11px] text-slate-700 break-all select-all">
                                ImagePath: {ev.details?.ImagePath || 'N/A'}
                              </div>
                            </div>
                          )}

                          {/* 5. Scheduled Tasks (4698, 4702) */}
                          {(ev.event_id === 4698 || ev.event_id === 4702) && (
                            <div className="p-3 bg-indigo-50/60 border border-indigo-200 rounded-xl text-xs space-y-1 font-mono">
                              <span className="text-indigo-900 font-bold block">
                                Task Name: {ev.task_name || ev.details?.TaskName || 'N/A'}
                              </span>
                            </div>
                          )}

                          {/* 6. PowerShell Script Blocks (4104) */}
                          {ev.event_id === 4104 && (ev.script_text || ev.details?.ScriptBlockText) && (
                            <div className="p-3 bg-slate-100 border border-slate-200 text-slate-900 rounded-xl font-mono text-xs space-y-1">
                              <span className="text-indigo-700 text-[10px] uppercase font-bold block">
                                Script Block Code
                              </span>
                              <pre className="text-slate-800 break-all select-all whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed text-[11px] font-mono">
                                {ev.script_text || ev.details?.ScriptBlockText}
                              </pre>
                            </div>
                          )}

                          {/* Basic Metadata Badges */}
                          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-500 pt-1">
                            {ev.computer && (
                              <span className="flex items-center gap-1 bg-slate-100 px-2 py-0.5 rounded">
                                <Monitor className="w-3 h-3 text-slate-400" />
                                <span>{ev.computer}</span>
                              </span>
                            )}
                            {ev.user && (
                              <span className="flex items-center gap-1 bg-slate-100 px-2 py-0.5 rounded">
                                <User className="w-3 h-3 text-slate-400" />
                                <span>{ev.user}</span>
                              </span>
                            )}
                            {ev.channel && (
                              <span className="text-slate-400">Channel: {ev.channel}</span>
                            )}
                          </div>

                          {/* Expandable Raw XML Details */}
                          {ev.details && Object.keys(ev.details).length > 0 && (
                            <div className="pt-2 border-t border-slate-100">
                              <div className="p-3 bg-slate-100 border border-slate-200 text-slate-900 rounded-xl font-mono text-xs overflow-x-auto relative">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-[10px] font-bold uppercase text-slate-500">
                                    Raw Event Properties (XML)
                                  </span>
                                  <button
                                    onClick={() =>
                                      copyToClipboard(JSON.stringify(ev.details, null, 2), `ev-${idx}`)
                                    }
                                    className="p-1.5 bg-white border border-slate-200 hover:bg-slate-50 rounded text-slate-700 text-[10px] flex items-center gap-1 cursor-pointer shadow-2xs"
                                  >
                                    {copiedId === `ev-${idx}` ? (
                                      <Check className="w-3 h-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                    <span>Copy XML JSON</span>
                                  </button>
                                </div>
                                <pre className="text-[11px] leading-relaxed max-h-60 overflow-y-auto">
                                  {JSON.stringify(ev.details, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No events matched your current search and severity filters.
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Threat Vector Findings */}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            <h4 className="text-sm font-bold text-slate-900">
              Aggregated Threat Vectors &amp; Suspicious Indicators ({allThreats.length})
            </h4>

            {allThreats.length > 0 ? (
              <div className="grid grid-cols-1 gap-3">
                {allThreats.map((threat, idx) => {
                  const safeSev = (threat.severity || 'info').toLowerCase();
                  return (
                    <div
                      key={idx}
                      className="p-4 bg-slate-50 hover:bg-slate-100/80 border border-slate-200 rounded-2xl transition-all"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className="px-2.5 py-0.5 rounded-lg font-mono font-bold text-xs bg-slate-100 text-slate-800 border border-slate-300">
                            Event {threat.event_id || 'Alert'}
                          </span>
                          <span className="font-bold text-slate-900 text-xs">
                            {threat.title || 'Security Indicator'}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                              threat.severity
                            )}`}
                          >
                            {safeSev}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {threat.timestamp ? formatTimestamp(threat.timestamp, timeConfig) : ''}
                        </span>
                      </div>

                      <p className="text-xs text-slate-700 mb-2">{threat.description}</p>

                      {threat.threat_reason && (
                        <div className="mb-2 p-2.5 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900">
                          <strong>Why flagged: </strong>
                          {threat.threat_reason}
                        </div>
                      )}

                      {threat.details && (
                        <div className="p-2.5 bg-white border border-slate-200 rounded-xl font-mono text-[11px] text-slate-600 overflow-x-auto space-y-1">
                          {threat.command_line && (
                            <div className="text-rose-700 font-bold break-all select-all flex items-start gap-1">
                              <span className="text-rose-400 select-none">cmd:</span>
                              <ReferencedText
                                text={threat.command_line}
                                workspaceJobs={workspaceJobs}
                                onSelectJob={onSelectJob}
                              />
                            </div>
                          )}
                          {threat.image && (
                            <div className="flex items-center gap-1">
                              <span className="text-slate-400">Image:</span>
                              <ReferencedText
                                text={threat.image}
                                workspaceJobs={workspaceJobs}
                                onSelectJob={onSelectJob}
                              />
                            </div>
                          )}
                          {threat.user && <div>Account: {threat.user}</div>}
                          {threat.details.ShareName && (
                            <div>
                              Share: {threat.details.ShareName}\
                              {threat.details.RelativeTargetName || ''}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-emerald-50 border border-emerald-200 rounded-2xl text-emerald-800 text-xs">
                ✓ No high-severity threats, ransomware commands, or anti-forensics indicators detected in the parsed logs.
              </div>
            )}
          </div>
        )}

        {/* Tab: Endpoints, Accounts & Forensic Indicators */}
        {activeTab === 'entities' && (
          <div className="space-y-5">
            {/* Header & Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <User className="w-4 h-4 text-amber-600" />
                  <span>Forensic Entities &amp; Indicator Inventory</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Breakdown of accounts, endpoints, network IPs, SMB shares, and executed binaries discovered in Windows Event logs. Click any entity to filter the timeline.
                </p>
              </div>

              {/* Subtab Segmented Switcher */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <div className="flex items-center bg-slate-100 rounded-xl p-0.5 text-xs font-semibold">
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('all')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'all' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    All ({forensicEntities.users.length + forensicEntities.computers.length + forensicEntities.ips.length + forensicEntities.shares.length + forensicEntities.processes.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('users')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'users' ? 'bg-white text-amber-800 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    👤 Accounts ({forensicEntities.users.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('computers')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'computers' ? 'bg-white text-emerald-800 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    💻 Endpoints ({forensicEntities.computers.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('ips')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'ips' ? 'bg-white text-purple-800 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    🌐 IP Addrs ({forensicEntities.ips.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('shares')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'shares' ? 'bg-white text-rose-800 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    📁 Shares ({forensicEntities.shares.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEntitiesSubTab('processes')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      entitiesSubTab === 'processes' ? 'bg-white text-indigo-800 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    ⚡ LOLBins ({forensicEntities.processes.length})
                  </button>
                </div>
              </div>
            </div>

            {/* Search Filter for Entities */}
            <div className="relative max-w-sm">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={entitiesSearch}
                onChange={(e) => setEntitiesSearch(e.target.value)}
                placeholder="Filter entities, users, hosts, IPs..."
                className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs focus:outline-none focus:ring-1 focus:ring-amber-500 font-medium"
              />
              {entitiesSearch && (
                <button
                  onClick={() => setEntitiesSearch('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            {/* 1. Accounts & Users Section */}
            {(entitiesSubTab === 'all' || entitiesSubTab === 'users') && (
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                  <span className="text-xs font-bold text-amber-900 uppercase tracking-wider flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-amber-600" />
                    <span>Identified Accounts &amp; Identities ({forensicEntities.users.length})</span>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {forensicEntities.users
                    .filter((u) => !entitiesSearch || u.username.toLowerCase().includes(entitiesSearch.toLowerCase()))
                    .map((user) => (
                      <div
                        key={user.username}
                        className={`p-3.5 rounded-2xl border transition-all flex flex-col justify-between ${
                          user.threatCount > 0
                            ? 'bg-amber-50/50 border-amber-200 shadow-2xs'
                            : 'bg-white border-slate-200'
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className="font-mono font-bold text-xs text-slate-900 truncate" title={user.username}>
                              {user.username}
                            </span>
                            <div className="flex items-center gap-1">
                              {user.isPrivileged && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-rose-100 text-rose-800 border border-rose-200">
                                  Privileged
                                </span>
                              )}
                              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-slate-100 text-slate-700 font-bold border border-slate-200">
                                {user.eventsCount} events
                              </span>
                            </div>
                          </div>

                          <div className="space-y-1 text-[11px] text-slate-600">
                            {user.computers.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Hosts:</span>
                                <span className="font-mono text-slate-800 truncate">
                                  {Array.from(user.computers).join(', ')}
                                </span>
                              </div>
                            )}

                            {user.ipAddresses.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">IPs:</span>
                                <span className="font-mono text-purple-700 truncate">
                                  {Array.from(user.ipAddresses).join(', ')}
                                </span>
                              </div>
                            )}

                            {user.logonTypes.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Logons:</span>
                                <span className="text-slate-700">
                                  {Array.from(user.logonTypes).map((lt) => LOGON_TYPE_NAMES[lt] || `Type ${lt}`).join(' • ')}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between">
                          {user.threatCount > 0 ? (
                            <span className="text-[10px] font-bold text-rose-700 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3 text-rose-600" />
                              <span>{user.threatCount} threat events</span>
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-400">Normal audit activity</span>
                          )}

                          <button
                            type="button"
                            onClick={() => {
                              setSearchFilter(user.username);
                              setActiveTab('timeline');
                            }}
                            className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                          >
                            Filter Timeline →
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* 2. Endpoints & Computers Section */}
            {(entitiesSubTab === 'all' || entitiesSubTab === 'computers') && (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                  <span className="text-xs font-bold text-emerald-900 uppercase tracking-wider flex items-center gap-1.5">
                    <Monitor className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Endpoints &amp; Workstations ({forensicEntities.computers.length})</span>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {forensicEntities.computers
                    .filter((c) => !entitiesSearch || c.hostname.toLowerCase().includes(entitiesSearch.toLowerCase()))
                    .map((comp) => (
                      <div
                        key={comp.hostname}
                        className="p-3.5 rounded-2xl bg-white border border-slate-200 transition-all flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className="font-mono font-bold text-xs text-slate-900 truncate" title={comp.hostname}>
                              {comp.hostname}
                            </span>
                            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-50 text-emerald-800 font-bold border border-emerald-200">
                              {comp.eventsCount} events
                            </span>
                          </div>

                          <div className="space-y-1 text-[11px] text-slate-600">
                            {comp.users.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Users:</span>
                                <span className="font-mono text-slate-800 truncate">
                                  {Array.from(comp.users).join(', ')}
                                </span>
                              </div>
                            )}

                            {comp.sourceFiles.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Logs:</span>
                                <span className="font-mono text-purple-700 truncate">
                                  {Array.from(comp.sourceFiles).join(', ')}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between">
                          <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${getSeverityBadge(comp.highestSeverity)}`}>
                            {comp.highestSeverity}
                          </span>

                          <button
                            type="button"
                            onClick={() => {
                              setSearchFilter(comp.hostname);
                              setActiveTab('timeline');
                            }}
                            className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                          >
                            Filter Timeline →
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* 3. IP Addresses Section */}
            {(entitiesSubTab === 'all' || entitiesSubTab === 'ips') && (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                  <span className="text-xs font-bold text-purple-900 uppercase tracking-wider flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-purple-600" />
                    <span>Observed IP Addresses &amp; Sockets ({forensicEntities.ips.length})</span>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {forensicEntities.ips
                    .filter((ip) => !entitiesSearch || ip.ip.toLowerCase().includes(entitiesSearch.toLowerCase()))
                    .map((ipItem) => (
                      <div
                        key={ipItem.ip}
                        className="p-3.5 rounded-2xl bg-white border border-slate-200 transition-all flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className="font-mono font-bold text-xs text-purple-900">
                              {ipItem.ip}
                            </span>
                            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-purple-50 text-purple-800 font-bold border border-purple-200">
                              {ipItem.eventsCount} events
                            </span>
                          </div>

                          <div className="space-y-1 text-[11px] text-slate-600">
                            {ipItem.ports.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Ports:</span>
                                <span className="font-mono text-slate-800">
                                  {Array.from(ipItem.ports).join(', ')}
                                </span>
                              </div>
                            )}

                            {ipItem.users.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Users:</span>
                                <span className="font-mono text-amber-700 truncate">
                                  {Array.from(ipItem.users).join(', ')}
                                </span>
                              </div>
                            )}

                            {ipItem.shares.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Shares:</span>
                                <span className="font-mono text-rose-700 truncate">
                                  {Array.from(ipItem.shares).join(', ')}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between">
                          <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${getSeverityBadge(ipItem.highestSeverity)}`}>
                            {ipItem.highestSeverity}
                          </span>

                          <button
                            type="button"
                            onClick={() => {
                              setSearchFilter(ipItem.ip);
                              setActiveTab('timeline');
                            }}
                            className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                          >
                            Filter Timeline →
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* 4. SMB Shares Section */}
            {(entitiesSubTab === 'all' || entitiesSubTab === 'shares') && forensicEntities.shares.length > 0 && (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                  <span className="text-xs font-bold text-rose-900 uppercase tracking-wider flex items-center gap-1.5">
                    <Share2 className="w-3.5 h-3.5 text-rose-600" />
                    <span>SMB Network Shares &amp; Lateral Targets ({forensicEntities.shares.length})</span>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {forensicEntities.shares
                    .filter((s) => !entitiesSearch || s.shareName.toLowerCase().includes(entitiesSearch.toLowerCase()))
                    .map((sItem) => (
                      <div
                        key={sItem.shareName}
                        className="p-3.5 rounded-2xl bg-white border border-slate-200 transition-all flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className="font-mono font-bold text-xs text-rose-900 truncate" title={sItem.shareName}>
                              {sItem.shareName}
                            </span>
                            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-rose-50 text-rose-800 font-bold border border-rose-200">
                              {sItem.eventsCount} accesses
                            </span>
                          </div>

                          <div className="space-y-1 text-[11px] text-slate-600">
                            {sItem.clientIps.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Clients:</span>
                                <span className="font-mono text-slate-800 truncate">
                                  {Array.from(sItem.clientIps).join(', ')}
                                </span>
                              </div>
                            )}

                            {sItem.relativeTargets.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Files:</span>
                                <span className="font-mono text-slate-800 truncate">
                                  {Array.from(sItem.relativeTargets).slice(0, 3).join(', ')}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-end">
                          <button
                            type="button"
                            onClick={() => {
                              setSearchFilter(sItem.shareName);
                              setActiveTab('timeline');
                            }}
                            className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                          >
                            Filter Timeline →
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* 5. Processes & LOLBins Section */}
            {(entitiesSubTab === 'all' || entitiesSubTab === 'processes') && forensicEntities.processes.length > 0 && (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                  <span className="text-xs font-bold text-indigo-900 uppercase tracking-wider flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Executed Processes &amp; LOLBins ({forensicEntities.processes.length})</span>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {forensicEntities.processes
                    .filter((p) => !entitiesSearch || p.processName.toLowerCase().includes(entitiesSearch.toLowerCase()))
                    .map((pItem) => (
                      <div
                        key={pItem.processName}
                        className={`p-3.5 rounded-2xl border transition-all flex flex-col justify-between ${
                          pItem.isLolbin ? 'bg-amber-50/40 border-amber-200' : 'bg-white border-slate-200'
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className="font-mono font-bold text-xs text-slate-900 truncate" title={pItem.processName}>
                              {pItem.processName}
                            </span>
                            <div className="flex items-center gap-1">
                              {pItem.isLolbin && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-100 text-amber-900 border border-amber-200">
                                  LOLBin
                                </span>
                              )}
                              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-slate-100 text-slate-700 font-bold border border-slate-200">
                                {pItem.eventsCount} runs
                              </span>
                            </div>
                          </div>

                          <div className="space-y-1 text-[11px] text-slate-600">
                            {pItem.parentProcesses.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Parent:</span>
                                <span className="font-mono text-slate-800 truncate">
                                  {Array.from(pItem.parentProcesses).join(', ')}
                                </span>
                              </div>
                            )}

                            {pItem.users.size > 0 && (
                              <div className="flex items-start gap-1">
                                <span className="text-slate-400 shrink-0">Users:</span>
                                <span className="font-mono text-amber-700 truncate">
                                  {Array.from(pItem.users).join(', ')}
                                </span>
                              </div>
                            )}

                            {pItem.decodedCommands.size > 0 && (
                              <div className="pt-1">
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-emerald-100 text-emerald-800">
                                  🔓 Decoded Base64 Payload Available
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-end">
                          <button
                            type="button"
                            onClick={() => {
                              setSearchFilter(pItem.processName);
                              setActiveTab('timeline');
                            }}
                            className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                          >
                            Filter Timeline →
                          </button>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: SMB Lateral Movement & Remote Staging (5145 / 5140) */}
        {activeTab === 'lateral' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-100">
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Share2 className="w-4 h-4 text-rose-600" />
                  <span>SMB Lateral Movement &amp; Remote File Access ({lateralMovementList.length})</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Detailed inspection of administrative shares (C$, ADMIN$, IPC$) and remote file copying (Event ID 5145/5140).
                </p>
              </div>
            </div>

            {lateralMovementList.length > 0 ? (
              <div className="space-y-3">
                {lateralMovementList.map((item: any, idx: number) => {
                  const share = item.share_name || item.details?.ShareName || 'N/A';
                  const target = item.relative_target_name || item.details?.RelativeTargetName || '\\';
                  const user = item.user || item.details?.SubjectUserName || 'Unknown';
                  const ip = item.ip_address || item.details?.IpAddress || 'Local';
                  const port = item.ip_port || item.details?.IpPort || '';
                  const access = item.access_list || item.details?.AccessList || item.details?.AccessMask || '';
                  const isPayload = item.is_payload_drop || Boolean(target.match(/\.(exe|bat|ps1|dll|vbs|js|cmd)$/i));

                  return (
                    <div
                      key={idx}
                      className={`p-4 rounded-2xl border transition-all ${
                        isPayload
                          ? 'bg-rose-50/40 border-rose-200 shadow-2xs'
                          : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-2.5 py-0.5 bg-slate-100 text-slate-800 border border-slate-300 rounded-lg font-mono font-bold text-xs">
                            Event {item.event_id || 5145}
                          </span>
                          <span className="font-bold text-slate-900 text-xs">
                            {share}\{target}
                          </span>
                          {isPayload && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                              Payload File Staging
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {item.timestamp ? formatTimestamp(item.timestamp, timeConfig) : ''}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono mb-2">
                        <div>
                          <span className="text-slate-400">Target Path: </span>
                          <strong className="text-rose-700 break-all">{target}</strong>
                        </div>
                        <div>
                          <span className="text-slate-400">Share: </span>
                          <strong>{share}</strong>
                        </div>
                        <div>
                          <span className="text-slate-400">Account: </span>
                          <strong>{user}</strong>
                        </div>
                        <div>
                          <span className="text-slate-400">Source Host: </span>
                          <strong>
                            {ip}
                            {port ? `:${port}` : ''}
                          </strong>
                        </div>
                      </div>

                      {access && (
                        <div className="p-2 bg-white rounded-lg border border-slate-200 text-[11px] font-mono text-slate-600 break-all">
                          Access Rights: {String(access).trim().replace(/\s+/g, ' ')}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No SMB lateral movement or Event ID 5145 detailed share checks recorded.
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Process Creation & LOLBins */}
        {activeTab === 'processes' && (
          <div className="space-y-4">
            <h4 className="text-sm font-bold text-slate-900">
              Process Invocations &amp; LOLBins (Event ID 4688 / Sysmon 1) ({threats.process_creation?.length || 0})
            </h4>

            {threats.process_creation && threats.process_creation.length > 0 ? (
              <div className="space-y-3">
                {threats.process_creation.map((proc, idx) => {
                  const title =
                    proc.title ||
                    (proc.process_name ? `Process: ${proc.process_name}` : 'Process Executed');
                  const cmdLine =
                    proc.command_line ||
                    proc.details?.CommandLine ||
                    proc.details?.ProcessCommandLine;
                  const image =
                    proc.image ||
                    proc.process_name ||
                    proc.details?.NewProcessName ||
                    proc.details?.Image;
                  const user =
                    proc.user || proc.details?.SubjectUserName || proc.details?.TargetUserName;
                  const parent = proc.parent_process || proc.details?.ParentProcessName;
                  const isLolbin = proc.is_lolbin || false;

                  return (
                    <div
                      key={idx}
                      className="p-4 bg-white hover:bg-slate-50 border border-slate-200 rounded-2xl shadow-2xs space-y-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-900 text-xs">{title}</span>
                          {isLolbin && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                              LOLBin Detected
                            </span>
                          )}
                        </div>
                        <span className="text-slate-400 font-mono text-[11px]">
                          {proc.timestamp ? formatTimestamp(proc.timestamp, timeConfig) : ''}
                        </span>
                      </div>

                      <p className="text-xs text-slate-600 font-mono break-all">
                        <ReferencedText
                          text={image || proc.description}
                          workspaceJobs={workspaceJobs}
                          onSelectJob={onSelectJob}
                        />
                      </p>

                      {cmdLine && (
                        <div className="p-2.5 bg-slate-100 text-slate-900 border border-slate-200 rounded-xl font-mono text-xs break-all select-all font-medium">
                          <span className="text-slate-400 select-none mr-1">cmd:</span>
                          <ReferencedText
                            text={cmdLine}
                            workspaceJobs={workspaceJobs}
                            onSelectJob={onSelectJob}
                          />
                        </div>
                      )}

                      {/* Decoded PowerShell Command (-EncodedCommand) Box if present */}
                      {(() => {
                        const psData =
                          proc.ps_decoded_info ||
                          (proc.decoded_command ? { decoded_command: proc.decoded_command } : null) ||
                          extractAndDecodePsCommand(cmdLine);
                        const decodedPayload = psData?.decoded_command || (psData as any)?.decoded;
                        if (!decodedPayload) return null;
                        const tokens: string[] = psData?.tokens_found || (psData as any)?.indicators || (psData as any)?.suspicious_tokens || [];

                        return (
                          <div className="p-3 bg-emerald-50/60 border border-emerald-300 rounded-xl space-y-2 text-xs">
                            <div className="flex items-center justify-between gap-2 flex-wrap">
                              <div className="flex items-center gap-2">
                                <span className="text-emerald-900 font-bold flex items-center gap-1.5">
                                  <span>🔓</span> Decoded PowerShell Command
                                </span>
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 uppercase tracking-wider">
                                  De-obfuscated Payload
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => copyToClipboard(decodedPayload, `proc-ps-${idx}`)}
                                className="px-2 py-1 bg-white border border-emerald-200 hover:bg-emerald-50 rounded-lg text-emerald-800 text-[10px] font-semibold flex items-center gap-1 cursor-pointer shadow-2xs"
                              >
                                {copiedId === `proc-ps-${idx}` ? (
                                  <Check className="w-3 h-3 text-emerald-600" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                                <span>Copy Script</span>
                              </button>
                            </div>

                            {tokens.length > 0 && (
                              <div className="flex items-center gap-1.5 flex-wrap text-[10px]">
                                <span className="text-rose-700 font-bold">Suspicious Primitives:</span>
                                {tokens.map((tok: string) => (
                                  <span
                                    key={tok}
                                    className="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 border border-rose-200 font-mono font-bold"
                                  >
                                    {tok}
                                  </span>
                                ))}
                              </div>
                            )}

                            <pre className="p-3 bg-white border border-emerald-200 text-slate-800 rounded-lg font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all select-all max-h-48 overflow-y-auto">
                              {decodedPayload}
                            </pre>
                          </div>
                        );
                      })()}

                      <div className="flex flex-wrap gap-3 text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-100">
                        {user && (
                          <span>
                            User: <strong className="text-slate-700">{user}</strong>
                          </span>
                        )}
                        {parent && (
                          <span>
                            Parent: <strong className="text-slate-700">{parent}</strong>
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No suspicious process creation or LOLBin patterns were detected.
              </div>
            )}
          </div>
        )}

        {/* Tab 5: PowerShell Script Blocks */}
        {activeTab === 'powershell' && (
          <div className="space-y-4">
            <h4 className="text-sm font-bold text-slate-900">
              PowerShell Script Block Logging (Event ID 4104) ({threats.powershell?.length || 0})
            </h4>

            {threats.powershell && threats.powershell.length > 0 ? (
              <div className="space-y-3">
                {threats.powershell.map((ps, idx) => {
                  const rawScript = ps.details?.script_block || ps.details?.ScriptBlockText || ps.description;
                  const psData =
                    ps.ps_decoded_info ||
                    (ps.decoded_command ? { decoded_command: ps.decoded_command } : null) ||
                    extractAndDecodePsCommand(rawScript);
                  const decodedPayload = psData?.decoded_command || (psData as any)?.decoded;
                  const tokens: string[] = psData?.tokens_found || (psData as any)?.indicators || (psData as any)?.suspicious_tokens || [];

                  return (
                    <div
                      key={idx}
                      className="p-4 bg-slate-50 border border-slate-200 text-slate-900 rounded-2xl font-mono text-xs space-y-2.5"
                    >
                      <div className="flex items-center justify-between pb-2 border-b border-slate-200 text-[11px]">
                        <span className="text-indigo-700 font-bold">Script Block Execution</span>
                        <span className="text-slate-500">{ps.timestamp ? formatTimestamp(ps.timestamp, timeConfig) : 'N/A'}</span>
                      </div>

                      {/* Decoded PowerShell payload if encoded */}
                      {decodedPayload && (
                        <div className="p-3 bg-emerald-50/70 border border-emerald-300 rounded-xl space-y-2 text-xs">
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-2">
                              <span className="text-emerald-900 font-bold flex items-center gap-1.5">
                                <span>🔓</span> Decoded Base64 Payload
                              </span>
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 uppercase tracking-wider">
                                De-obfuscated Script
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(decodedPayload, `psblock-dec-${idx}`)}
                              className="px-2 py-1 bg-white border border-emerald-200 hover:bg-emerald-50 rounded-lg text-emerald-800 text-[10px] font-semibold flex items-center gap-1 cursor-pointer shadow-2xs"
                            >
                              {copiedId === `psblock-dec-${idx}` ? (
                                <Check className="w-3 h-3 text-emerald-600" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                              <span>Copy Decoded</span>
                            </button>
                          </div>

                          {tokens.length > 0 && (
                            <div className="flex items-center gap-1.5 flex-wrap text-[10px]">
                              <span className="text-rose-700 font-bold">Suspicious Primitives:</span>
                              {tokens.map((tok: string) => (
                                <span
                                  key={tok}
                                  className="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 border border-rose-200 font-mono font-bold"
                                >
                                  {tok}
                                </span>
                              ))}
                            </div>
                          )}

                          <pre className="p-3 bg-white border border-emerald-200 text-slate-800 rounded-lg font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all select-all max-h-48 overflow-y-auto">
                            {decodedPayload}
                          </pre>
                        </div>
                      )}

                      <pre className="p-3 bg-white border border-slate-200 rounded-xl text-slate-800 break-all select-all leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto">
                        {rawScript}
                      </pre>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No PowerShell Event 4104 script block invocations were recorded in this log file.
              </div>
            )}
          </div>
        )}

        {/* Tab 6: Logons & Brute Force */}
        {activeTab === 'logons' && (
          <div className="space-y-4">
            <h4 className="text-sm font-bold text-slate-900">
              Authentication Events &amp; Failed Logons ({threats.brute_force?.length || 0})
            </h4>

            {threats.brute_force && threats.brute_force.length > 0 ? (
              <div className="space-y-2.5">
                {threats.brute_force.map((bf, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900">
                        {bf.title || 'Failed Logon'}
                      </span>
                      <span className="text-slate-400 font-mono text-[11px]">{bf.timestamp ? formatTimestamp(bf.timestamp, timeConfig) : ''}</span>
                    </div>
                    <p className="text-slate-600">{bf.description}</p>
                    <div className="flex flex-wrap gap-2 text-[11px] font-mono text-slate-500 pt-1">
                      {bf.details?.target_user && <span>User: {bf.details.target_user}</span>}
                      {bf.details?.ip_address && <span>Source IP: {bf.details.ip_address}</span>}
                      {bf.details?.logon_type && <span>Logon Type: {bf.details.logon_type}</span>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No repeated failed logons or brute force authentication attempts detected.
              </div>
            )}
          </div>
        )}

        {/* Tab 7: Services & Tasks */}
        {activeTab === 'persistence' && (
          <div className="space-y-4">
            <h4 className="text-sm font-bold text-slate-900">
              Persistence via Services &amp; Scheduled Tasks ({threats.services_and_tasks?.length || 0})
            </h4>

            {threats.services_and_tasks && threats.services_and_tasks.length > 0 ? (
              <div className="space-y-2.5">
                {threats.services_and_tasks.map((st, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900">
                        {st.title || 'Service / Task Event'}
                      </span>
                      <span className="text-slate-400 font-mono text-[11px]">{st.timestamp ? formatTimestamp(st.timestamp, timeConfig) : ''}</span>
                    </div>
                    <p className="text-slate-600">{st.description}</p>
                    {st.details?.service_name && (
                      <div className="p-2 bg-slate-100 rounded-xl font-mono text-[11px] text-slate-800">
                        Service: {st.details.service_name} • Image:{' '}
                        {st.details.image_path || 'N/A'}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No newly installed services (7045) or created scheduled tasks (4698) recorded.
              </div>
            )}
          </div>
        )}

        {/* Tab 8: Anti-Forensics & Audit Tampering */}
        {activeTab === 'anti_analysis' && (
          <div className="pt-2">
            <AntiAnalysisInspectorCard
              antiAnalysis={antiAnalysis}
              filename={filename}
              category="evtx"
            />
          </div>
        )}

        {/* Tab 9: Desktop Storyline */}
        {activeTab === 'storyline' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-indigo-600" />
                  <span>Human Desktop Storyline &amp; Session Narrative</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Chronological story of user actions reconstructed from security, system, and hardware events.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs font-semibold text-slate-600">Category:</label>
                <select
                  value={storylineCategoryFilter}
                  onChange={(e) => setStorylineCategoryFilter(e.target.value)}
                  className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700"
                >
                  <option value="all">All Storyline Events ({desktopStoryline.length})</option>
                  <option value="logon">Logon &amp; Auth</option>
                  <option value="usb">USB &amp; Hardware</option>
                  <option value="file_access">File &amp; Document Access</option>
                  <option value="execution">Execution &amp; Scripts</option>
                  <option value="defender_tampering">Defender Tampering</option>
                  <option value="print">Document Printing</option>
                  <option value="log_cleared">Log Purges</option>
                  <option value="logoff">Session Logoff</option>
                </select>
              </div>
            </div>

            {filteredStoryline.length > 0 ? (
              <div className="relative pl-6 sm:pl-8 space-y-4 before:absolute before:left-3 sm:before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                {filteredStoryline.map((item, idx) => {
                  const isCritical = item.severity === 'critical';
                  const isHigh = item.severity === 'high';
                  const isMedium = item.severity === 'medium';
                  const nodeColor = isCritical
                    ? 'bg-rose-500 ring-rose-200'
                    : isHigh
                    ? 'bg-amber-500 ring-amber-200'
                    : isMedium
                    ? 'bg-indigo-500 ring-indigo-200'
                    : 'bg-blue-500 ring-blue-200';

                  return (
                    <div key={item.id || idx} className="relative group">
                      <div
                        className={`absolute -left-6 sm:-left-8 top-3.5 w-3 h-3 rounded-full ${nodeColor} ring-4 ring-offset-1 ring-offset-white`}
                      />

                      <div className={`p-4 rounded-2xl border transition-all ${
                        isCritical
                          ? 'bg-rose-50/50 border-rose-200'
                          : isHigh
                          ? 'bg-amber-50/40 border-amber-200'
                          : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
                      }`}>
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-md ${
                                isCritical ? 'bg-rose-100 text-rose-800' : isHigh ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700'
                              }`}>
                                {item.category.replace('_', ' ')}
                              </span>
                              <span className="text-xs font-semibold text-slate-500 font-mono">
                                {item.timestamp ? formatTimestamp(item.timestamp, timeConfig) : 'Unknown Time'}
                              </span>
                              {item.event_ids && item.event_ids.length > 0 && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">
                                  EID {item.event_ids.join(', ')}
                                </span>
                              )}
                            </div>
                            <h5 className="text-sm font-bold text-slate-900">{item.title}</h5>
                            <p className="text-xs text-slate-700 leading-relaxed">{item.description}</p>
                          </div>

                          <div className="flex flex-col sm:items-end gap-1.5 shrink-0 text-right">
                            <span className="text-xs font-semibold text-slate-600">
                              User: <span className="font-mono text-slate-800">{item.user}</span>
                            </span>
                            <span className="text-[11px] text-slate-500">
                              Host: <span className="font-mono">{item.computer}</span>
                            </span>
                            {item.details && (item.details.IpAddress || item.details.DestinationIp) && (
                              <button
                                onClick={() => setSelectedCorrelationEvent({
                                  event_id: item.event_ids?.[0] || 0,
                                  ip_address: item.details?.IpAddress || item.details?.DestinationIp,
                                  ip_port: item.details?.IpPort || item.details?.DestinationPort,
                                  user: item.user,
                                  computer: item.computer,
                                  process_name: item.details?.ProcessName || item.title,
                                  timestamp: item.timestamp
                                })}
                                className="mt-1 px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-indigo-50 text-indigo-700 hover:bg-indigo-100 transition-colors flex items-center gap-1.5 border border-indigo-200 cursor-pointer"
                              >
                                <Globe className="w-3 h-3 text-indigo-600" />
                                <span>Jump to PCAP</span>
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No storyline narrative events found matching current filter.
              </div>
            )}
          </div>
        )}

        {/* Tab 10: USB & Hardware */}
        {activeTab === 'usb' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Total Hardware Events</span>
                <p className="text-2xl font-black text-slate-900 mt-1">{usbHistoryList.length}</p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Unique Storage Devices</span>
                <p className="text-2xl font-black text-indigo-600 mt-1">
                  {new Set(usbHistoryList.map(u => u.serial_number || u.device_name)).size}
                </p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Mounted Devices</span>
                <p className="text-2xl font-black text-emerald-600 mt-1">
                  {usbHistoryList.filter(u => u.status === 'Mounted').length}
                </p>
              </div>
            </div>

            {usbHistoryList.length > 0 ? (
              <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Device Name</th>
                        <th className="py-3 px-4">Vendor</th>
                        <th className="py-3 px-4">Drive</th>
                        <th className="py-3 px-4">Serial Number</th>
                        <th className="py-3 px-4">User &amp; Host</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4 text-right">Event ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
                      {usbHistoryList.map((usb, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              usb.status === 'Mounted' ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-600'
                            }`}>
                              {usb.status}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-sans font-semibold text-slate-900">{usb.device_name}</td>
                          <td className="py-3 px-4 font-sans text-slate-600">{usb.vendor}</td>
                          <td className="py-3 px-4 font-bold text-indigo-700">{usb.drive_letter}</td>
                          <td className="py-3 px-4 text-[11px] text-slate-500">{usb.serial_number}</td>
                          <td className="py-3 px-4 font-sans text-slate-700">
                            <div>{usb.user}</div>
                            <div className="text-[10px] text-slate-400 font-mono">{usb.computer}</div>
                          </td>
                          <td className="py-3 px-4 text-[11px] text-slate-500 font-sans">
                            {usb.timestamp ? formatTimestamp(usb.timestamp, timeConfig) : 'N/A'}
                          </td>
                          <td className="py-3 px-4 text-right text-slate-500">EID {usb.event_id}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No external storage device insertions or PnP hardware events recorded in analyzed event logs.
              </div>
            )}
          </div>
        )}

        {/* Tab 11: File & Share Audit */}
        {activeTab === 'file_audit' && (
          <div className="space-y-6">
            {fileAccessList.some(f => f.is_admin_share) && (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl flex items-center gap-3 text-rose-800 text-xs">
                <ShieldAlert className="w-5 h-5 text-rose-600 shrink-0" />
                <div>
                  <span className="font-bold">Administrative Share Access Detected (C$, ADMIN$, IPC$)!</span>
                  <p className="mt-0.5 text-rose-700">
                    Adversaries access administrative network shares to stage lateral movement payloads or harvest remote host files.
                  </p>
                </div>
              </div>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold text-slate-600">Filter Category:</span>
                {['all', 'Documents', 'Keys & Passwords', 'Archives', 'Source Code', 'Executables'].map(cat => (
                  <button
                    key={cat}
                    onClick={() => setFileAuditCategoryFilter(cat)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      fileAuditCategoryFilter === cat
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'bg-white border border-slate-200 text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    {cat} {cat === 'all' ? `(${fileAccessList.length})` : `(${fileAccessList.filter(f => f.file_category === cat).length})`}
                  </button>
                ))}
              </div>
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter file path or user..."
                  value={fileAuditSearch}
                  onChange={(e) => setFileAuditSearch(e.target.value)}
                  className="pl-9 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-indigo-500 w-full sm:w-60"
                />
              </div>
            </div>

            {filteredFileAccessAudit.length > 0 ? (
              <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">Operation</th>
                        <th className="py-3 px-4">File / Target Path</th>
                        <th className="py-3 px-4">Category</th>
                        <th className="py-3 px-4">User</th>
                        <th className="py-3 px-4">Process</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
                      {filteredFileAccessAudit.map((rec, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              rec.operation === 'Delete' ? 'bg-rose-100 text-rose-800' :
                              rec.operation === 'Write / Modify' ? 'bg-amber-100 text-amber-800' :
                              rec.operation === 'Execute' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
                            }`}>
                              {rec.operation}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                              <span>{rec.filename || rec.file_path}</span>
                              {rec.is_admin_share && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-100 text-rose-700 font-bold text-[9px]">
                                  ADMIN SHARE
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-slate-400 truncate max-w-md">{rec.file_path}</div>
                          </td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              rec.file_category === 'Keys & Passwords' ? 'bg-rose-100 text-rose-700' :
                              rec.file_category === 'Documents' ? 'bg-indigo-100 text-indigo-700' :
                              rec.file_category === 'Archives' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'
                            }`}>
                              {rec.file_category}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-sans text-slate-700">{rec.user}</td>
                          <td className="py-3 px-4 text-slate-600 text-[11px]">{rec.process}</td>
                          <td className="py-3 px-4 text-[11px] text-slate-500 font-sans">
                            {rec.timestamp ? formatTimestamp(rec.timestamp, timeConfig) : 'N/A'}
                          </td>
                          <td className="py-3 px-4 text-right">
                            {rec.is_admin_share && (
                              <button
                                onClick={() => setSelectedCorrelationEvent({
                                  event_id: 5145,
                                  share_name: rec.share_name,
                                  file_path: rec.file_path,
                                  user: rec.user,
                                  computer: rec.computer,
                                  timestamp: rec.timestamp
                                })}
                                className="px-2 py-1 text-[11px] font-semibold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 cursor-pointer"
                              >
                                Correlate
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No file or document access events matching current filter.
              </div>
            )}
          </div>
        )}

        {/* Tab 12: Print Spooler Audit */}
        {activeTab === 'print_audit' && (
          <div className="space-y-6">
            {printAuditList.some(p => p.is_bulk_print || p.is_sensitive) && (
              <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl flex items-center gap-3 text-amber-800 text-xs">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
                <div>
                  <span className="font-bold">Physical Data Exfiltration Alert: Large Volume / Sensitive Documents Printed!</span>
                  <p className="mt-0.5 text-amber-700">
                    Detected print spooler jobs with high page counts or sensitive filenames (financial, confidential, passwords).
                  </p>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Total Print Jobs</span>
                <p className="text-2xl font-black text-slate-900 mt-1">{printAuditList.length}</p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Total Pages Printed</span>
                <p className="text-2xl font-black text-indigo-600 mt-1">
                  {printAuditList.reduce((acc, p) => acc + (p.pages || 0), 0)}
                </p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Flagged Sensitive Prints</span>
                <p className="text-2xl font-black text-rose-600 mt-1">
                  {printAuditList.filter(p => p.is_sensitive || p.is_bulk_print).length}
                </p>
              </div>
            </div>

            {printAuditList.length > 0 ? (
              <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">Document Name</th>
                        <th className="py-3 px-4">Pages</th>
                        <th className="py-3 px-4">Size</th>
                        <th className="py-3 px-4">Printer &amp; Port</th>
                        <th className="py-3 px-4">User</th>
                        <th className="py-3 px-4">Client Machine</th>
                        <th className="py-3 px-4 text-right">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
                      {printAuditList.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-3 px-4">
                            <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                              <span>{item.document_name}</span>
                              {item.is_sensitive && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-100 text-rose-700 font-bold text-[9px]">
                                  SENSITIVE
                                </span>
                              )}
                              {item.is_bulk_print && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-100 text-amber-700 font-bold text-[9px]">
                                  BULK PRINT
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4 font-bold text-slate-900">{item.pages} pgs</td>
                          <td className="py-3 px-4 text-slate-600">{formatBytes(item.size_bytes)}</td>
                          <td className="py-3 px-4 font-sans text-slate-700">
                            <div>{item.printer}</div>
                            <div className="text-[10px] text-slate-400">{item.port}</div>
                          </td>
                          <td className="py-3 px-4 font-sans text-slate-800">{item.user}</td>
                          <td className="py-3 px-4 text-slate-600">{item.client_machine}</td>
                          <td className="py-3 px-4 text-right text-[11px] text-slate-500 font-sans">
                            {item.timestamp ? formatTimestamp(item.timestamp, timeConfig) : 'N/A'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No document print events recorded in analyzed event logs.
              </div>
            )}
          </div>
        )}

        {/* Tab 13: RDP Sessions */}
        {activeTab === 'rdp' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Total RDP Events</span>
                <p className="text-2xl font-black text-slate-900 mt-1">{rdpSessionsList.length}</p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Unique Remote Clients</span>
                <p className="text-2xl font-black text-indigo-600 mt-1">
                  {new Set(rdpSessionsList.map(r => r.client_ip)).size}
                </p>
              </div>
              <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <span className="text-xs font-semibold text-slate-500">Target Accounts</span>
                <p className="text-2xl font-black text-emerald-600 mt-1">
                  {new Set(rdpSessionsList.map(r => r.user)).size}
                </p>
              </div>
            </div>

            {rdpSessionsList.length > 0 ? (
              <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Remote Client IP &amp; Host</th>
                        <th className="py-3 px-4">Target User</th>
                        <th className="py-3 px-4">Target Computer</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4 text-right">PCAP Sync</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
                      {rdpSessionsList.map((rdp, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              rdp.status === 'Active Session' ? 'bg-emerald-100 text-emerald-800' :
                              rdp.status === 'Disconnected' ? 'bg-slate-100 text-slate-600' :
                              rdp.status === 'Authenticated' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'
                            }`}>
                              {rdp.status}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-bold text-slate-900">{rdp.client_ip}</div>
                            <div className="text-[10px] text-slate-500 font-sans">{rdp.client_name}</div>
                          </td>
                          <td className="py-3 px-4 font-sans font-semibold text-slate-800">{rdp.user}</td>
                          <td className="py-3 px-4 font-sans text-slate-600">{rdp.target_host}</td>
                          <td className="py-3 px-4 text-[11px] text-slate-500 font-sans">
                            {rdp.timestamp ? formatTimestamp(rdp.timestamp, timeConfig) : 'N/A'}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => setSelectedCorrelationEvent({
                                event_id: rdp.event_id,
                                ip_address: rdp.client_ip,
                                user: rdp.user,
                                computer: rdp.target_host,
                                process_name: 'mstsc.exe / RDP Listener',
                                timestamp: rdp.timestamp
                              })}
                              className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-indigo-50 text-indigo-700 hover:bg-indigo-100 transition-colors inline-flex items-center gap-1 cursor-pointer border border-indigo-200"
                            >
                              <Globe className="w-3 h-3 text-indigo-600" />
                              <span>Correlate</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No Remote Desktop (RDP) sessions or logon events recorded in analyzed event logs.
              </div>
            )}
          </div>
        )}

        {/* Tab 14: Command De-obfuscator */}
        {activeTab === 'deobfuscator' && (
          <div className="space-y-6">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Code2 className="w-4 h-4 text-indigo-600" />
                <span>Command-Line &amp; Script Execution De-obfuscator</span>
              </h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Automated normalization of caret escapes (^), backticks (`), string concatenation, environment variable slicing, and recursive Base64 decoders.
              </p>
            </div>

            {deobfuscatedCommandsList.length > 0 ? (
              <div className="space-y-4">
                {deobfuscatedCommandsList.map((cmd, idx) => (
                  <div key={idx} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold uppercase font-mono">
                          Obfuscated Command
                        </span>
                        <span className="text-xs font-semibold text-slate-700 font-mono">{cmd.process}</span>
                        <span className="text-xs text-slate-400">by</span>
                        <span className="text-xs font-semibold text-slate-800">{cmd.user}</span>
                        <span className="text-xs text-slate-400">at</span>
                        <span className="text-xs text-slate-500 font-mono">
                          {cmd.timestamp ? formatTimestamp(cmd.timestamp, timeConfig) : 'N/A'}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {cmd.obfuscation_types?.map((t, tidx) => (
                          <span key={tidx} className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-700 text-[10px] font-semibold">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>

                    {cmd.flagged_tokens && cmd.flagged_tokens.length > 0 && (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-rose-700">Flagged Malicious Primitives:</span>
                        {cmd.flagged_tokens.map((tok, tidx) => (
                          <span key={tidx} className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 font-mono text-[10px] font-bold">
                            {tok}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Raw Obfuscated Input</span>
                          <button
                            onClick={() => copyToClipboard(cmd.raw_command, `raw_${idx}`)}
                            className="p-1 text-slate-400 hover:text-slate-700 cursor-pointer"
                            title="Copy Raw"
                          >
                            {copiedId === `raw_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        <div className="p-3 bg-slate-900 rounded-xl font-mono text-rose-300 text-xs overflow-x-auto max-h-48 border border-slate-800">
                          {cmd.raw_command}
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-emerald-600 uppercase tracking-wider flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5" />
                            <span>Normalized De-obfuscated Result</span>
                          </span>
                          <button
                            onClick={() => copyToClipboard(cmd.deobfuscated_command, `deobf_${idx}`)}
                            className="p-1 text-slate-400 hover:text-slate-700 cursor-pointer"
                            title="Copy De-obfuscated"
                          >
                            {copiedId === `deobf_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        <div className="p-3 bg-emerald-950/40 rounded-xl font-mono text-emerald-400 text-xs overflow-x-auto max-h-48 border border-emerald-900/50">
                          {cmd.deobfuscated_command}
                        </div>
                      </div>
                    </div>

                    {cmd.steps && cmd.steps.length > 0 && (
                      <div className="text-xs text-slate-500 font-mono space-y-1 pt-1">
                        <span className="font-semibold text-slate-600 font-sans">De-obfuscation Pipeline:</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {cmd.steps.map((st: any, sidx: number) => {
                            const label = typeof st === 'string' ? st : `${st.type || `Stage ${st.step || sidx + 1}`}: ${st.output ? String(st.output).slice(0, 40) + '...' : ''}`;
                            return (
                              <span key={sidx} className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px]" title={typeof st === 'object' && st.output ? String(st.output) : undefined}>
                                {label}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No obfuscated commands requiring normalization detected in analyzed event logs.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Part 3 Item 1: Cross-Artifact PCAP Correlation Modal */}
      {selectedCorrelationEvent && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-2xl overflow-hidden flex flex-col">
            <div className="p-4 px-6 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div className="flex items-center gap-2.5">
                <Globe className="w-5 h-5 text-indigo-600" />
                <h4 className="text-sm font-bold text-slate-900">PCAP Network Stream Correlation</h4>
              </div>
              <button
                onClick={() => setSelectedCorrelationEvent(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-700">Target IP Address:</span>
                  <span className="font-mono text-indigo-700 font-bold text-sm">
                    {selectedCorrelationEvent.ip_address || 'N/A'}:{selectedCorrelationEvent.ip_port || '*'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Originating Process:</span>
                  <span className="font-mono text-slate-900">{selectedCorrelationEvent.process_name || 'System'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">User Account:</span>
                  <span className="font-mono text-slate-900">{selectedCorrelationEvent.user || 'N/A'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Computer:</span>
                  <span className="font-mono text-slate-900">{selectedCorrelationEvent.computer || 'N/A'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Timestamp:</span>
                  <span className="font-mono text-slate-900">
                    {selectedCorrelationEvent.timestamp ? formatTimestamp(selectedCorrelationEvent.timestamp, timeConfig) : 'N/A'}
                  </span>
                </div>
              </div>

              {(() => {
                const pcapJob = workspaceJobs?.find(j => j.category === 'pcap' || j.pcap_info || j.filename?.match(/\.(pcap|pcapng|cap)$/i));
                if (pcapJob) {
                  return (
                    <div className="p-4 rounded-xl bg-indigo-50/70 border border-indigo-200 space-y-3">
                      <div className="flex items-center gap-2 text-indigo-900 font-bold">
                        <CheckCircle2 className="w-4 h-4 text-indigo-600" />
                        <span>Matching PCAP Capture Found in Workspace ({pcapJob.filename || 'network.pcap'})</span>
                      </div>
                      <p className="text-slate-600 leading-relaxed">
                        Correlate packets and flows communicating with <span className="font-mono font-bold text-indigo-800">{selectedCorrelationEvent.ip_address}</span> directly inside the PCAP packet triage viewer.
                      </p>
                      <button
                        onClick={() => {
                          const targetIp = selectedCorrelationEvent.ip_address;
                          setSelectedCorrelationEvent(null);
                          if (onNavigateToPcap) {
                            onNavigateToPcap(pcapJob.job_id || pcapJob.jobId, targetIp);
                          }
                        }}
                        className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl flex items-center gap-2 cursor-pointer shadow-sm"
                      >
                        <ExternalLink className="w-4 h-4" />
                        <span>Open Matching Flows in PCAP Viewer</span>
                      </button>
                    </div>
                  );
                }
                return (
                  <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 space-y-2">
                    <div className="flex items-center gap-2 text-amber-900 font-bold">
                      <AlertTriangle className="w-4 h-4 text-amber-600" />
                      <span>No Network Capture (PCAP) Loaded in Current Workspace</span>
                    </div>
                    <p className="text-slate-600 leading-relaxed">
                      To inspect live packet transfers for <span className="font-mono font-bold">{selectedCorrelationEvent.ip_address}</span>, upload the corresponding .pcap or .pcapng file into this workspace.
                    </p>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
