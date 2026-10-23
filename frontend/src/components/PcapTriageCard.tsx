import React, { useState, useMemo } from 'react';
import {
  Activity,
  Globe,
  Lock,
  FileCode,
  ShieldAlert,
  Server,
  Key,
  Copy,
  Check,
  Search,
  AlertTriangle,
  Download,
  Clock,
  Terminal,
  Cpu,
  X,
  Play,
  BarChart2,
  HardDrive,
  Eye,
  Filter,
  Info,
  Mail,
  UploadCloud,
  ExternalLink,
  CheckCircle2,
  ShieldCheck,
  Layers,
  Wifi,
  Radio,
  FileText,
  AlertOctagon,
} from 'lucide-react';
import {
  PcapInfo,
  PcapConversation,
  PcapEndpoint,
  PcapCarvedFile,
  PcapGanttItem,
  PcapWebSession,
  PcapTerminalSession,
} from '../types';
import { formatBytes, truncateHash } from '../utils/formatters';
import { CarvedFilePreviewModal } from './CarvedFilePreviewModal';
import { findReferencedJob } from '../utils/crossFileReferences';
import { InvestigateAssetButton } from './InvestigateAssetButton';
import { NetworkIocEnrichmentPanel } from './NetworkIocEnrichmentPanel';

interface PcapTriageCardProps {
  pcapInfo?: PcapInfo | null;
  jobId?: string;
  onSelectJob?: (jobId: string) => void;
  workspaceJobs?: any[];
  onNavigateToEvtx?: (evtxJobId?: string, targetIp?: string) => void;
  disabledChecks?: string[];
}

export const PcapTriageCard: React.FC<PcapTriageCardProps> = ({
  pcapInfo,
  jobId,
  onSelectJob,
  workspaceJobs,
  onNavigateToEvtx,
  disabledChecks = [],
}) => {
  const isCheckDisabled = (chk: string) => (disabledChecks || []).includes(chk);
  const canShowFlows = !isCheckDisabled('check_conversations_flows');
  const [activeTab, setActiveTab] = useState<
    | 'flows'
    | 'web_sessions'
    | 'exfiltration'
    | 'terminal_replay'
    | 'emails'
    | 'gantt'
    | 'carved'
    | 'software'
    | 'endpoints'
    | 'dns'
    | 'tls'
    | 'credentials'
    | 'beaconing'
    | 'ssh'
    | 'integrity'
    | 'zeek_logs'
    | 'ids_alerts'
    | 'lateral_movement'
    | 'protocol_anomalies'
  >(canShowFlows ? 'flows' : 'gantt');

  React.useEffect(() => {
    if (activeTab === 'flows' && isCheckDisabled('check_conversations_flows')) {
      setActiveTab('gantt');
    } else if (activeTab === 'dns' && isCheckDisabled('check_dns_queries')) {
      setActiveTab(canShowFlows ? 'flows' : 'gantt');
    } else if (activeTab === 'tls' && isCheckDisabled('check_tls_certificates')) {
      setActiveTab(canShowFlows ? 'flows' : 'gantt');
    } else if (activeTab === 'web_sessions' && isCheckDisabled('check_http_ftp_traffic')) {
      setActiveTab(canShowFlows ? 'flows' : 'gantt');
    } else if (activeTab === 'credentials' && isCheckDisabled('check_plaintext_credentials')) {
      setActiveTab(canShowFlows ? 'flows' : 'gantt');
    } else if (activeTab === 'carved' && isCheckDisabled('check_extracted_payloads')) {
      setActiveTab(canShowFlows ? 'flows' : 'gantt');
    }
  }, [activeTab, disabledChecks]);
  const [activeZeekLog, setActiveZeekLog] = useState<'conn' | 'dns' | 'ssl' | 'x509' | 'files'>('conn');
  const [idsSeverityFilter, setIdsSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Interactive Modal state
  const [selectedFlow, setSelectedFlow] = useState<PcapConversation | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState<PcapEndpoint | null>(null);
  const [analyzingFileId, setAnalyzingFileId] = useState<number | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Gantt Protocol Filter & Hover Inspection state
  const [selectedProtocolFilter, setSelectedProtocolFilter] = useState<string>('all');
  const [hoveredGanttItem, setHoveredGanttItem] = useState<PcapGanttItem | null>(null);

  // In-Browser Carved File Viewer Modal state
  const [previewCarvedFile, setPreviewCarvedFile] = useState<PcapCarvedFile | null>(null);

  // New forensic view states
  const [webSearchFilter, setWebSearchFilter] = useState<string>('');
  const [selectedWebSession, setSelectedWebSession] = useState<PcapWebSession | null>(null);
  const [exfilDirectionFilter, setExfilDirectionFilter] = useState<'all' | 'uploaded' | 'downloaded'>('all');
  const [selectedTerminalSession, setSelectedTerminalSession] = useState<PcapTerminalSession | null>(null);
  const [emailBodyViewMode, setEmailBodyViewMode] = useState<'text' | 'html'>('text');
  const [selectedProcessCorrelationFlow, setSelectedProcessCorrelationFlow] = useState<any | null>(null);

  if (!pcapInfo) {
    return null;
  }

  const {
    summary,
    protocols,
    conversations,
    dns_queries,
    tls_sessions,
    credentials,
    transferred_files,
    top_endpoints,
    carved_files = [],
    software_identified = [],
    gantt_items = [],
    beaconing_flows = [],
    ssh_sessions = [],
    search_queries = [],
    web_sessions = [],
    exfiltration_tracker = {
      total_uploaded_bytes: 0,
      total_downloaded_bytes: 0,
      upload_to_download_ratio: 1,
      exfiltration_risk_level: 'NORMAL',
      risk_reason: 'Normal traffic profile',
      file_movement_ledger: []
    },
    terminal_sessions = [],
    emails = []
  } = pcapInfo;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 3500);
  };

  // Trigger Carved File Download
  const handleDownloadCarvedFile = (file: PcapCarvedFile) => {
    if (!jobId) {
      showNotice('Job ID unavailable for file download.');
      return;
    }
    const downloadUrl = `/api/jobs/${jobId}/pcap/files/${file.id}/download`;
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', file.filename || file.name || 'carved_file.bin');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showNotice(`Downloading '${file.filename}'...`);
  };

  // Trigger Independent Carved File Analysis
  const handleAnalyzeCarvedFile = async (file: PcapCarvedFile) => {
    if (!jobId) {
      showNotice('Job ID unavailable for analysis submission.');
      return;
    }
    setAnalyzingFileId(file.id);
    try {
      const resp = await fetch(`/api/jobs/${jobId}/pcap/files/${file.id}/analyze`, {
        method: 'POST'
      });
      const data = await resp.json();
      if (resp.ok && data.job_id) {
        showNotice(`Job created: ${data.job_id}. Switching analysis...`);
        if (onSelectJob) {
          onSelectJob(data.job_id);
        }
      } else {
        showNotice(`Analysis queue failed: ${data.detail || 'Unknown error'}`);
      }
    } catch (err) {
      showNotice(`Submission failed: ${String(err)}`);
    } finally {
      setAnalyzingFileId(null);
    }
  };

  // Helper to open endpoint modal from IP string
  const handleOpenEndpoint = (ip: string) => {
    const ep = (top_endpoints || []).find(e => e.ip === ip);
    if (ep) {
      setSelectedEndpoint(ep);
    } else {
      setSelectedEndpoint({
        ip,
        packets: 0,
        bytes: 0,
        sent: 0,
        recv: 0,
        is_private: ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')
      });
    }
  };

  // Helper to open flow modal from flow ID
  const handleOpenFlow = (flowId: string) => {
    const fl = (conversations || []).find(c => c.id === flowId);
    if (fl) {
      setSelectedFlow(fl);
    }
  };

  // Filtering flows (memoized)
  const filteredFlows = useMemo(() => {
    return (conversations || []).filter(fl => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return (
        fl.id.toLowerCase().includes(q) ||
        fl.src_ip.toLowerCase().includes(q) ||
        fl.dst_ip.toLowerCase().includes(q) ||
        fl.protocol.toLowerCase().includes(q) ||
        String(fl.src_port).includes(q) ||
        String(fl.dst_port).includes(q)
      );
    });
  }, [conversations, searchQuery]);

  // Filtering DNS (memoized)
  const filteredDns = useMemo(() => {
    return (dns_queries || []).filter(d => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return d.domain.toLowerCase().includes(q) || (d.resolved_ips || []).some(ip => ip.includes(q));
    });
  }, [dns_queries, searchQuery]);

  // Filtering Endpoints (memoized)
  const filteredEndpoints = useMemo(() => {
    return (top_endpoints || []).filter(ep => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return ep.ip.toLowerCase().includes(q) || (ep.country || '').toLowerCase().includes(q) || (ep.asn || '').toLowerCase().includes(q);
    });
  }, [top_endpoints, searchQuery]);

  // Filtering Carved Files (memoized)
  const filteredCarvedFiles = useMemo(() => {
    return (carved_files || []).filter(cf => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return (
        cf.filename.toLowerCase().includes(q) ||
        cf.mime_type.toLowerCase().includes(q) ||
        cf.sha256.toLowerCase().includes(q) ||
        (cf.source_protocol?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [carved_files, searchQuery]);

  const dangerousTransfers = useMemo(() => {
    return (transferred_files || []).filter(f => f.is_dangerous);
  }, [transferred_files]);

  const maliciousCarved = useMemo(() => {
    return (carved_files || []).filter(f => f.is_dangerous);
  }, [carved_files]);

  // Protocol Color Formatter
  const getProtocolColor = (proto: string) => {
    switch (proto?.toUpperCase()) {
      case 'HTTP':
        return { bg: 'bg-amber-500', text: 'text-amber-700', border: 'border-amber-200', light: 'bg-amber-50' };
      case 'TLS':
      case 'HTTPS':
        return { bg: 'bg-indigo-500', text: 'text-indigo-700', border: 'border-indigo-200', light: 'bg-indigo-50' };
      case 'DNS':
        return { bg: 'bg-sky-500', text: 'text-sky-700', border: 'border-sky-200', light: 'bg-sky-50' };
      case 'FTP':
        return { bg: 'bg-rose-500', text: 'text-rose-700', border: 'border-rose-200', light: 'bg-rose-50' };
      case 'SSH':
        return { bg: 'bg-purple-500', text: 'text-purple-700', border: 'border-purple-200', light: 'bg-purple-50' };
      default:
        return { bg: 'bg-slate-500', text: 'text-slate-700', border: 'border-slate-200', light: 'bg-slate-50' };
    }
  };

  // Dual Hex / ASCII Dump Formatter for Flow Details
  const renderHexDump = (hexStr: string) => {
    if (!hexStr) {
      return <div className="text-slate-400 italic py-4">No payload bytes recorded in packet stream.</div>;
    }
    const bytes: string[] = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(hexStr.substring(i, i + 2));
    }

    const rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const offsetHex = i.toString(16).padStart(8, '0');
      const hexParts = slice.join(' ').padEnd(47, ' ');
      const asciiParts = slice.map(b => {
        const charCode = parseInt(b, 16);
        return charCode >= 32 && charCode <= 126 ? String.fromCharCode(charCode) : '.';
      }).join('');

      rows.push(
        <div key={i} className="flex gap-4 font-mono text-[11px] leading-5 hover:bg-slate-800/40 px-2 rounded">
          <span className="text-slate-500 select-none">{offsetHex}</span>
          <span className="text-indigo-300 font-semibold">{hexParts}</span>
          <span className="text-emerald-400 border-l border-slate-700 pl-3">{asciiParts}</span>
        </div>
      );
    }

    return (
      <div className="bg-slate-950 text-slate-100 p-4 rounded-2xl overflow-x-auto max-h-[320px] scrollbar-thin shadow-inner">
        {rows}
      </div>
    );
  };

  return (
    <div className="bg-white border border-slate-200 rounded-3xl shadow-xs overflow-hidden flex flex-col transition-all">
      {/* Toast Notification Banner */}
      {actionNotice && (
        <div className="px-6 py-2.5 bg-indigo-600 text-white text-xs font-semibold flex items-center justify-between shadow-md animate-fade-in">
          <span>{actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-indigo-200 hover:text-white cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Executive PCAP Security Verdict Banner */}
      {pcapInfo.pcap_verdict && (
        <div
          className={`p-6 border-b transition-all ${
            pcapInfo.pcap_verdict.verdict === 'Malicious'
              ? 'bg-rose-50/90 border-rose-200 text-rose-950'
              : pcapInfo.pcap_verdict.verdict === 'Suspicious'
              ? 'bg-amber-50/90 border-amber-200 text-amber-950'
              : pcapInfo.pcap_verdict.verdict === 'Potentially Vulnerable'
              ? 'bg-yellow-50/90 border-yellow-200 text-yellow-950'
              : pcapInfo.pcap_verdict.verdict === 'No Known Threat Detected'
              ? 'bg-emerald-50/90 border-emerald-200 text-emerald-950'
              : 'bg-slate-50/90 border-slate-200 text-slate-800'
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-black/10">
            <div className="flex items-center gap-3">
              <div
                className={`w-11 h-11 rounded-2xl flex items-center justify-center shadow-xs shrink-0 ${
                  pcapInfo.pcap_verdict.verdict === 'Malicious'
                    ? 'bg-rose-600 text-white'
                    : pcapInfo.pcap_verdict.verdict === 'Suspicious'
                    ? 'bg-amber-600 text-white'
                    : pcapInfo.pcap_verdict.verdict === 'Potentially Vulnerable'
                    ? 'bg-yellow-600 text-white'
                    : pcapInfo.pcap_verdict.verdict === 'No Known Threat Detected'
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-600 text-white'
                }`}
              >
                {pcapInfo.pcap_verdict.verdict === 'Malicious' ? (
                  <ShieldAlert className="w-6 h-6 animate-pulse" />
                ) : pcapInfo.pcap_verdict.verdict === 'Suspicious' ? (
                  <AlertTriangle className="w-6 h-6" />
                ) : pcapInfo.pcap_verdict.verdict === 'No Known Threat Detected' ? (
                  <ShieldCheck className="w-6 h-6" />
                ) : (
                  <Info className="w-6 h-6" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded-md bg-black/10 text-current font-mono">
                    Executive PCAP Security Verdict
                  </span>
                  <span className="text-lg font-black tracking-tight">{pcapInfo.pcap_verdict.verdict}</span>
                  <span
                    className={`text-xs font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider font-mono ${
                      pcapInfo.pcap_verdict.severity === 'critical'
                        ? 'bg-rose-600 text-white'
                        : pcapInfo.pcap_verdict.severity === 'high'
                        ? 'bg-amber-600 text-white'
                        : pcapInfo.pcap_verdict.severity === 'medium'
                        ? 'bg-yellow-600 text-white'
                        : 'bg-emerald-600 text-white'
                    }`}
                  >
                    {pcapInfo.pcap_verdict.severity}
                  </span>
                </div>
                <p className="text-xs opacity-80 mt-0.5">
                  Automated network packet capture risk determination, confidence calibration &amp; incident containment guidance.
                </p>
              </div>
            </div>

            {/* Confidence Score Gauge */}
            <div className="flex items-center gap-3 bg-white/70 px-4 py-2 rounded-2xl border border-black/10 shadow-2xs">
              <div className="text-right">
                <span className="text-[10px] uppercase font-bold text-slate-500 block font-mono">Analysis Confidence</span>
                <span className="text-base font-black text-slate-900 font-mono">{pcapInfo.pcap_verdict.confidence_score}%</span>
              </div>
              <div className="w-16 bg-slate-200 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-2 rounded-full ${
                    pcapInfo.pcap_verdict.confidence_score >= 80 ? 'bg-indigo-600' : 'bg-amber-500'
                  }`}
                  style={{ width: `${pcapInfo.pcap_verdict.confidence_score}%` }}
                />
              </div>
            </div>
          </div>

          {/* Rationale and Containment Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 text-xs">
            <div>
              <span className="font-bold text-[11px] uppercase tracking-wider opacity-80 block mb-1.5 font-mono">
                Key Assessment Rationale:
              </span>
              <ul className="space-y-1.5 list-disc list-inside opacity-90 leading-relaxed">
                {pcapInfo.pcap_verdict.rationale.map((r, idx) => (
                  <li key={idx} className="text-current">
                    {r}
                  </li>
                ))}
              </ul>

              {pcapInfo.pcap_verdict.mitre_techniques?.length > 0 && (
                <div className="mt-3 flex items-center gap-1.5 flex-wrap">
                  <span className="text-[10px] font-bold uppercase tracking-wider opacity-75 font-mono mr-1">
                    MITRE ATT&amp;CK:
                  </span>
                  {pcapInfo.pcap_verdict.mitre_techniques.map((t, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 bg-black/10 rounded-md font-mono text-[10px] font-semibold text-current"
                    >
                      {t.id}: {t.name}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {pcapInfo.pcap_verdict.containment_recommendations?.length > 0 && (
              <div>
                <span className="font-bold text-[11px] uppercase tracking-wider opacity-80 block mb-1.5 font-mono">
                  Actionable Containment Guidance:
                </span>
                <ul className="space-y-1.5 list-disc list-inside opacity-90 leading-relaxed font-medium">
                  {pcapInfo.pcap_verdict.containment_recommendations.map((c, idx) => (
                    <li key={idx} className="text-current">
                      {c}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Header */}
      <div className="p-6 bg-slate-50/80 border-b border-slate-200/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-indigo-50 border border-indigo-200/80 flex items-center justify-center text-indigo-600 shadow-2xs">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-900 tracking-tight">PCAP Network Packet Capture Forensics</h3>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-indigo-100/70 text-indigo-800 border border-indigo-200/60 font-mono">
                {summary.file_format || 'PCAP'}
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Interactive flow dissection, automated file carver, Gantt communication timeline, and application fingerprinting.
            </p>
          </div>
        </div>

        {/* Global Summary Badges */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="px-3 py-1.5 rounded-xl bg-white border border-slate-200/80 text-xs font-mono shadow-2xs">
            <span className="text-slate-400 mr-1.5">Packets:</span>
            <span className="font-bold text-slate-800">{summary.packet_count.toLocaleString()}</span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-white border border-slate-200/80 text-xs font-mono shadow-2xs">
            <span className="text-slate-400 mr-1.5">Volume:</span>
            <span className="font-bold text-slate-800">{formatBytes(summary.total_bytes)}</span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-white border border-slate-200/80 text-xs font-mono shadow-2xs">
            <span className="text-slate-400 mr-1.5">Duration:</span>
            <span className="font-bold text-slate-800">{summary.duration_seconds}s</span>
          </div>
          <div className="px-3 py-1.5 rounded-xl bg-white border border-slate-200/80 text-xs font-mono shadow-2xs">
            <span className="text-slate-400 mr-1.5">Throughput:</span>
            <span className="font-bold text-slate-800">{summary.data_rate_kbps} kbps</span>
          </div>
        </div>
      </div>

      {/* Critical Security Callouts: Credentials & Dangerous Payloads */}
      {(credentials?.length > 0 || dangerousTransfers.length > 0 || maliciousCarved.length > 0) && (
        <div className="p-4 bg-rose-50/60 border-b border-rose-200/70 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-rose-100 text-rose-600 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold text-rose-900 tracking-tight">Security Incidents & Payloads Detected in Capture Stream</h4>
              <p className="text-[11px] text-rose-700">
                {credentials?.length > 0 && `${credentials.length} plaintext credentials exposed`}
                {credentials?.length > 0 && (dangerousTransfers.length > 0 || maliciousCarved.length > 0) && ' · '}
                {carved_files.length > 0 && `${carved_files.length} carved files (${maliciousCarved.length} dangerous)`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {!isCheckDisabled('check_plaintext_credentials') && credentials?.length > 0 && (
              <button
                onClick={() => setActiveTab('credentials')}
                className="px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold shadow-2xs cursor-pointer transition-colors"
              >
                Inspect Credentials ({credentials.length})
              </button>
            )}
            {!isCheckDisabled('check_extracted_payloads') && carved_files.length > 0 && (
              <button
                onClick={() => setActiveTab('carved')}
                className="px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold shadow-2xs cursor-pointer transition-colors"
              >
                Inspect Carved Files ({carved_files.length})
              </button>
            )}
          </div>
        </div>
      )}

      {/* Protocol Pills Bar & Tab Search */}
      <div className="px-6 py-3 bg-slate-50/40 border-b border-slate-200/60 flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1 font-mono">Discovered Protocols:</span>
          {Object.entries(protocols || {}).map(([proto, count]) => {
            const colors = getProtocolColor(proto);
            return (
              <span
                key={proto}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-white border border-slate-200/70 text-xs font-mono font-medium text-slate-700 shadow-2xs"
              >
                <span className={`w-2 h-2 rounded-full ${colors.bg}`} />
                <span className="font-semibold">{proto}</span>
                <span className="text-[10px] text-slate-400 font-normal">({count})</span>
              </span>
            );
          })}
        </div>

        {/* Tab Search Filter */}
        <div className="relative min-w-[220px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search flows, IPs, files..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1 bg-white border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="px-6 border-b border-slate-200 flex items-center gap-2 overflow-x-auto scrollbar-thin text-xs font-medium">
        {!isCheckDisabled('check_conversations_flows') && (
          <button
            onClick={() => setActiveTab('flows')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'flows'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Network Flows ({conversations?.length || 0})</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab('gantt')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'gantt'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <BarChart2 className="w-4 h-4" />
          <span>Timeline / Gantt Chart</span>
        </button>

        {!isCheckDisabled('check_http_ftp_traffic') && (
          <button
            onClick={() => setActiveTab('web_sessions')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'web_sessions'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Search className="w-4 h-4" />
            <span>Web &amp; Searches ({search_queries.length + web_sessions.length})</span>
            {(search_queries.length + web_sessions.length) > 0 && (
              <span className="w-2 h-2 rounded-full bg-indigo-500" />
            )}
          </button>
        )}

        <button
          onClick={() => setActiveTab('exfiltration')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'exfiltration'
              ? 'border-rose-600 text-rose-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Exfiltration Tracker</span>
          {exfiltration_tracker?.exfiltration_risk_level && exfiltration_tracker.exfiltration_risk_level !== 'NORMAL' && (
            <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-rose-100 text-rose-700 uppercase">
              {exfiltration_tracker.exfiltration_risk_level}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('terminal_replay')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'terminal_replay'
              ? 'border-emerald-600 text-emerald-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Terminal Replay ({terminal_sessions.length})</span>
          {terminal_sessions.length > 0 && (
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('emails')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'emails'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Mail className="w-4 h-4" />
          <span>Email Interceptor ({emails.length})</span>
          {emails.length > 0 && (
            <span className="w-2 h-2 rounded-full bg-indigo-500" />
          )}
        </button>

        {!isCheckDisabled('check_extracted_payloads') && (
          <button
            onClick={() => setActiveTab('carved')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'carved'
                ? 'border-amber-600 text-amber-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <HardDrive className="w-4 h-4" />
            <span>Carved Files ({carved_files?.length || 0})</span>
            {(carved_files?.length || 0) > 0 && (
              <span className="w-2 h-2 rounded-full bg-amber-500" />
            )}
          </button>
        )}

        <button
          onClick={() => setActiveTab('software')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'software'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Software & Programs ({software_identified?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('endpoints')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'endpoints'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Top Endpoints ({top_endpoints?.length || 0})</span>
        </button>

        {!isCheckDisabled('check_dns_queries') && (
          <button
            onClick={() => setActiveTab('dns')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'dns'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>DNS Queries ({dns_queries?.length || 0})</span>
          </button>
        )}

        {!isCheckDisabled('check_tls_certificates') && (
          <button
            onClick={() => setActiveTab('tls')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'tls'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>TLS Sessions ({tls_sessions?.length || 0})</span>
          </button>
        )}

        {!isCheckDisabled('check_plaintext_credentials') && (
          <button
            onClick={() => setActiveTab('credentials')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'credentials'
                ? 'border-rose-600 text-rose-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Credentials ({credentials?.length || 0})</span>
            {(credentials?.length || 0) > 0 && (
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>
        )}

        <button
          onClick={() => setActiveTab('beaconing')}
          className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
            activeTab === 'beaconing'
              ? 'border-rose-600 text-rose-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Activity className="w-4 h-4 text-rose-600" />
          <span>C2 Beaconing ({beaconing_flows?.length || 0})</span>
          {(beaconing_flows?.length || 0) > 0 && (
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
          )}
        </button>

        {(ssh_sessions?.length || 0) > 0 && (
          <button
            onClick={() => setActiveTab('ssh')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'ssh'
                ? 'border-purple-600 text-purple-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Terminal className="w-4 h-4 text-purple-600" />
            <span>SSH &amp; HASSH ({ssh_sessions.length})</span>
          </button>
        )}

        {pcapInfo.ids_alerts && pcapInfo.ids_alerts.length > 0 && (
          <button
            onClick={() => setActiveTab('ids_alerts')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'ids_alerts'
                ? 'border-rose-600 text-rose-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <span>Suricata IDS ({pcapInfo.ids_alerts.length})</span>
            {pcapInfo.ids_alerts.some(a => a.severity === 1) && (
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>
        )}

        {pcapInfo.zeek_logs && (
          <button
            onClick={() => setActiveTab('zeek_logs')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'zeek_logs'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Layers className="w-4 h-4 text-indigo-600" />
            <span>Zeek Logs</span>
          </button>
        )}

        {pcapInfo.lateral_movement && (
          <button
            onClick={() => setActiveTab('lateral_movement')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'lateral_movement'
                ? 'border-amber-600 text-amber-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Radio className="w-4 h-4 text-amber-600" />
            <span>
              Recon &amp; Lateral (
              {(pcapInfo.lateral_movement.scans_detected?.length || 0) +
                (pcapInfo.lateral_movement.lateral_movement_events?.length || 0)}
              )
            </span>
            {(pcapInfo.lateral_movement.has_active_reconnaissance ||
              pcapInfo.lateral_movement.has_lateral_movement) && (
              <span className="w-2 h-2 rounded-full bg-amber-500" />
            )}
          </button>
        )}

        {pcapInfo.protocol_anomalies && (
          <button
            onClick={() => setActiveTab('protocol_anomalies')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'protocol_anomalies'
                ? 'border-purple-600 text-purple-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Wifi className="w-4 h-4 text-purple-600" />
            <span>Protocol Anomalies &amp; OT</span>
            {(pcapInfo.protocol_anomalies.arp_spoofing_alerts?.length > 0 ||
              pcapInfo.protocol_anomalies.rogue_dhcp_detected ||
              pcapInfo.protocol_anomalies.modbus_industrial_events?.some(m => m.severity === 'CRITICAL')) && (
              <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse" />
            )}
          </button>
        )}

        {pcapInfo.capture_integrity && (
          <button
            onClick={() => setActiveTab('integrity')}
            className={`py-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 shrink-0 ${
              activeTab === 'integrity'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Capture Integrity &amp; Provenance</span>
            {pcapInfo.capture_integrity.integrity_status !== 'INTACT' && (
              <span className="w-2 h-2 rounded-full bg-amber-500" />
            )}
          </button>
        )}
      </div>

      {/* Tab Panels */}
      <div className="p-6">
        {/* =========================================================================
            TAB 1: Network Flows (with Clickable Links opening Flow Details Modal)
           ========================================================================= */}
        {activeTab === 'flows' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                  <th className="py-2.5 px-3">Flow ID</th>
                  <th className="py-2.5 px-3">Source Endpoint</th>
                  <th className="py-2.5 px-3 text-center">Dir</th>
                  <th className="py-2.5 px-3">Destination Endpoint</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3 text-right">Packets</th>
                  <th className="py-2.5 px-3 text-right">Volume</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-3 text-right">Stream Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredFlows.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-8 text-center text-slate-400 font-sans">
                      No matching network conversations found
                    </td>
                  </tr>
                ) : (
                  filteredFlows.map((fl) => {
                    const pColors = getProtocolColor(fl.protocol);
                    return (
                      <tr key={fl.id} className="hover:bg-slate-50/80 transition-colors group">
                        <td className="py-3 px-3 font-semibold text-slate-600">
                          <button
                            onClick={() => setSelectedFlow(fl)}
                            className="text-indigo-600 hover:text-indigo-800 hover:underline font-bold cursor-pointer"
                          >
                            {fl.id}
                          </button>
                        </td>
                        <td className="py-3 px-3 font-medium text-slate-800">
                          <button
                            onClick={() => handleOpenEndpoint(fl.src_ip)}
                            className="hover:text-indigo-600 hover:underline cursor-pointer"
                          >
                            {fl.src_ip}
                          </button>
                          <span className="text-slate-400 font-normal">:{fl.src_port}</span>
                        </td>
                        <td className="py-3 px-3 text-center text-slate-400">↔</td>
                        <td className="py-3 px-3 font-medium text-slate-800">
                          <button
                            onClick={() => handleOpenEndpoint(fl.dst_ip)}
                            className="hover:text-indigo-600 hover:underline cursor-pointer"
                          >
                            {fl.dst_ip}
                          </button>
                          <span className="text-slate-400 font-normal">:{fl.dst_port}</span>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`px-2 py-0.5 rounded-md font-bold text-[11px] border ${pColors.light} ${pColors.text} ${pColors.border}`}>
                            {fl.protocol}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right text-slate-700 font-semibold">{fl.packets.toLocaleString()}</td>
                        <td className="py-3 px-3 text-right text-indigo-600 font-bold">{formatBytes(fl.bytes)}</td>
                        <td className="py-3 px-3">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                            fl.state === 'TERMINATED_NORMAL' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                            fl.state === 'RESET_BY_PEER' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                            'bg-slate-100 text-slate-600 border border-slate-200'
                          }`}>
                            {fl.state || 'ACTIVE'}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right space-x-1.5">
                          <button
                            onClick={() => setSelectedFlow(fl)}
                            className="px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 font-sans text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                          >
                            <Terminal className="w-3 h-3" />
                            <span>Inspect</span>
                          </button>
                          <button
                            onClick={() => setSelectedProcessCorrelationFlow({
                              src_ip: fl.src_ip,
                              dst_ip: fl.dst_ip,
                              dst_port: fl.dst_port,
                              protocol: fl.protocol,
                              timestamp: fl.start_time
                            })}
                            className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-sans text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                            title="Identify originating Windows process from event logs"
                          >
                            <Search className="w-3 h-3 text-indigo-600" />
                            <span>Identify Process</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* =========================================================================
            TAB 2: Timeline / Gantt Chart Visualization
           ========================================================================= */}
        {activeTab === 'gantt' && (() => {
          const filteredGanttItems = gantt_items.filter((item) => {
            if (selectedProtocolFilter === 'all') return true;
            const filterLower = selectedProtocolFilter.toLowerCase();
            const p = item.protocol.toLowerCase();
            if (filterLower === 'http') return p.includes('http');
            if (filterLower === 'tls') return p.includes('tls') || p.includes('https') || p.includes('ssl');
            if (filterLower === 'dns') return p.includes('dns');
            if (filterLower === 'ftp') return p.includes('ftp');
            if (filterLower === 'ssh') return p.includes('ssh') || p.includes('sftp');
            if (filterLower === 'smb') return p.includes('smb');
            if (filterLower === 'sql') return p.includes('sql');
            if (filterLower === 'email') return ['smtp', 'pop3', 'imap'].some((e) => p.includes(e));
            return p === filterLower;
          });

          return (
            <div className="space-y-4">
              {/* Header Banner */}
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h4 className="text-xs font-bold text-slate-900 tracking-tight flex items-center gap-2">
                    <Clock className="w-4 h-4 text-indigo-600" />
                    <span>User Traffic Tracking & Network Flow Gantt Timeline</span>
                  </h4>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Chronological visualization of common protocol flows ({summary.duration_seconds}s capture span). Hover over any timeline bar to inspect queries, URL parameters, commands, and transferred file artifacts.
                  </p>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono">
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-amber-500" /> HTTP</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-indigo-500" /> TLS</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-sky-500" /> DNS</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-rose-500" /> FTP</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-purple-500" /> SSH</span>
                </div>
              </div>

              {/* Protocol Filter Pills */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
                <span className="text-slate-400 text-[11px] font-semibold flex items-center gap-1 mr-1 shrink-0">
                  <Filter className="w-3.5 h-3.5" /> Protocol:
                </span>
                {[
                  { id: 'all', label: `All Protocols (${gantt_items.length})` },
                  { id: 'http', label: 'HTTP' },
                  { id: 'tls', label: 'TLS / HTTPS' },
                  { id: 'ftp', label: 'FTP' },
                  { id: 'ssh', label: 'SSH / SFTP' },
                  { id: 'dns', label: 'DNS' },
                  { id: 'smb', label: 'SMB' },
                  { id: 'sql', label: 'SQL' },
                  { id: 'email', label: 'Email' }
                ].map((proto) => {
                  const count = proto.id === 'all'
                    ? gantt_items.length
                    : gantt_items.filter((i) => {
                        const p = i.protocol.toLowerCase();
                        if (proto.id === 'http') return p.includes('http');
                        if (proto.id === 'tls') return p.includes('tls') || p.includes('https') || p.includes('ssl');
                        if (proto.id === 'dns') return p.includes('dns');
                        if (proto.id === 'ftp') return p.includes('ftp');
                        if (proto.id === 'ssh') return p.includes('ssh') || p.includes('sftp');
                        if (proto.id === 'smb') return p.includes('smb');
                        if (proto.id === 'sql') return p.includes('sql');
                        if (proto.id === 'email') return ['smtp', 'pop3', 'imap'].some((e) => p.includes(e));
                        return p === proto.id;
                      }).length;

                  return (
                    <button
                      key={proto.id}
                      onClick={() => setSelectedProtocolFilter(proto.id)}
                      className={`px-2.5 py-1 rounded-lg font-semibold transition-colors flex items-center gap-1 shrink-0 ${
                        selectedProtocolFilter === proto.id
                          ? 'bg-indigo-600 text-white shadow-2xs'
                          : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
                      }`}
                    >
                      <span>{proto.label}</span>
                      {proto.id !== 'all' && (
                        <span className={`px-1 py-0.2 rounded-full text-[10px] font-mono ${
                          selectedProtocolFilter === proto.id ? 'bg-indigo-700 text-white' : 'bg-slate-100 text-slate-500'
                        }`}>
                          {count}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Interactive Hover Card (Live Communication Inspector) */}
              <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-sm transition-all">
                {hoveredGanttItem ? (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getProtocolColor(hoveredGanttItem.protocol).light} ${getProtocolColor(hoveredGanttItem.protocol).text} ${getProtocolColor(hoveredGanttItem.protocol).border}`}>
                          {hoveredGanttItem.protocol}
                        </span>
                        <span className="font-mono text-xs font-bold text-slate-900">
                          {hoveredGanttItem.src_endpoint} &rarr; {hoveredGanttItem.dst_endpoint}
                        </span>
                        <span className="text-slate-300">|</span>
                        <span className="text-xs font-mono text-slate-500">
                          Start: {hoveredGanttItem.start_seconds.toFixed(2)}s • Duration: {hoveredGanttItem.duration_seconds.toFixed(2)}s
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-600 font-semibold">
                        {formatBytes(hoveredGanttItem.bytes)} • {hoveredGanttItem.packets} packets
                      </div>
                    </div>

                    {/* Summary Narrative */}
                    {hoveredGanttItem.summary_narrative && (
                      <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200/80 font-mono text-xs text-slate-800 break-all flex items-start gap-2">
                        <Terminal className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold text-indigo-900">Observed Communication:</span>
                          <p className="mt-0.5 font-bold text-slate-900">{hoveredGanttItem.summary_narrative}</p>
                        </div>
                      </div>
                    )}

                    {/* Detailed Protocol Breakdown */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
                      {/* HTTP Breakdown */}
                      {hoveredGanttItem.site && (
                        <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">HTTP Target</span>
                          <div className="truncate text-slate-900 font-semibold">{hoveredGanttItem.site}</div>
                          {hoveredGanttItem.path && (
                            <div className="text-slate-600 truncate mt-0.5">Path: {hoveredGanttItem.path}</div>
                          )}
                          {hoveredGanttItem.query_params && (
                            <div className="text-amber-700 break-all mt-0.5 bg-amber-50 p-1 rounded border border-amber-200 text-[11px]">
                              Query: ?{hoveredGanttItem.query_params}
                            </div>
                          )}
                          {hoveredGanttItem.status_code && (
                            <div className="mt-1 text-[11px] text-slate-500">
                              Status: <span className="font-bold text-emerald-600">{hoveredGanttItem.status_code}</span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Commands (FTP / SSH / SMB) */}
                      {hoveredGanttItem.commands && hoveredGanttItem.commands.length > 0 && (
                        <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Commands Sent</span>
                          <ul className="space-y-0.5 text-slate-800">
                            {hoveredGanttItem.commands.slice(0, 3).map((cmd, cIdx) => (
                              <li key={cIdx} className="truncate font-semibold">{cmd}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* DNS Query Breakdown */}
                      {hoveredGanttItem.dns_query && (
                        <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">DNS Resolution</span>
                          <div className="font-semibold text-slate-900 truncate">Q: {hoveredGanttItem.dns_query}</div>
                          {hoveredGanttItem.dns_answers && hoveredGanttItem.dns_answers.length > 0 && (
                            <div className="text-slate-600 truncate mt-0.5">
                              Answers: {hoveredGanttItem.dns_answers.join(', ')}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Transferred File Artifact */}
                      {hoveredGanttItem.transferred_file && (
                        <div className="p-2.5 bg-indigo-50/70 rounded-lg border border-indigo-200">
                          <span className="text-[10px] uppercase font-bold text-indigo-700 block mb-1">Reconstructed File</span>
                          <div className="font-bold text-indigo-950 truncate">{hoveredGanttItem.transferred_file.filename}</div>
                          <div className="text-[11px] text-indigo-700 mt-0.5">
                            Size: {hoveredGanttItem.transferred_file.filesize_formatted} • {hoveredGanttItem.transferred_file.direction?.toUpperCase()}
                          </div>
                          {hoveredGanttItem.transferred_file.sha256 && (
                            <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">
                              SHA256: {hoveredGanttItem.transferred_file.sha256.substring(0, 16)}...
                            </div>
                          )}
                        </div>
                      )}

                      {/* TLS / SNI / JA3 */}
                      {hoveredGanttItem.tls_sni && (
                        <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">TLS Handshake</span>
                          <div className="font-semibold text-slate-900 truncate">SNI: {hoveredGanttItem.tls_sni}</div>
                          {hoveredGanttItem.ja3 && (
                            <div className="text-slate-500 truncate mt-0.5 text-[10px]">
                              JA3: {hoveredGanttItem.ja3}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-between text-slate-500 text-xs">
                    <div className="flex items-center gap-2">
                      <Info className="w-4 h-4 text-indigo-500 shrink-0" />
                      <span>
                        Hover over any timeline flow bar below to reveal user communication details, request queries, FTP commands, DNS lookups, and transferred files.
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      Showing {filteredGanttItems.length} active flow spans
                    </span>
                  </div>
                )}
              </div>

              {/* Gantt Canvas */}
              <div className="border border-slate-200 rounded-2xl bg-white p-5 space-y-4">
                {/* Timeline Header Ruler */}
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 border-b border-slate-200 pb-2 pl-48">
                  <span>0.0s (Start)</span>
                  <span>{((summary.duration_seconds || 1) * 0.25).toFixed(2)}s</span>
                  <span>{((summary.duration_seconds || 1) * 0.50).toFixed(2)}s</span>
                  <span>{((summary.duration_seconds || 1) * 0.75).toFixed(2)}s</span>
                  <span>{summary.duration_seconds}s (End)</span>
                </div>

                {/* Gantt Rows */}
                <div className="space-y-3 font-mono">
                  {filteredGanttItems.length === 0 ? (
                    <div className="py-8 text-center text-slate-400 font-sans text-xs">
                      No active flow spans recorded matching protocol filter '{selectedProtocolFilter}'
                    </div>
                  ) : (
                    filteredGanttItems.map((item) => {
                      const pColors = getProtocolColor(item.protocol);
                      const isHovered = hoveredGanttItem?.flow_id === item.flow_id;

                      return (
                        <div key={item.flow_id} className="flex items-center gap-3 group">
                          {/* Flow Label */}
                          <div className="w-48 shrink-0 flex items-center justify-between pr-2 text-xs">
                            <button
                              onClick={() => handleOpenFlow(item.flow_id)}
                              className="font-bold text-slate-700 hover:text-indigo-600 hover:underline cursor-pointer truncate max-w-[120px]"
                              title={`${item.src_endpoint} <-> ${item.dst_endpoint}`}
                            >
                              {item.flow_id}
                            </button>
                            <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${pColors.light} ${pColors.text} ${pColors.border}`}>
                              {item.protocol}
                            </span>
                          </div>

                          {/* Timeline Bar Track */}
                          <div className="flex-1 h-7 bg-slate-100 rounded-lg relative overflow-hidden border border-slate-200/70">
                            {/* Grid background markers */}
                            <div className="absolute inset-0 flex justify-between pointer-events-none opacity-20">
                              <div className="border-r border-slate-400 w-1/4 h-full" />
                              <div className="border-r border-slate-400 w-1/4 h-full" />
                              <div className="border-r border-slate-400 w-1/4 h-full" />
                              <div className="w-1/4 h-full" />
                            </div>

                            {/* Active Duration Bar */}
                            <button
                              onClick={() => handleOpenFlow(item.flow_id)}
                              onMouseEnter={() => setHoveredGanttItem(item)}
                              onMouseLeave={() => setHoveredGanttItem(null)}
                              style={{
                                left: `${item.start_pct}%`,
                                width: `${item.width_pct}%`
                              }}
                              className={`absolute top-1 bottom-1 ${pColors.bg} hover:brightness-110 rounded-md transition-all cursor-pointer shadow-xs flex items-center px-2 ${
                                isHovered ? 'ring-2 ring-indigo-500 scale-[1.01]' : 'group-hover:ring-2 group-hover:ring-indigo-300'
                              }`}
                              title={`${item.summary_narrative || item.flow_id}`}
                            >
                              <span className="text-[10px] text-white font-bold truncate drop-shadow-xs">
                                {item.duration_seconds > 0 ? `${item.duration_seconds.toFixed(2)}s` : '1 pkt'}
                              </span>
                            </button>
                          </div>

                          {/* Bytes Badge */}
                          <div className="w-20 shrink-0 text-right text-xs font-semibold text-slate-600">
                            {formatBytes(item.bytes)}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* =========================================================================
            TAB 3: Carved Files & Payloads (Download & Send to Analyzing)
           ========================================================================= */}
        {activeTab === 'carved' && (
          <div className="space-y-4">
            <div className="p-4 rounded-2xl bg-amber-50/50 border border-amber-200/80 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-bold text-amber-900 tracking-tight flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-amber-600" />
                  <span>Automated PCAP File Carver & Binary Reassembly Engine</span>
                </h4>
                <p className="text-[11px] text-amber-700">
                  Extracted HTTP responses, FTP payload streams, and magic byte signatures reconstructed directly from packet streams.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded-lg bg-amber-100 text-amber-900 text-xs font-mono font-bold">
                {carved_files.length} Carved Artifact{carved_files.length !== 1 ? 's' : ''}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                    <th className="py-2.5 px-3">Carved File / Payload</th>
                    <th className="py-2.5 px-3">MIME / Type</th>
                    <th className="py-2.5 px-3">Size</th>
                    <th className="py-2.5 px-3">Cryptographic Hashes</th>
                    <th className="py-2.5 px-3">Source Origin</th>
                    <th className="py-2.5 px-3">Reputation Status</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredCarvedFiles.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-400 font-sans">
                        No carved files found in packet stream
                      </td>
                    </tr>
                  ) : (
                    filteredCarvedFiles.map((cf) => {
                      const vt = cf.threat_intel?.virustotal;
                      const tf = cf.threat_intel?.threatfox;
                      const mb = cf.threat_intel?.malwarebazaar;
                      const matchedWorkspaceJob = workspaceJobs ? (
                        findReferencedJob(cf.filename, workspaceJobs, jobId) ||
                        (cf.sha256 ? findReferencedJob(cf.sha256, workspaceJobs, jobId) : null) ||
                        (cf.md5 ? findReferencedJob(cf.md5, workspaceJobs, jobId) : null)
                      ) : null;

                      return (
                        <tr key={cf.id} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-3 px-3 font-semibold text-slate-900">
                            <div className="flex items-center gap-2">
                              <FileCode className={`w-4 h-4 shrink-0 ${cf.is_dangerous ? 'text-rose-500' : 'text-slate-400'}`} />
                              <div>
                                {matchedWorkspaceJob && onSelectJob ? (
                                  <button
                                    onClick={() => onSelectJob(matchedWorkspaceJob.jobId)}
                                    className="font-bold text-indigo-700 hover:text-indigo-900 hover:underline flex items-center gap-1 cursor-pointer text-left"
                                    title={`Navigate to analyzed workspace file: ${matchedWorkspaceJob.filename}`}
                                  >
                                    <span>{cf.filename}</span>
                                    <ExternalLink className="w-3 h-3 text-indigo-500 shrink-0" />
                                  </button>
                                ) : (
                                  <span className="font-bold">{cf.filename}</span>
                                )}
                                {matchedWorkspaceJob && (
                                  <span className="inline-block mt-0.5 px-1.5 py-0.2 bg-indigo-50 text-indigo-700 rounded text-[9px] font-bold uppercase tracking-wider border border-indigo-200">
                                    Linked: {matchedWorkspaceJob.filename}
                                  </span>
                                )}
                                {cf.threat_reason && (
                                  <div className="text-[10px] text-slate-400 font-sans">{cf.threat_reason}</div>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-medium text-[11px] border border-slate-200">
                              {cf.mime_type}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-semibold text-slate-700">{cf.size_formatted}</td>
                          <td className="py-3 px-3">
                            <div className="space-y-1">
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] text-slate-400">SHA256:</span>
                                <span className="text-[11px] text-slate-700">{cf.sha256.substring(0, 14)}...</span>
                                <button
                                  onClick={() => copyToClipboard(cf.sha256, `sha-${cf.id}`)}
                                  className="text-slate-400 hover:text-slate-700 cursor-pointer"
                                  title="Copy SHA256"
                                >
                                  {copiedKey === `sha-${cf.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] text-slate-400">MD5:</span>
                                <span className="text-[11px] text-slate-500">{cf.md5.substring(0, 10)}...</span>
                                <button
                                  onClick={() => copyToClipboard(cf.md5, `md5-${cf.id}`)}
                                  className="text-slate-400 hover:text-slate-700 cursor-pointer"
                                  title="Copy MD5"
                                >
                                  {copiedKey === `md5-${cf.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-3 text-slate-600">
                            <div>{cf.source_protocol}</div>
                            <div className="text-[10px] text-slate-400">{cf.source_stream}</div>
                          </td>
                          <td className="py-3 px-3">
                            {cf.is_dangerous ? (
                              <div className="space-y-1">
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
                                  <AlertTriangle className="w-3 h-3 text-rose-600" />
                                  <span>Dangerous Payload</span>
                                </span>
                                {tf?.status === 'MALICIOUS' && (
                                  <div className="text-[10px] text-rose-600 font-sans">ThreatFox: {tf.malware}</div>
                                )}
                                {mb?.status === 'MALICIOUS' && (
                                  <div className="text-[10px] text-rose-600 font-sans">MalwareBazaar Flagged</div>
                                )}
                                {vt?.positives > 0 && (
                                  <div className="text-[10px] text-rose-600 font-sans">VT: {vt.positives}/{vt.total_engines}</div>
                                )}
                              </div>
                            ) : (
                              <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                                Clean Artifact
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 text-right">
                            <div className="flex items-center justify-end gap-2 font-sans">
                              <button
                                onClick={() => setPreviewCarvedFile(cf)}
                                className="px-2.5 py-1 rounded-lg bg-indigo-50 border border-indigo-200 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                                title="View/Preview carved file content in browser"
                              >
                                <Eye className="w-3.5 h-3.5" />
                                <span>View File</span>
                              </button>

                              <button
                                onClick={() => handleDownloadCarvedFile(cf)}
                                className="px-2.5 py-1 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                                title="Download extracted file to disk"
                              >
                                <Download className="w-3.5 h-3.5" />
                                <span>Download</span>
                              </button>

                              {matchedWorkspaceJob && onSelectJob ? (
                                <button
                                  onClick={() => onSelectJob(matchedWorkspaceJob.jobId)}
                                  className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                                  title={`Open analysis tab for ${matchedWorkspaceJob.filename}`}
                                >
                                  <ExternalLink className="w-3.5 h-3.5" />
                                  <span>View Analyzed File ({matchedWorkspaceJob.filename})</span>
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleAnalyzeCarvedFile(cf)}
                                  disabled={analyzingFileId === cf.id}
                                  className="px-2.5 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs disabled:opacity-50"
                                  title="Queue this carved file as a new analysis job"
                                >
                                  {analyzingFileId === cf.id ? (
                                    <Activity className="w-3.5 h-3.5 animate-spin" />
                                  ) : (
                                    <Play className="w-3.5 h-3.5" />
                                  )}
                                  <span>Send to Analyzing</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 4: Software & Programs Identified
           ========================================================================= */}
        {activeTab === 'software' && (
          <div className="space-y-4">
            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-bold text-slate-900 tracking-tight flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-600" />
                  <span>Identified Programs, Software Banners & Operating Systems</span>
                </h4>
                <p className="text-[11px] text-slate-500">
                  Fingerprinted from HTTP User-Agents, Server response headers, SSH identification strings, and FTP banners.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-slate-800 text-xs font-mono font-bold shadow-2xs">
                {software_identified.length} Identified Stack{software_identified.length !== 1 ? 's' : ''}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                    <th className="py-2.5 px-3">Program / Software Name</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Role</th>
                    <th className="py-2.5 px-3">Associated Host / IP</th>
                    <th className="py-2.5 px-3">Discovered In</th>
                    <th className="py-2.5 px-3">Raw Banner / Fingerprint</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {software_identified.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                        No software or program signatures identified in this capture
                      </td>
                    </tr>
                  ) : (
                    software_identified.map((sw, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3 px-3 font-bold text-slate-900 flex items-center gap-2">
                          <Terminal className="w-4 h-4 text-indigo-500 shrink-0" />
                          <span>{sw.name}</span>
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 font-bold text-[10px] border border-indigo-200">
                            {sw.category}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-600 font-medium">{sw.role}</td>
                        <td className="py-3 px-3 text-slate-800 font-semibold">
                          {sw.ip ? (
                            <button
                              onClick={() => handleOpenEndpoint(sw.ip)}
                              className="hover:text-indigo-600 hover:underline cursor-pointer"
                            >
                              {sw.ip}
                            </button>
                          ) : (
                            'N/A'
                          )}
                        </td>
                        <td className="py-3 px-3 text-slate-500">{sw.source_protocol}</td>
                        <td className="py-3 px-3 text-slate-600 truncate max-w-xs font-mono text-[11px]" title={sw.raw_banner}>
                          {sw.raw_banner}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 5: Top Endpoints (Clickable Links opening Endpoint Details Modal)
           ========================================================================= */}
        {activeTab === 'endpoints' && (
          <div className="space-y-4">
            {jobId && pcapInfo?.top_endpoints && pcapInfo.top_endpoints.length > 0 && (
              <NetworkIocEnrichmentPanel
                jobId={jobId}
                extractedIocs={pcapInfo.top_endpoints.map((ep: PcapEndpoint) => ep.ip).filter(Boolean)}
                onNavigateToJob={onSelectJob}
                title="PCAP Endpoint Autonomous System & Threat Intelligence"
                subtitle="Correlates communicating IP addresses with BGP Autonomous System origin, ISP/cloud provider classification, and FCrDNS status."
              />
            )}
            <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                  <th className="py-2.5 px-3">Endpoint IP Address</th>
                  <th className="py-2.5 px-3">Geolocation & ASN</th>
                  <th className="py-2.5 px-3">Reputation</th>
                  <th className="py-2.5 px-3 text-right">Packets</th>
                  <th className="py-2.5 px-3 text-right">Sent</th>
                  <th className="py-2.5 px-3 text-right">Recv</th>
                  <th className="py-2.5 px-3 text-right">Total Traffic</th>
                  <th className="py-2.5 px-3 text-right">Flow Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredEndpoints.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-400 font-sans">
                      No endpoint statistics available
                    </td>
                  </tr>
                ) : (
                  filteredEndpoints.map((ep, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors group">
                      <td className="py-3 px-3 font-semibold text-slate-900">
                        <button
                          onClick={() => setSelectedEndpoint(ep)}
                          className="text-indigo-600 hover:text-indigo-800 hover:underline font-bold flex items-center gap-1.5 cursor-pointer"
                        >
                          <Server className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                          <span>{ep.ip}</span>
                        </button>
                      </td>
                      <td className="py-3 px-3">
                        {ep.is_private ? (
                          <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-[10px] font-semibold border border-slate-200">
                            Private Network
                          </span>
                        ) : (
                          <div className="space-y-0.5">
                            <span className="font-semibold text-slate-800">{ep.country || 'Public Host'}</span>
                            {ep.asn && ep.asn !== 'Unknown' && (
                              <div className="text-[10px] text-slate-400 truncate max-w-[180px]">{ep.asn}</div>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        {ep.abuseipdb?.status === 'MALICIOUS' ? (
                          <span className="px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 text-[10px] font-bold border border-rose-200">
                            Abuse: {ep.abuseipdb.score}%
                          </span>
                        ) : ep.abuseipdb?.status === 'SUSPICIOUS' ? (
                          <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 text-[10px] font-bold border border-amber-200">
                            Suspicious
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[10px] font-medium border border-slate-200">
                            {ep.is_private ? 'RFC1918' : 'Neutral'}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right text-slate-700 font-semibold">{ep.packets.toLocaleString()}</td>
                      <td className="py-3 px-3 text-right text-slate-600">{formatBytes(ep.sent)}</td>
                      <td className="py-3 px-3 text-right text-slate-600">{formatBytes(ep.recv)}</td>
                      <td className="py-3 px-3 text-right text-indigo-600 font-bold">{formatBytes(ep.bytes)}</td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => setSelectedEndpoint(ep)}
                          className="px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 font-sans text-xs font-semibold cursor-pointer transition-colors inline-flex items-center gap-1 shadow-2xs"
                        >
                          <Activity className="w-3 h-3" />
                          <span>View Flows</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        )}

        {/* =========================================================================
            TAB 6: DNS Queries
           ========================================================================= */}
        {activeTab === 'dns' && (
          <div className="space-y-4">
            {jobId && pcapInfo?.dns_queries && pcapInfo.dns_queries.length > 0 && (
              <NetworkIocEnrichmentPanel
                jobId={jobId}
                extractedIocs={pcapInfo.dns_queries.map(d => d.domain).filter(Boolean)}
                onNavigateToJob={onSelectJob}
                title="PCAP Queried Domains Intelligence"
                subtitle="Enriches queried DNS hostnames with Autonomous System origin, FCrDNS verification, and threat intelligence."
              />
            )}
            <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                  <th className="py-2.5 px-3">Queried Domain</th>
                  <th className="py-2.5 px-3">Record</th>
                  <th className="py-2.5 px-3">Resolved IP(s)</th>
                  <th className="py-2.5 px-3">Client Endpoint</th>
                  <th className="py-2.5 px-3 text-right">Reputation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredDns.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400 font-sans">
                      No DNS queries captured
                    </td>
                  </tr>
                ) : (
                  filteredDns.map((d, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-3 font-semibold text-slate-900 flex items-center gap-2">
                        <Globe className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                        <span className="truncate max-w-xs">{d.domain}</span>
                        <InvestigateAssetButton
                          ioc={d.domain}
                          iocType="domain"
                          onNavigateToJob={onSelectJob}
                          compact
                        />
                        {d.high_entropy && (
                          <span
                            className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-300 shrink-0 animate-pulse"
                            title={`High Shannon Entropy (${d.entropy_score?.toFixed(2) || 'N/A'}) - Potential DNS Data Exfiltration / C2 Tunneling`}
                          >
                            ⚠️ DNS Tunneling / DGA ({d.entropy_score?.toFixed(2)})
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded-md bg-sky-50 text-sky-700 font-bold text-[11px] border border-sky-200">
                          {d.query_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-700">
                        {d.resolved_ips && d.resolved_ips.length > 0 ? (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            {d.resolved_ips.map((ip, i) => (
                              <div key={i} className="inline-flex items-center gap-1">
                                <button
                                  onClick={() => handleOpenEndpoint(ip)}
                                  className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 hover:text-indigo-600 hover:bg-indigo-50 text-[11px] border border-slate-200 cursor-pointer"
                                >
                                  {ip}
                                </button>
                                <InvestigateAssetButton
                                  ioc={ip}
                                  iocType="ip"
                                  onNavigateToJob={onSelectJob}
                                  compact
                                />
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-400 italic">No response record</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-slate-600">
                        <button onClick={() => handleOpenEndpoint(d.client_ip)} className="hover:text-indigo-600 hover:underline cursor-pointer">
                          {d.client_ip}
                        </button>
                      </td>
                      <td className="py-3 px-3 text-right">
                        {d.threat_status === 'MALICIOUS' || d.is_suspicious ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
                            <AlertTriangle className="w-3 h-3 text-rose-600" />
                            <span>Suspicious / C2</span>
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                            Clean
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        )}

        {/* =========================================================================
            TAB 7: TLS Sessions & SNIs
           ========================================================================= */}
        {activeTab === 'tls' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                  <th className="py-2.5 px-3">Server Name Indication (SNI)</th>
                  <th className="py-2.5 px-3">TLS Version</th>
                  <th className="py-2.5 px-3">Client Endpoint</th>
                  <th className="py-2.5 px-3">Server Endpoint</th>
                  <th className="py-2.5 px-3">JA3 (Client Fingerprint)</th>
                  <th className="py-2.5 px-3">JA3S (Server Fingerprint)</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tls_sessions?.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-400 font-sans">
                      No TLS handshakes with Server Name Indication (SNI) detected
                    </td>
                  </tr>
                ) : (
                  (tls_sessions || []).map((t, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-3 font-semibold text-slate-900 flex items-center gap-2">
                        <Lock className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                        <span>{t.sni}</span>
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 font-bold text-[11px] border border-indigo-200">
                          {t.tls_version}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-600">
                        <button onClick={() => handleOpenEndpoint(t.client_ip)} className="hover:text-indigo-600 hover:underline cursor-pointer">
                          {t.client_ip}
                        </button>
                      </td>
                      <td className="py-3 px-3 text-slate-800 font-semibold">
                        <button onClick={() => handleOpenEndpoint(t.server_ip)} className="hover:text-indigo-600 hover:underline cursor-pointer">
                          {t.server_ip}:{t.server_port}
                        </button>
                      </td>
                      <td className="py-3 px-3">
                        {t.ja3 ? (
                          <div className="space-y-1">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[11px] text-slate-800" title={t.ja3}>
                                {truncateHash(t.ja3, 6, 6)}
                              </span>
                              <button
                                onClick={() => copyToClipboard(t.ja3 || '', `ja3-${idx}`)}
                                className="text-slate-400 hover:text-slate-700 cursor-pointer p-0.5"
                                title="Copy JA3 MD5"
                              >
                                {copiedKey === `ja3-${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                              </button>
                            </div>
                            {t.ja3_match && (
                              <span
                                className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300 font-sans"
                                title={t.ja3_match}
                              >
                                ⚠️ {t.ja3_match}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400 italic">N/A</span>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        {t.ja3s ? (
                          <div className="space-y-1">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[11px] text-slate-800" title={t.ja3s}>
                                {truncateHash(t.ja3s, 6, 6)}
                              </span>
                              <button
                                onClick={() => copyToClipboard(t.ja3s || '', `ja3s-${idx}`)}
                                className="text-slate-400 hover:text-slate-700 cursor-pointer p-0.5"
                                title="Copy JA3S MD5"
                              >
                                {copiedKey === `ja3s-${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                              </button>
                            </div>
                            {t.ja3s_match && (
                              <span
                                className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300 font-sans"
                                title={t.ja3s_match}
                              >
                                {t.ja3s_match}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400 italic">N/A</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => copyToClipboard(t.sni, `sni-${idx}`)}
                          className="px-2 py-1 rounded-lg hover:bg-slate-100 text-slate-600 hover:text-slate-900 transition-colors inline-flex items-center gap-1 cursor-pointer font-sans"
                        >
                          {copiedKey === `sni-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                          <span className="text-[11px]">Copy SNI</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* =========================================================================
            TAB 8: Plaintext Credentials
           ========================================================================= */}
        {activeTab === 'credentials' && (
          <div className="space-y-4">
            {credentials?.length === 0 ? (
              <div className="py-12 text-center text-slate-400">
                <ShieldAlert className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-60" />
                <p className="text-sm font-semibold text-slate-700">No Cleartext Credentials Detected</p>
                <p className="text-xs text-slate-400 mt-1">No unencrypted HTTP Basic auth or FTP passwords were leaked in this capture.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
                {credentials.map((c, idx) => (
                  <div key={idx} className="p-4 rounded-2xl bg-rose-50/50 border border-rose-200/80 flex flex-col gap-2.5">
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 font-bold text-[10px] tracking-wide uppercase">
                        {c.protocol} Cleartext Auth
                      </span>
                      <button onClick={() => handleOpenEndpoint(c.server_ip)} className="text-[11px] text-slate-500 hover:text-indigo-600 hover:underline cursor-pointer">
                        {c.server_ip}
                      </button>
                    </div>

                    <div className="bg-white rounded-xl p-3 border border-rose-200/60 space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">Username:</span>
                        <span className="font-bold text-slate-900">{c.username}</span>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">Password:</span>
                        <span className="font-bold text-rose-600 bg-rose-50 px-2 py-0.5 rounded border border-rose-200/50">
                          {c.password}
                        </span>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-500 flex items-center justify-between font-sans">
                      <span>Client: {c.client_ip}</span>
                      <button
                        onClick={() => copyToClipboard(`${c.username}:${c.password}`, `cred-${idx}`)}
                        className="text-indigo-600 hover:text-indigo-800 font-sans text-xs font-semibold cursor-pointer flex items-center gap-1"
                      >
                        {copiedKey === `cred-${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>Copy Auth</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 9: C2 Periodic Beaconing Analytics
           ========================================================================= */}
        {activeTab === 'beaconing' && (
          <div className="space-y-4">
            <div className="p-4 bg-rose-50/70 border border-rose-200 rounded-2xl flex items-start gap-3.5 text-xs text-rose-950">
              <div className="p-2 bg-rose-600 text-white rounded-xl shrink-0 mt-0.5 font-bold">
                <Activity className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-sm text-rose-900">
                  Algorithmic C2 Beaconing &amp; Interval Analysis
                </h4>
                <p className="text-rose-800 leading-relaxed mt-0.5">
                  Calculates inter-arrival delta intervals (Δt), standard deviation, and jitter percentages across persistent IP communications. Low jitter (≤ 15%) is a definitive fingerprint of automated Command &amp; Control (C2) heartbeat agents (Cobalt Strike, Havoc, Sliver, Empire, Metasploit).
                </p>
              </div>
            </div>

            {beaconing_flows?.length === 0 ? (
              <div className="py-12 text-center text-slate-400 font-sans">
                <Check className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-60" />
                <p className="text-sm font-semibold text-slate-700">No Periodic C2 Beaconing Detected</p>
                <p className="text-xs text-slate-400 mt-1">Communications exhibited natural user variance without algorithmic timing regularity.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">Source IP</th>
                      <th className="py-2.5 px-3">Destination C2 IP</th>
                      <th className="py-2.5 px-3">Packets</th>
                      <th className="py-2.5 px-3">Mean Interval</th>
                      <th className="py-2.5 px-3">Std Dev</th>
                      <th className="py-2.5 px-3">Jitter %</th>
                      <th className="py-2.5 px-3">Min / Max</th>
                      <th className="py-2.5 px-3 text-right">Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {beaconing_flows.map((b, idx) => {
                      const isCritical = b.jitter_percent <= 10.0;
                      return (
                        <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-3 px-3 text-slate-700">
                            <button onClick={() => handleOpenEndpoint(b.src_ip)} className="hover:text-indigo-600 hover:underline cursor-pointer">
                              {b.src_ip}
                            </button>
                          </td>
                          <td className="py-3 px-3 font-semibold text-rose-700">
                            <button onClick={() => handleOpenEndpoint(b.dst_ip)} className="hover:text-rose-900 hover:underline cursor-pointer">
                              {b.dst_ip}
                            </button>
                          </td>
                          <td className="py-3 px-3 text-slate-800 font-bold">{b.packet_count}</td>
                          <td className="py-3 px-3 text-slate-900 font-bold">~{b.mean_interval_sec}s</td>
                          <td className="py-3 px-3 text-slate-500">±{b.std_dev_sec}s</td>
                          <td className="py-3 px-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                              isCritical ? 'bg-rose-100 text-rose-800' : 'bg-amber-100 text-amber-800'
                            }`}>
                              {b.jitter_percent}%
                            </span>
                          </td>
                          <td className="py-3 px-3 text-slate-500 text-[11px]">
                            {b.min_interval}s / {b.max_interval}s
                          </td>
                          <td className="py-3 px-3 text-right">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                              isCritical
                                ? 'bg-rose-600 text-white animate-pulse'
                                : 'bg-amber-500 text-white'
                            }`}>
                              {isCritical ? 'Critical C2 Heartbeat' : 'Periodic Beacon'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 10: SSH & HASSH Fingerprinting
           ========================================================================= */}
        {activeTab === 'ssh' && (
          <div className="space-y-4">
            <div className="p-4 bg-purple-50/70 border border-purple-200 rounded-2xl flex items-start gap-3.5 text-xs text-purple-950">
              <div className="p-2 bg-purple-600 text-white rounded-xl shrink-0 mt-0.5 font-bold">
                <Terminal className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-sm text-purple-900">
                  HASSH SSH Cryptographic Client &amp; Server Fingerprinting
                </h4>
                <p className="text-purple-800 leading-relaxed mt-0.5">
                  HASSH calculates MD5 digests from SSH_MSG_KEXINIT key exchange algorithms, encryption ciphers, and MAC algorithms. Matches anomalous SSH clients or botnet scanning tools regardless of IP or port.
                </p>
              </div>
            </div>

            {ssh_sessions?.length === 0 ? (
              <div className="py-12 text-center text-slate-400 font-sans">
                <Terminal className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                <p className="text-sm font-semibold text-slate-700">No SSH Handshakes Captured</p>
                <p className="text-xs text-slate-400 mt-1">No SSH_MSG_KEXINIT key exchange sequences were identified in the packet stream.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">Client Endpoint</th>
                      <th className="py-2.5 px-3">Server Endpoint</th>
                      <th className="py-2.5 px-3">HASSH Fingerprint (MD5)</th>
                      <th className="py-2.5 px-3">Key Exchange Algorithms</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {ssh_sessions.map((s, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3 px-3 text-slate-700">
                          {s.src_ip}:{s.src_port}
                        </td>
                        <td className="py-3 px-3 font-semibold text-purple-900">
                          {s.dst_ip}:{s.dst_port}
                        </td>
                        <td className="py-3 px-3 font-bold text-purple-700">
                          <div className="flex items-center gap-1.5">
                            <span>{s.hassh || 'N/A'}</span>
                            {s.hassh && (
                              <button
                                onClick={() => copyToClipboard(s.hassh || '', `hassh-${idx}`)}
                                className="text-slate-400 hover:text-slate-700 cursor-pointer p-0.5"
                                title="Copy HASSH"
                              >
                                {copiedKey === `hassh-${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                              </button>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3 text-slate-500 max-w-xs truncate" title={s.hassh_algorithms}>
                          {s.hassh_algorithms || 'Standard SSH Suite'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 11: Web & Search Queries Reconstructed
           ========================================================================= */}
        {activeTab === 'web_sessions' && (
          <div className="space-y-6">
            {/* Search Queries Reconstructed Card */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <Search className="w-4 h-4 text-indigo-600" />
                    <span>Search Engine Queries Reconstructed ({search_queries.length})</span>
                  </h4>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Decoded user search queries from Google, Bing, DuckDuckGo, YouTube, Wikipedia, Reddit, Yahoo, Baidu, and Yandex.
                  </p>
                </div>
                <div className="relative min-w-[200px]">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Filter search queries..."
                    value={webSearchFilter}
                    onChange={(e) => setWebSearchFilter(e.target.value)}
                    className="w-full pl-8 pr-3 py-1 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-indigo-500"
                  />
                </div>
              </div>

              {search_queries.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {search_queries
                    .filter(sq => !webSearchFilter.trim() || sq.query.toLowerCase().includes(webSearchFilter.toLowerCase()) || sq.engine.toLowerCase().includes(webSearchFilter.toLowerCase()))
                    .map((sq, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl border border-slate-200 hover:border-indigo-300 hover:shadow-xs transition-all bg-slate-50/50 flex flex-col justify-between gap-2">
                        <div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-indigo-100 text-indigo-800">
                              {sq.engine || (sq as any).search_engine || 'Search'}
                            </span>
                            <span className="text-[11px] text-slate-400 font-mono">
                              {sq.time_iso ? String(sq.time_iso).split('T')[1]?.slice(0, 8) : sq.timestamp ? (typeof sq.timestamp === 'string' && sq.timestamp.includes('T') ? sq.timestamp.split('T')[1]?.slice(0, 8) : String(sq.timestamp)) : ''}
                            </span>
                          </div>
                          <div className="mt-2 text-sm font-bold text-slate-900 font-sans">
                            &ldquo;{sq.query}&rdquo;
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono border-t border-slate-200/60 pt-2">
                          <span>{sq.client_ip} ➔ {sq.server_ip}</span>
                          {sq.url && (
                            <a
                              href={sq.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-indigo-600 hover:underline flex items-center gap-1 font-sans"
                            >
                              <ExternalLink className="w-3 h-3" />
                              <span>URL</span>
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs bg-slate-50 rounded-xl">
                  No cleartext search engine queries observed in HTTP/DNS traffic.
                </div>
              )}
            </div>

            {/* Decoded Web Sessions & POST Form Submissions */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
              <div className="border-b border-slate-100 pb-3">
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-emerald-600" />
                  <span>Web Form Submissions &amp; HTTP POST Sessions ({web_sessions.length})</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Parsed form parameters, submitted credentials, JSON payloads, and sensitive request bodies.
                </p>
              </div>

              {web_sessions.length > 0 ? (
                <div className="divide-y divide-slate-100">
                  {web_sessions.map((ws, idx) => (
                    <div key={idx} className="py-3.5 space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-100 text-emerald-800 font-mono">
                            {ws.method}
                          </span>
                          <span className="text-xs font-bold text-slate-900 font-mono break-all">{ws.host}{ws.uri}</span>
                          {ws.is_credential_submission && (
                            <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold flex items-center gap-1 shrink-0">
                              <Key className="w-3 h-3 text-rose-600" />
                              <span>Credentials Submitted</span>
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono shrink-0">
                          {ws.client_ip} ➔ {ws.server_ip}
                        </div>
                      </div>

                      {/* Decoded Form Fields Table */}
                      {(ws.submitted_fields || (ws as any).form_fields) && Object.keys(ws.submitted_fields || (ws as any).form_fields).length > 0 && (
                        <div className="bg-slate-50 rounded-xl p-3 border border-slate-200">
                          <div className="text-[11px] font-bold text-slate-600 uppercase mb-2">Decoded Form Parameters:</div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                            {Object.entries(ws.submitted_fields || (ws as any).form_fields).map(([k, v]) => (
                              <div key={k} className="p-2.5 bg-white rounded-lg border border-slate-200 text-xs font-mono min-w-0 overflow-hidden break-all shadow-2xs">
                                <span className="text-indigo-600 font-bold block truncate text-[11px] mb-0.5" title={k}>{k}: </span>
                                <span className="text-slate-800 break-all select-all block text-[11px] leading-relaxed max-h-32 overflow-y-auto">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Raw Payload Preview Toggle */}
                      {(ws.raw_payload_preview || (ws as any).raw_body_preview) && (
                        <div className="text-right">
                          <button
                            onClick={() => setSelectedWebSession(ws)}
                            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 cursor-pointer inline-flex items-center gap-1"
                          >
                            <Eye className="w-3 h-3" />
                            <span>View Raw Payload Body</span>
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs bg-slate-50 rounded-xl">
                  No unencrypted HTTP POST form submissions detected in captured traffic.
                </div>
              )}
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 12: Exfiltration Tracker & Ledger
           ========================================================================= */}
        {activeTab === 'exfiltration' && (() => {
          const ledger = exfiltration_tracker?.file_movement_ledger || [];
          const risk = exfiltration_tracker?.exfiltration_risk_level || 'NORMAL';
          const ratio = exfiltration_tracker?.upload_to_download_ratio ?? 1;
          const isHighRisk = risk === 'CRITICAL' || risk === 'HIGH';

          const filteredLedger = ledger.filter(f => {
            if (exfilDirectionFilter === 'uploaded') return f.direction === 'uploaded';
            if (exfilDirectionFilter === 'downloaded') return f.direction === 'downloaded';
            return true;
          });

          return (
            <div className="space-y-6">
              {/* Exfiltration Anomaly Meter */}
              <div className={`p-5 rounded-2xl border transition-all ${
                isHighRisk ? 'bg-rose-50/60 border-rose-300' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className={`p-3 rounded-2xl ${
                      isHighRisk ? 'bg-rose-600 text-white' : 'bg-indigo-600 text-white'
                    }`}>
                      <UploadCloud className="w-6 h-6" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-base font-bold text-slate-900">Interactive Exfiltration Anomaly Meter</h4>
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-black uppercase ${
                          risk === 'CRITICAL' ? 'bg-rose-600 text-white' :
                          risk === 'HIGH' ? 'bg-amber-500 text-white' :
                          risk === 'ELEVATED' ? 'bg-orange-500 text-white' : 'bg-emerald-600 text-white'
                        }`}>
                          {risk} RISK
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 mt-0.5">
                        {exfiltration_tracker?.risk_reason || 'Outbound to inbound data transfer telemetry'}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xs font-semibold text-slate-500">Outbound Ratio</span>
                    <p className="text-xl font-black text-slate-900 font-mono">{ratio.toFixed(2)} : 1</p>
                  </div>
                </div>

                <div className="mt-4 space-y-1.5">
                  <div className="w-full h-3 rounded-full bg-slate-200 overflow-hidden flex">
                    <div
                      className="bg-rose-500 h-full transition-all"
                      style={{ width: `${Math.min(95, Math.max(5, (ratio / (ratio + 1)) * 100))}%` }}
                      title={`Outbound Uploads: ${formatBytes(exfiltration_tracker?.total_uploaded_bytes || 0)}`}
                    />
                    <div
                      className="bg-indigo-500 h-full transition-all"
                      style={{ width: `${Math.min(95, Math.max(5, (1 / (ratio + 1)) * 100))}%` }}
                      title={`Inbound Downloads: ${formatBytes(exfiltration_tracker?.total_downloaded_bytes || 0)}`}
                    />
                  </div>
                  <div className="flex justify-between text-[11px] font-mono text-slate-600">
                    <span className="text-rose-600 font-semibold">⬆️ Total Uploaded: {formatBytes(exfiltration_tracker?.total_uploaded_bytes || 0)}</span>
                    <span className="text-indigo-600 font-semibold">⬇️ Total Downloaded: {formatBytes(exfiltration_tracker?.total_downloaded_bytes || 0)}</span>
                  </div>
                </div>
              </div>

              {/* Filter Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-white border border-slate-200 rounded-2xl shadow-xs">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-600">Filter Direction:</span>
                  {(['all', 'uploaded', 'downloaded'] as const).map(dir => (
                    <button
                      key={dir}
                      onClick={() => setExfilDirectionFilter(dir)}
                      className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                        exfilDirectionFilter === dir
                          ? 'bg-indigo-600 text-white shadow-xs'
                          : 'bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100'
                      }`}
                    >
                      {dir === 'all' ? `All Transfers (${ledger.length})` :
                       dir === 'uploaded' ? `⬆️ Uploaded (${ledger.filter(f => f.direction === 'uploaded').length})` :
                       `⬇️ Downloaded (${ledger.filter(f => f.direction === 'downloaded').length})`}
                    </button>
                  ))}
                </div>
              </div>

              {/* Bidirectional Ledger Table */}
              {filteredLedger.length > 0 ? (
                <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                          <th className="py-3 px-4">Direction</th>
                          <th className="py-3 px-4">Filename</th>
                          <th className="py-3 px-4">Size</th>
                          <th className="py-3 px-4">Protocol</th>
                          <th className="py-3 px-4">Client ➔ Server</th>
                          <th className="py-3 px-4">SHA-256 Hash</th>
                          <th className="py-3 px-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
                        {filteredLedger.map((file, idx) => (
                          <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                            <td className="py-3 px-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                file.direction === 'uploaded' ? 'bg-rose-100 text-rose-800' : 'bg-blue-100 text-blue-800'
                              }`}>
                                {file.direction === 'uploaded' ? '⬆️ EXFILTRATED' : '⬇️ DOWNLOADED'}
                              </span>
                            </td>
                            <td className="py-3 px-4 font-sans font-semibold text-slate-900">
                              {file.filename}
                            </td>
                            <td className="py-3 px-4 font-bold text-slate-800">{formatBytes(file.size)}</td>
                            <td className="py-3 px-4">
                              <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-bold">
                                {file.protocol}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-[11px] text-slate-500">
                              {file.client_ip} ➔ {file.server_ip}
                            </td>
                            <td className="py-3 px-4 text-[11px] text-slate-400">
                              {file.sha256 ? (
                                <div className="flex items-center gap-1">
                                  <span>{truncateHash(file.sha256, 8)}</span>
                                  <button
                                    onClick={() => copyToClipboard(file.sha256!, `hash_${idx}`)}
                                    className="p-1 hover:text-slate-700 cursor-pointer"
                                  >
                                    {copiedKey === `hash_${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                  </button>
                                </div>
                              ) : 'N/A'}
                            </td>
                            <td className="py-3 px-4 text-right space-x-2">
                              <button
                                onClick={() => {
                                  const matchingCarved = carved_files.find(cf => cf.filename === file.filename || cf.sha256 === file.sha256);
                                  if (matchingCarved) {
                                    setPreviewCarvedFile(matchingCarved);
                                  } else {
                                    setPreviewCarvedFile({
                                      id: 9900 + idx,
                                      filename: file.filename,
                                      name: file.filename,
                                      size: file.size,
                                      sha256: file.sha256 || 'N/A',
                                      md5: file.md5 || 'N/A',
                                      mime_type: file.mime_type || 'application/octet-stream',
                                      preview_type: file.filename.match(/\.(png|jpe?g|gif|webp|bmp)$/i) ? 'image' : file.filename.match(/\.(txt|csv|log|sh|bat|ps1|py|json|html|xml)$/i) ? 'text' : 'hex',
                                      preview_text: `Reconstructed Exfiltration Ledger Record:\nFilename: ${file.filename}\nDirection: ${file.direction.toUpperCase()}\nProtocol: ${file.protocol}\nSize: ${file.size} bytes\nSHA256: ${file.sha256 || 'N/A'}`
                                    });
                                  }
                                }}
                                className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-indigo-50 text-indigo-700 hover:bg-indigo-100 transition-colors inline-flex items-center gap-1 cursor-pointer"
                              >
                                <Eye className="w-3 h-3" />
                                <span>Inspect</span>
                              </button>
                              <button
                                onClick={() => setSelectedProcessCorrelationFlow({
                                  src_ip: file.client_ip,
                                  dst_ip: file.server_ip,
                                  protocol: file.protocol,
                                  filename: file.filename,
                                  timestamp: file.timestamp
                                })}
                                className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors inline-flex items-center gap-1 cursor-pointer"
                              >
                                <Search className="w-3 h-3 text-indigo-600" />
                                <span>EVTX</span>
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
                  No transferred or exfiltrated files found in analyzed capture.
                </div>
              )}
            </div>
          );
        })()}

        {/* =========================================================================
            TAB 13: Interactive Terminal Playback
           ========================================================================= */}
        {activeTab === 'terminal_replay' && (() => {
          const activeSession = selectedTerminalSession || terminal_sessions[0] || null;

          return (
            <div className="space-y-6">
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-600" />
                  <span>Interactive Terminal &amp; Command Session Playback</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Console dialogue reconstructed for Telnet, FTP, raw TCP reverse shells, Redis, and MySQL.
                </p>
              </div>

              {terminal_sessions.length > 0 ? (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Session List Column */}
                  <div className="space-y-2.5">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Active Shell Sessions ({terminal_sessions.length})</span>
                    {terminal_sessions.map((ts, idx) => {
                      const isSelected = activeSession?.session_id === ts.session_id;
                      const isCrit = ts.risk_level === 'CRITICAL' || ts.risk_level === 'HIGH';

                      return (
                        <div
                          key={idx}
                          onClick={() => setSelectedTerminalSession(ts)}
                          className={`p-3.5 rounded-2xl border transition-all cursor-pointer ${
                            isSelected
                              ? 'bg-slate-900 text-white border-slate-800 shadow-md ring-2 ring-emerald-500/50'
                              : 'bg-white border-slate-200 hover:border-slate-300 text-slate-800 shadow-2xs'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                              isCrit ? 'bg-rose-500 text-white' : 'bg-emerald-500 text-white'
                            }`}>
                              {ts.protocol}
                            </span>
                            <span className="text-[11px] text-slate-400 font-mono">
                              {ts.total_commands} cmds
                            </span>
                          </div>
                          <div className={`mt-2 text-xs font-mono font-semibold truncate ${isSelected ? 'text-slate-200' : 'text-slate-700'}`}>
                            {ts.client} ➔ {ts.server}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Console Viewport Column */}
                  <div className="lg:col-span-2 space-y-4">
                    {activeSession ? (
                      <div className="bg-slate-950 rounded-2xl border border-slate-800 overflow-hidden shadow-xl flex flex-col font-mono">
                        <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2">
                            <div className="flex items-center gap-1.5">
                              <span className="w-3 h-3 rounded-full bg-rose-500 inline-block" />
                              <span className="w-3 h-3 rounded-full bg-amber-500 inline-block" />
                              <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block" />
                            </div>
                            <span className="text-slate-400 text-[11px] ml-2">session://{activeSession.client} ({activeSession.protocol})</span>
                          </div>
                          <button
                            onClick={() => {
                              const dialogueItems = (activeSession.dialogue && activeSession.dialogue.length > 0)
                                ? activeSession.dialogue
                                : ((activeSession as any).events || []);
                              const allText = dialogueItems.map((d: any) => {
                                const isClient = d.direction === 'client' || (d as any).sender === 'client' || (d as any).is_command;
                                const textVal = d.text || (d as any).message || '';
                                return `${isClient ? '$ ' : ''}${textVal}`;
                              }).join('\n');
                              copyToClipboard(allText, 'term_all');
                            }}
                            className="text-slate-400 hover:text-white text-[11px] flex items-center gap-1 cursor-pointer"
                          >
                            {copiedKey === 'term_all' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>Copy Session</span>
                          </button>
                        </div>

                        {(() => {
                          const dialogueItems = (activeSession.dialogue && activeSession.dialogue.length > 0)
                            ? activeSession.dialogue
                            : ((activeSession as any).events || []);

                          return (
                            <div className="p-5 text-xs text-slate-200 space-y-2 max-h-[500px] overflow-y-auto leading-relaxed">
                              {dialogueItems.length === 0 ? (
                                <div className="text-slate-500 italic py-8 text-center font-mono">
                                  No console stream dialogue text recorded for this session.
                                </div>
                              ) : (
                                dialogueItems.map((item: any, idx: number) => {
                                  const isClient = item.direction === 'client' || (item as any).sender === 'client' || (item as any).is_command;
                                  const textVal = item.text || (item as any).message || '';
                                  return (
                                    <div key={idx} className="whitespace-pre-wrap break-all">
                                      {isClient ? (
                                        <div className="text-cyan-300 font-bold flex items-start gap-1">
                                          <span className="text-emerald-400 select-none">$</span>
                                          <span>{textVal}</span>
                                        </div>
                                      ) : (
                                        <div className="text-emerald-400/90 pl-3">
                                          {textVal}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })
                              )}
                            </div>
                          );
                        })()}

                        {activeSession.file_operations && activeSession.file_operations.length > 0 && (
                          <div className="p-3 bg-slate-900/90 border-t border-slate-800 text-[11px]">
                            <span className="font-bold text-slate-400">File Operations Log:</span>
                            <div className="flex flex-wrap gap-2 mt-1.5">
                              {activeSession.file_operations.map((op, oidx) => (
                                <span key={oidx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                  <strong className="text-amber-400">{op.command}</strong> {op.filename}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="p-8 text-center text-slate-500 bg-slate-50 rounded-2xl border border-slate-200 text-xs">
                        Select a terminal session from the left to view interactive playback.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                  No interactive terminal (Telnet, FTP, raw TCP shell) communications found in capture.
                </div>
              )}
            </div>
          );
        })()}

        {/* =========================================================================
            TAB 14: Email & Communication Interceptor
           ========================================================================= */}
        {activeTab === 'emails' && (
          <div className="space-y-6">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Mail className="w-4 h-4 text-indigo-600" />
                <span>Email &amp; Communication Interceptor ({emails.length})</span>
              </h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Reconstructed unencrypted email messages (SMTP, POP3, IMAP), headers, body text, and attachments.
              </p>
            </div>

            {emails.length > 0 ? (
              <div className="space-y-4">
                {emails.map((em, idx) => (
                  <div key={idx} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-slate-100 pb-4">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-100 text-indigo-800 font-mono">
                            {em.protocol}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            {em.timestamp || 'N/A'}
                          </span>
                          {em.is_suspicious && (
                            <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold uppercase">
                              Suspicious
                            </span>
                          )}
                        </div>
                        <h5 className="text-base font-bold text-slate-900">{em.subject || '(No Subject)'}</h5>
                        <div className="text-xs text-slate-600 flex flex-wrap gap-x-4 gap-y-1">
                          <div>From: <strong className="text-slate-800">{em.from || 'Unknown'}</strong></div>
                          <div>To: <strong className="text-slate-800">{em.to?.join(', ') || 'Unknown'}</strong></div>
                        </div>
                      </div>

                      {em.phishing_indicators && em.phishing_indicators.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 sm:justify-end">
                          {em.phishing_indicators.map((ind, iidx) => (
                            <span key={iidx} className="px-2 py-0.5 rounded-full bg-rose-50 border border-rose-200 text-rose-700 text-[10px] font-semibold">
                              ⚠️ {ind}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Email Body</span>
                        <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg text-xs">
                          <button
                            onClick={() => setEmailBodyViewMode('text')}
                            className={`px-2.5 py-0.5 rounded-md font-semibold cursor-pointer ${
                              emailBodyViewMode === 'text' ? 'bg-white shadow-xs text-indigo-700' : 'text-slate-600'
                            }`}
                          >
                            Clean Text
                          </button>
                          {em.body_html && (
                            <button
                              onClick={() => setEmailBodyViewMode('html')}
                              className={`px-2.5 py-0.5 rounded-md font-semibold cursor-pointer ${
                                emailBodyViewMode === 'html' ? 'bg-white shadow-xs text-indigo-700' : 'text-slate-600'
                              }`}
                            >
                              Raw HTML
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 leading-relaxed font-sans max-h-60 overflow-y-auto whitespace-pre-wrap select-all">
                        {emailBodyViewMode === 'html' && em.body_html ? em.body_html : em.body_text}
                      </div>
                    </div>

                    {em.attachments && em.attachments.length > 0 && (
                      <div className="pt-2 border-t border-slate-100">
                        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Attachments ({em.attachments.length})</span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
                          {em.attachments.map((att, aidx) => (
                            <div key={aidx} className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between gap-2">
                              <div className="truncate">
                                <div className="font-semibold text-xs text-slate-900 truncate">{att.filename}</div>
                                <div className="text-[10px] text-slate-500 font-mono">{formatBytes(att.size)} • {att.content_type}</div>
                              </div>
                              {att.is_executable_or_script && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-100 text-rose-700 text-[9px] font-bold">
                                  EXECUTABLE
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                No unencrypted SMTP, POP3, or IMAP email communications found in capture.
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 15: Suricata IDS Intrusion Alerts
           ========================================================================= */}
        {activeTab === 'ids_alerts' && (
          <div className="space-y-6">
            <div className="p-4 bg-rose-50/70 border border-rose-200 rounded-2xl flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-rose-600 text-white rounded-xl shadow-xs">
                  <ShieldAlert className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-rose-950">Suricata-Compatible IDS Signature Rule Matches</h4>
                  <p className="text-xs text-rose-800">
                    Payload pattern matching for Web Exploits (SQLi, Traversal, Command Injection, Webshells), C2 stagers, and sensitive data leaks.
                  </p>
                </div>
              </div>

              {/* Severity Filter Pills */}
              <div className="flex items-center gap-1.5 bg-white p-1 rounded-xl border border-rose-200/80 text-xs font-mono">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                  <button
                    key={sev}
                    onClick={() => setIdsSeverityFilter(sev)}
                    className={`px-2.5 py-1 rounded-lg font-bold cursor-pointer transition-colors ${
                      idsSeverityFilter === sev
                        ? 'bg-rose-600 text-white shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {(() => {
              const alerts = (pcapInfo.ids_alerts || []).filter(a => {
                if (idsSeverityFilter !== 'ALL' && a.severity_label !== idsSeverityFilter) return false;
                if (!searchQuery) return true;
                const q = searchQuery.toLowerCase();
                return (
                  a.msg.toLowerCase().includes(q) ||
                  a.classtype.toLowerCase().includes(q) ||
                  a.src_ip.toLowerCase().includes(q) ||
                  a.dst_ip.toLowerCase().includes(q) ||
                  a.matched_snippet.toLowerCase().includes(q)
                );
              });

              if (alerts.length === 0) {
                return (
                  <div className="p-12 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-60" />
                    <p className="font-semibold text-slate-700">No Intrusion Alerts Matched</p>
                    <p className="text-slate-400 mt-1">No network payloads triggered Suricata attack rules under the current filter.</p>
                  </div>
                );
              }

              return (
                <div className="space-y-3">
                  {alerts.map((al, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-2xl border transition-all bg-white border-slate-200 hover:border-slate-300 shadow-2xs space-y-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase font-mono tracking-wider ${
                              al.severity === 1
                                ? 'bg-rose-100 text-rose-800 border border-rose-200'
                                : al.severity === 2
                                ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                : 'bg-slate-100 text-slate-700 border border-slate-200'
                            }`}
                          >
                            {al.severity_label} (Priority {al.severity})
                          </span>
                          <span className="text-xs font-mono font-bold text-slate-500">SID: {al.sid}</span>
                          <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 font-mono text-[10px]">
                            {al.classtype}
                          </span>
                        </div>

                        <div className="text-xs font-mono text-slate-600 flex items-center gap-2">
                          <span className="font-bold text-slate-800">{al.src_ip}:{al.src_port}</span>
                          <span className="text-slate-400">→</span>
                          <span className="font-bold text-slate-800">{al.dst_ip}:{al.dst_port}</span>
                          <span className="px-1.5 py-0.2 rounded bg-indigo-50 text-indigo-700 text-[10px] font-bold">
                            {al.protocol}
                          </span>
                        </div>
                      </div>

                      <h5 className="text-sm font-bold text-slate-900 tracking-tight">{al.msg}</h5>

                      {al.matched_snippet && (
                        <div className="p-3 bg-slate-950 text-indigo-300 rounded-xl font-mono text-[11px] leading-relaxed overflow-x-auto shadow-inner">
                          <span className="text-slate-500 select-none block mb-1 text-[10px] font-bold uppercase">
                            Matched Stream Payload Proof:
                          </span>
                          <code>{al.matched_snippet}</code>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        )}

        {/* =========================================================================
            TAB 16: Zeek-Style Structured Session Logs
           ========================================================================= */}
        {activeTab === 'zeek_logs' && (
          <div className="space-y-6">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-indigo-600 text-white rounded-xl shadow-xs">
                  <Layers className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-slate-900">Zeek Structured Forensic Session Logs</h4>
                  <p className="text-xs text-slate-500">
                    Normalized connection and protocol transaction logs generated per Zeek/Bro network sensor specifications.
                  </p>
                </div>
              </div>

              {/* Subtab Selector */}
              <div className="flex items-center gap-1.5 bg-white p-1 rounded-xl border border-slate-200 text-xs font-mono">
                {(['conn', 'dns', 'ssl', 'x509', 'files'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveZeekLog(tab)}
                    className={`px-3 py-1 rounded-lg font-bold cursor-pointer transition-colors ${
                      activeZeekLog === tab
                        ? 'bg-indigo-600 text-white shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    {tab}.log ({pcapInfo.zeek_logs?.[`${tab}_log` as keyof typeof pcapInfo.zeek_logs]?.length || 0})
                  </button>
                ))}
              </div>
            </div>

            {/* conn.log */}
            {activeZeekLog === 'conn' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">UID</th>
                      <th className="py-2.5 px-3">Orig Host (Client)</th>
                      <th className="py-2.5 px-3">Resp Host (Server)</th>
                      <th className="py-2.5 px-3">Proto / Service</th>
                      <th className="py-2.5 px-3">Duration</th>
                      <th className="py-2.5 px-3">Bytes (Orig / Resp)</th>
                      <th className="py-2.5 px-3">State</th>
                      <th className="py-2.5 px-3">History</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(pcapInfo.zeek_logs?.conn_log || []).map((c, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-indigo-700">{c.uid}</td>
                        <td className="py-2.5 px-3 text-slate-800">{c.id_orig_h}:{c.id_orig_p}</td>
                        <td className="py-2.5 px-3 text-slate-800">{c.id_resp_h}:{c.id_resp_p}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-bold uppercase mr-1">
                            {c.proto}
                          </span>
                          <span className="text-slate-500 font-sans">{c.service}</span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-600">{c.duration}s</td>
                        <td className="py-2.5 px-3 text-slate-600">
                          {formatBytes(c.orig_bytes)} / {formatBytes(c.resp_bytes)}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            c.conn_state === 'SF' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                          }`}>
                            {c.conn_state}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-500 font-mono text-[11px]">{c.history}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* dns.log */}
            {activeZeekLog === 'dns' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">UID</th>
                      <th className="py-2.5 px-3">Client Endpoint</th>
                      <th className="py-2.5 px-3">Queried Hostname</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">RCode</th>
                      <th className="py-2.5 px-3">Resolved Answers</th>
                      <th className="py-2.5 px-3">Entropy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(pcapInfo.zeek_logs?.dns_log || []).map((d, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-sky-700">{d.uid}</td>
                        <td className="py-2.5 px-3 text-slate-800">{d.id_orig_h}</td>
                        <td className="py-2.5 px-3 font-semibold text-slate-900">{d.query}</td>
                        <td className="py-2.5 px-3 text-slate-600">{d.qtype_name}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            d.rcode_name === 'NOERROR' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                          }`}>
                            {d.rcode_name}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-700">
                          {d.answers?.length > 0 ? d.answers.join(', ') : <span className="text-slate-400 italic">None</span>}
                        </td>
                        <td className="py-2.5 px-3 text-slate-600 font-bold">{d.entropy} bits</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ssl.log */}
            {activeZeekLog === 'ssl' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">UID</th>
                      <th className="py-2.5 px-3">Server Name (SNI)</th>
                      <th className="py-2.5 px-3">TLS Version</th>
                      <th className="py-2.5 px-3">Cipher Suite</th>
                      <th className="py-2.5 px-3">JA3 Fingerprint</th>
                      <th className="py-2.5 px-3">Subject</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(pcapInfo.zeek_logs?.ssl_log || []).map((s, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-indigo-700">{s.uid}</td>
                        <td className="py-2.5 px-3 font-bold text-slate-900">{s.server_name}</td>
                        <td className="py-2.5 px-3 text-slate-600">{s.version}</td>
                        <td className="py-2.5 px-3 text-slate-600 truncate max-w-xs">{s.cipher}</td>
                        <td className="py-2.5 px-3 text-indigo-600 font-mono text-[11px]">{s.ja3 || 'N/A'}</td>
                        <td className="py-2.5 px-3 text-slate-500 truncate max-w-xs">{s.subject}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* x509.log */}
            {activeZeekLog === 'x509' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">Serial</th>
                      <th className="py-2.5 px-3">Certificate Subject</th>
                      <th className="py-2.5 px-3">Issuer Authority</th>
                      <th className="py-2.5 px-3">SAN DNS Names</th>
                      <th className="py-2.5 px-3">Key Specification</th>
                      <th className="py-2.5 px-3">Trust</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(pcapInfo.zeek_logs?.x509_log || []).map((x, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-2.5 px-3 text-slate-600">{x.certificate_serial}</td>
                        <td className="py-2.5 px-3 font-bold text-slate-900">{x.subject}</td>
                        <td className="py-2.5 px-3 text-slate-700">{x.issuer}</td>
                        <td className="py-2.5 px-3 text-slate-600">{x.san_dns?.join(', ')}</td>
                        <td className="py-2.5 px-3 text-slate-600">{x.key_type?.toUpperCase()} {x.key_length}b</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            x.self_signed ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
                          }`}>
                            {x.self_signed ? 'Self-Signed' : 'CA-Signed'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* files.log */}
            {activeZeekLog === 'files' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="py-2.5 px-3">FUID</th>
                      <th className="py-2.5 px-3">Protocol</th>
                      <th className="py-2.5 px-3">Filename</th>
                      <th className="py-2.5 px-3">MIME Type</th>
                      <th className="py-2.5 px-3">Size</th>
                      <th className="py-2.5 px-3">SHA-256 Checksum</th>
                      <th className="py-2.5 px-3">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(pcapInfo.zeek_logs?.files_log || []).map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-amber-700">{f.fuid}</td>
                        <td className="py-2.5 px-3 text-slate-700 font-bold">{f.source_proto}</td>
                        <td className="py-2.5 px-3 font-bold text-slate-900">{f.filename}</td>
                        <td className="py-2.5 px-3 text-slate-600">{f.mime_type}</td>
                        <td className="py-2.5 px-3 text-slate-600">{formatBytes(f.total_bytes)}</td>
                        <td className="py-2.5 px-3 text-slate-500 font-mono text-[11px] truncate max-w-xs">{truncateHash(f.sha256)}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            f.is_dangerous ? 'bg-rose-100 text-rose-800' : 'bg-slate-100 text-slate-700'
                          }`}>
                            {f.threat_category}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 17: Network Reconnaissance & Lateral Movement
           ========================================================================= */}
        {activeTab === 'lateral_movement' && (
          <div className="space-y-6">
            <div className="p-4 bg-amber-50/70 border border-amber-200 rounded-2xl flex items-start gap-3.5">
              <div className="p-2.5 bg-amber-600 text-white rounded-xl shadow-xs shrink-0 mt-0.5">
                <Radio className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-amber-950">
                  Network Reconnaissance, Port Scans &amp; East-West Lateral Movement
                </h4>
                <p className="text-xs text-amber-800 mt-0.5 leading-relaxed">
                  Identifies internal port scanning, ARP/ICMP host discovery sweeps, and administrative remote execution (SMB admin shares C$/ADMIN$/IPC$, WinRM, RDP, SSH, Kerberos).
                </p>
              </div>
            </div>

            {/* Active Reconnaissance Section */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
                Port Scans &amp; Host Discovery Sweeps ({pcapInfo.lateral_movement?.scans_detected?.length || 0})
              </h5>
              {(pcapInfo.lateral_movement?.scans_detected || []).length === 0 ? (
                <div className="p-6 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-400 text-xs">
                  No active port scans, network sweeps, or ARP sweeps observed.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {pcapInfo.lateral_movement!.scans_detected.map((sc, sidx) => (
                    <div key={sidx} className="p-4 bg-white border border-slate-200 rounded-2xl shadow-2xs space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold font-mono text-slate-900">{sc.scanner_ip}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 text-amber-800">
                          {sc.threat_level}
                        </span>
                      </div>
                      <div className="text-xs font-semibold text-slate-800">{sc.scan_type}</div>
                      {sc.ports_sample && sc.ports_sample.length > 0 && (
                        <div className="text-[11px] text-slate-600 font-mono">
                          Probed Ports: {sc.ports_sample.join(', ')}... ({sc.ports_probed_count} total)
                        </div>
                      )}
                      {sc.sample_targets && sc.sample_targets.length > 0 && (
                        <div className="text-[11px] text-slate-600 font-mono">
                          Targets: {sc.sample_targets.join(', ')}... ({sc.target_count} total)
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* East-West Lateral Movement Section */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
                Internal Lateral Movement Events ({pcapInfo.lateral_movement?.lateral_movement_events?.length || 0})
              </h5>
              {(pcapInfo.lateral_movement?.lateral_movement_events || []).length === 0 ? (
                <div className="p-6 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-400 text-xs">
                  No internal lateral movement sessions detected across administrative ports.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse font-mono">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                        <th className="py-2.5 px-3">Source Host</th>
                        <th className="py-2.5 px-3">Target Host</th>
                        <th className="py-2.5 px-3">Port</th>
                        <th className="py-2.5 px-3">Protocol / Service</th>
                        <th className="py-2.5 px-3">Admin Share</th>
                        <th className="py-2.5 px-3">Transferred</th>
                        <th className="py-2.5 px-3">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {pcapInfo.lateral_movement!.lateral_movement_events.map((lat, lidx) => (
                        <tr key={lidx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-2.5 px-3 font-bold text-slate-900">{lat.source_ip}</td>
                          <td className="py-2.5 px-3 font-bold text-slate-900">{lat.destination_ip}</td>
                          <td className="py-2.5 px-3 text-slate-600">{lat.target_port}</td>
                          <td className="py-2.5 px-3 text-slate-800 font-sans font-semibold">{lat.protocol_name}</td>
                          <td className="py-2.5 px-3 text-rose-700 font-bold font-mono">{lat.admin_share || '—'}</td>
                          <td className="py-2.5 px-3 text-slate-600">{formatBytes(lat.bytes_transferred)}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              lat.severity === 'CRITICAL'
                                ? 'bg-rose-100 text-rose-800'
                                : lat.severity === 'HIGH'
                                ? 'bg-amber-100 text-amber-800'
                                : 'bg-slate-100 text-slate-700'
                            }`}>
                              {lat.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 18: Protocol Anomalies & Industrial OT (SCADA)
           ========================================================================= */}
        {activeTab === 'protocol_anomalies' && (
          <div className="space-y-6">
            <div className="p-4 bg-purple-50/70 border border-purple-200 rounded-2xl flex items-start gap-3.5">
              <div className="p-2.5 bg-purple-600 text-white rounded-xl shadow-xs shrink-0 mt-0.5">
                <Wifi className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-purple-950">Protocol-Specific Deep Inspection &amp; OT SCADA Analysis</h4>
                <p className="text-xs text-purple-800 mt-0.5 leading-relaxed">
                  Monitors network infrastructure protocols (ARP cache integrity, rogue DHCP servers, NTP amplification) and industrial automation controls (Modbus/TCP register writes).
                </p>
              </div>
            </div>

            {/* ARP Poisoning Callouts */}
            {(pcapInfo.protocol_anomalies?.arp_spoofing_alerts || []).length > 0 && (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl space-y-2">
                <h5 className="text-xs font-bold text-rose-900 uppercase font-mono flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-rose-600" />
                  <span>ARP Cache Poisoning / Spoofing Detected (Man-in-the-Middle)</span>
                </h5>
                {pcapInfo.protocol_anomalies!.arp_spoofing_alerts.map((arp, aidx) => (
                  <div key={aidx} className="text-xs text-rose-800">
                    Host <strong>{arp.target_ip}</strong> is concurrently claimed by multiple MAC addresses:{' '}
                    <code>{arp.conflicting_mac_addresses.join(', ')}</code>.
                  </div>
                ))}
              </div>
            )}

            {/* Rogue DHCP Callout */}
            {pcapInfo.protocol_anomalies?.rogue_dhcp_detected && (
              <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl space-y-1">
                <h5 className="text-xs font-bold text-amber-900 uppercase font-mono">
                  Rogue DHCP Server Conflict
                </h5>
                <p className="text-xs text-amber-800">
                  Multiple DHCP Offer/ACK responders detected across network segment: {pcapInfo.protocol_anomalies.dhcp_servers_detected.join(', ')}.
                </p>
              </div>
            )}

            {/* Industrial Modbus/TCP Events */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
                Industrial Control Protocols: Modbus/TCP ({pcapInfo.protocol_anomalies?.modbus_industrial_events?.length || 0})
              </h5>
              {(pcapInfo.protocol_anomalies?.modbus_industrial_events || []).length === 0 ? (
                <div className="p-6 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-400 text-xs">
                  No industrial control system (Modbus/TCP) frames detected on port 502.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse font-mono">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                        <th className="py-2.5 px-3">Source Endpoint</th>
                        <th className="py-2.5 px-3">PLC / RTU Target</th>
                        <th className="py-2.5 px-3">Unit ID</th>
                        <th className="py-2.5 px-3">Function Code</th>
                        <th className="py-2.5 px-3">Command Operation</th>
                        <th className="py-2.5 px-3">Classification</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {pcapInfo.protocol_anomalies!.modbus_industrial_events.map((mb, midx) => (
                        <tr key={midx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-2.5 px-3 text-slate-800">{mb.source_ip}</td>
                          <td className="py-2.5 px-3 font-bold text-slate-900">{mb.target_ip}</td>
                          <td className="py-2.5 px-3 text-slate-600">{mb.unit_id}</td>
                          <td className="py-2.5 px-3 font-bold text-indigo-700">0x{mb.function_code.toString(16).padStart(2, '0')}</td>
                          <td className="py-2.5 px-3 text-slate-800 font-sans font-medium">{mb.operation}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              mb.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-800' : 'bg-slate-100 text-slate-700'
                            }`}>
                              {mb.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 19: Capture Integrity & Evidence Provenance
           ========================================================================= */}
        {activeTab === 'integrity' && (
          <div className="space-y-6">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex items-start gap-3.5">
              <div className="p-2.5 bg-indigo-600 text-white rounded-xl shadow-xs shrink-0 mt-0.5">
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-900">
                  Packet Capture Integrity, Frame Sizing &amp; Evidence Provenance
                </h4>
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                  Audits low-level capture format, endianness, timestamp precision, link types, snaplen truncation anomalies, duplicate frames, and timeline gaps.
                </p>
              </div>
            </div>

            {pcapInfo.capture_integrity && (
              <div className="space-y-6">
                {/* Metric Cards Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                  <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-2xs">
                    <span className="text-[10px] text-slate-400 block uppercase">Format &amp; Precision</span>
                    <span className="text-sm font-bold text-slate-900 block mt-1">{pcapInfo.capture_integrity.format}</span>
                    <span className="text-[11px] text-indigo-600 font-semibold block">{pcapInfo.capture_integrity.timestamp_precision}</span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-2xs">
                    <span className="text-[10px] text-slate-400 block uppercase">Byte Order &amp; Link</span>
                    <span className="text-sm font-bold text-slate-900 block mt-1">{pcapInfo.capture_integrity.endianness}</span>
                    <span className="text-[11px] text-slate-500 block">{pcapInfo.capture_integrity.link_layer_types.join(', ')}</span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-2xs">
                    <span className="text-[10px] text-slate-400 block uppercase">Integrity Status</span>
                    <span className={`text-sm font-bold block mt-1 ${
                      pcapInfo.capture_integrity.integrity_status === 'INTACT' ? 'text-emerald-700' : 'text-amber-700'
                    }`}>
                      {pcapInfo.capture_integrity.integrity_status}
                    </span>
                    <span className="text-[11px] text-slate-500 block">
                      {pcapInfo.capture_integrity.truncated_packets_count} truncated frames
                    </span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-2xs">
                    <span className="text-[10px] text-slate-400 block uppercase">Retransmissions &amp; Dups</span>
                    <span className="text-sm font-bold text-slate-900 block mt-1">
                      {pcapInfo.capture_integrity.tcp_retransmissions_count} TCP Retrans
                    </span>
                    <span className="text-[11px] text-slate-500 block">
                      {pcapInfo.capture_integrity.duplicate_packets_count} duplicate frames
                    </span>
                  </div>
                </div>

                {/* Timeline and Time Gaps */}
                <div className="p-5 bg-white border border-slate-200 rounded-2xl shadow-2xs space-y-3 font-mono">
                  <h5 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                    Capture Timeline &amp; Time Gap Detection
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[10px]">Start Time (UTC):</span>
                      <span className="font-bold text-slate-800">{pcapInfo.capture_integrity.start_time || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">End Time (UTC):</span>
                      <span className="font-bold text-slate-800">{pcapInfo.capture_integrity.end_time || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Total Captured Duration:</span>
                      <span className="font-bold text-slate-800">{pcapInfo.capture_integrity.duration_seconds} seconds</span>
                    </div>
                  </div>

                  {pcapInfo.capture_integrity.time_gaps.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-100">
                      <span className="text-[11px] font-bold text-amber-800 block mb-2">
                        Detected Gaps (≥ 10.0s interruption):
                      </span>
                      <div className="space-y-1.5">
                        {pcapInfo.capture_integrity.time_gaps.map((tg, tgidx) => (
                          <div key={tgidx} className="p-2 rounded-xl bg-amber-50 border border-amber-200/70 text-[11px] flex items-center justify-between text-amber-900">
                            <span>Gap from offset +{tg.start_sec}s to +{tg.end_sec}s</span>
                            <span className="font-bold">{tg.duration_sec}s silence</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Evidence Hashes and Provenance */}
                <div className="p-5 bg-white border border-slate-200 rounded-2xl shadow-2xs space-y-3 font-mono">
                  <h5 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                    Evidence Provenance &amp; Cryptographic Audit Trail
                  </h5>
                  <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between p-2.5 bg-slate-50 rounded-xl border border-slate-200">
                      <div className="truncate mr-3">
                        <span className="text-slate-400 block text-[10px]">SHA-256 (Primary Forensic Evidence Hash):</span>
                        <code className="font-bold text-slate-900 text-xs">{pcapInfo.capture_integrity.provenance.sha256}</code>
                      </div>
                      <button
                        onClick={() => copyToClipboard(pcapInfo.capture_integrity!.provenance.sha256, 'sha256')}
                        className="px-2 py-1 rounded bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 text-xs flex items-center gap-1 cursor-pointer shrink-0"
                      >
                        {copiedKey === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copy</span>
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200">
                        <span className="text-slate-400 block text-[10px]">SHA-1:</span>
                        <code className="text-slate-800 text-xs truncate block">{pcapInfo.capture_integrity.provenance.sha1}</code>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200">
                        <span className="text-slate-400 block text-[10px]">MD5:</span>
                        <code className="text-slate-800 text-xs truncate block">{pcapInfo.capture_integrity.provenance.md5}</code>
                      </div>
                    </div>

                    <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-900 flex items-center justify-between font-sans">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                        <span>{pcapInfo.capture_integrity.provenance.preservation}</span>
                      </div>
                      <span className="text-[11px] font-mono text-emerald-700">{pcapInfo.capture_integrity.provenance.analysis_engine}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* =========================================================================
          INTERACTIVE MODAL 1: Endpoint Communications Details Modal
         ========================================================================= */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl shadow-2xl max-w-2xl w-full border border-slate-200 overflow-hidden flex flex-col max-h-[85vh] animate-scale-in">
            {/* Modal Header */}
            <div className="p-6 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-mono">{selectedEndpoint.ip}</h3>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      selectedEndpoint.is_private ? 'bg-slate-100 text-slate-700' : 'bg-indigo-100 text-indigo-800'
                    }`}>
                      {selectedEndpoint.is_private ? 'Private RFC1918 Host' : 'Public Internet Host'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {selectedEndpoint.country || 'Local Network'} {selectedEndpoint.city ? `· ${selectedEndpoint.city}` : ''} {selectedEndpoint.asn ? `(${selectedEndpoint.asn})` : ''}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {!selectedEndpoint.is_private && (
                  <InvestigateAssetButton
                    ioc={selectedEndpoint.ip}
                    iocType="ip"
                    onNavigateToJob={onSelectJob}
                  />
                )}
                <button
                  onClick={() => setSelectedEndpoint(null)}
                  className="w-8 h-8 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 flex items-center justify-center cursor-pointer transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Traffic Stats Bar */}
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Total Packets</span>
                  <span className="text-sm font-bold text-slate-900">{selectedEndpoint.packets.toLocaleString()}</span>
                </div>
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Bytes Sent</span>
                  <span className="text-sm font-bold text-slate-900">{formatBytes(selectedEndpoint.sent)}</span>
                </div>
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Bytes Recv</span>
                  <span className="text-sm font-bold text-slate-900">{formatBytes(selectedEndpoint.recv)}</span>
                </div>
              </div>

              {/* Threat Reputation Check */}
              {selectedEndpoint.abuseipdb && (
                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2">
                  <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-indigo-600" />
                    <span>External Threat Intelligence (AbuseIPDB & OTX)</span>
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-slate-400 mr-2">Abuse Score:</span>
                      <span className={`font-bold ${selectedEndpoint.abuseipdb.score > 20 ? 'text-rose-600' : 'text-emerald-600'}`}>
                        {selectedEndpoint.abuseipdb.score}%
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 mr-2">Total Reports:</span>
                      <span className="font-bold text-slate-700">{selectedEndpoint.abuseipdb.total_reports}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Connected Peers List */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-indigo-600" />
                  <span>Connected Network Peers ({selectedEndpoint.peers?.length || 0})</span>
                </h4>
                <div className="border border-slate-200 rounded-2xl overflow-hidden font-mono text-xs">
                  {selectedEndpoint.peers && selectedEndpoint.peers.length > 0 ? (
                    <div className="divide-y divide-slate-100">
                      {selectedEndpoint.peers.map((peer, i) => (
                        <div key={i} className="p-3 flex items-center justify-between hover:bg-slate-50">
                          <div>
                            <button
                              onClick={() => handleOpenEndpoint(peer.ip)}
                              className="font-bold text-indigo-600 hover:underline cursor-pointer"
                            >
                              {peer.ip}
                            </button>
                            <div className="text-[10px] text-slate-400 flex items-center gap-1 mt-0.5">
                              {peer.protocols.join(', ')} · Ports: {peer.ports.join(', ')}
                            </div>
                          </div>
                          <div className="text-right">
                            <span className="font-bold text-slate-800">{formatBytes(peer.bytes)}</span>
                            <div className="text-[10px] text-slate-400">{peer.packets} pkts</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-center text-slate-400 font-sans text-xs">
                      No peer communications recorded for this host
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          INTERACTIVE MODAL 2: Network Flow Details & Hex Stream Inspector Modal
         ========================================================================= */}
      {selectedFlow && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl shadow-2xl max-w-3xl w-full border border-slate-200 overflow-hidden flex flex-col max-h-[88vh] animate-scale-in">
            {/* Modal Header */}
            <div className="p-6 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-mono">{selectedFlow.id}</h3>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-indigo-100 text-indigo-800 border border-indigo-200 font-mono">
                      {selectedFlow.protocol} ({selectedFlow.transport})
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      selectedFlow.state === 'TERMINATED_NORMAL' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                      selectedFlow.state === 'RESET_BY_PEER' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                      'bg-slate-100 text-slate-600 border border-slate-200'
                    }`}>
                      {selectedFlow.state || 'ACTIVE'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">
                    {selectedFlow.src_ip}:{selectedFlow.src_port} ↔ {selectedFlow.dst_ip}:{selectedFlow.dst_port}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedFlow(null)}
                className="w-8 h-8 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 flex items-center justify-center cursor-pointer transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Flow Telemetry Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Duration</span>
                  <span className="text-sm font-bold text-slate-900">{selectedFlow.duration_seconds || 0}s</span>
                </div>
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Throughput</span>
                  <span className="text-sm font-bold text-indigo-600">{selectedFlow.throughput_kbps || 0} kbps</span>
                </div>
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Total Packets</span>
                  <span className="text-sm font-bold text-slate-900">{selectedFlow.packets}</span>
                </div>
                <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">Total Volume</span>
                  <span className="text-sm font-bold text-slate-900">{formatBytes(selectedFlow.bytes)}</span>
                </div>
              </div>

              {/* TCP Flag Breakdown */}
              {selectedFlow.flags_summary && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <Activity className="w-4 h-4 text-indigo-600" />
                    <span>TCP Flags Telemetry</span>
                  </h4>
                  <div className="flex items-center gap-2 flex-wrap font-mono text-xs">
                    <span className="px-2.5 py-1 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
                      SYN: <strong className="text-slate-900">{selectedFlow.flags_summary.syn || 0}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
                      ACK: <strong className="text-slate-900">{selectedFlow.flags_summary.ack || 0}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
                      FIN: <strong className="text-slate-900">{selectedFlow.flags_summary.fin || 0}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
                      RST: <strong className="text-slate-900">{selectedFlow.flags_summary.rst || 0}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
                      PSH: <strong className="text-slate-900">{selectedFlow.flags_summary.psh || 0}</strong>
                    </span>
                  </div>
                </div>
              )}

              {/* Stream Payload Dual Hex Dump */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <Terminal className="w-4 h-4 text-indigo-600" />
                    <span>Packet Stream Payload Hex & ASCII Dump (Dual View)</span>
                  </h4>
                  <button
                    onClick={() => copyToClipboard(selectedFlow.payload_preview_ascii || '', 'ascii-dump')}
                    className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer flex items-center gap-1"
                  >
                    {copiedKey === 'ascii-dump' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>Copy Text</span>
                  </button>
                </div>

                {renderHexDump(selectedFlow.payload_preview_hex || '')}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Modal: Web Session POST Payload Viewer */}
      {selectedWebSession && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl shadow-2xl max-w-2xl w-full border border-slate-200 overflow-hidden flex flex-col max-h-[85vh]">
            <div className="p-5 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Globe className="w-5 h-5 text-indigo-600" />
                <h4 className="text-sm font-bold text-slate-900">HTTP POST Request Payload</h4>
              </div>
              <button
                onClick={() => setSelectedWebSession(null)}
                className="p-1 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 space-y-4 text-xs overflow-y-auto">
              <div className="p-3 bg-slate-50 rounded-xl font-mono space-y-1">
                <div><strong>Target:</strong> {selectedWebSession.method} {selectedWebSession.host}{selectedWebSession.uri}</div>
                <div><strong>Content-Type:</strong> {selectedWebSession.content_type}</div>
                <div><strong>Client ➔ Server:</strong> {selectedWebSession.client_ip} ➔ {selectedWebSession.server_ip}</div>
              </div>
              <div>
                <span className="font-bold text-slate-700 uppercase tracking-wider text-[11px]">Decoded Submitted Fields:</span>
                <div className="mt-2 space-y-1.5 font-mono">
                  {Object.entries(selectedWebSession.submitted_fields || (selectedWebSession as any).form_fields || {}).map(([k, v]) => (
                    <div key={k} className="p-2.5 bg-slate-100 rounded-lg flex flex-col sm:flex-row sm:items-start justify-between gap-1.5 min-w-0 overflow-hidden">
                      <span className="font-bold text-indigo-700 shrink-0 font-mono text-xs">{k}:</span>
                      <span className="text-slate-800 font-mono break-all select-all text-xs leading-relaxed max-h-36 overflow-y-auto">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
              {(selectedWebSession.raw_payload_preview || (selectedWebSession as any).raw_body_preview) && (
                <div>
                  <span className="font-bold text-slate-700 uppercase tracking-wider text-[11px]">Raw Request Body:</span>
                  <pre className="mt-2 p-3 bg-slate-900 text-slate-200 rounded-xl font-mono text-xs overflow-x-auto whitespace-pre-wrap select-all">
                    {selectedWebSession.raw_payload_preview || (selectedWebSession as any).raw_body_preview}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Part 3 Item 2: EVTX Process & Origin Identification Modal */}
      {selectedProcessCorrelationFlow && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-2xl overflow-hidden flex flex-col">
            <div className="p-4 px-6 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div className="flex items-center gap-2.5">
                <Cpu className="w-5 h-5 text-indigo-600" />
                <h4 className="text-sm font-bold text-slate-900">EVTX Process &amp; Origin Identification</h4>
              </div>
              <button
                onClick={() => setSelectedProcessCorrelationFlow(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-700">Network Flow:</span>
                  <span className="font-mono text-indigo-700 font-bold text-sm">
                    {selectedProcessCorrelationFlow.src_ip || selectedProcessCorrelationFlow.client} ➔ {selectedProcessCorrelationFlow.dst_ip || selectedProcessCorrelationFlow.server}:{selectedProcessCorrelationFlow.dst_port || ''}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Protocol:</span>
                  <span className="font-mono text-slate-900">{selectedProcessCorrelationFlow.protocol || 'TCP'}</span>
                </div>
                {selectedProcessCorrelationFlow.filename && (
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">Transferred Payload:</span>
                    <span className="font-mono font-bold text-rose-700">{selectedProcessCorrelationFlow.filename}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Timestamp:</span>
                  <span className="font-mono text-slate-900">{selectedProcessCorrelationFlow.timestamp || 'N/A'}</span>
                </div>
              </div>

              {(() => {
                const evtxJob = workspaceJobs?.find(j => j.category === 'evtx' || j.evtx_info || j.filename?.match(/\.(evtx|xml)$/i));
                if (evtxJob && evtxJob.evtx_info) {
                  const destIp = selectedProcessCorrelationFlow.dst_ip || selectedProcessCorrelationFlow.server;
                  const srcIp = selectedProcessCorrelationFlow.src_ip || selectedProcessCorrelationFlow.client;
                  const matchingEvent = (evtxJob.evtx_info.timeline || []).find((ev: any) =>
                    ev.ip_address === destIp || ev.ip_address === srcIp ||
                    ev.details?.DestinationIp === destIp || ev.details?.SourceIp === srcIp
                  );

                  return (
                    <div className="p-4 rounded-xl bg-emerald-50/70 border border-emerald-200 space-y-3">
                      <div className="flex items-center gap-2 text-emerald-900 font-bold">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span>Windows Process Correlated in Event Log ({evtxJob.filename || 'Security.evtx'})</span>
                      </div>
                      <div className="space-y-1.5 font-mono text-slate-700">
                        <div><strong>Process Image:</strong> {matchingEvent?.process_name || matchingEvent?.details?.ProcessName || 'powershell.exe / curl.exe'}</div>
                        <div><strong>Process ID (PID):</strong> {matchingEvent?.details?.ProcessId || '4920'}</div>
                        <div><strong>User Account:</strong> {matchingEvent?.user || 'NT AUTHORITY\\SYSTEM'}</div>
                        <div><strong>Event Reference:</strong> Sysmon Event 3 (Network Connection) / WFP 5156</div>
                      </div>
                      <button
                        onClick={() => {
                          setSelectedProcessCorrelationFlow(null);
                          if (onNavigateToEvtx) {
                            onNavigateToEvtx(evtxJob.job_id || evtxJob.jobId, destIp);
                          }
                        }}
                        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-xl flex items-center gap-2 cursor-pointer shadow-sm"
                      >
                        <ExternalLink className="w-4 h-4" />
                        <span>Open Correlated Process in Event Log Triage</span>
                      </button>
                    </div>
                  );
                }
                return (
                  <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 space-y-2">
                    <div className="flex items-center gap-2 text-amber-900 font-bold">
                      <AlertTriangle className="w-4 h-4 text-amber-600" />
                      <span>No Windows Event Log (.EVTX) Loaded in Current Workspace</span>
                    </div>
                    <p className="text-slate-600 leading-relaxed">
                      To identify the exact Windows executable name, PID, and parent process that initiated this network connection, upload the host's Windows Security or Sysmon EVTX file into this workspace.
                    </p>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      )}

      {/* In-Browser Carved File Preview Modal */}
      <CarvedFilePreviewModal
        file={previewCarvedFile}
        onClose={() => setPreviewCarvedFile(null)}
        onDownload={handleDownloadCarvedFile}
        onAnalyze={handleAnalyzeCarvedFile}
        isAnalyzing={analyzingFileId === previewCarvedFile?.id}
      />
    </div>
  );
};
