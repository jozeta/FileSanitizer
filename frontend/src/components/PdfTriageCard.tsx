import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Code,
  Copy,
  Check,
  Zap,
  Layers,
  FileCode,
  PlayCircle,
  ShieldAlert,
  Search,
  Eye,
  Binary,
  AlertTriangle,
  X,
  Info,
  ArrowRight,
  ExternalLink,
  Download,
  RefreshCw,
  ShieldCheck,
  FileArchive,
  Cpu,
  Mail,
  EyeOff,
  Lock,
  Shield,
  Link2
} from 'lucide-react';
import {
  PdfTriageInfo,
  Finding,
  AntiAnalysisInfo,
  PdfTokenDetail,
  PdfTokenOccurrence,
  PdfObjectItem,
  PdfStreamInspection,
  EmbeddedFileItem
} from '../types';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import { apiClient } from '../api/client';
import { findReferencedJob } from '../utils/crossFileReferences';
import { formatBytes, truncateHash } from '../utils/formatters';
import { InvestigateAssetButton } from './InvestigateAssetButton';

interface PdfTriageCardProps {
  jobId?: string;
  pdfInfo?: PdfTriageInfo;
  filename?: string;
  findings?: Finding[];
  antiAnalysis?: AntiAnalysisInfo;
  workspaceJobs?: any[];
  onSelectJob?: (newJobId: string) => void;
  embeddedFiles?: EmbeddedFileItem[];
  disabledChecks?: string[];
}

const getTagDescription = (tag: string): string => {
  switch (tag) {
    case '/JavaScript':
    case '/JS':
      return 'JavaScript execution engine inside PDF reader. High-risk vector for memory corruption, heap spraying, and arbitrary code execution.';
    case '/Launch':
      return 'Launches an external application, shell command, or executable file on the victim host. Critical RCE risk.';
    case '/OpenAction':
    case '/AA':
      return 'Automatic execution triggers that fire immediately upon opening or viewing document pages without user consent.';
    case '/URI':
      return 'Navigates to external web URLs, HTTP/S endpoints, or UNC paths (\\\\server\\share) used for NTLM hash theft.';
    case '/EmbeddedFiles':
      return 'Contains embedded file attachments, payload archives, or malicious droppers hidden inside the PDF container.';
    case '/AcroForm':
    case '/XFA':
      return 'Interactive forms or XML Forms Architecture. Vector for FormCalc RCE, XXE injection, and remote data exfiltration.';
    case '/FontMatrix':
      return 'PostScript font transformation matrix. Exploited in CVE-2024-4367 for pdf.js sandbox breakout and arbitrary code execution.';
    case '/JBIG2Decode':
      return 'JBIG2 bi-level compression filter. Heavily targeted in zero-day state-sponsored exploits (e.g., Pegasus FORCEDENTRY).';
    case '/RichMedia':
      return 'RichMedia flash/3D annotation handler. Exploited in CVE-2022-28244 for Content Security Policy bypass and local file theft.';
    case '/GoToE':
    case '/GoToR':
      return 'Embedded or remote document jump destinations. Used in forced authentication and UNC network exfiltration.';
    case '/SubmitForm':
    case '/ImportData':
      return 'Form submission endpoints capable of silently posting document contents or session tokens to remote servers.';
    case '/ObjStm':
      return 'Object stream container used to pack multiple PDF objects to evade signature detection and static pattern scanning.';
    case '/Colors':
      return 'Color space parameters. Exploited in CVE-2018-5158 to trigger PostScript calculator stack exhaustion in Mozilla Firefox.';
    case '/Annot':
      return 'Interactive page annotations, including external links, media widgets, and pop-up triggers.';
    default:
      return 'PDF structural element or internal object reference.';
  }
};

function formatHexDumpFallback(str: string, maxLen = 4096): string {
  const bytes = new TextEncoder().encode(str.slice(0, maxLen));
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hexParts: string[] = [];
    let asciiPart = '';
    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        const b = chunk[j];
        hexParts.push(b.toString(16).padStart(2, '0'));
        asciiPart += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
      }
    }
    const offset = i.toString(16).padStart(8, '0');
    lines.push(`${offset}  ${hexParts.slice(0, 8).join(' ')}  ${hexParts.slice(8).join(' ')}  |${asciiPart}|`);
  }
  return lines.join('\n');
}

export const PdfTriageCard: React.FC<PdfTriageCardProps> = ({
  jobId,
  pdfInfo,
  filename = 'document.pdf',
  findings: _findings,
  antiAnalysis,
  workspaceJobs,
  onSelectJob,
  embeddedFiles: propsEmbeddedFiles,
  disabledChecks = [],
}) => {
  const isCheckDisabled = (chk: string) => (disabledChecks || []).includes(chk);
  const canShowTokens = !isCheckDisabled('check_didier_pdfid');
  const [activeSubTab, setActiveSubTab] = useState<'tokens' | 'internals' | 'javascript' | 'actions' | 'concealed' | 'forensics' | 'embedded' | 'anti_analysis'>(canShowTokens ? 'tokens' : 'internals');

  useEffect(() => {
    if (activeSubTab === 'tokens' && isCheckDisabled('check_didier_pdfid')) {
      setActiveSubTab('internals');
    } else if (activeSubTab === 'javascript' && isCheckDisabled('check_javascript')) {
      setActiveSubTab('internals');
    } else if (activeSubTab === 'actions' && (isCheckDisabled('check_launch_actions') && isCheckDisabled('check_open_actions'))) {
      setActiveSubTab('internals');
    } else if (activeSubTab === 'embedded' && isCheckDisabled('check_embedded_files')) {
      setActiveSubTab('internals');
    } else if (activeSubTab === 'anti_analysis' && (isCheckDisabled('check_anti_analysis') || isCheckDisabled('anti_analysis_enabled'))) {
      setActiveSubTab('internals');
    }
  }, [activeSubTab, disabledChecks]);
  const [selectedStreamIdx, setSelectedStreamIdx] = useState<number>(0);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [showDeobfuscatedJs, setShowDeobfuscatedJs] = useState<boolean>(false);

  // Embedded Files State
  const [embeddedItems, setEmbeddedItems] = useState<EmbeddedFileItem[]>(propsEmbeddedFiles || []);
  const [loadingEmbedded, setLoadingEmbedded] = useState<boolean>(false);
  const [analyzingIds, setAnalyzingIds] = useState<Record<number, boolean>>({});
  const [analyzedSuccess, setAnalyzedSuccess] = useState<Record<number, { jobId: string; filename: string }>>({});
  const [embeddedError, setEmbeddedError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [embeddedSearch, setEmbeddedSearch] = useState<string>('');
  const [embeddedFilter, setEmbeddedFilter] = useState<'all' | 'dangerous' | 'safe'>('all');

  // Didier Stevens Token Inspection Modal State
  const [selectedToken, setSelectedToken] = useState<PdfTokenDetail | null>(null);
  const [tokenSearchQuery, setTokenSearchQuery] = useState<string>('');
  const [copiedSnippetIdx, setCopiedSnippetIdx] = useState<number | null>(null);
  const [copiedTokenFull, setCopiedTokenFull] = useState<boolean>(false);

  // PDF Object & Stream Inspector Modal State
  const [inspectedObject, setInspectedObject] = useState<PdfObjectItem | null>(null);
  const [streamModalTab, setStreamModalTab] = useState<'text' | 'hex' | 'dict' | 'tokens'>('text');
  const [streamTextSearch, setStreamTextSearch] = useState<string>('');
  const [remoteStreamData, setRemoteStreamData] = useState<PdfStreamInspection | null>(null);
  const [loadingRemoteStream, setLoadingRemoteStream] = useState<boolean>(false);
  const [remoteStreamError, setRemoteStreamError] = useState<string | null>(null);
  const [copiedModalText, setCopiedModalText] = useState<boolean>(false);
  const [copiedModalHex, setCopiedModalHex] = useState<boolean>(false);
  const [copiedModalDict, setCopiedModalDict] = useState<boolean>(false);

  // Internals table search & filter state
  const [internalsFilter, setInternalsFilter] = useState<'all' | 'streams' | 'suspicious' | 'text' | 'entropy'>('all');
  const [internalsSearch, setInternalsSearch] = useState<string>('');

  // Handle escape key to close modals
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (selectedToken) setSelectedToken(null);
        if (inspectedObject) setInspectedObject(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedToken, inspectedObject]);

  useEffect(() => {
    if (propsEmbeddedFiles && propsEmbeddedFiles.length > 0) {
      setEmbeddedItems(propsEmbeddedFiles);
    }
  }, [propsEmbeddedFiles]);

  useEffect(() => {
    if (jobId && (!propsEmbeddedFiles || propsEmbeddedFiles.length === 0)) {
      setLoadingEmbedded(true);
      apiClient
        .getEmbeddedFiles(jobId)
        .then((res) => {
          if (res?.files && res.files.length > 0) {
            setEmbeddedItems(res.files);
          }
        })
        .catch((err) => {
          console.debug('Embedded files fetch note:', err);
        })
        .finally(() => setLoadingEmbedded(false));
    }
  }, [jobId, propsEmbeddedFiles]);

  const {
    page_count = 0,
    pdfid = {},
    pdfid_counts = {},
    obfuscated_tags = {},
    has_javascript = false,
    has_launch = false,
    has_open_action = false,
    embedded_files = [],
    eof_count = 1,
    incremental_updates = 0,
    javascript_streams = [],
    extracted_code,
    pdfid_token_details = {},
    structure_forensics,
    digital_signatures = [],
    concealed_content,
    action_chains = [],
    carved_attachments = [],
    js_analysis
  } = pdfInfo || {};

  const effectiveEmbeddedFiles = useMemo<EmbeddedFileItem[]>(() => {
    if (embeddedItems && embeddedItems.length > 0) {
      return embeddedItems;
    }
    if (embedded_files && embedded_files.length > 0) {
      return embedded_files.map((item: any, idx: number) => {
        if (typeof item === 'object' && item !== null && item.name) {
          return {
            id: item.id !== undefined ? item.id : idx,
            name: item.name,
            source_type: item.source_type || 'pdf_attachment',
            parent_format: item.parent_format || 'PDF Document',
            origin_stream: item.origin_stream || `/EmbeddedFiles index ${idx}`,
            size: item.size || 0,
            size_formatted: item.size_formatted || (item.size ? formatBytes(item.size) : '0 B'),
            mime_type: item.mime_type || 'application/octet-stream',
            md5: item.md5 || '',
            sha256: item.sha256 || '',
            is_dangerous: Boolean(item.is_dangerous),
            threat_reason: item.threat_reason || '',
            disk_filename: item.disk_filename || ''
          };
        }
        const nameStr = String(item || `attachment_${idx}`);
        const isDangerous = /\.(exe|dll|vbs|ps1|bat|cmd|scr|hta|js|jar|py|sh|msi)$/i.test(nameStr);
        return {
          id: idx,
          name: nameStr,
          source_type: 'pdf_attachment',
          parent_format: 'PDF Document',
          origin_stream: `/EmbeddedFiles index ${idx}`,
          size: 0,
          size_formatted: 'Unknown',
          mime_type: 'application/octet-stream',
          md5: '',
          sha256: '',
          is_dangerous: isDangerous,
          threat_reason: isDangerous ? 'Executable or script extension inside PDF attachment' : '',
          disk_filename: ''
        };
      });
    }
    return [];
  }, [embeddedItems, embedded_files]);

  const filteredEmbeddedFiles = useMemo(() => {
    return effectiveEmbeddedFiles.filter((f) => {
      if (embeddedFilter === 'dangerous' && !f.is_dangerous) return false;
      if (embeddedFilter === 'safe' && f.is_dangerous) return false;
      if (!embeddedSearch.trim()) return true;
      const q = embeddedSearch.toLowerCase();
      return (
        f.name.toLowerCase().includes(q) ||
        (f.origin_stream && f.origin_stream.toLowerCase().includes(q)) ||
        (f.mime_type && f.mime_type.toLowerCase().includes(q)) ||
        (f.sha256 && f.sha256.toLowerCase().includes(q)) ||
        (f.threat_reason && f.threat_reason.toLowerCase().includes(q))
      );
    });
  }, [effectiveEmbeddedFiles, embeddedFilter, embeddedSearch]);

  const dangerousEmbeddedCount = useMemo(
    () => effectiveEmbeddedFiles.filter((f) => f.is_dangerous).length,
    [effectiveEmbeddedFiles]
  );
  const safeEmbeddedCount = effectiveEmbeddedFiles.length - dangerousEmbeddedCount;

  const handleAnalyzeEmbedded = async (file: EmbeddedFileItem) => {
    if (!jobId) {
      setEmbeddedError("Cannot analyze: Parent job ID is missing.");
      return;
    }
    setAnalyzingIds((prev) => ({ ...prev, [file.id]: true }));
    setEmbeddedError(null);
    try {
      const res = await apiClient.analyzeEmbeddedFile(jobId, file.id);
      setAnalyzedSuccess((prev) => ({
        ...prev,
        [file.id]: { jobId: res.job_id, filename: res.filename },
      }));
      if (onSelectJob && res.job_id) {
        onSelectJob(res.job_id);
      }
    } catch (err: any) {
      setEmbeddedError(err.message || `Failed to analyze embedded file '${file.name}'`);
    } finally {
      setAnalyzingIds((prev) => ({ ...prev, [file.id]: false }));
    }
  };

  const handleRefreshEmbedded = async () => {
    if (!jobId) return;
    setLoadingEmbedded(true);
    setEmbeddedError(null);
    try {
      const res = await apiClient.getEmbeddedFiles(jobId);
      if (res?.files) {
        setEmbeddedItems(res.files);
      }
    } catch (err: any) {
      setEmbeddedError(err.message || "Failed to refresh embedded files");
    } finally {
      setLoadingEmbedded(false);
    }
  };

  const handleCopyHash = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getFormatIcon = (format: string, name: string) => {
    const fLower = (format || '').toLowerCase();
    const nLower = (name || '').toLowerCase();
    if (fLower.includes('pdf') || nLower.endsWith('.pdf')) {
      return <FileText className="w-5 h-5 text-rose-600" />;
    }
    if (fLower.includes('office') || ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.xls', '.doc'].some(ext => nLower.endsWith(ext))) {
      return <FileCode className="w-5 h-5 text-blue-600" />;
    }
    if (fLower.includes('executable') || fLower.includes('binary') || ['.exe', '.dll', '.bin', '.scr', '.elf', '.dylib'].some(ext => nLower.endsWith(ext))) {
      return <Cpu className="w-5 h-5 text-purple-600" />;
    }
    if (fLower.includes('email') || ['.eml', '.msg'].some(ext => nLower.endsWith(ext))) {
      return <Mail className="w-5 h-5 text-indigo-600" />;
    }
    if (fLower.includes('archive') || ['.zip', '.tar', '.gz', '.7z', '.rar'].some(ext => nLower.endsWith(ext))) {
      return <FileArchive className="w-5 h-5 text-amber-600" />;
    }
    return <FileCode className="w-5 h-5 text-slate-600" />;
  };

  const rawCounts = {
    ...pdfid,
    ...pdfid_counts,
    ...((pdfInfo as any)?.pdfid_tags || {})
  };

  const standardTags = [
    'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
    '/Page', '/Encrypt', '/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction',
    '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFiles', '/XFA',
    '/URI', '/FontMatrix', '/GoToE', '/GoToR', '/SubmitForm', '/Colors'
  ];

  const mergedCounts: Record<string, number> = { ...rawCounts };
  for (const st of standardTags) {
    if (mergedCounts[st] === undefined) {
      mergedCounts[st] = 0;
    }
  }

  const pdfObjects: PdfObjectItem[] = (pdfInfo as any)?.pdf_objects || [];
  const totalObjects = (pdfInfo as any)?.total_objects || pdfObjects.length;
  const totalStreams = (pdfInfo as any)?.total_streams || pdfObjects.filter((o: any) => o.is_stream).length;
  const filterCounts: Record<string, number> = (pdfInfo as any)?.filter_counts || {};
  const isLinearized = Boolean((pdfInfo as any)?.is_linearized);

  const currentStream = javascript_streams[selectedStreamIdx] || (extracted_code ? { stream_id: 1, size: extracted_code.code.length, code: extracted_code.code } : null);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const getTagRiskBadge = (tag: string, count: number) => {
    if (count === 0) return null;
    if (
      tag === '/Launch' ||
      tag === '/OpenAction' ||
      tag === '/AA' ||
      tag === '/JavaScript' ||
      tag === '/JS' ||
      tag === '/FontMatrix' ||
      tag === '/JBIG2Decode'
    ) {
      return 'bg-rose-50 text-rose-700 border-rose-200 font-bold';
    }
    if (
      tag === '/EmbeddedFiles' ||
      tag === '/AcroForm' ||
      tag === '/XFA' ||
      tag === '/URI' ||
      tag === '/RichMedia' ||
      tag === '/GoToE' ||
      tag === '/SubmitForm'
    ) {
      return 'bg-amber-50 text-amber-700 border-amber-200 font-semibold';
    }
    return 'bg-slate-100 text-slate-700 border-slate-200';
  };

  // Click handler for a PDFiD token card
  const handleTokenClick = (tag: string, count: number) => {
    if (count === 0) return;

    let detail: PdfTokenDetail | undefined = pdfid_token_details[tag];
    if (!detail) {
      // Reconstruct token detail from objects
      const matchingObjects = pdfObjects.filter(
        o => o.tokens?.includes(tag) || o.type === tag || o.raw_dict?.includes(tag)
      );

      const occurrences: PdfTokenOccurrence[] = matchingObjects.map(o => ({
        token: tag,
        raw_token: tag,
        is_obfuscated: false,
        snippet: o.raw_dict || `Object #${o.xref} (${o.type})`,
        extracted_value: o.stream_text ? o.stream_text.slice(0, 300) : undefined,
        threat_summary: o.suspicious_reason,
        xref: o.xref
      }));

      detail = {
        token: tag,
        count: count,
        obfuscated_count: obfuscated_tags[tag] || 0,
        obfuscated_samples: ((pdfInfo as any)?.obfuscated_samples || {})[tag] || [],
        threat_summary: getTagDescription(tag),
        occurrences: occurrences.length > 0 ? occurrences : [
          {
            token: tag,
            raw_token: tag,
            is_obfuscated: Boolean((obfuscated_tags[tag] || 0) > 0),
            snippet: `Found ${count} occurrences of token "${tag}" in PDF internal dictionary structure.`,
            threat_summary: getTagDescription(tag)
          }
        ]
      };
    }

    setSelectedToken(detail);
    setTokenSearchQuery('');
  };

  // Inspect an object stream
  const handleInspectObject = async (obj: PdfObjectItem) => {
    setInspectedObject(obj);
    setRemoteStreamData(null);
    setRemoteStreamError(null);
    setStreamTextSearch('');

    // Pick best initial tab
    if (obj.stream_text && obj.stream_text.trim().length > 0) {
      setStreamModalTab('text');
    } else if (obj.stream_hex && obj.stream_hex.trim().length > 0) {
      setStreamModalTab('hex');
    } else if (obj.raw_dict && obj.raw_dict.trim().length > 0) {
      setStreamModalTab('dict');
    } else {
      setStreamModalTab('text');
    }

    // If stream content is missing and it's a stream, fetch from API
    if (obj.is_stream && (!obj.stream_text || !obj.stream_hex) && jobId) {
      setLoadingRemoteStream(true);
      try {
        const streamData = await apiClient.getPdfStreamContent(jobId, obj.xref);
        setRemoteStreamData(streamData);
      } catch (err: any) {
        setRemoteStreamError(err.message || 'Failed to fetch stream content');
      } finally {
        setLoadingRemoteStream(false);
      }
    }
  };

  // Filtered internals table objects
  const filteredInternalsObjects = useMemo(() => {
    return pdfObjects.filter(obj => {
      if (internalsFilter === 'streams' && !obj.is_stream) return false;
      if (internalsFilter === 'suspicious' && !obj.is_suspicious) return false;
      if (internalsFilter === 'text' && !obj.is_text) return false;
      if (internalsFilter === 'entropy' && (!obj.is_stream || (obj.entropy || 0) <= 7.5)) return false;

      if (internalsSearch.trim()) {
        const query = internalsSearch.toLowerCase().trim();
        const matchesXref = String(obj.xref).includes(query);
        const matchesType = (obj.type || '').toLowerCase().includes(query);
        const matchesFilter = (obj.filter || '').toLowerCase().includes(query);
        const matchesReason = (obj.suspicious_reason || '').toLowerCase().includes(query);
        const matchesTokens = (obj.tokens || []).some(t => t.toLowerCase().includes(query));
        return matchesXref || matchesType || matchesFilter || matchesReason || matchesTokens;
      }
      return true;
    });
  }, [pdfObjects, internalsFilter, internalsSearch]);

  // Filtered occurrences in Token Modal
  const filteredTokenOccurrences = useMemo(() => {
    if (!selectedToken) return [];
    if (!tokenSearchQuery.trim()) return selectedToken.occurrences || [];
    const q = tokenSearchQuery.toLowerCase().trim();
    return (selectedToken.occurrences || []).filter(occ => {
      const matchXref = occ.xref !== undefined && occ.xref !== null && String(occ.xref).includes(q);
      const matchRaw = (occ.raw_token || '').toLowerCase().includes(q);
      const matchSnippet = (occ.snippet || '').toLowerCase().includes(q);
      const matchExtVal = (occ.extracted_value || '').toLowerCase().includes(q);
      const matchThreat = (occ.threat_summary || '').toLowerCase().includes(q);
      return matchXref || matchRaw || matchSnippet || matchExtVal || matchThreat;
    });
  }, [selectedToken, tokenSearchQuery]);

  // Modal active stream data resolution
  const activeStreamText = remoteStreamData?.text_content || inspectedObject?.stream_text || '';
  const activeStreamHex = remoteStreamData?.hex_dump || inspectedObject?.stream_hex || (activeStreamText ? formatHexDumpFallback(activeStreamText) : '');
  const activeRawDict = remoteStreamData?.raw_dict || inspectedObject?.raw_dict || '';

  if (!pdfInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <FileText className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No PDF triage metadata available for this file.</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-rose-50 text-rose-600 rounded-2xl shrink-0">
            <FileText className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Adobe PDF Structural &amp; Didier Stevens PDFiD Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                {filename}
              </span>
              {has_open_action && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  /OpenAction Auto-Run
                </span>
              )}
              {has_javascript && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-50 text-amber-700 border border-amber-300">
                  JavaScript Embedded
                </span>
              )}
              {has_launch && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-red-600 text-white animate-pulse">
                  /Launch Process Execution
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Interactive Didier Stevens PDFiD token dissection, cross-reference object stream analysis, deobfuscated JavaScript streams, and shadow attack incremental update forensics.
            </p>
          </div>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Pages</span>
            <strong className="text-slate-900">{page_count}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Streams</span>
            <strong className="text-blue-600">{totalStreams}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">JS Streams</span>
            <strong className={javascript_streams.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {javascript_streams.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Updates (%%EOF)</span>
            <strong className="text-slate-900">{eof_count}</strong>
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        {!isCheckDisabled('check_didier_pdfid') && (
          <button
            onClick={() => setActiveSubTab('tokens')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'tokens'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            <span>Didier Stevens PDFiD Tokens</span>
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('internals')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'internals'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-500" />
          <span>PDF Internals &amp; Streams ({totalObjects})</span>
        </button>

        {!isCheckDisabled('check_javascript') && (
          <button
            onClick={() => setActiveSubTab('javascript')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'javascript'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Code className="w-3.5 h-3.5 text-rose-500" />
            <span>JavaScript Streams ({javascript_streams.length})</span>
          </button>
        )}

        {!(isCheckDisabled('check_launch_actions') && isCheckDisabled('check_open_actions')) && (
          <button
            onClick={() => setActiveSubTab('actions')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'actions'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <PlayCircle className="w-3.5 h-3.5 text-blue-500" />
            <span>Action Chains ({action_chains.length || (has_open_action || has_launch ? '!' : 0)})</span>
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('concealed')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'concealed'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <EyeOff className="w-3.5 h-3.5 text-indigo-500" />
          <span>Concealed &amp; Phishing</span>
          {Boolean(
            (concealed_content?.white_text_count || 0) +
            (concealed_content?.deceptive_link_count || 0) +
            (concealed_content?.tiny_font_count || 0) > 0
          ) && (
            <span className="px-1.5 py-0.2 bg-indigo-500 text-white rounded-full text-[10px] font-bold">
              {(concealed_content?.white_text_count || 0) +
                (concealed_content?.deceptive_link_count || 0) +
                (concealed_content?.tiny_font_count || 0)}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('forensics')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'forensics'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-amber-500" />
          <span>Structure &amp; Signatures</span>
          {Boolean(
            structure_forensics?.has_overlay ||
            structure_forensics?.is_polyglot ||
            digital_signatures.some(s => s.has_shadow_attack)
          ) && (
            <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold animate-pulse">
              !
            </span>
          )}
        </button>

        {!isCheckDisabled('check_embedded_files') && (
          <button
            onClick={() => setActiveSubTab('embedded')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'embedded'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <FileArchive className="w-3.5 h-3.5 text-emerald-500" />
            <span>Embedded Files ({effectiveEmbeddedFiles.length})</span>
            {dangerousEmbeddedCount > 0 && (
              <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold animate-pulse">
                {dangerousEmbeddedCount}
              </span>
            )}
          </button>
        )}

        {!isCheckDisabled('check_anti_analysis') && !isCheckDisabled('anti_analysis_enabled') && (
          <button
            onClick={() => setActiveSubTab('anti_analysis')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'anti_analysis'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
            <span>Anti-Analysis &amp; Evasion</span>
            {Boolean(antiAnalysis?.techniques && antiAnalysis.techniques.length > 0) && (
              <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold">
                {antiAnalysis?.techniques.length}
              </span>
            )}
          </button>
        )}
      </div>

      {/* Tab 1: Didier Stevens PDFiD Tokens */}
      {activeSubTab === 'tokens' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-500 px-1">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-500" />
              <span className="font-semibold text-slate-700">Interactive PDFiD Token Inspector</span>
              <span>— Click any detected token card to inspect raw dictionary context, extracted values, and hex obfuscations</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Didier Stevens PDFiD Engine</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.entries(mergedCounts).map(([tag, count]) => {
              const obfCount = obfuscated_tags[tag] || 0;
              const hasCount = (count as number) > 0;
              const badgeClass = getTagRiskBadge(tag, count as number);

              return (
                <div
                  key={tag}
                  onClick={() => hasCount && handleTokenClick(tag, count as number)}
                  className={`p-3 rounded-2xl border transition-all ${
                    hasCount
                      ? 'bg-white border-slate-300 shadow-2xs hover:border-blue-400 hover:shadow-md hover:bg-blue-50/10 cursor-pointer group'
                      : 'bg-slate-50/50 border-slate-200 opacity-60 cursor-default'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-slate-800 group-hover:text-blue-600 transition-colors">
                      {tag}
                    </span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${badgeClass || 'bg-slate-100 text-slate-600'}`}>
                      {count}
                    </span>
                  </div>

                  {obfCount > 0 && (
                    <div className="text-[10px] font-mono text-purple-700 bg-purple-50 px-1.5 py-0.5 rounded border border-purple-200 mt-1">
                      ⚠️ {obfCount} hex-obfuscated (#xx)
                    </div>
                  )}

                  {hasCount && (
                    <div className="mt-2 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px] text-blue-600 font-medium opacity-0 group-hover:opacity-100 transition-opacity">
                      <span>Inspect artifacts</span>
                      <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {incremental_updates > 0 && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl text-xs text-amber-900 space-y-1">
              <strong className="block font-bold">Incremental Updates Detected ({incremental_updates} shadow updates)</strong>
              <p className="leading-relaxed">
                Document contains {eof_count} %%EOF terminal markers. Attackers use incremental updates (Shadow Attacks)
                to hide malicious actions, overlay signatures, or replace visible document layers without invalidating initial signatures.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Tab: PDF Internals & Object Streams */}
      {activeSubTab === 'internals' && (
        <div className="space-y-4 text-xs">
          {/* Metrics summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Total Objects</span>
              <strong className="text-sm text-slate-900">{totalObjects}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Data Streams</span>
              <strong className="text-sm text-blue-600">{totalStreams}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Linearized (Fast Web)</span>
              <strong className="text-sm text-slate-800">{isLinearized ? 'Yes' : 'No'}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Active Filters</span>
              <strong className="text-sm text-purple-600">{Object.keys(filterCounts).length}</strong>
            </div>
          </div>

          {/* Compression Filters Breakdown */}
          {Object.keys(filterCounts).length > 0 && (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold text-slate-700 font-sans mr-2">Stream Filters:</span>
              {Object.entries(filterCounts).map(([flt, count]) => (
                <span
                  key={flt}
                  className="px-2.5 py-1 rounded-xl text-xs font-mono font-semibold bg-white border border-slate-300 text-slate-800 flex items-center gap-1.5 shadow-2xs"
                >
                  <span>{flt}</span>
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-100 text-slate-600 font-bold">{count}</span>
                </span>
              ))}
            </div>
          )}

          {/* Table Controls (Filter & Search) */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-50 p-3 rounded-2xl border border-slate-200">
            <div className="flex items-center gap-1.5 overflow-x-auto">
              <button
                onClick={() => setInternalsFilter('all')}
                className={`px-2.5 py-1 rounded-xl font-medium transition-colors cursor-pointer ${
                  internalsFilter === 'all'
                    ? 'bg-slate-900 text-white font-bold'
                    : 'text-slate-600 hover:bg-slate-200/60'
                }`}
              >
                All Objects ({pdfObjects.length})
              </button>
              <button
                onClick={() => setInternalsFilter('streams')}
                className={`px-2.5 py-1 rounded-xl font-medium transition-colors cursor-pointer ${
                  internalsFilter === 'streams'
                    ? 'bg-blue-600 text-white font-bold'
                    : 'text-slate-600 hover:bg-slate-200/60'
                }`}
              >
                Only Streams ({pdfObjects.filter(o => o.is_stream).length})
              </button>
              <button
                onClick={() => setInternalsFilter('suspicious')}
                className={`px-2.5 py-1 rounded-xl font-medium transition-colors cursor-pointer ${
                  internalsFilter === 'suspicious'
                    ? 'bg-rose-600 text-white font-bold'
                    : 'text-slate-600 hover:bg-slate-200/60'
                }`}
              >
                Suspicious / Exploits ({pdfObjects.filter(o => o.is_suspicious).length})
              </button>
              <button
                onClick={() => setInternalsFilter('text')}
                className={`px-2.5 py-1 rounded-xl font-medium transition-colors cursor-pointer ${
                  internalsFilter === 'text'
                    ? 'bg-purple-600 text-white font-bold'
                    : 'text-slate-600 hover:bg-slate-200/60'
                }`}
              >
                Text &amp; Code Streams
              </button>
              <button
                onClick={() => setInternalsFilter('entropy')}
                className={`px-2.5 py-1 rounded-xl font-medium transition-colors cursor-pointer ${
                  internalsFilter === 'entropy'
                    ? 'bg-amber-600 text-white font-bold'
                    : 'text-slate-600 hover:bg-slate-200/60'
                }`}
              >
                High Entropy &gt; 7.5 ({pdfObjects.filter(o => o.is_stream && (o.entropy || 0) > 7.5).length})
              </button>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={internalsSearch}
                onChange={e => setInternalsSearch(e.target.value)}
                placeholder="Search XRef, type, filter..."
                className="w-full pl-8 pr-3 py-1.5 bg-white border border-slate-300 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              {internalsSearch && (
                <button
                  onClick={() => setInternalsSearch('')}
                  className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Object & Stream Table */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
            <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-600" />
                <span>Object &amp; Stream Cross-Reference Table ({filteredInternalsObjects.length} shown)</span>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">Click any row or Inspect button to view stream/code/hex</span>
            </div>
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200 sticky top-0">
                  <tr>
                    <th className="px-3.5 py-2">XRef #</th>
                    <th className="px-3.5 py-2">Object Type</th>
                    <th className="px-3.5 py-2">Container</th>
                    <th className="px-3.5 py-2">Filter</th>
                    <th className="px-3.5 py-2 text-right">Stream Size</th>
                    <th className="px-3.5 py-2 text-right">Entropy</th>
                    <th className="px-3.5 py-2">Indicators / Flags</th>
                    <th className="px-3.5 py-2 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredInternalsObjects.map((obj, idx) => (
                    <tr
                      key={idx}
                      onClick={() => handleInspectObject(obj)}
                      className={`cursor-pointer transition-colors ${
                        obj.is_suspicious ? 'bg-rose-50/40 hover:bg-rose-50/80' : 'hover:bg-blue-50/40'
                      }`}
                    >
                      <td className="px-3.5 py-2 text-slate-600 font-bold">
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200">
                          #{obj.xref}
                        </span>
                      </td>
                      <td className="px-3.5 py-2 text-slate-800 font-semibold">{obj.type || 'Object'}</td>
                      <td className="px-3.5 py-2">
                        {obj.is_stream ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
                            Stream
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                            Dictionary
                          </span>
                        )}
                      </td>
                      <td className="px-3.5 py-2 text-slate-600 font-sans text-[11px]">{obj.filter || '-'}</td>
                      <td className="px-3.5 py-2 text-right font-sans">
                        {obj.size > 0 ? `${(obj.size / 1024).toFixed(1)} KB` : '-'}
                      </td>
                      <td className="px-3.5 py-2 text-right">
                        {obj.is_stream && obj.entropy !== undefined ? (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono ${
                              obj.entropy > 7.5
                                ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                : obj.entropy > 6.0
                                ? 'bg-amber-50 text-amber-800 border border-amber-200'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                            title={`Shannon Entropy: ${obj.entropy.toFixed(3)} / 8.000`}
                          >
                            {obj.entropy.toFixed(2)}
                          </span>
                        ) : (
                          <span className="text-slate-400 font-sans text-[11px]">-</span>
                        )}
                      </td>
                      <td className="px-3.5 py-2">
                        {obj.is_suspicious ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white animate-pulse">
                            ⚠️ {obj.suspicious_reason}
                          </span>
                        ) : (
                          <span className="text-slate-400 font-sans text-[11px]">Normal</span>
                        )}
                      </td>
                      <td className="px-3.5 py-2 text-center" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => handleInspectObject(obj)}
                          className="px-2.5 py-1 bg-white hover:bg-blue-50 text-blue-700 border border-blue-200 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1 mx-auto transition-colors cursor-pointer shadow-2xs"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredInternalsObjects.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-slate-400 font-sans">
                        No PDF objects matched the selected filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: JavaScript Streams & Code Viewer */}
      {activeSubTab === 'javascript' && (
        <div className="space-y-4">
          {/* Dangerous Acrobat JavaScript APIs */}
          {js_analysis?.dangerous_apis && js_analysis.dangerous_apis.length > 0 && (
            <div className="p-4 bg-rose-50/70 border border-rose-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-rose-950 text-xs">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <span>Dangerous Acrobat JavaScript APIs Detected ({js_analysis.dangerous_apis.length})</span>
                </div>
                <span className="text-[10px] uppercase font-bold text-rose-700 bg-rose-100 px-2 py-0.5 rounded-full">
                  High Exploit Risk
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                {js_analysis.dangerous_apis.map((apiItem, aIdx) => (
                  <div key={aIdx} className="p-2.5 bg-white border border-rose-200 rounded-xl text-xs space-y-1 shadow-2xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-rose-700">{apiItem.api}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        apiItem.risk === 'critical' ? 'bg-rose-600 text-white' : 'bg-amber-100 text-amber-800'
                      }`}>
                        {apiItem.risk}
                      </span>
                    </div>
                    <p className="text-slate-600 text-[11px] leading-relaxed">{apiItem.description}</p>
                    {apiItem.mitre && (
                      <span className="inline-block text-[10px] font-mono text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                        MITRE {apiItem.mitre}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Shellcode Indicators */}
          {js_analysis?.shellcode_indicators && js_analysis.shellcode_indicators.length > 0 && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-900 flex items-start gap-2 shadow-2xs">
              <ShieldAlert className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-bold">Memory Corruption &amp; Shellcode Patterns Detected:</strong>
                <ul className="list-disc list-inside mt-1 space-y-0.5 text-[11px]">
                  {js_analysis.shellcode_indicators.map((ind, iIdx) => (
                    <li key={iIdx}>{ind}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {javascript_streams.length === 0 && !extracted_code ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No JavaScript streams discovered in this PDF document.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              {/* Stream Selector */}
              <div className="lg:col-span-1 space-y-1.5 border border-slate-200 rounded-2xl p-2 bg-slate-50/50">
                <span className="text-[10px] uppercase font-bold text-slate-400 px-2 block">
                  Extracted Streams ({javascript_streams.length || 1})
                </span>
                {(javascript_streams.length > 0
                  ? javascript_streams
                  : [{ stream_id: 1, size: extracted_code?.code.length || 0, code: extracted_code?.code || '' }]
                ).map((st, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSelectedStreamIdx(idx)}
                    className={`w-full text-left p-2.5 rounded-xl text-xs font-mono transition-all flex items-center justify-between cursor-pointer ${
                      selectedStreamIdx === idx
                        ? 'bg-white shadow-xs text-rose-700 font-bold border border-rose-200'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <div>
                      <div>Stream #{st.stream_id}</div>
                      <div className="text-[10px] text-slate-400 font-normal">{st.size} bytes</div>
                    </div>
                    <FileCode className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </button>
                ))}
              </div>

              {/* Code Viewer */}
              <div className="lg:col-span-3 border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 text-slate-800 font-mono text-xs">
                <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-800">
                      {showDeobfuscatedJs ? 'Deobfuscated JavaScript Stream' : `Stream #${currentStream?.stream_id}`}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      ({(showDeobfuscatedJs && js_analysis?.deobfuscated_code ? js_analysis.deobfuscated_code.length : (currentStream?.size || 0))} bytes)
                    </span>
                    {js_analysis?.deobfuscated_applied && (
                      <span className="text-[10px] bg-purple-100 text-purple-800 border border-purple-200 px-2 py-0.5 rounded-full font-semibold">
                        Deobfuscation Available
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {js_analysis?.deobfuscated_applied && (
                      <button
                        onClick={() => setShowDeobfuscatedJs(!showDeobfuscatedJs)}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-sans font-semibold transition-colors cursor-pointer border ${
                          showDeobfuscatedJs
                            ? 'bg-purple-600 text-white border-purple-700'
                            : 'bg-white text-purple-700 border-purple-200 hover:bg-purple-50'
                        }`}
                      >
                        {showDeobfuscatedJs ? '✓ Showing Deobfuscated' : 'View Deobfuscated JS'}
                      </button>
                    )}
                    <button
                      onClick={() => handleCopyCode(showDeobfuscatedJs && js_analysis?.deobfuscated_code ? js_analysis.deobfuscated_code : (currentStream?.code || ''))}
                      className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedCode ? 'Copied' : 'Copy JS'}</span>
                    </button>
                  </div>
                </div>

                <div className="p-4 max-h-[500px] overflow-y-auto space-y-0.5 bg-white">
                  {((showDeobfuscatedJs && js_analysis?.deobfuscated_code ? js_analysis.deobfuscated_code : (currentStream?.code || ''))).split('\n').map((line, lIdx) => (
                    <div key={lIdx} className="flex hover:bg-slate-50 leading-5">
                      <span className="w-10 select-none text-slate-400 text-right pr-3 shrink-0">
                        {lIdx + 1}
                      </span>
                      <span className="whitespace-pre text-slate-800">{line || ' '}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Actions & Execution Chains */}
      {activeSubTab === 'actions' && (
        <div className="space-y-4 text-xs">
          <div className="p-4 bg-rose-50/50 border border-rose-200 rounded-2xl space-y-2">
            <h4 className="font-bold text-rose-950 flex items-center gap-2">
              <PlayCircle className="w-4 h-4 text-rose-600" />
              <span>Automatic Execution Hooks &amp; Action Chains</span>
            </h4>
            <p className="text-rose-900 leading-relaxed">
              PDF files support auto-executing scripts or launching applications upon document open, page transition, bookmark click, or field validation.
              Attackers chain /OpenAction, /AA, and /Next sequences to execute shellcode or exfiltrate data silently.
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <span
                className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                  has_open_action ? 'bg-rose-600 text-white animate-pulse' : 'bg-slate-100 text-slate-700'
                }`}
              >
                {has_open_action ? '⚠️ /OpenAction Present' : '✓ No /OpenAction'}
              </span>
              <span
                className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                  has_launch ? 'bg-rose-600 text-white animate-pulse' : 'bg-slate-100 text-slate-700'
                }`}
              >
                {has_launch ? '⚠️ /Launch Present (RCE Vector)' : '✓ No /Launch'}
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-blue-100 text-blue-800">
                {action_chains.length} Hook{action_chains.length !== 1 ? 's' : ''} Identified
              </span>
            </div>
          </div>

          {/* Action Chains Table */}
          {action_chains && action_chains.length > 0 ? (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <PlayCircle className="w-4 h-4 text-blue-600" />
                  <span>Execution Action Manifest ({action_chains.length})</span>
                </div>
                <span className="text-[11px] text-slate-500 font-mono">Catalog, Annotation, and Lifecycle Triggers</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200">
                    <tr>
                      <th className="px-3.5 py-2">Trigger Event Hook</th>
                      <th className="px-3.5 py-2">Scope</th>
                      <th className="px-3.5 py-2">Action Type</th>
                      <th className="px-3.5 py-2">Raw Snippet</th>
                      <th className="px-3.5 py-2 text-center">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {action_chains.map((act, idx) => (
                      <tr key={idx} className="hover:bg-slate-50">
                        <td className="px-3.5 py-2 font-bold text-slate-800 font-sans">{act.trigger_hook}</td>
                        <td className="px-3.5 py-2 text-slate-600 font-sans">{act.scope}</td>
                        <td className="px-3.5 py-2 font-semibold text-rose-700 font-sans">{act.action_type}</td>
                        <td className="px-3.5 py-2 text-slate-500 truncate max-w-xs" title={act.raw_snippet}>
                          {act.raw_snippet || '-'}
                        </td>
                        <td className="px-3.5 py-2 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            act.severity === 'critical'
                              ? 'bg-rose-600 text-white animate-pulse'
                              : act.severity === 'high'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-slate-100 text-slate-700'
                          }`}>
                            {act.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              ✓ No automatic execution hooks, event lifecycle triggers, or /Next action chains discovered.
            </div>
          )}
        </div>
      )}

      {/* Tab: Concealed & Phishing Inspection */}
      {activeSubTab === 'concealed' && (
        <div className="space-y-4 text-xs">
          {/* Summary Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">White-on-White</span>
              <strong className={concealed_content?.white_text_count ? 'text-rose-600 text-base' : 'text-slate-800 text-base'}>
                {concealed_content?.white_text_count || 0}
              </strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">Sub-Pixel (&lt;1pt)</span>
              <strong className={concealed_content?.tiny_font_count ? 'text-rose-600 text-base' : 'text-slate-800 text-base'}>
                {concealed_content?.tiny_font_count || 0}
              </strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">Off-Page</span>
              <strong className={concealed_content?.off_page_count ? 'text-amber-600 text-base' : 'text-slate-800 text-base'}>
                {concealed_content?.off_page_count || 0}
              </strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">Invisible (3 Tr)</span>
              <strong className={concealed_content?.has_invisible_render_mode ? 'text-rose-600 text-base' : 'text-emerald-600 text-base'}>
                {concealed_content?.has_invisible_render_mode ? 'Detected' : 'None'}
              </strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">Phish Mismatches</span>
              <strong className={concealed_content?.deceptive_link_count ? 'text-rose-600 text-base' : 'text-slate-800 text-base'}>
                {concealed_content?.deceptive_link_count || 0}
              </strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans font-bold">OCG Layers</span>
              <strong className="text-slate-800 text-base">
                {concealed_content?.has_ocg ? (concealed_content?.ocg_layers?.length || 'Yes') : 'None'}
              </strong>
            </div>
          </div>

          {/* Deceptive Phishing Hyperlink Mismatch Table */}
          {concealed_content?.deceptive_links && concealed_content.deceptive_links.length > 0 && (
            <div className="border border-rose-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-rose-50 px-4 py-2.5 border-b border-rose-200 font-bold text-rose-950 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-rose-600" />
                  <span>Deceptive Phishing Hyperlink Mismatches ({concealed_content.deceptive_links.length})</span>
                </div>
                <span className="text-[10px] uppercase font-bold text-rose-700 bg-rose-100 px-2 py-0.5 rounded-full">
                  Phishing / Brand Spoofing
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200">
                    <tr>
                      <th className="px-3.5 py-2">Page</th>
                      <th className="px-3.5 py-2">Visible Label Domain</th>
                      <th className="px-3.5 py-2">Actual Destination Domain</th>
                      <th className="px-3.5 py-2">Full Target URI</th>
                      <th className="px-3.5 py-2 text-center">Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {concealed_content.deceptive_links.map((dl, idx) => (
                      <tr key={idx} className="hover:bg-rose-50/30">
                        <td className="px-3.5 py-2 font-bold text-slate-700">p.{dl.page}</td>
                        <td className="px-3.5 py-2 font-semibold text-blue-700 font-sans">{dl.display_domain}</td>
                        <td className="px-3.5 py-2 font-semibold text-rose-700 font-sans">{dl.target_domain}</td>
                        <td className="px-3.5 py-2 text-slate-600 truncate max-w-xs" title={dl.destination_uri}>
                          {dl.destination_uri}
                        </td>
                        <td className="px-3.5 py-2 text-center">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white">
                            Spoofed Link
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Concealed & Invisible Text Spans Table */}
          {((concealed_content?.white_text_spans?.length || 0) + (concealed_content?.tiny_font_spans?.length || 0) + (concealed_content?.off_page_spans?.length || 0) > 0) ? (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <EyeOff className="w-4 h-4 text-indigo-600" />
                  <span>Concealed &amp; Evasion Text Spans Discovered</span>
                </div>
                <span className="text-[11px] text-slate-500 font-mono">Hidden Prompt Injection / Scraping Evasion</span>
              </div>
              <div className="overflow-x-auto max-h-80">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200 sticky top-0">
                    <tr>
                      <th className="px-3.5 py-2">Page</th>
                      <th className="px-3.5 py-2">Technique</th>
                      <th className="px-3.5 py-2">Extracted Hidden Text</th>
                      <th className="px-3.5 py-2">Font &amp; Size</th>
                      <th className="px-3.5 py-2">Coordinates / Color</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(concealed_content?.white_text_spans || []).map((s, idx) => (
                      <tr key={`white-${idx}`} className="hover:bg-indigo-50/30">
                        <td className="px-3.5 py-2 font-bold text-slate-700">p.{s.page}</td>
                        <td className="px-3.5 py-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200">
                            White-on-White
                          </span>
                        </td>
                        <td className="px-3.5 py-2 text-slate-800 font-sans font-medium">{s.text}</td>
                        <td className="px-3.5 py-2 text-slate-500">{s.font} ({s.size}pt)</td>
                        <td className="px-3.5 py-2 text-slate-500 font-mono">{s.color_hex || '#FFFFFF'}</td>
                      </tr>
                    ))}
                    {(concealed_content?.tiny_font_spans || []).map((s, idx) => (
                      <tr key={`tiny-${idx}`} className="hover:bg-indigo-50/30">
                        <td className="px-3.5 py-2 font-bold text-slate-700">p.{s.page}</td>
                        <td className="px-3.5 py-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
                            Sub-Pixel Font
                          </span>
                        </td>
                        <td className="px-3.5 py-2 text-slate-800 font-sans font-medium">{s.text}</td>
                        <td className="px-3.5 py-2 text-rose-600 font-bold">{s.size} pt</td>
                        <td className="px-3.5 py-2 text-slate-500 font-mono">[{s.bbox.join(', ')}]</td>
                      </tr>
                    ))}
                    {(concealed_content?.off_page_spans || []).map((s, idx) => (
                      <tr key={`off-${idx}`} className="hover:bg-indigo-50/30">
                        <td className="px-3.5 py-2 font-bold text-slate-700">p.{s.page}</td>
                        <td className="px-3.5 py-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200">
                            Off-Page Bounds
                          </span>
                        </td>
                        <td className="px-3.5 py-2 text-slate-800 font-sans font-medium">{s.text}</td>
                        <td className="px-3.5 py-2 text-slate-500">{s.size} pt</td>
                        <td className="px-3.5 py-2 text-slate-500 font-mono">[{s.bbox.join(', ')}]</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-6 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              ✓ No concealed white-on-white text, sub-pixel fonts, or off-page rendering detected.
            </div>
          )}
        </div>
      )}

      {/* Tab: Structure Forensics & Signatures */}
      {activeSubTab === 'forensics' && (
        <div className="space-y-4 text-xs">
          {/* Dual Format Polyglot Card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className={`p-4 rounded-2xl border ${
              structure_forensics?.is_polyglot
                ? 'bg-rose-50 border-rose-300'
                : 'bg-emerald-50/60 border-emerald-200'
            }`}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold flex items-center gap-1.5 text-slate-900">
                  <Layers className="w-4 h-4 text-blue-600" />
                  <span>Polyglot Dual-Format Inspection</span>
                </span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                  structure_forensics?.is_polyglot ? 'bg-rose-600 text-white animate-pulse' : 'bg-emerald-600 text-white'
                }`}>
                  {structure_forensics?.is_polyglot ? 'Polyglot Detected' : 'Valid PDF Container'}
                </span>
              </div>
              <p className="text-slate-600 text-[11px] leading-relaxed">
                {structure_forensics?.is_polyglot
                  ? `File contains prepended foreign binary wrapper (${structure_forensics.polyglot_type}) before %PDF- header (offset ${structure_forensics.header_offset}). Evades binary format filters.`
                  : 'File begins directly with standard %PDF- header at offset 0 without prepended binary wrappers or dual-execution containers.'}
              </p>
            </div>

            {/* Incremental Updates & Revisions */}
            <div className="p-4 rounded-2xl border border-slate-200 bg-white">
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold flex items-center gap-1.5 text-slate-900">
                  <RefreshCw className="w-4 h-4 text-purple-600" />
                  <span>Incremental Revisions (%%EOF)</span>
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-700">
                  {structure_forensics?.eof_count || eof_count} Revisions
                </span>
              </div>
              <p className="text-slate-600 text-[11px] leading-relaxed">
                {(structure_forensics?.eof_count || eof_count) > 1
                  ? 'Multiple incremental updates discovered. Attackers append updates to overwrite existing catalog references or execute Shadow Attacks.'
                  : 'Single revision document without incremental updates or appended object modifications.'}
              </p>
            </div>
          </div>

          {/* Trailing Overlay Card */}
          {structure_forensics?.has_overlay ? (
            <div className="p-4 bg-rose-50/70 border border-rose-300 rounded-2xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-rose-950">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <span>Trailing Overlay Data Past Final %%EOF Marker</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white uppercase">
                    {structure_forensics.overlay_threat} Threat
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-white">
                    Entropy: {structure_forensics.overlay_entropy?.toFixed(2)} / 8.0
                  </span>
                </div>
              </div>
              <p className="text-rose-900 leading-relaxed font-sans text-xs">
                {structure_forensics.overlay_desc} ({structure_forensics.overlay_size} bytes appended after end of document).
              </p>
              {structure_forensics.overlay_hex && (
                <div className="border border-slate-300 rounded-xl overflow-hidden bg-slate-950 p-3 font-mono text-[11px] text-emerald-400 max-h-48 overflow-y-auto">
                  <pre>{structure_forensics.overlay_hex}</pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-4 bg-emerald-50/60 border border-emerald-200 rounded-2xl text-xs text-emerald-800 flex items-center justify-between">
              <span>✓ No extraneous binary data or hidden overlays detected past the final %%EOF token.</span>
              <span className="text-[11px] font-mono text-emerald-700">Clean Trailer</span>
            </div>
          )}

          {/* Digital Signatures & Shadow Attack Analysis */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
            <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-blue-600" />
                <span>Cryptographic Digital Signatures &amp; Shadow Attacks ({digital_signatures.length})</span>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">/Type /Sig &amp; /ByteRange Forensics</span>
            </div>
            {digital_signatures.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs font-sans">
                No cryptographic digital signature (/Sig) dictionaries found in document.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200">
                    <tr>
                      <th className="px-3.5 py-2">XRef</th>
                      <th className="px-3.5 py-2">Signer Identity</th>
                      <th className="px-3.5 py-2">Filter</th>
                      <th className="px-3.5 py-2">ByteRange</th>
                      <th className="px-3.5 py-2 text-center">Shadow Attack Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {digital_signatures.map((sig, sIdx) => (
                      <tr key={sIdx} className={sig.has_shadow_attack ? 'bg-rose-50/50' : 'hover:bg-slate-50'}>
                        <td className="px-3.5 py-2 font-bold text-slate-600">#{sig.xref}</td>
                        <td className="px-3.5 py-2 font-semibold text-slate-800 font-sans">{sig.signer}</td>
                        <td className="px-3.5 py-2 text-slate-600">{sig.subfilter}</td>
                        <td className="px-3.5 py-2 text-slate-500">[{sig.byte_range.join(', ')}]</td>
                        <td className="px-3.5 py-2 text-center">
                          {sig.has_shadow_attack ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white animate-pulse">
                              ⚠️ Shadow Attack ({sig.shadow_bytes_count} modified bytes)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800">
                              ✓ Range Valid
                            </span>
                          )}
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

      {/* Tab 4: Embedded Files */}
      {activeSubTab === 'embedded' && (
        <div className="space-y-4">
          {/* Header Banner */}
          <div className="p-5 bg-white border border-slate-200 rounded-3xl shadow-sm">
            <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-emerald-50 text-emerald-600 rounded-2xl border border-emerald-100 text-lg">
                  <Layers className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    PDF Embedded Files &amp; Payload Attachments ({effectiveEmbeddedFiles.length})
                  </h3>
                  <p className="text-xs text-slate-500">
                    Extracted from PDF catalog <code className="bg-slate-100 px-1 py-0.5 rounded font-mono text-slate-700">/EmbeddedFiles</code>, <code className="bg-slate-100 px-1 py-0.5 rounded font-mono text-slate-700">/Names</code> tree, and annotation streams.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {dangerousEmbeddedCount > 0 ? (
                  <span className="px-3 py-1 bg-rose-50 text-rose-800 border border-rose-200 rounded-full text-xs font-bold flex items-center gap-1.5 animate-pulse">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                    {dangerousEmbeddedCount} Dangerous Payload{dangerousEmbeddedCount > 1 ? 's' : ''}
                  </span>
                ) : (
                  <span className="px-3 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    All Attachments Benign
                  </span>
                )}
                <button
                  onClick={handleRefreshEmbedded}
                  disabled={loadingEmbedded}
                  className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl transition-colors cursor-pointer"
                  title="Refresh embedded files"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingEmbedded ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            {/* Error Banner */}
            {embeddedError && (
              <div className="mt-4 p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 flex items-center justify-between">
                <span className="font-semibold">⚠️ {embeddedError}</span>
                <button
                  onClick={() => setEmbeddedError(null)}
                  className="text-slate-400 hover:text-slate-600 font-bold ml-2 cursor-pointer"
                >
                  ×
                </button>
              </div>
            )}

            {/* Filter and Search Bar */}
            {effectiveEmbeddedFiles.length > 0 && (
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <div className="relative flex-1 min-w-[240px]">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-2.5" />
                  <input
                    type="text"
                    value={embeddedSearch}
                    onChange={(e) => setEmbeddedSearch(e.target.value)}
                    placeholder="Search embedded files by filename, hash, or stream..."
                    className="w-full pl-9 pr-4 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 font-mono"
                  />
                  {embeddedSearch && (
                    <button
                      onClick={() => setEmbeddedSearch('')}
                      className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-600"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
                  <button
                    onClick={() => setEmbeddedFilter('all')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      embeddedFilter === 'all'
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    All ({effectiveEmbeddedFiles.length})
                  </button>
                  <button
                    onClick={() => setEmbeddedFilter('dangerous')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      embeddedFilter === 'dangerous'
                        ? 'bg-white text-rose-700 shadow-sm font-bold'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Dangerous ({dangerousEmbeddedCount})
                  </button>
                  <button
                    onClick={() => setEmbeddedFilter('safe')}
                    className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                      embeddedFilter === 'safe'
                        ? 'bg-white text-emerald-700 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    Benign ({safeEmbeddedCount})
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Empty State */}
          {effectiveEmbeddedFiles.length === 0 ? (
            <div className="p-10 bg-white border border-slate-200 rounded-3xl text-center shadow-xs">
              <Layers className="w-10 h-10 text-slate-300 mx-auto mb-3" />
              <h4 className="text-sm font-bold text-slate-800">No Embedded Files Discovered</h4>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                No nested file attachments, droppers, or stream payloads were detected in the PDF catalog or annotations.
              </p>
            </div>
          ) : filteredEmbeddedFiles.length === 0 ? (
            <div className="p-8 bg-white border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No embedded files match your search criteria.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredEmbeddedFiles.map((file) => {
                const isAnalyzing = analyzingIds[file.id];
                const matchedJob = workspaceJobs && workspaceJobs.length > 0
                  ? (findReferencedJob(file.name, workspaceJobs, jobId) || (file.sha256 ? findReferencedJob(file.sha256, workspaceJobs, jobId) : null))
                  : null;
                const analyzedInfo = analyzedSuccess[file.id];
                const targetJobId = analyzedInfo?.jobId || matchedJob?.jobId;
                const targetJobName = analyzedInfo?.filename || matchedJob?.filename || file.name;
                const downloadUrl = jobId ? apiClient.getEmbeddedFileDownloadUrl(jobId, file.id) : null;

                return (
                  <div
                    key={file.id}
                    className={`bg-white rounded-2xl border p-4.5 transition-all shadow-2xs hover:shadow-sm ${
                      file.is_dangerous
                        ? 'border-rose-200 hover:border-rose-300'
                        : 'border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      {/* Left: Icon and Basic Info */}
                      <div className="flex items-start gap-3.5 min-w-0 flex-1">
                        <div
                          className={`p-3 rounded-2xl shrink-0 ${
                            file.is_dangerous
                              ? 'bg-rose-50 text-rose-600 border border-rose-100'
                              : 'bg-slate-100 text-slate-600 border border-slate-200'
                          }`}
                        >
                          {getFormatIcon(file.parent_format, file.name)}
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <span className="font-mono text-sm font-bold text-slate-900 break-all">
                              {file.name}
                            </span>

                            {file.is_dangerous ? (
                              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3 text-rose-600" />
                                Dangerous Payload
                              </span>
                            ) : (
                              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                                <ShieldCheck className="w-3 h-3 text-emerald-600" />
                                Benign Attachment
                              </span>
                            )}

                            {targetJobId && (
                              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 flex items-center gap-1">
                                <ExternalLink className="w-3 h-3 text-indigo-600" />
                                Analyzed in Workspace
                              </span>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 font-mono mt-1">
                            {file.size_formatted && file.size_formatted !== 'Unknown' && (
                              <span>Size: {file.size_formatted}</span>
                            )}
                            {file.mime_type && <span>MIME: {file.mime_type}</span>}
                            {file.origin_stream && (
                              <span>Origin: {file.origin_stream}</span>
                            )}
                          </div>

                          {/* Threat Warning Banner */}
                          {file.threat_reason && (
                            <div className="mt-2.5 p-2 bg-rose-50/70 border border-rose-200/80 rounded-xl text-xs text-rose-800 flex items-start gap-1.5 font-sans">
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                              <span>{file.threat_reason}</span>
                            </div>
                          )}

                          {/* Hashes Row */}
                          {(file.sha256 || file.md5) && (
                            <div className="mt-2.5 flex flex-wrap items-center gap-2 text-[11px] font-mono">
                              {file.sha256 && (
                                <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded-lg px-2 py-0.5 text-slate-600">
                                  <span className="font-semibold text-slate-500">SHA256:</span>
                                  <span title={file.sha256}>{truncateHash(file.sha256, 10, 10)}</span>
                                  <button
                                    onClick={() => handleCopyHash(file.sha256)}
                                    className="text-slate-400 hover:text-slate-600 cursor-pointer ml-0.5"
                                    title="Copy SHA-256"
                                  >
                                    {copiedHash === file.sha256 ? (
                                      <Check className="w-3 h-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                  </button>
                                </div>
                              )}
                              {file.md5 && (
                                <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded-lg px-2 py-0.5 text-slate-600">
                                  <span className="font-semibold text-slate-500">MD5:</span>
                                  <span title={file.md5}>{truncateHash(file.md5, 6, 6)}</span>
                                  <button
                                    onClick={() => handleCopyHash(file.md5)}
                                    className="text-slate-400 hover:text-slate-600 cursor-pointer ml-0.5"
                                    title="Copy MD5"
                                  >
                                    {copiedHash === file.md5 ? (
                                      <Check className="w-3 h-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                  </button>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Right: Actions */}
                      <div className="flex items-center gap-2 self-start pt-1 shrink-0">
                        {/* Primary Analyze / View Action Button */}
                        {targetJobId ? (
                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() => onSelectJob && onSelectJob(targetJobId)}
                              className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-2xs hover:shadow-xs transition-all cursor-pointer"
                              title={`Go to already analysed file '${targetJobName}' in current workspace`}
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                              <span>Go to already analysed file</span>
                            </button>
                            <button
                              onClick={() => handleAnalyzeEmbedded(file)}
                              disabled={isAnalyzing}
                              className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl transition-colors cursor-pointer"
                              title="Re-analyze this embedded payload"
                            >
                              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => handleAnalyzeEmbedded(file)}
                            disabled={isAnalyzing}
                            className="px-3.5 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-2xs hover:shadow-xs transition-all cursor-pointer disabled:opacity-50"
                            title="Queue this embedded file for independent sandbox, static, and dynamic analysis"
                          >
                            {isAnalyzing ? (
                              <>
                                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                <span>Queueing Analysis...</span>
                              </>
                            ) : (
                              <>
                                <PlayCircle className="w-3.5 h-3.5 text-indigo-200" />
                                <span>Send to Analysis</span>
                              </>
                            )}
                          </button>
                        )}

                        {/* Download button */}
                        {downloadUrl && (
                          <a
                            href={downloadUrl}
                            download={file.name}
                            className="px-3 py-2 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 hover:text-slate-900 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs"
                            title={`Download ${file.name}`}
                          >
                            <Download className="w-3.5 h-3.5 text-slate-500" />
                            <span>Download</span>
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Carved Attachments Table */}
          {carved_attachments && carved_attachments.length > 0 && (
            <div className="mt-4 border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Binary className="w-4 h-4 text-emerald-600" />
                  <span>Payload Stream Binary Carving &amp; Classification ({carved_attachments.length})</span>
                </div>
                <span className="text-[11px] text-slate-500 font-mono">PE Executables, Scripts, Macros &amp; Archives</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200">
                    <tr>
                      <th className="px-3.5 py-2">Filename</th>
                      <th className="px-3.5 py-2">Classification</th>
                      <th className="px-3.5 py-2">Size</th>
                      <th className="px-3.5 py-2">SHA-256 Hash</th>
                      <th className="px-3.5 py-2 text-center">Threat Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {carved_attachments.map((cat, cIdx) => (
                      <tr key={cIdx} className={cat.is_threat ? 'bg-rose-50/40 hover:bg-rose-50/70' : 'hover:bg-slate-50'}>
                        <td className="px-3.5 py-2 font-bold text-slate-800">{cat.filename}</td>
                        <td className="px-3.5 py-2 font-sans font-semibold text-slate-700">{cat.classification}</td>
                        <td className="px-3.5 py-2 font-sans text-slate-600">{cat.size_formatted}</td>
                        <td className="px-3.5 py-2 text-slate-500 text-[11px]">
                          <span title={cat.sha256}>{truncateHash(cat.sha256, 8, 8)}</span>
                        </td>
                        <td className="px-3.5 py-2 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            cat.threat_level === 'critical'
                              ? 'bg-rose-600 text-white animate-pulse'
                              : cat.threat_level === 'suspicious'
                              ? 'bg-amber-100 text-amber-800 border border-amber-300'
                              : 'bg-slate-100 text-slate-700'
                          }`}>
                            {cat.threat_level}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 6: Anti-Analysis & PDF Evasion */}
      {activeSubTab === 'anti_analysis' && (
        <div className="pt-2">
          <AntiAnalysisInspectorCard antiAnalysis={antiAnalysis} filename={filename} category="pdf" />
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 1: Didier Stevens PDFiD Token Artifact Inspector Modal */}
      {/* ========================================================================= */}
      {selectedToken && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-4xl w-full max-h-[88vh] flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/90">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-amber-100 text-amber-800 rounded-xl">
                  <Zap className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-mono">
                      PDFiD Token Artifact Inspector: {selectedToken.token}
                    </h3>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
                      {selectedToken.count} total
                    </span>
                    {selectedToken.obfuscated_count > 0 && (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-purple-100 text-purple-800 border border-purple-200">
                        ⚠️ {selectedToken.obfuscated_count} obfuscated (#xx)
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Surrounding dictionary context, extracted payloads, and object cross-references for token {selectedToken.token}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const fullData = JSON.stringify(selectedToken, null, 2);
                    navigator.clipboard.writeText(fullData);
                    setCopiedTokenFull(true);
                    setTimeout(() => setCopiedTokenFull(false), 2000);
                  }}
                  className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-xl text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copiedTokenFull ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedTokenFull ? 'Copied JSON' : 'Export JSON'}</span>
                </button>

                <button
                  onClick={() => setSelectedToken(null)}
                  className="p-2 hover:bg-slate-200/60 rounded-xl text-slate-400 hover:text-slate-600 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              {/* Threat Description Banner */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex items-start gap-3">
                <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-slate-900 mb-0.5">Token Threat Assessment</h4>
                  <p className="text-slate-700 leading-relaxed">
                    {selectedToken.threat_summary || getTagDescription(selectedToken.token)}
                  </p>
                </div>
              </div>

              {/* Special Call-to-Action for /EmbeddedFiles token */}
              {selectedToken.token === '/EmbeddedFiles' && (
                <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-2xl flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 bg-emerald-100 text-emerald-800 rounded-xl shrink-0">
                      <Layers className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-bold text-emerald-950 text-xs">
                        {effectiveEmbeddedFiles.length} Embedded File Attachment{effectiveEmbeddedFiles.length !== 1 ? 's' : ''} Available for Analysis
                      </h4>
                      <p className="text-emerald-800 text-[11px] mt-0.5">
                        These payload files can be safely extracted and sent directly to the independent malware analysis engine.
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedToken(null);
                      setActiveSubTab('embedded');
                    }}
                    className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
                  >
                    <span>View &amp; Analyze Embedded Files ({effectiveEmbeddedFiles.length})</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {/* Obfuscated Hex Samples Alert if any */}
              {selectedToken.obfuscated_samples && selectedToken.obfuscated_samples.length > 0 && (
                <div className="p-4 bg-purple-50 border border-purple-200 rounded-2xl space-y-2">
                  <div className="flex items-center gap-2 font-bold text-purple-900">
                    <AlertTriangle className="w-4 h-4 text-purple-700" />
                    <span>Hex-Encoded Token Evasion Detected ({selectedToken.obfuscated_samples.length} patterns)</span>
                  </div>
                  <p className="text-purple-800 leading-relaxed">
                    Attackers insert hex escape sequences (e.g. <code className="bg-purple-100 px-1 py-0.5 rounded text-purple-950 font-mono">#4a</code> for 'J') to evade basic string and AV scanners while maintaining full PDF syntax validity:
                  </p>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {selectedToken.obfuscated_samples.map((s, i) => (
                      <span key={i} className="px-2.5 py-1 bg-white border border-purple-200 rounded-xl font-mono text-purple-900 font-semibold shadow-2xs">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Search Occurrences */}
              <div className="flex items-center justify-between gap-3 pt-1">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-800 text-sm">
                    Token Occurrences ({filteredTokenOccurrences.length} of {selectedToken.occurrences?.length || 0})
                  </span>
                </div>
                <div className="relative w-72">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    value={tokenSearchQuery}
                    onChange={e => setTokenSearchQuery(e.target.value)}
                    placeholder="Search occurrence snippet, xref, value..."
                    className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                  {tokenSearchQuery && (
                    <button
                      onClick={() => setTokenSearchQuery('')}
                      className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Occurrences List */}
              <div className="space-y-4">
                {filteredTokenOccurrences.map((occ, idx) => (
                  <div
                    key={idx}
                    className="p-4 bg-slate-50/60 border border-slate-200 rounded-2xl space-y-3 hover:border-slate-300 transition-colors"
                  >
                    {/* Occurrence Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded font-mono font-bold bg-slate-200 text-slate-800 text-[11px]">
                          Item #{idx + 1}
                        </span>
                        {occ.xref !== undefined && occ.xref !== null && (
                          <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-100 text-blue-800 text-[11px] border border-blue-200">
                            XRef #{occ.xref}
                          </span>
                        )}
                        <span className="font-mono text-slate-700 font-semibold">
                          Raw: <code className="text-slate-900 bg-white px-1.5 py-0.5 rounded border border-slate-200">{occ.raw_token || occ.token}</code>
                        </span>
                        {occ.is_obfuscated && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200">
                            Hex Obfuscated
                          </span>
                        )}
                      </div>

                      {occ.xref !== undefined && occ.xref !== null && (
                        <button
                          onClick={() => {
                            const targetObj = pdfObjects.find(o => o.xref === occ.xref);
                            if (targetObj) {
                              setSelectedToken(null);
                              handleInspectObject(targetObj);
                            }
                          }}
                          className="px-2.5 py-1 bg-white hover:bg-blue-50 text-blue-700 border border-blue-200 rounded-lg text-[11px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect Object #{occ.xref} Stream</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>

                    {/* Threat indicator if present */}
                    {occ.threat_summary && (
                      <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-900 font-medium flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                        <span>{occ.threat_summary}</span>
                      </div>
                    )}

                    {/* Extracted Payload / Action / URL */}
                    {occ.extracted_value && (
                      <div>
                        <div className="flex items-center justify-between text-[11px] font-semibold text-slate-700 mb-1">
                          <div className="flex items-center gap-2">
                            <span>Extracted Parameter / Action Value:</span>
                            {Boolean(occ.extracted_value?.match(/^(https?:\/\/|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})/i)) && (
                              <InvestigateAssetButton
                                ioc={occ.extracted_value}
                                onNavigateToJob={onSelectJob}
                                compact
                              />
                            )}
                          </div>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(occ.extracted_value || '');
                              setCopiedSnippetIdx(idx);
                              setTimeout(() => setCopiedSnippetIdx(null), 2000);
                            }}
                            className="text-blue-600 hover:text-blue-800 flex items-center gap-1 font-normal cursor-pointer"
                          >
                            {copiedSnippetIdx === idx ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedSnippetIdx === idx ? 'Copied' : 'Copy Value'}</span>
                          </button>
                        </div>
                        <div className="p-3 bg-white border border-slate-200 rounded-xl font-mono text-xs text-rose-700 break-all select-all shadow-2xs">
                          {occ.extracted_value}
                        </div>
                      </div>
                    )}

                    {/* Surrounding Context Snippet */}
                    {occ.snippet && (
                      <div>
                        <div className="flex items-center justify-between text-[11px] font-semibold text-slate-600 mb-1">
                          <span>Surrounding PDF Structure / Dictionary:</span>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(occ.snippet || '');
                              setCopiedSnippetIdx(idx + 1000);
                              setTimeout(() => setCopiedSnippetIdx(null), 2000);
                            }}
                            className="text-slate-500 hover:text-slate-700 flex items-center gap-1 font-normal cursor-pointer"
                          >
                            {copiedSnippetIdx === idx + 1000 ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedSnippetIdx === idx + 1000 ? 'Copied' : 'Copy Snippet'}</span>
                          </button>
                        </div>
                        <pre className="p-3 bg-slate-900 text-slate-100 rounded-xl font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-48">
                          {occ.snippet}
                        </pre>
                      </div>
                    )}
                  </div>
                ))}

                {filteredTokenOccurrences.length === 0 && (
                  <div className="p-8 text-center text-slate-400 bg-slate-50 rounded-2xl border border-slate-200">
                    No token occurrences matched your search query.
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
              <span>Token: <strong className="text-slate-800 font-mono">{selectedToken.token}</strong></span>
              <button
                onClick={() => setSelectedToken(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl font-medium transition-colors cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: PDF Stream & Object Inspector Modal */}
      {/* ========================================================================= */}
      {inspectedObject && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-5xl w-full max-h-[90vh] flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/90">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-blue-100 text-blue-800 rounded-xl">
                  {inspectedObject.is_stream ? <Binary className="w-5 h-5" /> : <Layers className="w-5 h-5" />}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-mono">
                      PDF Object Inspector: XRef #{inspectedObject.xref}
                    </h3>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-blue-100 text-blue-800 border border-blue-200">
                      {inspectedObject.type || 'Object'}
                    </span>
                    {inspectedObject.is_stream ? (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                        Stream ({inspectedObject.size > 0 ? `${(inspectedObject.size / 1024).toFixed(1)} KB` : 'Data'})
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-600 border border-slate-200">
                        Dictionary
                      </span>
                    )}
                    {inspectedObject.is_suspicious && (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-600 text-white animate-pulse">
                        ⚠️ Exploit Indicator
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Filter: {inspectedObject.filter || 'None'} | Size: {inspectedObject.size} bytes | XRef: #{inspectedObject.xref}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setInspectedObject(null)}
                  className="p-2 hover:bg-slate-200/60 rounded-xl text-slate-400 hover:text-slate-600 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Suspicious rationale banner */}
            {inspectedObject.is_suspicious && (
              <div className="px-6 py-3 bg-rose-50 border-b border-rose-200 flex items-center gap-2 text-xs font-bold text-rose-800">
                <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                <span>Detection Rationale: {inspectedObject.suspicious_reason}</span>
              </div>
            )}

            {/* Navigation Tabs inside Stream Inspector */}
            <div className="flex items-center justify-between border-b border-slate-200 px-6 pt-3 bg-white text-xs font-semibold">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setStreamModalTab('text')}
                  className={`px-3.5 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                    streamModalTab === 'text'
                      ? 'border-blue-600 text-blue-700 font-bold'
                      : 'border-transparent text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Code className="w-4 h-4" />
                  <span>Decoded Text / Code</span>
                </button>

                <button
                  onClick={() => setStreamModalTab('hex')}
                  className={`px-3.5 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                    streamModalTab === 'hex'
                      ? 'border-blue-600 text-blue-700 font-bold'
                      : 'border-transparent text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Binary className="w-4 h-4" />
                  <span>Raw Hex Dump (16-Byte HxD)</span>
                </button>

                <button
                  onClick={() => setStreamModalTab('dict')}
                  className={`px-3.5 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                    streamModalTab === 'dict'
                      ? 'border-blue-600 text-blue-700 font-bold'
                      : 'border-transparent text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Layers className="w-4 h-4" />
                  <span>Object Dictionary Header</span>
                </button>

                {Boolean(inspectedObject.tokens && inspectedObject.tokens.length > 0) && (
                  <button
                    onClick={() => setStreamModalTab('tokens')}
                    className={`px-3.5 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                      streamModalTab === 'tokens'
                        ? 'border-blue-600 text-blue-700 font-bold'
                        : 'border-transparent text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Zap className="w-4 h-4 text-amber-500" />
                    <span>Object Tokens ({inspectedObject.tokens?.length})</span>
                  </button>
                )}
              </div>

              {/* Search in text/code if active */}
              {streamModalTab === 'text' && activeStreamText && (
                <div className="relative w-64 pb-2">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-2 text-slate-400" />
                  <input
                    type="text"
                    value={streamTextSearch}
                    onChange={e => setStreamTextSearch(e.target.value)}
                    placeholder="Search in stream text..."
                    className="w-full pl-8 pr-3 py-1 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                  {streamTextSearch && (
                    <button
                      onClick={() => setStreamTextSearch('')}
                      className="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs flex-1">
              {loadingRemoteStream && (
                <div className="p-12 text-center text-slate-500 space-y-2">
                  <div className="w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto" />
                  <p className="font-medium">Decompressing and formatting stream from PDF...</p>
                </div>
              )}

              {remoteStreamError && (
                <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl text-rose-900">
                  Failed to load stream: {remoteStreamError}
                </div>
              )}

              {/* Tab: Decoded Text / Code */}
              {!loadingRemoteStream && streamModalTab === 'text' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="font-semibold text-slate-700">
                      {inspectedObject.is_text ? 'Decompressed ASCII / UTF-8 Text Content' : 'Stream Content / String Extraction'}
                    </span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(activeStreamText);
                        setCopiedModalText(true);
                        setTimeout(() => setCopiedModalText(false), 2000);
                      }}
                      disabled={!activeStreamText}
                      className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {copiedModalText ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedModalText ? 'Copied' : 'Copy Text'}</span>
                    </button>
                  </div>

                  {activeStreamText ? (
                    <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-slate-100 font-mono text-xs">
                      <div className="p-4 max-h-[480px] overflow-y-auto space-y-0.5">
                        {activeStreamText
                          .split('\n')
                          .filter(line => !streamTextSearch || line.toLowerCase().includes(streamTextSearch.toLowerCase()))
                          .map((line, lIdx) => (
                            <div key={lIdx} className="flex hover:bg-slate-800 leading-5">
                              <span className="w-12 select-none text-slate-500 text-right pr-4 shrink-0 font-normal">
                                {lIdx + 1}
                              </span>
                              <span className="whitespace-pre text-slate-100 break-all">{line || ' '}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-slate-500 space-y-2">
                      <Binary className="w-8 h-8 text-slate-400 mx-auto" />
                      <p className="font-medium text-slate-700">This object contains binary / non-text stream data.</p>
                      <p className="text-[11px]">
                        Switch to the <strong className="text-blue-600 cursor-pointer" onClick={() => setStreamModalTab('hex')}>Raw Hex Dump tab</strong> to inspect raw byte structures, or check the dictionary header.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Raw Hex Dump */}
              {!loadingRemoteStream && streamModalTab === 'hex' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="font-semibold text-slate-700">
                      Standard 16-Byte Hex Representation (Offset | Hex Bytes | ASCII)
                    </span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(activeStreamHex);
                        setCopiedModalHex(true);
                        setTimeout(() => setCopiedModalHex(false), 2000);
                      }}
                      disabled={!activeStreamHex}
                      className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {copiedModalHex ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedModalHex ? 'Copied Hex' : 'Copy Hex Dump'}</span>
                    </button>
                  </div>

                  {activeStreamHex ? (
                    <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-emerald-400 font-mono text-xs">
                      <pre className="p-4 max-h-[480px] overflow-x-auto whitespace-pre leading-relaxed select-all">
                        {activeStreamHex}
                      </pre>
                    </div>
                  ) : (
                    <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-slate-400">
                      No hex dump available for this object.
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Object Dictionary Header */}
              {!loadingRemoteStream && streamModalTab === 'dict' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="font-semibold text-slate-700">
                      Raw PDF Object Dictionary Definition (&lt;&lt; ... &gt;&gt;)
                    </span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(activeRawDict);
                        setCopiedModalDict(true);
                        setTimeout(() => setCopiedModalDict(false), 2000);
                      }}
                      disabled={!activeRawDict}
                      className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {copiedModalDict ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedModalDict ? 'Copied' : 'Copy Dictionary'}</span>
                    </button>
                  </div>

                  {activeRawDict ? (
                    <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-amber-300 font-mono text-xs">
                      <pre className="p-4 max-h-[480px] overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                        {activeRawDict}
                      </pre>
                    </div>
                  ) : (
                    <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-slate-400">
                      No raw dictionary header recorded for this object.
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Object Tokens */}
              {!loadingRemoteStream && streamModalTab === 'tokens' && (
                <div className="space-y-3">
                  <span className="font-semibold text-slate-700 block">
                    Didier Stevens Tokens Detected Inside Object #{inspectedObject.xref}:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {(inspectedObject.tokens || []).map((tok, tIdx) => (
                      <button
                        key={tIdx}
                        onClick={() => {
                          setInspectedObject(null);
                          handleTokenClick(tok, 1);
                        }}
                        className="px-3 py-1.5 rounded-xl bg-slate-50 hover:bg-blue-50 border border-slate-200 hover:border-blue-300 font-mono text-xs font-bold text-slate-800 hover:text-blue-700 flex items-center gap-1.5 transition-all cursor-pointer shadow-2xs"
                      >
                        <Zap className="w-3 h-3 text-amber-500" />
                        <span>{tok}</span>
                        <ArrowRight className="w-3 h-3 text-slate-400" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
              <span className="font-mono">
                XRef: <strong>#{inspectedObject.xref}</strong> | Type: <strong>{inspectedObject.type || 'Object'}</strong> | Size: <strong>{inspectedObject.size}B</strong>
              </span>
              <button
                onClick={() => setInspectedObject(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl font-medium transition-colors cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
