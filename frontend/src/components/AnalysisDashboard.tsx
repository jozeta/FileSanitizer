import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Copy, Check, ArrowLeft, RefreshCw, FileText, Globe, Shield, Sparkles, AlertCircle, ZoomIn, X, Lock, Unlock, Mail, Download, ChevronDown, Cpu, Layers, Terminal, ShieldAlert, BarChart3, Clock, FileCode, FileSpreadsheet, Coffee, Image as ImageIcon, Network, Activity } from 'lucide-react';
import { JobDetail, SanitizationOptions } from '../types';
import { apiClient } from '../api/client';
import { formatBytes, truncateHash } from '../utils/formatters';
import { SecurityCard } from './SecurityCard';
import { MetadataViewer } from './MetadataViewer';
import { UrlExplorer } from './UrlExplorer';
import { SanitizationPanel } from './SanitizationPanel';
import { ValidationComparison } from './ValidationComparison';
import { MacroWarningBanner } from './MacroWarningBanner';
import { CodeViewerModal } from './CodeViewerModal';
import { AnalyzingSplashscreen } from './AnalyzingSplashscreen';
import { EmailTriageCard } from './EmailTriageCard';
import { BinaryTriageCard } from './BinaryTriageCard';
import { EmbeddedFilesCard } from './EmbeddedFilesCard';
import { ScriptTriageCard } from './ScriptTriageCard';
import { AttackNavigatorCard } from './AttackNavigatorCard';
import { EntropyProfileCard } from './EntropyProfileCard';
import { ForensicTimelineCard } from './ForensicTimelineCard';
import { DomainAnalyticsCard } from './DomainAnalyticsCard';
import { ExtensionTriageCard } from './ExtensionTriageCard';
import { AppleScriptTriageCard } from './AppleScriptTriageCard';
import { HexRawInspector } from './HexRawInspector';
import { OfficeTriageCard } from './OfficeTriageCard';
import { PdfTriageCard } from './PdfTriageCard';
import { JarTriageCard } from './JarTriageCard';
import { ImageTriageCard } from './ImageTriageCard';
import { EntityGraphCard } from './EntityGraphCard';
import { CdrDiffInspector } from './CdrDiffInspector';
import { SimilarityClusterCard } from './SimilarityClusterCard';
import { PcapTriageCard } from './PcapTriageCard';
import { EvtxTriageCard } from './EvtxTriageCard';
import { JobDiagnosticsCard } from './JobDiagnosticsCard';
import { LnkCard } from './LnkCard';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import { DetectionRulesModal } from './DetectionRulesModal';
import { ErrorBoundary } from './ErrorBoundary';
import { CrossArtifactNavigator } from './CrossArtifactNavigator';
import { detectCrossArtifactReferences } from '../utils/crossFileReferences';

type TabType =
  | 'security'
  | 'format_triage'
  | 'metadata'
  | 'urls'
  | 'timeline'
  | 'entropy'
  | 'graph'
  | 'cdr_diff'
  | 'sanitize'
  | 'result'
  | 'email'
  | 'binary'
  | 'script'
  | 'embedded'
  | 'mitre'
  | 'ai_image'
  | 'image'
  | 'domain'
  | 'extension'
  | 'applescript'
  | 'office'
  | 'pdf'
  | 'jar'
  | 'pcap'
  | 'evtx'
  | 'lnk'
  | 'diagnostics'
  | 'raw_inspector';

interface AnalysisDashboardProps {
  jobId: string;
  cachedJob?: JobDetail | null;
  onBack: () => void;
  onSelectJob?: (newJobId: string) => void;
  onJobUpdate?: (job: JobDetail) => void;
  workspaceJobs?: any[];
}

function getFormatSections(job: JobDetail | null) {
  if (!job) return [];
  const sections: { id: string; label: string; icon: any; count?: number }[] = [];
  const isDomain = job.category === 'domain' || Boolean(job.domain_info);
  const isAppleScript = job.category === 'applescript' || Boolean(job.applescript_info) || Boolean(job.filename?.match(/\.(applescript|applescrip|scpt|scptd)$/i));

  if (isDomain) {
    sections.push({ id: 'domain', label: 'Domain & IP Infrastructure', icon: Globe });
  }
  if (job.category === 'extension' || Boolean(job.extension_info)) {
    sections.push({ id: 'extension', label: 'Extension Manifest & Scripts', icon: Layers });
  }
  if (isAppleScript) {
    sections.push({ id: 'applescript', label: 'AppleScript Decompilation', icon: Terminal, count: job.applescript_info?.findings?.length });
  }
  if (job.category === 'email' || Boolean(job.email_info)) {
    sections.push({ id: 'email', label: 'Email Headers & Tracking', icon: Mail, count: job.email_info?.tracking_pixel_count });
  }
  if (job.category === 'office' || Boolean(job.office_info) || job.filename?.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|rtf)$/i)) {
    sections.push({ id: 'office', label: 'Office & Macro Triage', icon: FileSpreadsheet, count: job.office_info?.macro_modules?.length });
  }
  if (job.category === 'pdf' || Boolean(job.pdf_info) || job.filename?.toLowerCase().endsWith('.pdf')) {
    sections.push({ id: 'pdf', label: 'PDF Structure & JavaScript', icon: FileText, count: job.pdf_info?.javascript_streams?.length });
  }
  if (Boolean(job.jar_info) || job.filename?.toLowerCase().endsWith('.jar')) {
    sections.push({ id: 'jar', label: 'JAR Java Bytecode Triage', icon: Coffee, count: job.jar_info?.suspicious_apis?.length });
  }
  if (job.category === 'image' || Boolean(job.image_info) || Boolean(job.ai_image_provenance) || job.filename?.match(/\.(png|jpe?g|gif|webp|bmp|tiff?)$/i)) {
    sections.push({ id: 'image', label: 'Image Forensics & Provenance', icon: ImageIcon });
  }
  if (!isAppleScript && (job.category === 'executable' || job.category === 'binary' || Boolean(job.binary_info))) {
    sections.push({ id: 'binary', label: 'PE / ELF Binary Headers', icon: Cpu });
  }
  if (job.category === 'script' || Boolean(job.script_triage)) {
    sections.push({ id: 'script', label: 'Script Syntax & AST Triage', icon: Terminal, count: job.script_triage?.risk_score });
  }
  if (job.mitre_attack && job.mitre_attack.length > 0) {
    sections.push({ id: 'mitre', label: 'ATT&CK Navigator Matrix', icon: ShieldAlert, count: job.mitre_attack.length });
  }
  if (job.embedded_files && job.embedded_files.length > 0) {
    sections.push({ id: 'embedded', label: 'Embedded Artifacts', icon: Layers, count: job.embedded_files.length });
  }
  if (job.category === 'pcap' || Boolean(job.pcap_info) || job.filename?.match(/\.(pcap|pcapng|cap)$/i)) {
    sections.push({ id: 'pcap', label: 'PCAP Network Packet Forensics', icon: Activity, count: job.pcap_info?.summary?.packet_count });
  }
  if (job.category === 'evtx' || Boolean(job.evtx_info) || job.filename?.match(/\.(evtx)$/i)) {
    sections.push({ id: 'evtx', label: 'Windows Event Log Forensics', icon: Terminal, count: job.evtx_info?.total_records });
  }
  if (job.category === 'lnk' || Boolean(job.lnk_info) || job.filename?.toLowerCase().endsWith('.lnk')) {
    sections.push({ id: 'lnk', label: 'LNK Shortcut Dissection', icon: Terminal });
  }
  if (job.anti_analysis && (job.anti_analysis.evasion_detected || (job.anti_analysis.techniques && job.anti_analysis.techniques.length > 0))) {
    sections.push({
      id: 'anti_analysis',
      label: 'Anti-Analysis & Evasion',
      icon: ShieldAlert,
      count: job.anti_analysis.techniques_count || job.anti_analysis.techniques?.length
    });
  }
  // Universal Raw & Hex Inspector for all file-based inputs
  if (!isDomain) {
    sections.push({ id: 'raw_inspector', label: 'Raw & Hex Inspector', icon: FileCode });
  }
  return sections;
}

function getFormatTabConfig(sections: any[], job: JobDetail | null) {
  if (sections.length === 0 || !job) return null;
  const isAppleScript = job.category === 'applescript' || Boolean(job.applescript_info) || Boolean(job.filename?.match(/\.(applescript|applescrip|scpt|scptd)$/i));
  if (job.category === 'domain' || job.domain_info) {
    return { label: 'Domain / IP Intelligence', icon: Globe };
  }
  if (job.category === 'extension' || job.extension_info) {
    return { label: 'Browser Extension', icon: Layers };
  }
  if (isAppleScript) {
    return { label: 'AppleScript Triage', icon: Terminal };
  }
  if (job.category === 'email' || job.email_info) {
    return { label: 'Email Triage', icon: Mail };
  }
  if (job.category === 'office' || job.office_info || job.filename?.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|rtf)$/i)) {
    return { label: 'Office & Macro Triage', icon: FileSpreadsheet };
  }
  if (job.category === 'pdf' || job.pdf_info || job.filename?.toLowerCase().endsWith('.pdf')) {
    return { label: 'PDF Structure & Triage', icon: FileText };
  }
  if (job.jar_info || job.filename?.toLowerCase().endsWith('.jar')) {
    return { label: 'JAR Java Triage', icon: Coffee };
  }
  if (job.category === 'image' || job.image_info || job.ai_image_provenance || job.filename?.match(/\.(png|jpe?g|gif|webp|bmp|tiff?)$/i)) {
    return { label: 'Image Forensics & Provenance', icon: ImageIcon };
  }
  if (!isAppleScript && (job.category === 'executable' || job.category === 'binary' || job.binary_info)) {
    return { label: 'PE / Binary Analysis', icon: Cpu };
  }
  if (job.category === 'lnk' || job.lnk_info || job.filename?.toLowerCase().endsWith('.lnk')) {
    return { label: 'LNK Shortcut Dissection', icon: Terminal };
  }
  if (job.category === 'pcap' || job.pcap_info || job.filename?.match(/\.(pcap|pcapng|cap)$/i)) {
    return { label: 'PCAP Network Forensics', icon: Activity };
  }
  if (job.category === 'evtx' || job.evtx_info || job.filename?.match(/\.(evtx)$/i)) {
    return { label: 'Windows Event Log Forensics', icon: Terminal };
  }
  if (job.category === 'script' || job.script_triage) {
    return { label: 'Script Triage', icon: Terminal };
  }
  if (job.embedded_files && job.embedded_files.length > 0) {
    return { label: `Embedded Files (${job.embedded_files.length})`, icon: Layers };
  }
  return { label: 'Raw & Hex Inspector', icon: FileCode };
}

export const AnalysisDashboard: React.FC<AnalysisDashboardProps> = ({ jobId, cachedJob, onBack, onSelectJob, onJobUpdate, workspaceJobs }) => {
  const [job, setJob] = useState<JobDetail | null>(() => {
    if (cachedJob && cachedJob.job_id === jobId) return cachedJob;
    return null;
  });
  const [activeTab, setActiveTab] = useState<TabType>(() => {
    try {
      const t = new URLSearchParams(window.location.search).get('tab');
      if (t) return t as TabType;
    } catch {}
    return 'security';
  });
  const [formatSubTab, setFormatSubTab] = useState<string>(() => {
    try {
      return new URLSearchParams(window.location.search).get('subtab') || '';
    } catch {
      return '';
    }
  });
  const [cdrActiveSubTab, setCdrActiveSubTab] = useState<'sanitize' | 'diff' | 'validation'>('sanitize');
  const [customExt, setCustomExt] = useState('');
  const [isReanalyzing, setIsReanalyzing] = useState(false);
  const [reanalyzeError, setReanalyzeError] = useState('');
  const [copiedHash, setCopiedHash] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isCodeModalOpen, setIsCodeModalOpen] = useState(false);
  const [showThumbnailModal, setShowThumbnailModal] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState('');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState('');
  const [showReportMenu, setShowReportMenu] = useState(false);
  const [showDetectionRulesModal, setShowDetectionRulesModal] = useState<boolean>(() => {
    try {
      return new URLSearchParams(window.location.search).get('rules') === 'true';
    } catch {
      return false;
    }
  });
  const [copiedRichHash, setCopiedRichHash] = useState(false);
  const [cdrPolicies, setCdrPolicies] = useState<Record<string, any> | null>(null);
  const initialTabSelectedRef = useRef(false);
  const [splashFinished, setSplashFinished] = useState<boolean>(() => {
    try {
      if (new URLSearchParams(window.location.search).get('nosplash') === 'true') return true;
      if (cachedJob && cachedJob.job_id === jobId && (cachedJob.state === 'ANALYZED' || cachedJob.state === 'COMPLETED')) return true;
      return sessionStorage.getItem(`fs_analyzed_${jobId}`) === 'true';
    } catch {
      return false;
    }
  });

  const crossReferences = useMemo(() => {
    if (!job) return [];
    return detectCrossArtifactReferences(job, workspaceJobs || []);
  }, [job, workspaceJobs]);

  // Fetch CDR policies once on mount
  useEffect(() => {
    apiClient.getCdrPolicies().then(res => {
      if (res?.policies) setCdrPolicies(res.policies);
    }).catch(() => {});
  }, []);

  // Poll job status until done or during processing
  useEffect(() => {
    const isAlreadyFinished =
      (cachedJob && cachedJob.job_id === jobId && (cachedJob.state === 'ANALYZED' || cachedJob.state === 'COMPLETED')) ||
      sessionStorage.getItem(`fs_analyzed_${jobId}`) === 'true';

    if (cachedJob && cachedJob.job_id === jobId) {
      setJob(cachedJob);
    }

    try {
      const urlTab = new URLSearchParams(window.location.search).get('tab') as TabType;
      if (urlTab) setActiveTab(urlTab);
      else setActiveTab('security');
      const urlSubTab = new URLSearchParams(window.location.search).get('subtab');
      if (urlSubTab) setFormatSubTab(urlSubTab);
      if (new URLSearchParams(window.location.search).get('nosplash') === 'true' || isAlreadyFinished) {
        setSplashFinished(true);
      } else {
        setSplashFinished(false);
      }
    } catch {
      setActiveTab('security');
      setSplashFinished(isAlreadyFinished);
    }
    initialTabSelectedRef.current = false;
    let interval: any = null;

    const fetchDetails = async () => {
      try {
        const fullJob = await apiClient.getJobAnalysis(jobId);
        // Also fetch metadata & URLs if analyzed
        if (fullJob.state !== 'QUEUED' && fullJob.state !== 'ANALYZING') {
          const [meta, urlData] = await Promise.all([
            apiClient.getJobMetadata(jobId).catch(() => undefined),
            apiClient.getJobUrls(jobId).catch(() => ({ urls: [] })),
          ]);
          fullJob.metadata = meta;
          fullJob.urls = urlData.urls;

          if (fullJob.state === 'COMPLETED') {
            const res = await apiClient.getJobResult(jobId).catch(() => undefined);
            if (res && res.validation) {
              fullJob.validation = res.validation;
            }
          }
        }

        setJob(fullJob);
        if (fullJob.state === 'COMPLETED' || fullJob.state === 'ANALYZED') {
          try {
            sessionStorage.setItem(`fs_analyzed_${jobId}`, 'true');
          } catch {}
          setSplashFinished(true);
        }
        if (onJobUpdate) {
          onJobUpdate(fullJob);
        }

        // Pre-configure specialized format sub-tab ONCE on initial load (keeping Security Analysis in focus)
        if (!initialTabSelectedRef.current) {
          initialTabSelectedRef.current = true;
          const urlSubTab = new URLSearchParams(window.location.search).get('subtab');
          if (urlSubTab) {
            setFormatSubTab(urlSubTab);
          } else if (fullJob.category === 'domain' || Boolean(fullJob.domain_info)) {
            setFormatSubTab('domain');
          } else if (fullJob.category === 'extension' || Boolean(fullJob.extension_info)) {
            setFormatSubTab('extension');
          } else if (fullJob.category === 'applescript' || Boolean(fullJob.applescript_info) || Boolean(fullJob.filename?.match(/\.(applescript|applescrip|scpt|scptd)$/i))) {
            setFormatSubTab('applescript');
          } else if (fullJob.category === 'office' || Boolean(fullJob.office_info) || fullJob.filename?.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|rtf)$/i)) {
            setFormatSubTab('office');
          } else if (fullJob.category === 'pdf' || Boolean(fullJob.pdf_info) || fullJob.filename?.toLowerCase().endsWith('.pdf')) {
            setFormatSubTab('pdf');
          } else if (Boolean(fullJob.jar_info) || fullJob.filename?.toLowerCase().endsWith('.jar')) {
            setFormatSubTab('jar');
          } else if (fullJob.category === 'image' || Boolean(fullJob.image_info) || Boolean(fullJob.ai_image_provenance) || fullJob.filename?.match(/\.(png|jpe?g|gif|webp|bmp|tiff?)$/i)) {
            setFormatSubTab('image');
          } else if (fullJob.category === 'executable' || fullJob.category === 'binary' || Boolean(fullJob.binary_info)) {
            setFormatSubTab('binary');
          } else if (fullJob.category === 'script' || Boolean(fullJob.script_triage)) {
            setFormatSubTab('script');
          } else if (fullJob.category === 'email' || Boolean(fullJob.email_info)) {
            setFormatSubTab('email');
          } else if (fullJob.category === 'pcap' || Boolean(fullJob.pcap_info)) {
            setFormatSubTab('pcap');
          } else if (fullJob.category === 'evtx' || Boolean(fullJob.evtx_info)) {
            setFormatSubTab('evtx');
          } else if (fullJob.category === 'lnk' || Boolean(fullJob.lnk_info) || fullJob.filename?.toLowerCase().endsWith('.lnk')) {
            setFormatSubTab('lnk');
          }
        }

        if (fullJob.state === 'COMPLETED' || fullJob.state === 'FAILED' || fullJob.state === 'ANALYZED') {
          setIsProcessing(false);
          if (interval) {
            clearInterval(interval);
            interval = null;
          }
        }
      } catch (err) {
        console.error('Error fetching job details:', err);
      }
    };

    fetchDetails();

    interval = setInterval(() => {
      fetchDetails();
    }, 1000);

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [jobId]);

  const copySha256 = () => {
    if (job?.hashes?.sha256) {
      navigator.clipboard.writeText(job.hashes.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const copyRichHash = () => {
    const hash = job?.hashes?.rich_header_hash || job?.binary_info?.rich_header_hash;
    if (hash) {
      navigator.clipboard.writeText(hash);
      setCopiedRichHash(true);
      setTimeout(() => setCopiedRichHash(false), 2000);
    }
  };

  const handleSanitize = async (profile: string, customOptions?: SanitizationOptions) => {
    setIsProcessing(true);
    try {
      await apiClient.startSanitization(jobId, profile, customOptions);
      setActiveTab('sanitize');

      let attempts = 0;
      const pollSanitization = async () => {
        attempts++;
        try {
          const fullJob = await apiClient.getJobAnalysis(jobId);
          if (fullJob.state === 'COMPLETED') {
            const res = await apiClient.getJobResult(jobId).catch(() => undefined);
            if (res && res.validation) {
              fullJob.validation = res.validation;
            }
            setJob(fullJob);
            setIsProcessing(false);
            return;
          } else if (fullJob.state === 'FAILED') {
            setJob(fullJob);
            setIsProcessing(false);
            return;
          }
          setJob(fullJob);
          if (attempts < 75) {
            setTimeout(pollSanitization, 700);
          } else {
            setIsProcessing(false);
          }
        } catch {
          if (attempts < 75) {
            setTimeout(pollSanitization, 1000);
          } else {
            setIsProcessing(false);
          }
        }
      };
      setTimeout(pollSanitization, 500);
    } catch (err: any) {
      alert(err.message || 'Sanitization request failed');
      setIsProcessing(false);
    }
  };

  const handleDownload = () => {
    window.location.href = apiClient.getDownloadUrl(jobId);
  };

  const handleDownloadReport = () => {
    window.location.href = apiClient.getReportUrl(jobId, 'html');
  };

  const handleUnlockFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!unlockPassword.trim()) return;
    setIsUnlocking(true);
    setUnlockError('');
    try {
      const res = await apiClient.unlockJob(jobId, unlockPassword.trim());
      if (res.is_unlocked) {
        setUnlockPassword('');
        const fullJob = await apiClient.getJobAnalysis(jobId);
        setJob(fullJob);
      } else {
        setUnlockError('Incorrect password. Could not decrypt document.');
      }
    } catch (err: any) {
      setUnlockError(err.message || 'Failed to unlock document.');
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleDownloadForensicReport = (format: 'json' | 'html') => {
    setShowReportMenu(false);
    if (format === 'html') {
      window.open(apiClient.getForensicReportUrl(jobId, 'html'), '_blank');
    } else {
      window.location.href = apiClient.getForensicReportUrl(jobId, 'json');
    }
  };

  if (!job) {
    return (
      <div className="max-w-[96rem] mx-auto py-20 px-4 text-center">
        <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-4" />
        <p className="text-sm text-slate-600 font-mono">Loading job workspace...</p>
      </div>
    );
  }

  const isAnalyzing = job.state === 'QUEUED' || job.state === 'ANALYZING';
  const isSanitizing = job.state === 'SANITIZING' || job.state === 'VALIDATING';
  const isCompleted = job.state === 'COMPLETED';
  const isFailed = job.state === 'FAILED';
  const hasMacros = job.findings?.some(f => f.category === 'macro') || false;
  const isDomainOrIp = job.category === 'domain' || Boolean(job.domain_info);
  const isAppleScript = job.category === 'applescript' || Boolean(job.applescript_info) || Boolean(job.filename?.match(/\.(applescript|applescrip|scpt|scptd)$/i));
  const isCdrDisabledByAdmin = Boolean(cdrPolicies && job?.category && cdrPolicies[job.category]?.enabled === false);
  const isCdrSupported = !isDomainOrIp &&
    !isAppleScript &&
    job.category !== 'domain' &&
    job.category !== 'binary' &&
    job.category !== 'executable' &&
    job.category !== 'script' &&
    job.category !== 'applescript' &&
    job.category !== 'extension' &&
    job.category !== 'email' &&
    job.category !== 'pcap' &&
    job.category !== 'evtx' &&
    job.category !== 'hta' &&
    !Boolean(job.pcap_info) &&
    !Boolean(job.evtx_info) &&
    !Boolean(job.email_info) &&
    !job.filename?.match(/\.(eml|msg|mbox)$/i) &&
    !job.filename?.match(/\.(pcap|pcapng|cap)$/i) &&
    !job.filename?.match(/\.(evtx)$/i) &&
    !job.filename?.match(/\.hta$/i) &&
    !job.filename?.toLowerCase().endsWith('.crx') &&
    !isCdrDisabledByAdmin;

  const handleReanalyze = async (overrideExt: string) => {
    if (!job || !overrideExt) return;
    setIsReanalyzing(true);
    setReanalyzeError('');
    try {
      const res = await apiClient.reanalyzeJob(job.job_id, overrideExt);
      if (res?.job_id && onSelectJob) {
        onSelectJob(res.job_id);
      } else if (res?.job_id) {
        window.location.reload();
      }
    } catch (err: any) {
      setReanalyzeError(err.message || 'Failed to re-analyze file.');
    } finally {
      setIsReanalyzing(false);
    }
  };

  const mismatchFinding = job.findings?.find(
    (f) =>
      f.category === 'mime_confusion' ||
      f.title?.toLowerCase().includes('mime type confusion') ||
      f.title?.toLowerCase().includes('extension mismatch') ||
      f.title?.toLowerCase().includes('spoofing detected')
  );

  const formatSections = getFormatSections(job);
  const formatTabConfig = getFormatTabConfig(formatSections, job);

  return (
    <div className="max-w-[96rem] mx-auto py-8 px-4 sm:px-6">
      {/* Back Button */}
      <button
        onClick={() => {
          try {
            sessionStorage.removeItem(`fs_analyzed_${jobId}`);
          } catch {}
          onBack();
        }}
        className="inline-flex items-center gap-2 text-xs font-semibold text-slate-500 hover:text-slate-900 mb-6 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Upload another file</span>
      </button>

      {isAnalyzing || !splashFinished ? (
        <AnalyzingSplashscreen
          filename={job.filename}
          category={job.category}
          fileSize={job.file_size}
          progress={job.progress}
          currentStep={job.current_step}
          currentStepLabel={job.current_step_label}
          isBackendReady={!isAnalyzing}
          onFinish={() => {
            try {
              sessionStorage.setItem(`fs_analyzed_${jobId}`, 'true');
            } catch {}
            setSplashFinished(true);
          }}
        />
      ) : (
        <>
          {/* Top File Summary Header */}
          <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-7 shadow-sm mb-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-4 min-w-0">
                {job.thumbnail_available && job.thumbnail_url && (
                  <div
                    onClick={() => setShowThumbnailModal(true)}
                    className="w-16 h-16 sm:w-20 sm:h-20 rounded-2xl overflow-hidden border border-slate-200 hover:border-indigo-400 shadow-sm shrink-0 bg-slate-50 cursor-pointer group relative transition-all"
                    title="Click to enlarge preview"
                  >
                    <img
                      src={job.thumbnail_url}
                      alt="File preview thumbnail"
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
                    />
                    <div className="absolute inset-0 bg-slate-900/0 group-hover:bg-slate-900/30 transition-colors flex items-center justify-center">
                      <ZoomIn className="w-4 h-4 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </div>
                )}
                <div className="min-w-0">
                  <div className="flex items-center gap-2.5 mb-1.5 flex-wrap">
                    <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight truncate">
                      {job.filename}
                    </h2>
                    <span className="px-2.5 py-0.5 bg-slate-100 text-slate-700 text-xs font-mono font-medium rounded-full border border-slate-200 uppercase">
                      {job.category}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 font-mono">
                    <span>Size: {formatBytes(job.file_size)}</span>
                    <span>MIME: {job.mime_type}</span>
                    {job.signature_description && (
                      <span>Signature: {job.signature_description}</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
                {/* Automated Detection Rules (KQL & YARA) Button */}
                <button
                  onClick={() => setShowDetectionRulesModal(true)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-2xl text-xs font-semibold shadow-xs transition-all cursor-pointer"
                  title="Automated Detection Rule Generation (Sentinel KQL & YARA)"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Detection Rules</span>
                </button>

                {/* Forensic Dossier Export Button */}
                <div className="relative">
                  <button
                    onClick={() => setShowReportMenu(!showReportMenu)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2.5 bg-white border border-slate-200 hover:border-slate-300 rounded-2xl text-xs font-semibold text-slate-700 hover:text-slate-900 shadow-2xs hover:bg-slate-50 transition-all cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Forensic Report</span>
                    <ChevronDown className="w-3 h-3 text-slate-400" />
                  </button>

                  {showReportMenu && (
                    <div className="absolute right-0 mt-2 w-56 bg-white border border-slate-200 rounded-2xl shadow-xl p-1.5 z-30 animate-modal-fade font-sans">
                      <button
                        onClick={() => handleDownloadForensicReport('html')}
                        className="w-full text-left px-3 py-2 text-xs text-slate-700 hover:bg-indigo-50 hover:text-indigo-700 rounded-xl transition-colors flex items-center gap-2 cursor-pointer font-medium"
                      >
                        <span>📄</span>
                        <div>
                          <div className="font-semibold text-slate-900">HTML Dossier</div>
                          <div className="text-[10px] text-slate-400 font-normal">Printable & PDF-Ready</div>
                        </div>
                      </button>
                      <button
                        onClick={() => handleDownloadForensicReport('json')}
                        className="w-full text-left px-3 py-2 text-xs text-slate-700 hover:bg-indigo-50 hover:text-indigo-700 rounded-xl transition-colors flex items-center gap-2 cursor-pointer font-medium"
                      >
                        <span>📦</span>
                        <div>
                          <div className="font-semibold text-slate-900">JSON Incident Export</div>
                          <div className="text-[10px] text-slate-400 font-normal">SIEM / SOAR Structured</div>
                        </div>
                      </button>
                    </div>
                  )}
                </div>

                {/* Cryptographic SHA-256 with Copy Action */}
                {job.hashes?.sha256 && (
                  <div className="flex items-center gap-2 bg-slate-50 p-2.5 rounded-2xl border border-slate-200/80">
                    <div className="text-right">
                      <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block">
                        SHA-256 Hash
                      </span>
                      <span className="text-xs font-mono font-semibold text-slate-800">
                        {truncateHash(job.hashes.sha256, 10, 10)}
                      </span>
                    </div>
                    <button
                      onClick={copySha256}
                      className="p-1.5 rounded-xl text-slate-500 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                      title="Copy full SHA-256 hash"
                    >
                      {copiedHash ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                )}

                {/* Rich Header Hash (Cleartext MD5) with Copy Action */}
                {(job.hashes?.rich_header_hash || job.binary_info?.rich_header_hash) && (
                  <div className="flex items-center gap-2 bg-slate-50 p-2.5 rounded-2xl border border-slate-200/80">
                    <div className="text-right">
                      <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block">
                        Rich Header MD5
                      </span>
                      <span className="text-xs font-mono font-semibold text-indigo-700">
                        {truncateHash(job.hashes?.rich_header_hash || job.binary_info?.rich_header_hash || '', 8, 8)}
                      </span>
                    </div>
                    <button
                      onClick={copyRichHash}
                      className="p-1.5 rounded-xl text-slate-500 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                      title="Copy full Rich Header Cleartext MD5"
                    >
                      {copiedRichHash ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Processing Progress Bar */}
            {(isAnalyzing || isSanitizing) && (
              <div className="mt-5 pt-4 border-t border-slate-100">
                <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-2">
                  <span className="flex items-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" />
                    <span>
                      {isAnalyzing ? 'Conducting Deep Security Analysis & Scanner Inspection...' :
                       'Performing Content Disarm & Reconstruction (CDR)...'}
                    </span>
                  </span>
                  <span className="font-bold">{job.progress}%</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${job.progress}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Password-Protected File Locked Banner */}
          {job.is_password_protected && !job.is_unlocked && (
            <div className="mb-6 p-5 bg-amber-50/90 border border-amber-300 rounded-3xl shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="p-2.5 bg-amber-100 text-amber-800 rounded-2xl shrink-0 text-xl border border-amber-200">
                  <Lock className="w-5 h-5 text-amber-700" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="font-bold text-sm text-amber-950">
                      {job.category === 'archive' || job.filename?.match(/\.(zip|rar|7z)$/i)
                        ? 'Password-Protected Archive (Locked)'
                        : 'Password-Protected Document (Locked)'}
                    </h4>
                    <span className="px-2 py-0.5 bg-amber-200/70 text-amber-900 rounded-md text-[10px] font-bold uppercase tracking-wider">
                      Decryption Required
                    </span>
                  </div>
                  <p className="text-xs text-amber-800 mt-1 max-w-xl leading-relaxed">
                    {job.category === 'archive' || job.filename?.match(/\.(zip|rar|7z)$/i)
                      ? 'This archive is encrypted. Standard passwords were tested automatically but failed. Enter the archive password below to decrypt and extract member files for deep scanning.'
                      : 'This file is encrypted. Standard malware passwords were tested automatically but failed. Enter the password below to decrypt and unlock deep inspection (YARA signatures, ClamAV, URLs, and CDR sanitization).'}
                  </p>
                  {unlockError && (
                    <div className="mt-2 text-xs font-semibold text-rose-700 flex items-center gap-1.5">
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{unlockError}</span>
                    </div>
                  )}
                </div>
              </div>
              <form onSubmit={handleUnlockFile} className="flex items-center gap-2 shrink-0">
                <input
                  type="password"
                  placeholder="Enter archive / file password..."
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  className="bg-white border border-amber-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 font-mono shadow-inner"
                />
                <button
                  type="submit"
                  disabled={isUnlocking || !unlockPassword}
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white font-semibold text-xs rounded-xl shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  {isUnlocking ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Unlock className="w-3.5 h-3.5" />}
                  <span>{isUnlocking ? 'Decrypting...' : 'Unlock & Re-analyze'}</span>
                </button>
              </form>
            </div>
          )}

          {/* Password-Protected File Decrypted Success Banner */}
          {job.is_password_protected && job.is_unlocked && (
            <div className="mb-6 p-4 bg-emerald-50 border border-emerald-200 rounded-2xl flex items-center justify-between text-xs text-emerald-800">
              <div className="flex items-center gap-2">
                <span className="text-base">🔓</span>
                <span className="font-semibold">
                  {job.category === 'archive' || job.filename?.match(/\.(zip|rar|7z)$/i)
                    ? 'Archive Successfully Decrypted'
                    : 'Document Successfully Decrypted'}
                </span>
                {job.unlock_password && (
                  <span className="text-emerald-700 font-mono bg-emerald-100/70 px-2 py-0.5 rounded border border-emerald-200">
                    Password: {job.unlock_password}
                  </span>
                )}
              </div>
              <span className="text-[11px] text-emerald-600 font-medium">Unlocked for deep scanning & CDR</span>
            </div>
          )}

      {/* Extension Mismatch / Spoofing Re-analysis Banner */}
      {mismatchFinding && (
        <div className="mb-6 p-5 bg-gradient-to-r from-amber-50 via-orange-50 to-amber-50 border border-amber-300 rounded-3xl shadow-sm text-slate-900">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="p-2.5 bg-amber-500 text-white rounded-2xl shadow-xs shrink-0 font-bold text-lg">
                ⚠️
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="font-bold text-sm text-amber-950">
                    MIME Type Confusion / Extension Mismatch Detected
                  </h4>
                  <span className="px-2 py-0.5 bg-amber-200/80 text-amber-900 rounded-md text-[10px] font-bold uppercase tracking-wider">
                    Extension Spoofing
                  </span>
                </div>
                <p className="text-xs text-amber-900 mt-1 max-w-2xl leading-relaxed">
                  The file was uploaded as <strong>{job.filename}</strong>, but internal magic byte and container signatures reveal it is actually{' '}
                  <strong className="text-amber-950 font-mono">
                    {mismatchFinding.details?.detected_format || mismatchFinding.details?.detected_mime || job.mime_type}
                  </strong>.
                  Re-analyzing with the true extension unlocks format-specific decoders, AST parsers, and specialized triage.
                </p>
                {reanalyzeError && (
                  <p className="text-xs text-rose-700 font-semibold mt-1">
                    {reanalyzeError}
                  </p>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              {mismatchFinding.details?.suggested_extension && (
                <button
                  type="button"
                  disabled={isReanalyzing}
                  onClick={() => mismatchFinding.details?.suggested_extension && handleReanalyze(mismatchFinding.details.suggested_extension)}
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {isReanalyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                  <span>Re-analyze as {mismatchFinding.details?.suggested_extension}</span>
                </button>
              )}

              <div className="flex items-center gap-1.5">
                <input
                  type="text"
                  placeholder="e.g. .docx or .exe"
                  value={customExt}
                  onChange={(e) => setCustomExt(e.target.value)}
                  className="w-28 px-3 py-1.5 bg-white border border-amber-300 rounded-xl text-xs font-mono text-slate-800 focus:outline-hidden focus:ring-1 focus:ring-amber-500"
                />
                <button
                  type="button"
                  disabled={isReanalyzing || !customExt.trim()}
                  onClick={() => handleReanalyze(customExt.trim())}
                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-white rounded-xl text-xs font-semibold shadow-xs transition-colors cursor-pointer"
                >
                  Override Ext
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Prominent Macro Warning Banner */}
      {hasMacros && (
        <MacroWarningBanner
          macroDetails={job.findings?.find(f => f.category === 'macro')?.details?.findings}
          onViewCode={() => setIsCodeModalOpen(true)}
        />
      )}

      {/* Failure Banner */}
      {isFailed && (
        <div className="mb-6 p-5 bg-rose-50 border border-rose-200 rounded-2xl flex items-start gap-3 text-rose-900">
          <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-bold text-sm">Processing Encountered an Error</h4>
            <p className="text-xs mt-1 text-rose-800 leading-relaxed font-mono">
              {job.error_message || 'Operation failed during pipeline execution.'}
            </p>
          </div>
        </div>
      )}

      {/* Cross-Artifact Connected Incident Navigator */}
      {crossReferences.length > 0 && (
        <div className="mb-6">
          <CrossArtifactNavigator
            references={crossReferences}
            onSelectJob={onSelectJob}
          />
        </div>
      )}

      {/* Section Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-3 mb-6 overflow-x-auto">
        <button
          onClick={() => setActiveTab('security')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'security'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Security Analysis</span>
          {job.findings && job.findings.length > 0 && (
            <span className="px-1.5 py-0.2 bg-white/20 rounded-full text-[10px]">
              {job.findings.length}
            </span>
          )}
        </button>

        {!isDomainOrIp && (job.metadata?.total_fields || 0) > 0 && (
          <button
            onClick={() => setActiveTab('metadata')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'metadata'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Metadata ({job.metadata?.total_fields || 0})</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab('urls')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'urls'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Discovered URLs ({job.urls?.length || 0})</span>
        </button>

        {/* Grouped Format-Specific Deep Triage Tab */}
        {formatSections.length > 0 && formatTabConfig && (() => {
          const Icon = formatTabConfig.icon;
          const isFormatActive = activeTab === 'format_triage' || formatSections.some(s => s.id === activeTab);
          return (
            <button
              onClick={() => {
                setActiveTab('format_triage');
                if (!formatSections.some(s => s.id === formatSubTab)) {
                  setFormatSubTab(formatSections[0].id);
                }
              }}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                isFormatActive
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-indigo-700 bg-indigo-50 hover:bg-indigo-100'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{formatTabConfig.label}</span>
              {formatSections.length > 1 && (
                <span className="px-1.5 py-0.2 bg-white/20 text-white rounded-full text-[10px] font-bold">
                  {formatSections.length}
                </span>
              )}
            </button>
          );
        })()}

        {!isDomainOrIp && (
          <button
            onClick={() => setActiveTab('timeline')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'timeline'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-700 bg-slate-100 hover:bg-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Forensic Timeline</span>
          </button>
        )}

        {!isDomainOrIp && (
          <button
            onClick={() => setActiveTab('entropy')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'entropy'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-700 bg-slate-100 hover:bg-slate-200'
            }`}
          >
            <BarChart3 className="w-4 h-4" />
            <span>Entropy Profile</span>
            {job.entropy_profile?.verdict === 'SUSPICIOUS_HIGH_ENTROPY' && (
              <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold">
                Packed
              </span>
            )}
          </button>
        )}

        {!isDomainOrIp && (
          <button
            onClick={() => setActiveTab('graph')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'graph'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-700 bg-slate-100 hover:bg-slate-200'
            }`}
          >
            <Network className="w-4 h-4 text-indigo-500" />
            <span>Entity Graph</span>
            {Boolean(job.entity_graph?.nodes?.length) && (
              <span className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 rounded-full text-[10px] font-bold border border-indigo-200">
                {job.entity_graph!.nodes.length}
              </span>
            )}
          </button>
        )}

        {/* Telemetry & Pipeline Diagnostics Tab */}
        <button
          onClick={() => setActiveTab('diagnostics')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'diagnostics'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-700 bg-slate-100 hover:bg-slate-200'
          }`}
        >
          <Activity className="w-4 h-4 text-cyan-500" />
          <span>Telemetry &amp; Diagnostics</span>
          {job.telemetry?.total_duration_ms !== undefined && (
            <span className="px-1.5 py-0.2 bg-cyan-100 text-cyan-800 rounded-full text-[10px] font-mono font-bold">
              {job.telemetry.total_duration_ms > 1000
                ? `${(job.telemetry.total_duration_ms / 1000).toFixed(1)}s`
                : `${job.telemetry.total_duration_ms.toFixed(0)}ms`}
            </span>
          )}
        </button>

        {/* Consolidated Sanitization & CDR Tab (Hidden for PCAP, EVTX, Binaries, etc.) */}
        {isCdrSupported && (
          <button
            onClick={() => setActiveTab('sanitize')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'sanitize'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-blue-700 bg-blue-50 hover:bg-blue-100'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            <span>Sanitization &amp; CDR</span>
            {isCompleted && (
              <span className="px-1.5 py-0.2 bg-emerald-500 text-white rounded-full text-[10px] font-bold">
                Clean Ready
              </span>
            )}
          </button>
        )}
      </div>

      {/* Active Tab View */}
      <div>
        {activeTab === 'security' && (
          <div className="space-y-6">
            <SecurityCard
              risk={job.risk}
              clamav={job.clamav as any}
              findings={job.findings}
              jobHashes={job.hashes}
              virustotal={job.virustotal}
              hybrid_analysis={job.hybrid_analysis}
              threatfox={job.threatfox}
              malwarebazaar={job.malwarebazaar}
              circl={job.circl}
              alienvault_otx={job.alienvault_otx}
              yara={job.yara}
              extractedCode={job.extracted_code}
              onViewCode={() => setIsCodeModalOpen(true)}
              disabledChecks={(job as any).disabled_checks}
              reanalysisIntelDiff={job.reanalysis_intel_diff}
            />

            <SimilarityClusterCard
              hashes={job.hashes}
              similarSamples={job.similar_samples}
              onSelectJob={onSelectJob}
            />
          </div>
        )}

        {(activeTab === 'format_triage' || formatSections.some(s => s.id === activeTab)) && (
          <div className="space-y-6">
            {/* If multiple format-specific sections exist, render sleek sub-tabs */}
            {formatSections.length > 1 && (
              <div className="flex items-center gap-2 p-1.5 bg-slate-100 rounded-2xl overflow-x-auto border border-slate-200">
                {formatSections.map(sec => {
                  const Icon = sec.icon;
                  const currentSubTab = formatSubTab || (formatSections.some(s => s.id === activeTab) ? activeTab : formatSections[0].id);
                  const isSecActive = currentSubTab === sec.id;
                  return (
                    <button
                      key={sec.id}
                      onClick={() => {
                        setFormatSubTab(sec.id);
                        if (activeTab !== 'format_triage') setActiveTab('format_triage');
                      }}
                      className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                        isSecActive
                          ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80 font-bold'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{sec.label}</span>
                      {sec.count !== undefined && sec.count > 0 && (
                        <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-200 text-slate-700 font-bold">
                          {sec.count}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}

            {/* Active Sub-section */}
            {(() => {
              const currentSubTab = formatSubTab || (formatSections.some(s => s.id === activeTab) ? activeTab : formatSections[0]?.id);
              switch (currentSubTab) {
                case 'domain':
                  return job.domain_info ? (
                    <DomainAnalyticsCard domainInfo={job.domain_info} thumbnailUrl={job.thumbnail_url} />
                  ) : (
                    <div className="bg-white rounded-3xl border border-slate-200 p-8 text-center text-slate-500">
                      <Globe className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                      <p className="text-sm font-semibold text-slate-700">Domain / Network Infrastructure Analysis Pending</p>
                      <p className="text-xs text-slate-400 mt-1">Collecting DNS records, WHOIS registration, and IP threat telemetry...</p>
                    </div>
                  );
                case 'extension':
                  return job.extension_info ? (
                    <ErrorBoundary fallbackTitle="Browser Extension Analysis Error" onReset={() => setActiveTab('security')}>
                      <ExtensionTriageCard extensionInfo={job.extension_info} />
                    </ErrorBoundary>
                  ) : null;
                case 'applescript':
                  return job.applescript_info ? (
                    <ErrorBoundary fallbackTitle="AppleScript Triage Error" onReset={() => setActiveTab('security')}>
                      <AppleScriptTriageCard applescriptInfo={job.applescript_info} />
                    </ErrorBoundary>
                  ) : (
                    <div className="p-8 text-center text-slate-500 bg-white rounded-2xl border border-slate-200">
                      No AppleScript format triage metadata available for this file.
                    </div>
                  );
                case 'email':
                  return (
                    <ErrorBoundary fallbackTitle="Email Triage Display Error" onReset={() => setActiveTab('security')}>
                      <EmailTriageCard
                        jobId={jobId}
                        emailInfo={job.email_info}
                        findings={job.findings}
                        onSelectJob={onSelectJob}
                        workspaceJobs={workspaceJobs}
                      />
                    </ErrorBoundary>
                  );
                case 'binary':
                  return (
                    <ErrorBoundary fallbackTitle="Binary Analysis Display Error" onReset={() => setActiveTab('security')}>
                      <BinaryTriageCard
                        jobId={jobId}
                        binaryInfo={job.binary_info}
                        filename={job.filename}
                        findings={job.findings}
                        antiAnalysis={job.anti_analysis}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                      />
                    </ErrorBoundary>
                  );
                case 'script':
                  return (
                    <ErrorBoundary fallbackTitle="Script Triage Display Error" onReset={() => setActiveTab('security')}>
                      <ScriptTriageCard
                        scriptTriage={job.script_triage}
                        filename={job.filename}
                        category={job.category}
                        antiAnalysis={job.anti_analysis}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                      />
                    </ErrorBoundary>
                  );
                case 'office':
                  return (
                    <ErrorBoundary fallbackTitle="Office Document Triage Error" onReset={() => setActiveTab('security')}>
                      <OfficeTriageCard
                        officeInfo={job.office_info}
                        filename={job.filename}
                        findings={job.findings}
                        antiAnalysis={job.anti_analysis}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                      />
                    </ErrorBoundary>
                  );
                case 'pdf':
                  return (
                    <ErrorBoundary fallbackTitle="PDF Triage Error" onReset={() => setActiveTab('security')}>
                      <PdfTriageCard
                        jobId={job.job_id}
                        pdfInfo={job.pdf_info}
                        filename={job.filename}
                        findings={job.findings}
                        antiAnalysis={job.anti_analysis}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                      />
                    </ErrorBoundary>
                  );
                case 'jar':
                  return (
                    <ErrorBoundary fallbackTitle="JAR Java Triage Error" onReset={() => setActiveTab('security')}>
                      <JarTriageCard jarInfo={job.jar_info} filename={job.filename} findings={job.findings} />
                    </ErrorBoundary>
                  );
                case 'image':
                  return (
                    <ErrorBoundary fallbackTitle="Image Forensics Error" onReset={() => setActiveTab('security')}>
                      <ImageTriageCard imageInfo={job.image_info} provenance={job.ai_image_provenance} filename={job.filename} />
                    </ErrorBoundary>
                  );
                case 'mitre':
                  return (
                    <ErrorBoundary fallbackTitle="ATT&CK Navigator Display Error" onReset={() => setActiveTab('security')}>
                      <AttackNavigatorCard mitreAttack={job.mitre_attack} jobId={job.job_id} />
                    </ErrorBoundary>
                  );
                case 'embedded':
                  return (
                    <ErrorBoundary fallbackTitle="Embedded Files Display Error" onReset={() => setActiveTab('security')}>
                      <EmbeddedFilesCard
                        jobId={jobId}
                        embeddedFiles={job.embedded_files || []}
                        onSelectJob={onSelectJob}
                        workspaceJobs={workspaceJobs}
                      />
                    </ErrorBoundary>
                  );
                case 'pcap':
                  return (
                    <ErrorBoundary fallbackTitle="PCAP Forensics Display Error" onReset={() => setActiveTab('security')}>
                      <PcapTriageCard
                        pcapInfo={job.pcap_info}
                        jobId={job.job_id}
                        onSelectJob={onSelectJob}
                        workspaceJobs={workspaceJobs}
                        onNavigateToEvtx={(evtxJobId?: string, _targetIp?: string) => {
                          if (onSelectJob && evtxJobId) {
                            onSelectJob(evtxJobId);
                          }
                        }}
                      />
                    </ErrorBoundary>
                  );
                case 'evtx':
                  return (
                    <ErrorBoundary fallbackTitle="Windows Event Log Forensics Error" onReset={() => setActiveTab('security')}>
                      <EvtxTriageCard
                        evtxInfo={job.evtx_info || undefined}
                        filename={job.filename}
                        antiAnalysis={job.anti_analysis}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                        onNavigateToPcap={(pcapJobId?: string, _targetIp?: string) => {
                          if (onSelectJob && pcapJobId) {
                            onSelectJob(pcapJobId);
                          }
                        }}
                      />
                    </ErrorBoundary>
                  );
                case 'anti_analysis':
                  return (
                    <ErrorBoundary fallbackTitle="Anti-Analysis & Evasion Error" onReset={() => setActiveTab('security')}>
                      <AntiAnalysisInspectorCard
                        antiAnalysis={job.anti_analysis}
                        filename={job.filename}
                        category={job.category}
                      />
                    </ErrorBoundary>
                  );
                case 'lnk':
                  return (
                    <ErrorBoundary fallbackTitle="LNK Shortcut Dissection Error" onReset={() => setActiveTab('security')}>
                      <LnkCard lnkInfo={job.lnk_info} filename={job.filename} findings={job.findings} />
                    </ErrorBoundary>
                  );
                case 'raw_inspector':
                  return (
                    <ErrorBoundary fallbackTitle="Raw & Hex Inspector Error" onReset={() => setActiveTab('security')}>
                      <HexRawInspector jobId={job.job_id} filename={job.filename} category={job.category} />
                    </ErrorBoundary>
                  );
                default:
                  return null;
              }
            })()}
          </div>
        )}

        {activeTab === 'metadata' && !isDomainOrIp && (
          <MetadataViewer metadata={job.metadata} />
        )}

        {activeTab === 'urls' && (
          <UrlExplorer urls={job.urls} />
        )}

        {activeTab === 'timeline' && !isDomainOrIp && (
          <ErrorBoundary fallbackTitle="Forensic Timeline Error" onReset={() => setActiveTab('security')}>
            <ForensicTimelineCard jobId={job.job_id} />
          </ErrorBoundary>
        )}

        {activeTab === 'entropy' && !isDomainOrIp && (
          <ErrorBoundary fallbackTitle="Entropy Profile Error" onReset={() => setActiveTab('security')}>
            <EntropyProfileCard jobId={job.job_id} entropy={job.entropy_profile} />
          </ErrorBoundary>
        )}

        {activeTab === 'graph' && (
          <ErrorBoundary>
            <EntityGraphCard graphData={job.entity_graph} onSelectJob={onSelectJob} />
          </ErrorBoundary>
        )}

        {activeTab === 'diagnostics' && (
          <ErrorBoundary fallbackTitle="Diagnostics Display Error" onReset={() => setActiveTab('security')}>
            <JobDiagnosticsCard
              telemetry={job.telemetry}
              fileSize={job.file_size}
              mimeType={job.mime_type}
              category={job.category}
              filename={job.filename}
            />
          </ErrorBoundary>
        )}

        {activeTab === 'sanitize' && isCdrSupported && (
          <div className="space-y-6">
            {/* Sanitization & CDR Sub-Navigation */}
            <div className="flex border-b border-slate-200 gap-2 overflow-x-auto pb-1">
              <button
                type="button"
                onClick={() => setCdrActiveSubTab('sanitize')}
                className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
                  cdrActiveSubTab === 'sanitize'
                    ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Disarm &amp; Configuration</span>
              </button>

              <button
                type="button"
                onClick={() => setCdrActiveSubTab('diff')}
                className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
                  cdrActiveSubTab === 'diff'
                    ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                <Layers className="w-3.5 h-3.5 text-emerald-600" />
                <span>CDR Diff Inspector</span>
                {Boolean(job.cdr_diff?.structural_modifications?.length) && (
                  <span className="px-1.5 py-0.2 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-bold">
                    {job.cdr_diff!.structural_modifications.length}
                  </span>
                )}
              </button>

              {isCompleted && job.validation && (
                <button
                  type="button"
                  onClick={() => setCdrActiveSubTab('validation')}
                  className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
                    cdrActiveSubTab === 'validation'
                      ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5 text-teal-600" />
                  <span>Clean File &amp; Validation</span>
                </button>
              )}
            </div>

            {/* Sub-Tab 1: Disarm & Configuration */}
            {cdrActiveSubTab === 'sanitize' && (
              <SanitizationPanel
                category={job.category}
                isProcessing={isSanitizing || isProcessing}
                onSanitize={handleSanitize}
                suggestedProfile={job.risk?.suggested_profile}
                isMalicious={job.risk?.level === 'MALICIOUS'}
                isCompleted={isCompleted}
                onDownload={handleDownload}
                cdrPolicy={cdrPolicies?.[job.category]}
              />
            )}

            {/* Sub-Tab 2: CDR Diff Inspector (Inspect before download!) */}
            {cdrActiveSubTab === 'diff' && (
              <CdrDiffInspector
                cdrDiff={job.cdr_diff}
                onRunSanitization={() => setCdrActiveSubTab('sanitize')}
                onDownload={isCompleted ? handleDownload : undefined}
              />
            )}

            {/* Sub-Tab 3: Clean File & Validation */}
            {cdrActiveSubTab === 'validation' && isCompleted && job.validation && (
              <ValidationComparison
                validation={job.validation}
                sanitizedFilename={job.filename}
                onDownload={handleDownload}
                onDownloadReport={handleDownloadReport}
                warnings={job.validation.warnings}
              />
            )}
          </div>
        )}
      </div>
      </>
      )}

      <CodeViewerModal
        isOpen={isCodeModalOpen}
        onClose={() => setIsCodeModalOpen(false)}
        extractedCode={
          job.extracted_code ||
          (hasMacros
            ? {
                type: 'vba',
                language: 'vb',
                code:
                  "' Visual Basic for Applications (VBA) macro indicators detected.\n' Raw code streams were embedded or protected within the document structure.\n' Review flagged triggers in the macro warning section.",
                modules: [
                  {
                    name: 'Detected Indicators',
                    code: JSON.stringify(
                      job.findings?.find((f) => f.category === 'macro')?.details || {},
                      null,
                      2
                    ),
                  },
                ],
              }
            : null)
        }
        sourceFilename={job.filename}
      />

      {/* Click-to-Enlarge Safe Thumbnail Preview Modal */}
      {showThumbnailModal && job.thumbnail_url && (
        <div
          onClick={() => setShowThumbnailModal(false)}
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-overlay-fade"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="bg-white border border-slate-200 rounded-3xl max-w-3xl w-full p-6 shadow-2xl animate-modal-fade space-y-4"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2.5">
                <span className="text-xl">🖼️</span>
                <div>
                  <h3 className="font-bold text-slate-900 text-sm">{job.filename}</h3>
                  <span className="text-xs text-slate-500 font-mono uppercase">
                    Format: {job.category} · Sandboxed Visual Preview
                  </span>
                </div>
              </div>
              <button
                onClick={() => setShowThumbnailModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 flex items-center justify-center max-h-[70vh] p-2">
              <img
                src={job.thumbnail_url}
                alt={`Preview of ${job.filename}`}
                className="w-full h-auto object-contain max-h-[68vh] rounded-xl shadow-xs"
              />
            </div>

            <div className="flex justify-between items-center text-xs text-slate-500 pt-1">
              <span>Sandboxed visual render of original file content without executing active scripts.</span>
              <button
                onClick={() => setShowThumbnailModal(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold rounded-xl text-xs transition-colors cursor-pointer"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Automated Detection Rules (Sentinel KQL & YARA) Modal */}
      {showDetectionRulesModal && (
        <DetectionRulesModal
          isOpen={showDetectionRulesModal}
          onClose={() => setShowDetectionRulesModal(false)}
          jobId={job.job_id}
          filename={job.filename}
          initialRules={job.detection_rules}
        />
      )}
    </div>
  );
};
