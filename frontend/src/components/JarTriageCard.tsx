import React, { useState, useMemo } from 'react';
import {
  Coffee,
  Copy,
  Check,
  FileCode,
  Terminal,
  Package,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Bug,
  Globe,
  Search,
  KeyRound,
  Archive,
  ExternalLink,
  Code,
  Boxes,
  Zap,
  Filter,
  Flag,
  Key,
  Layers,
  Download,
  FileWarning
} from 'lucide-react';
import {
  JarTriageInfo,
  Finding,
  AntiAnalysisInfo,
  JarClassEntry,
  JarBase64Block,
  JarLolbinMatch,
  JarEmbeddedResource
} from '../types';
import { JavaBehavioralForensics } from './JavaBehavioralForensics';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import { formatBytes } from '../utils/formatters';
import { ReferencedText } from './ReferencedFileLink';

interface JarTriageCardProps {
  jarInfo?: JarTriageInfo;
  filename?: string;
  findings?: Finding[];
  antiAnalysis?: AntiAnalysisInfo;
  workspaceJobs?: any[];
  onSelectJob?: (newJobId: string) => void;
}

export const JarTriageCard: React.FC<JarTriageCardProps> = ({
  jarInfo,
  filename = 'application.jar',
  findings: _findings = [],
  antiAnalysis,
  workspaceJobs,
  onSelectJob,
}) => {
  // Determine default subtab
  const initialTab = useMemo(() => {
    if (jarInfo?.behavioral_analysis) return 'forensics';
    if (jarInfo?.classes_decompiled && jarInfo.classes_decompiled.length > 0) return 'classes';
    return 'manifest';
  }, [jarInfo]);

  const [activeSubTab, setActiveSubTab] = useState<
    | 'forensics'
    | 'archive'
    | 'dependencies'
    | 'classes'
    | 'apis'
    | 'strings'
    | 'secrets'
    | 'base64'
    | 'lolbins'
    | 'manifest'
    | 'signature'
    | 'resources'
    | 'urls'
    | 'anti_analysis'
  >(initialTab);

  // Class Explorer State
  const [selectedClassIndex, setSelectedClassIndex] = useState<number>(0);
  const [classSearch, setClassSearch] = useState<string>('');
  const [copiedClassCode, setCopiedClassCode] = useState<boolean>(false);

  // Strings Explorer State
  const [stringSearch, setStringSearch] = useState<string>('');
  const [stringCategory, setStringCategory] = useState<'all' | 'network' | 'commands' | 'file_paths' | 'registry'>('all');
  const [minStrLength, setMinStrLength] = useState<string>('4');
  const [copiedStringIdx, setCopiedStringIdx] = useState<number | null>(null);

  // Dangerous APIs State
  const [apiSearch, setApiSearch] = useState<string>('');
  const [apiCategory, setApiCategory] = useState<string>('all');

  // Manifest Copy State
  const [copiedManifest, setCopiedManifest] = useState<boolean>(false);

  // Base64 Copy State
  const [copiedB64Idx, setCopiedB64Idx] = useState<number | null>(null);
  const [showRawB64, setShowRawB64] = useState<Record<number, boolean>>({});

  // URL Copy State
  const [copiedUrlIdx, setCopiedUrlIdx] = useState<number | null>(null);

  // Dependencies & SBOM State
  const [copiedSbom, setCopiedSbom] = useState<boolean>(false);
  const [sbomViewMode, setSbomViewMode] = useState<'table' | 'json'>('table');

  // Secrets & CTF State
  const [copiedFlagIdx, setCopiedFlagIdx] = useState<number | null>(null);
  const [copiedSecretIdx, setCopiedSecretIdx] = useState<number | null>(null);

  if (!jarInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Coffee className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">
          No Java Archive (JAR) triage metadata available for this file.
        </p>
      </div>
    );
  }

  const {
    main_class,
    permissions,
    manifest_content = '',
    class_count = 0,
    classes_count = 0,
    embedded_binaries = [],
    packages = [],
    total_entries = 0,
    suspicious_apis = [],
    dangerous_apis = [],
    behavioral_analysis,
    strrat_profile,
    rat_detections = [],
    classes_decompiled = [],
    strings,
    b64_blocks = [],
    lolbin_matches = [],
    has_lolbins = false,
    detected_commands = [],
    digital_signature,
    signing_info,
    embedded_resources = [],
    iocs = { urls: [], ips: [] },
    archive_security,
    dependencies = [],
    shaded_libraries = [],
    cve_advisories = [],
    cyclonedx_sbom,
    secrets_and_ctf
  } = jarInfo;

  const totalClasses = classes_count || class_count || classes_decompiled.length;
  const apisList = dangerous_apis.length > 0 ? dangerous_apis : suspicious_apis;

  // Filtered Classes for Code Explorer
  const filteredClasses: JarClassEntry[] = useMemo(() => {
    if (!classSearch.trim()) return classes_decompiled;
    const q = classSearch.toLowerCase();
    return classes_decompiled.filter(
      (c) => c.class_name.toLowerCase().includes(q) || c.class_file.toLowerCase().includes(q)
    );
  }, [classes_decompiled, classSearch]);

  const activeClass: JarClassEntry | null =
    filteredClasses[selectedClassIndex] || filteredClasses[0] || classes_decompiled[0] || null;

  // Strings Explorer Categorization
  const allRawStrings = strings?.all_sample || [];
  const categorized = strings?.categorized || {
    network: [],
    file_paths: [],
    registry: [],
    commands: [],
    all_sample: allRawStrings
  };

  const activeStringsList = useMemo(() => {
    let pool: string[] = [];
    if (stringCategory === 'all') {
      pool = categorized.all_sample?.length ? categorized.all_sample : allRawStrings;
    } else if (stringCategory === 'network') {
      pool = categorized.network || [];
    } else if (stringCategory === 'commands') {
      pool = categorized.commands || [];
    } else if (stringCategory === 'file_paths') {
      pool = categorized.file_paths || [];
    } else if (stringCategory === 'registry') {
      pool = categorized.registry || [];
    }

    const minLen = parseInt(minStrLength, 10) || 0;
    const q = stringSearch.toLowerCase().trim();

    return pool.filter((s) => {
      if (typeof s !== 'string') return false;
      if (s.length < minLen) return false;
      if (q && !s.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [stringCategory, categorized, allRawStrings, stringSearch, minStrLength]);

  // APIs Categories
  const apiCategories = useMemo(() => {
    const set = new Set<string>();
    apisList.forEach((a) => {
      if (a.category) set.add(a.category);
    });
    return Array.from(set);
  }, [apisList]);

  const filteredApis = useMemo(() => {
    const q = apiSearch.toLowerCase().trim();
    return apisList.filter((a) => {
      if (apiCategory !== 'all' && a.category !== apiCategory) return false;
      if (q) {
        const matchTitle = (a.title || '').toLowerCase().includes(q);
        const matchApi = (a.api || '').toLowerCase().includes(q);
        const matchClass = (a.class_file || '').toLowerCase().includes(q);
        const matchDesc = (a.description || '').toLowerCase().includes(q);
        if (!matchTitle && !matchApi && !matchClass && !matchDesc) return false;
      }
      return true;
    });
  }, [apisList, apiCategory, apiSearch]);

  // URLs & Network Endpoints
  const allUrls = useMemo(() => {
    const set = new Set<string>();
    (iocs.urls || []).forEach((u) => set.add(u));
    if (behavioral_analysis?.internet_activity?.endpoints) {
      behavioral_analysis.internet_activity.endpoints.forEach((e) => set.add(e));
    }
    return Array.from(set);
  }, [iocs, behavioral_analysis]);

  // Digital Signature Status
  const isSigned = Boolean(
    signing_info?.is_signed ||
    (digital_signature && digital_signature.status !== 'UNSIGNED')
  );
  const signatureStatus =
    signing_info?.status || digital_signature?.status || (isSigned ? 'SIGNED' : 'UNSIGNED');

  const isAllPermissions =
    permissions && permissions.toLowerCase().includes('all-permissions');

  const hasAntiAnalysis = Boolean(
    antiAnalysis && antiAnalysis.techniques && antiAnalysis.techniques.length > 0
  );

  const handleCopyManifest = () => {
    navigator.clipboard.writeText(manifest_content);
    setCopiedManifest(true);
    setTimeout(() => setCopiedManifest(false), 2000);
  };

  const handleCopyClassCode = () => {
    if (activeClass?.decompiled_source) {
      navigator.clipboard.writeText(activeClass.decompiled_source);
      setCopiedClassCode(true);
      setTimeout(() => setCopiedClassCode(false), 2000);
    }
  };

  const handleCopyString = (str: string, idx: number) => {
    navigator.clipboard.writeText(str);
    setCopiedStringIdx(idx);
    setTimeout(() => setCopiedStringIdx(null), 2000);
  };

  const handleCopyB64 = (txt: string, idx: number) => {
    navigator.clipboard.writeText(txt);
    setCopiedB64Idx(idx);
    setTimeout(() => setCopiedB64Idx(null), 2000);
  };

  const handleCopyUrl = (url: string, idx: number) => {
    navigator.clipboard.writeText(url);
    setCopiedUrlIdx(idx);
    setTimeout(() => setCopiedUrlIdx(null), 2000);
  };

  const handleCopySbom = () => {
    if (cyclonedx_sbom) {
      navigator.clipboard.writeText(JSON.stringify(cyclonedx_sbom, null, 2));
      setCopiedSbom(true);
      setTimeout(() => setCopiedSbom(false), 2000);
    }
  };

  const handleDownloadSbom = () => {
    if (cyclonedx_sbom) {
      const blob = new Blob([JSON.stringify(cyclonedx_sbom, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename.replace(/\.jar$/i, '')}-cyclonedx-sbom.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleCopyFlag = (flag: string, idx: number) => {
    navigator.clipboard.writeText(flag);
    setCopiedFlagIdx(idx);
    setTimeout(() => setCopiedFlagIdx(null), 2000);
  };

  const handleCopySecret = (secret: string, idx: number) => {
    navigator.clipboard.writeText(secret);
    setCopiedSecretIdx(idx);
    setTimeout(() => setCopiedSecretIdx(null), 2000);
  };

  const getSeverityBadge = (sev: string = 'MEDIUM') => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-amber-50 text-amber-600 rounded-2xl shrink-0">
            <Coffee className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Java Archive (JAR) Deep Bytecode &amp; Forensic Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-700 border border-amber-200 font-mono">
                {filename}
              </span>

              {main_class && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                  Executable JAR (Main-Class)
                </span>
              )}

              {isAllPermissions && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  ⚠️ all-permissions Requested
                </span>
              )}

              {/* Archive Structural Security Alert */}
              {archive_security?.verdict === 'VULNERABLE' && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  🛡️ Archive Vulnerability ({archive_security.issues_count} Issues)
                </span>
              )}

              {/* Known CVE Vulnerability Alert */}
              {cve_advisories.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-100 text-rose-800 border border-rose-300">
                  ⚠️ Vulnerable Dependency ({cve_advisories.length} CVEs)
                </span>
              )}

              {/* CTF Flag Captured Alert */}
              {secrets_and_ctf?.flags_count && secrets_and_ctf.flags_count > 0 ? (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-100 text-purple-800 border border-purple-300">
                  🚩 CTF Flag Captured ({secrets_and_ctf.flags_count})
                </span>
              ) : null}

              {/* Partially Signed JAR Alert */}
              {signing_info?.is_partially_signed && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-orange-100 text-orange-800 border border-orange-300">
                  ⚠️ Partially Signed ({signing_info.unsigned_classes_count} Unsigned Classes)
                </span>
              )}

              {/* Digital Signature Badge */}
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${
                  signatureStatus === 'VALID'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-300'
                    : signatureStatus === 'SELF_SIGNED' || signatureStatus === 'DEBUG_KEY'
                    ? 'bg-rose-50 text-rose-700 border-rose-300'
                    : signatureStatus === 'EXPIRED'
                    ? 'bg-amber-50 text-amber-700 border-amber-300'
                    : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                {signatureStatus === 'VALID' && '✓ Signed & Verified'}
                {signatureStatus === 'SELF_SIGNED' && '⚠️ Self-Signed Untrusted'}
                {signatureStatus === 'DEBUG_KEY' && '⚠️ Debug Signing Key'}
                {signatureStatus === 'EXPIRED' && '⚠️ Expired Certificate'}
                {signatureStatus === 'UNSIGNED' && 'Unsigned Archive'}
                {signatureStatus === 'INVALID' && '❌ Invalid Signature'}
              </span>

              {/* LOLBins Badge */}
              {(has_lolbins || lolbin_matches.length > 0) && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300">
                  LOLBins Invoked ({lolbin_matches.length})
                </span>
              )}

              {/* STRRAT RAT Profile Match */}
              {(strrat_profile?.is_strrat_candidate || rat_detections.length > 0) && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  🚨 RAT Detected ({rat_detections.join(', ') || 'STRRAT Candidate'})
                </span>
              )}

              {/* Native Dropper Payloads */}
              {embedded_binaries.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-50 text-purple-700 border border-purple-300">
                  Native Payloads ({embedded_binaries.length})
                </span>
              )}
            </div>

            <p className="text-xs text-slate-500">
              Classes &amp; bytecode decompiler, constant pool strings categorization, Base64 payload extraction, dangerous execution APIs, digital certificate audit, and SecurityScorecard STRRAT 4-pillar heuristics.
            </p>
          </div>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {archive_security && (
            <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Archive Sec</span>
              <strong className={archive_security.verdict === 'VULNERABLE' ? 'text-rose-600' : (archive_security.verdict === 'SUSPICIOUS' ? 'text-amber-600' : 'text-emerald-600')}>
                {archive_security.verdict}
              </strong>
            </div>
          )}
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Dependencies</span>
            <strong className={cve_advisories.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {dependencies.length || shaded_libraries.length || 0}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Secrets/CTF</span>
            <strong className={(secrets_and_ctf?.flags_count || 0) > 0 ? 'text-purple-600' : ((secrets_and_ctf?.secrets_count || 0) > 0 ? 'text-rose-600' : 'text-slate-900')}>
              {(secrets_and_ctf?.flags_count || 0) + (secrets_and_ctf?.secrets_count || 0)}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Classes</span>
            <strong className="text-slate-900">{totalClasses}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Dangerous APIs</span>
            <strong className={apisList.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {apisList.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Strings</span>
            <strong className="text-indigo-600">{strings?.total_count || allRawStrings.length}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">LOLBins</span>
            <strong className={lolbin_matches.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {lolbin_matches.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Base64</span>
            <strong className={b64_blocks.length > 0 ? 'text-purple-600' : 'text-slate-900'}>
              {b64_blocks.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Entries</span>
            <strong className="text-slate-900">{total_entries}</strong>
          </div>
        </div>
      </div>

      {/* Sub Tabs Navigation */}
      <div className="flex items-center gap-1.5 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        {behavioral_analysis && (
          <button
            onClick={() => setActiveSubTab('forensics')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'forensics'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Bug className="w-3.5 h-3.5 text-rose-200" />
            <span>Behavioral Forensics (STRRAT)</span>
          </button>
        )}

        {archive_security && (
          <button
            onClick={() => setActiveSubTab('archive')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'archive'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className={`w-3.5 h-3.5 ${archive_security.verdict === 'VULNERABLE' ? 'text-rose-500' : 'text-amber-500'}`} />
            <span>Archive Security {archive_security.issues_count > 0 ? `(${archive_security.issues_count})` : ''}</span>
          </button>
        )}

        {(dependencies.length > 0 || shaded_libraries.length > 0 || cyclonedx_sbom) && (
          <button
            onClick={() => setActiveSubTab('dependencies')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'dependencies'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Layers className={`w-3.5 h-3.5 ${cve_advisories.length > 0 ? 'text-rose-500' : 'text-indigo-400'}`} />
            <span>Dependencies &amp; SBOM ({dependencies.length || shaded_libraries.length})</span>
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('classes')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'classes'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Code className="w-3.5 h-3.5 text-indigo-400" />
          <span>Classes &amp; Bytecode ({classes_decompiled.length || totalClasses})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('apis')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'apis'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Zap className="w-3.5 h-3.5 text-rose-500" />
          <span>Dangerous APIs ({apisList.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('strings')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'strings'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Search className="w-3.5 h-3.5 text-blue-400" />
          <span>Categorized Strings ({strings?.total_count || allRawStrings.length})</span>
        </button>

        {secrets_and_ctf && (
          <button
            onClick={() => setActiveSubTab('secrets')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'secrets'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Flag className={`w-3.5 h-3.5 ${secrets_and_ctf.flags_count > 0 ? 'text-rose-500' : 'text-emerald-500'}`} />
            <span>Secrets &amp; CTF ({secrets_and_ctf.flags_count + secrets_and_ctf.secrets_count})</span>
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('base64')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'base64'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Boxes className="w-3.5 h-3.5 text-purple-400" />
          <span>Base64 Payloads ({b64_blocks.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('lolbins')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'lolbins'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-amber-500" />
          <span>LOLBins &amp; Commands ({lolbin_matches.length + detected_commands.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('manifest')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'manifest'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-slate-400" />
          <span>MANIFEST.MF &amp; Entry</span>
        </button>

        <button
          onClick={() => setActiveSubTab('signature')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'signature'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <KeyRound className="w-3.5 h-3.5 text-emerald-500" />
          <span>Digital Signature</span>
        </button>

        <button
          onClick={() => setActiveSubTab('resources')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeSubTab === 'resources'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Archive className="w-3.5 h-3.5 text-purple-500" />
          <span>Embedded Resources ({embedded_resources.length + embedded_binaries.length})</span>
        </button>

        {allUrls.length > 0 && (
          <button
            onClick={() => setActiveSubTab('urls')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'urls'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Globe className="w-3.5 h-3.5 text-blue-500" />
            <span>Network IOCs ({allUrls.length})</span>
          </button>
        )}

        {hasAntiAnalysis && (
          <button
            onClick={() => setActiveSubTab('anti_analysis')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeSubTab === 'anti_analysis'
                ? 'bg-rose-600 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-300" />
            <span>Anti-Analysis ({antiAnalysis?.techniques?.length})</span>
          </button>
        )}
      </div>

      {/* ========================================================================= */}
      {/* Tab: Behavioral Forensics (STRRAT Case Study) */}
      {/* ========================================================================= */}
      {activeSubTab === 'forensics' && behavioral_analysis && (
        <JavaBehavioralForensics
          behavioral={behavioral_analysis}
          filename={filename}
          isJar={true}
        />
      )}

      {/* ========================================================================= */}
      {/* Tab: Archive Structural Security & Integrity (Zip Slip, Bomb, Polyglot) */}
      {/* ========================================================================= */}
      {activeSubTab === 'archive' && archive_security && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div
            className={`p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
              archive_security.verdict === 'VULNERABLE'
                ? 'bg-rose-50 border-rose-200'
                : archive_security.verdict === 'SUSPICIOUS'
                ? 'bg-amber-50 border-amber-200'
                : 'bg-emerald-50 border-emerald-200'
            }`}
          >
            <div className="flex items-start gap-3">
              {archive_security.verdict === 'VULNERABLE' ? (
                <ShieldAlert className="w-6 h-6 text-rose-600 shrink-0 mt-0.5" />
              ) : archive_security.verdict === 'SUSPICIOUS' ? (
                <AlertTriangle className="w-6 h-6 text-amber-600 shrink-0 mt-0.5" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-emerald-600 shrink-0 mt-0.5" />
              )}
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <span>Archive Integrity Verdict:</span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold ${
                      archive_security.verdict === 'VULNERABLE'
                        ? 'bg-rose-600 text-white'
                        : archive_security.verdict === 'SUSPICIOUS'
                        ? 'bg-amber-500 text-white'
                        : 'bg-emerald-600 text-white'
                    }`}
                  >
                    {archive_security.verdict}
                  </span>
                </h4>
                <p className="text-xs text-slate-600 mt-1">
                  {archive_security.verdict === 'VULNERABLE'
                    ? 'Critical archive structure anomalies detected. Extracting or processing this file blindly poses high security risks.'
                    : archive_security.verdict === 'SUSPICIOUS'
                    ? 'Structural inconsistencies observed (e.g. duplicate entries, trailing payload, or concealed resources).'
                    : 'No path traversal, compression bomb, or archive structure tampering detected.'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-slate-500 font-sans">Total Issues:</span>
              <span className="px-3 py-1 rounded-xl bg-white border border-slate-200 font-bold text-slate-800 shadow-sm">
                {archive_security.issues_count}
              </span>
            </div>
          </div>

          {/* 4 Core Pillars Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Zip Slip */}
            <div className={`p-4 rounded-2xl border ${archive_security.zip_slip.detected ? 'bg-rose-50 border-rose-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Path Traversal / Zip Slip</span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.zip_slip.detected ? 'text-rose-700' : 'text-slate-700'}`}>
                  {archive_security.zip_slip.detected ? `${archive_security.zip_slip.count} Traversal Paths` : 'Clean (0)'}
                </span>
                {archive_security.zip_slip.detected ? (
                  <AlertTriangle className="w-5 h-5 text-rose-600" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-600" />
                )}
              </div>
            </div>

            {/* Zip Bomb / Ratio */}
            <div className={`p-4 rounded-2xl border ${archive_security.zip_bomb.is_dangerous ? 'bg-rose-50 border-rose-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Decompression Ratio</span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.zip_bomb.is_dangerous ? 'text-rose-700' : 'text-slate-700'}`}>
                  {archive_security.zip_bomb.compression_ratio}:1
                </span>
                <span className="text-[10px] font-mono text-slate-500 font-sans">
                  {formatBytes(archive_security.zip_bomb.uncompressed_size)} total
                </span>
              </div>
            </div>

            {/* Duplicate Entries */}
            <div className={`p-4 rounded-2xl border ${archive_security.duplicate_entries.detected ? 'bg-amber-50 border-amber-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Duplicate Entries</span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.duplicate_entries.detected ? 'text-amber-700' : 'text-slate-700'}`}>
                  {archive_security.duplicate_entries.count} Duplicates
                </span>
                {archive_security.duplicate_entries.detected ? (
                  <FileWarning className="w-5 h-5 text-amber-600" />
                ) : (
                  <Check className="w-5 h-5 text-emerald-600" />
                )}
              </div>
            </div>

            {/* Polyglot / Trailing */}
            <div className={`p-4 rounded-2xl border ${archive_security.polyglot_and_trailing.has_trailing_data || archive_security.polyglot_and_trailing.has_leading_polyglot ? 'bg-amber-50 border-amber-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Structure / Trailing</span>
              <div className="flex items-center justify-between">
                <span className={`text-sm font-bold font-mono truncate max-w-[140px] ${archive_security.polyglot_and_trailing.has_trailing_data || archive_security.polyglot_and_trailing.has_leading_polyglot ? 'text-amber-700' : 'text-slate-700'}`}>
                  {archive_security.polyglot_and_trailing.has_leading_polyglot ? archive_security.polyglot_and_trailing.leading_magic : (archive_security.polyglot_and_trailing.has_trailing_data ? `+${archive_security.polyglot_and_trailing.trailing_bytes_count}B Trailing` : 'Standard ZIP')}
                </span>
                <Archive className="w-5 h-5 text-slate-400" />
              </div>
            </div>
          </div>

          {/* Zip Slip Details Card */}
          {archive_security.zip_slip.detected && (
            <div className="border border-rose-300 bg-rose-50/50 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-rose-900 font-bold text-sm">
                <AlertTriangle className="w-4 h-4 text-rose-600" />
                <span>Zip Slip Path Traversal Entries ({archive_security.zip_slip.paths.length})</span>
              </div>
              <p className="text-xs text-rose-700 leading-relaxed">
                The archive contains paths designed to escape the extraction directory using &apos;../&apos; or absolute root paths. Unpacking this archive with standard tools will overwrite arbitrary operating system files.
              </p>
              <div className="bg-white border border-rose-200 rounded-xl p-3 font-mono text-xs text-rose-800 space-y-1 max-h-48 overflow-y-auto">
                {archive_security.zip_slip.paths.map((p, idx) => (
                  <div key={idx} className="flex items-center justify-between py-0.5 border-b border-rose-50 last:border-0">
                    <span className="break-all">{p}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Extension & Magic Mismatches (Concealed Executables) */}
          {archive_security.extension_mismatches && archive_security.extension_mismatches.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Concealed Executables &amp; Extension Mismatches ({archive_security.extension_mismatches.length})</span>
                <span className="text-[10px] text-slate-400 font-mono">Magic bytes vs declared file extension</span>
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {archive_security.extension_mismatches.map((item, idx) => (
                  <div key={idx} className="p-3 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50">
                    <div className="flex items-center gap-3">
                      <span className="font-bold text-slate-800 break-all">{item.filename}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-sans">
                        Extension: {item.declared_extension}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 font-sans">
                      <span className="text-indigo-600 font-mono text-xs font-bold">
                        Actual: {item.actual_type}
                      </span>
                      <span className="text-slate-400 text-xs font-mono">{formatBytes(item.file_size)}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold uppercase bg-rose-100 text-rose-800 border border-rose-300">
                        {item.threat_level}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Duplicate Entries */}
          {archive_security.duplicate_entries.detected && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Duplicate Central-Directory / Local-Header Entries ({archive_security.duplicate_entries.entries.length})</span>
                <span className="text-[10px] text-slate-400 font-mono">Parser differential &amp; filter evasion risk</span>
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs p-3">
                {archive_security.duplicate_entries.entries.map((d, idx) => (
                  <div key={idx} className="py-1 text-slate-800 flex items-center justify-between">
                    <span>{d}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-sans font-semibold">
                      Duplicate Path
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Nested Archives */}
          {archive_security.nested_archives && archive_security.nested_archives.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Nested Archives &amp; Embedded Containers ({archive_security.nested_archives.length})</span>
                <span className="text-[10px] text-slate-400 font-mono">Embedded JAR / WAR / ZIP payloads</span>
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {archive_security.nested_archives.map((na, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between gap-3 hover:bg-slate-50">
                    <span className="font-bold text-slate-800 break-all">{na.filename}</span>
                    <div className="flex items-center gap-3 font-sans">
                      <span className="text-slate-500 font-mono text-xs">{formatBytes(na.size)}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-purple-100 text-purple-800 font-mono font-bold">
                        {na.type}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Dependencies, Shaded Libraries & CycloneDX SBOM */}
      {/* ========================================================================= */}
      {activeSubTab === 'dependencies' && (
        <div className="space-y-6">
          {/* Sub Navigation: Table vs CycloneDX JSON */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50 p-3 rounded-2xl border border-slate-200">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSbomViewMode('table')}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-colors ${
                  sbomViewMode === 'table' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                Dependencies &amp; CVEs ({dependencies.length})
              </button>
              <button
                onClick={() => setSbomViewMode('json')}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-colors ${
                  sbomViewMode === 'json' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                CycloneDX v1.4 SBOM (JSON)
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopySbom}
                disabled={!cyclonedx_sbom}
                className="px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-100 rounded-xl text-xs font-semibold text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedSbom ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSbom ? 'Copied SBOM' : 'Copy CycloneDX'}</span>
              </button>

              <button
                onClick={handleDownloadSbom}
                disabled={!cyclonedx_sbom}
                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>

          {/* Known CVE Vulnerability Advisories */}
          {cve_advisories.length > 0 && (
            <div className="border border-rose-300 bg-rose-50/40 rounded-2xl p-5 space-y-4">
              <div className="flex items-center gap-2 text-rose-900 font-bold text-sm">
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
                <span>Identified Vulnerabilities &amp; CVE Advisories ({cve_advisories.length})</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {cve_advisories.map((cve, idx) => (
                  <div key={idx} className="bg-white border border-rose-200 rounded-xl p-4 shadow-sm space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold font-mono text-rose-700 bg-rose-50 px-2.5 py-0.5 rounded border border-rose-200">
                        {cve.cve}
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase bg-rose-600 text-white">
                        CVSS {cve.cvss} • {cve.severity}
                      </span>
                    </div>
                    <h5 className="text-xs font-bold text-slate-900">{cve.name}</h5>
                    <p className="text-[11px] text-slate-600 leading-relaxed">{cve.description}</p>
                    <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>Artifact: {cve.artifact} ({cve.version})</span>
                      <span>{cve.cwe}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* View Mode: Table */}
          {sbomViewMode === 'table' && (
            <div className="space-y-6">
              {/* Primary / Maven Dependencies */}
              <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
                <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                  <span>Maven &amp; Bundled Dependencies ({dependencies.length})</span>
                  <span className="text-[10px] text-slate-400 font-mono">Extracted from pom.properties / pom.xml</span>
                </div>
                {dependencies.length === 0 ? (
                  <div className="p-6 text-center text-xs text-slate-400">
                    No Maven pom.properties metadata located in archive META-INF/maven.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 font-mono text-xs">
                    {dependencies.map((dep, idx) => (
                      <div key={idx} className="p-3 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50">
                        <div className="flex items-center gap-3">
                          <Package className="w-4 h-4 text-indigo-500 shrink-0" />
                          <div>
                            <span className="text-slate-400 text-[11px] block">{dep.group_id}</span>
                            <span className="font-bold text-slate-900">{dep.artifact_id}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 font-sans">
                          <span className="text-xs font-mono font-bold bg-slate-100 px-2 py-0.5 rounded text-slate-800">
                            v{dep.version}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono truncate max-w-[200px]">
                            {dep.source}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Shaded Libraries */}
              {shaded_libraries.length > 0 && (
                <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
                  <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                    <span>Shaded &amp; Repackaged Third-Party Libraries ({shaded_libraries.length})</span>
                    <span className="text-[10px] text-slate-400 font-mono">Detected via package namespaces</span>
                  </div>
                  <div className="divide-y divide-slate-100 font-mono text-xs">
                    {shaded_libraries.map((lib, idx) => (
                      <div key={idx} className="p-3 flex items-center justify-between gap-3 hover:bg-slate-50">
                        <div className="flex items-center gap-3">
                          <Boxes className="w-4 h-4 text-purple-500 shrink-0" />
                          <div>
                            <span className="font-bold text-slate-900">{lib.name}</span>
                            <span className="text-[11px] text-slate-400 block">{lib.package_prefix}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 font-sans">
                          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 uppercase font-bold">
                            {lib.category}
                          </span>
                          <span className="text-xs text-slate-500 font-mono">
                            {lib.packages_count} packages
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Multi-Release JAR Info */}
              {cyclonedx_sbom?.multi_release?.is_multi_release && (
                <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-2xl flex items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-3">
                    <Coffee className="w-5 h-5 text-indigo-600 shrink-0" />
                    <div>
                      <strong className="text-indigo-900 block font-sans">Multi-Release JAR (MRJAR) Structure Detected</strong>
                      <span className="text-indigo-700 font-sans">
                        Contains version-specific class implementations in META-INF/versions/
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 font-mono">
                    {cyclonedx_sbom.multi_release.versions.map((ver, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded bg-white text-indigo-800 font-bold border border-indigo-200 text-xs">
                        Java {ver}+
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* View Mode: CycloneDX JSON Viewer */}
          {sbomViewMode === 'json' && cyclonedx_sbom && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-slate-100">
              <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 font-mono text-xs flex items-center justify-between text-slate-300">
                <span>CycloneDX v1.4 JSON Specification (URN: {cyclonedx_sbom.serialNumber})</span>
                <span className="text-emerald-400">specVersion: 1.4</span>
              </div>
              <pre className="p-4 font-mono text-xs overflow-x-auto max-h-[500px] leading-relaxed text-slate-200 select-all">
                {JSON.stringify(cyclonedx_sbom, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Classes & Disassembled Code Explorer */}
      {/* ========================================================================= */}
      {activeSubTab === 'classes' && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-50 p-3 rounded-2xl border border-slate-200">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Search classes (e.g. TrojanAgent, a.a)..."
                value={classSearch}
                onChange={(e) => {
                  setClassSearch(e.target.value);
                  setSelectedClassIndex(0);
                }}
                className="w-full bg-white border border-slate-200 rounded-xl px-3 py-1.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>
            <div className="text-xs text-slate-500 font-mono">
              Showing {filteredClasses.length} of {classes_decompiled.length} disassembled classes
            </div>
          </div>

          {classes_decompiled.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No class bytecode disassembled. Archive may contain encrypted classes or non-standard bytecode structure.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Class Selector Sidebar */}
              <div className="lg:col-span-4 border border-slate-200 rounded-2xl overflow-hidden bg-white max-h-[550px] flex flex-col">
                <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                  <span>Class Catalog ({filteredClasses.length})</span>
                  <span className="text-[10px] text-slate-400 font-mono">Select to inspect</span>
                </div>
                <div className="divide-y divide-slate-100 overflow-y-auto flex-1 font-mono text-xs">
                  {filteredClasses.map((cls, idx) => {
                    const isSelected = activeClass?.class_file === cls.class_file;
                    return (
                      <button
                        key={idx}
                        onClick={() => setSelectedClassIndex(idx)}
                        className={`w-full text-left p-3 transition-colors cursor-pointer flex flex-col gap-1 ${
                          isSelected
                            ? 'bg-indigo-50 border-l-4 border-indigo-600 text-indigo-950 font-semibold'
                            : 'hover:bg-slate-50 text-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-xs font-bold font-mono">
                            {cls.class_name || cls.class_file}
                          </span>
                          {cls.is_entry && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-sans font-bold bg-indigo-600 text-white shrink-0">
                              ENTRY
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-[10px] text-slate-400 font-sans">
                          <span>{cls.methods_count || cls.methods?.length || 0} methods</span>
                          <span>•</span>
                          <span>{cls.fields_count || cls.fields?.length || 0} fields</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Disassembled Pseudo-Java Code Viewer */}
              <div className="lg:col-span-8 border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-slate-200 flex flex-col max-h-[550px]">
                {activeClass ? (
                  <>
                    <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-indigo-400" />
                        <span className="font-mono text-xs font-bold text-white">
                          {activeClass.class_file}
                        </span>
                        {activeClass.is_entry && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/30 text-indigo-300 border border-indigo-500/40">
                            Main-Class Entry
                          </span>
                        )}
                      </div>
                      <button
                        onClick={handleCopyClassCode}
                        className="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                      >
                        {copiedClassCode ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        <span>{copiedClassCode ? 'Copied' : 'Copy Source'}</span>
                      </button>
                    </div>

                    {/* Methods & Fields Quick Chips */}
                    {(activeClass.methods?.length > 0 || activeClass.fields?.length > 0) && (
                      <div className="bg-slate-800/60 p-2.5 border-b border-slate-700/80 flex flex-wrap gap-1.5 text-[10px] font-mono max-h-24 overflow-y-auto">
                        {activeClass.methods?.map((m, mIdx) => (
                          <span
                            key={mIdx}
                            className="px-2 py-0.5 rounded bg-slate-700/70 text-slate-300 border border-slate-600/50"
                            title={m.signature || m.name}
                          >
                            fn {m.name}()
                          </span>
                        ))}
                        {activeClass.fields?.map((f, fIdx) => (
                          <span
                            key={`f-${fIdx}`}
                            className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700"
                            title={f.formatted || f.name}
                          >
                            field {f.name}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Code Lines Viewer */}
                    <div className="p-4 overflow-y-auto flex-1 font-mono text-xs leading-relaxed space-y-0.5">
                      {(activeClass.decompiled_source || '// Empty decompilation')
                        .split('\n')
                        .map((line, i) => (
                          <div key={i} className="flex hover:bg-slate-800/50 rounded px-1">
                            <span className="w-10 select-none text-slate-500 text-right pr-4 shrink-0">
                              {i + 1}
                            </span>
                            <span className="whitespace-pre text-slate-200">{line || ' '}</span>
                          </div>
                        ))}
                    </div>
                  </>
                ) : (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    Select a class from the left catalog to inspect decompiled bytecode.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Dangerous Bytecode APIs */}
      {/* ========================================================================= */}
      {activeSubTab === 'apis' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            {/* Category Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                onClick={() => setApiCategory('all')}
                className={`px-3 py-1 rounded-xl text-xs font-semibold transition-colors cursor-pointer ${
                  apiCategory === 'all'
                    ? 'bg-slate-900 text-white'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                All ({apisList.length})
              </button>
              {apiCategories.map((cat, idx) => {
                const count = apisList.filter((a) => a.category === cat).length;
                return (
                  <button
                    key={idx}
                    onClick={() => setApiCategory(cat)}
                    className={`px-3 py-1 rounded-xl text-xs font-semibold capitalize transition-colors cursor-pointer ${
                      apiCategory === cat
                        ? 'bg-rose-600 text-white'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {cat} ({count})
                  </button>
                );
              })}
            </div>

            {/* API Search Input */}
            <div className="relative min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search APIs..."
                value={apiSearch}
                onChange={(e) => setApiSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-rose-500"
              />
            </div>
          </div>

          {filteredApis.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No matching dangerous Java bytecode APIs discovered.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white divide-y divide-slate-100 font-mono text-xs">
              <div className="bg-slate-100 px-4 py-2 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Categorized Dangerous Bytecode Invocations ({filteredApis.length})</span>
                <span className="text-[10px] text-slate-500 font-normal">
                  CWE, OWASP &amp; MITRE ATT&amp;CK Mappings
                </span>
              </div>

              {filteredApis.map((item, i) => (
                <div key={i} className="p-4 hover:bg-slate-50/80 transition-colors space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold font-sans border ${getSeverityBadge(
                          item.severity
                        )}`}
                      >
                        {item.severity || 'HIGH'}
                      </span>
                      {item.category && (
                        <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-md bg-slate-200 text-slate-700 font-sans">
                          {item.category}
                        </span>
                      )}
                      <strong className="text-xs font-bold text-slate-900 font-sans">
                        {item.title || item.api}
                      </strong>
                      {item.class_file && (
                        <span className="text-[11px] font-mono text-slate-500">
                          ({item.class_file})
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 font-sans">
                      {item.cwe && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded-md">
                          {item.cwe}
                        </span>
                      )}
                      {item.owasp && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-md">
                          {item.owasp}
                        </span>
                      )}
                      {item.mitre && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md">
                          MITRE {item.mitre}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="font-mono text-xs text-rose-700 font-semibold bg-slate-50 p-2.5 rounded-xl border border-slate-200 break-all">
                    {workspaceJobs && workspaceJobs.length > 0 ? (
                      <ReferencedText
                        text={item.api}
                        workspaceJobs={workspaceJobs}
                        onSelectJob={onSelectJob}
                      />
                    ) : (
                      item.api
                    )}
                  </div>

                  {item.description && (
                    <p className="text-xs text-slate-600 leading-relaxed font-sans">
                      {item.description}
                    </p>
                  )}

                  {/* Threat Model & Exploitation Rationale */}
                  {item.risk_explanation && (
                    <div className="p-3 bg-amber-50/80 rounded-xl border border-amber-200 text-xs text-amber-900 space-y-1 font-sans">
                      <span className="font-bold flex items-center gap-1.5 text-amber-800">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                        Threat Model &amp; Exploitation Rationale:
                      </span>
                      <p className="leading-relaxed text-amber-800/90">{item.risk_explanation}</p>
                    </div>
                  )}

                  {/* Remediation */}
                  {item.remediation && (
                    <div className="p-3 bg-emerald-50/80 rounded-xl border border-emerald-200 text-xs text-emerald-900 space-y-1 font-sans">
                      <span className="font-bold flex items-center gap-1.5 text-emerald-800">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        Remediation &amp; Secure Pattern:
                      </span>
                      <p className="leading-relaxed text-emerald-800/90">{item.remediation}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Categorized Strings Explorer (Like PE/ELF Binaries) */}
      {/* ========================================================================= */}
      {activeSubTab === 'strings' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={stringSearch}
                onChange={(e) => setStringSearch(e.target.value)}
                placeholder="Search extracted strings..."
                className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Category Pills */}
            <div className="flex flex-wrap items-center gap-1 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
              <button
                onClick={() => setStringCategory('all')}
                className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                  stringCategory === 'all'
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All ({strings?.total_count || allRawStrings.length})
              </button>
              <button
                onClick={() => setStringCategory('network')}
                className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                  stringCategory === 'network'
                    ? 'bg-white text-indigo-700 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Network ({categorized.network?.length || 0})
              </button>
              <button
                onClick={() => setStringCategory('commands')}
                className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                  stringCategory === 'commands'
                    ? 'bg-white text-rose-700 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Commands / LOLBins ({categorized.commands?.length || 0})
              </button>
              <button
                onClick={() => setStringCategory('file_paths')}
                className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                  stringCategory === 'file_paths'
                    ? 'bg-white text-blue-700 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                File Paths ({categorized.file_paths?.length || 0})
              </button>
              <button
                onClick={() => setStringCategory('registry')}
                className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                  stringCategory === 'registry'
                    ? 'bg-white text-purple-700 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Registry / Configs ({categorized.registry?.length || 0})
              </button>
            </div>
          </div>

          {/* Min Length Filter */}
          <div className="flex items-center gap-3 p-3 bg-slate-50 border border-slate-200 rounded-2xl text-xs">
            <span className="font-semibold text-slate-700 flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-500" />
              <span>Min Length Filter:</span>
            </span>
            <input
              type="number"
              min="1"
              max="1000"
              value={minStrLength}
              onChange={(e) => setMinStrLength(e.target.value)}
              className="w-16 px-2.5 py-1 text-xs bg-white border border-slate-300 rounded-lg text-slate-800 font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            <span className="text-slate-500 font-mono text-[11px]">
              Showing {activeStringsList.length} matching strings
            </span>
          </div>

          {/* String Table */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white max-h-[500px] overflow-y-auto font-mono text-xs divide-y divide-slate-100">
            {activeStringsList.length === 0 ? (
              <div className="p-8 text-center text-slate-400">No strings found matching filter.</div>
            ) : (
              activeStringsList.map((str, idx) => (
                <div
                  key={idx}
                  className="p-2.5 hover:bg-slate-50 flex items-center justify-between gap-3 group"
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <span className="w-10 text-right select-none text-slate-400 text-[11px] shrink-0">
                      {idx + 1}
                    </span>
                    <span className="text-slate-800 break-all select-all font-mono">
                      {workspaceJobs && workspaceJobs.length > 0 ? (
                        <ReferencedText
                          text={str}
                          workspaceJobs={workspaceJobs}
                          onSelectJob={onSelectJob}
                        />
                      ) : (
                        str
                      )}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopyString(str, idx)}
                    className="p-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 transition-colors opacity-0 group-hover:opacity-100 shrink-0 cursor-pointer"
                    title="Copy string"
                  >
                    {copiedStringIdx === idx ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Hardcoded Secrets & CTF Flags */}
      {/* ========================================================================= */}
      {activeSubTab === 'secrets' && secrets_and_ctf && (
        <div className="space-y-6">
          {/* CTF Flags */}
          {secrets_and_ctf.ctf_flags.length > 0 && (
            <div className="border border-purple-300 bg-purple-50/50 rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-purple-900 font-bold text-sm">
                  <Flag className="w-5 h-5 text-purple-600" />
                  <span>Captured CTF Flags ({secrets_and_ctf.ctf_flags.length})</span>
                </div>
                <span className="text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded bg-purple-600 text-white">
                  CTF Solved
                </span>
              </div>

              <div className="divide-y divide-purple-100 font-mono text-xs bg-white rounded-xl border border-purple-200 overflow-hidden">
                {secrets_and_ctf.ctf_flags.map((flagItem, idx) => (
                  <div key={idx} className="p-3.5 flex flex-wrap items-center justify-between gap-3 hover:bg-purple-50/40">
                    <div className="flex items-center gap-2">
                      <span className="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-800 font-sans font-semibold">
                        {flagItem.format}
                      </span>
                      <span className="font-bold text-purple-900 select-all break-all">{flagItem.flag}</span>
                    </div>

                    <div className="flex items-center gap-2 font-sans">
                      {flagItem.source && (
                        <span className="text-[10px] text-slate-400 font-mono truncate max-w-[150px]">
                          {flagItem.source}
                        </span>
                      )}
                      <button
                        onClick={() => handleCopyFlag(flagItem.flag, idx)}
                        className="px-2.5 py-1 bg-purple-100 hover:bg-purple-200 text-purple-800 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        {copiedFlagIdx === idx ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedFlagIdx === idx ? 'Copied' : 'Copy Flag'}</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Hardcoded API Credentials & Secrets */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
              <span>Hardcoded API Keys &amp; Credentials ({secrets_and_ctf.secrets.length})</span>
              <span className="text-[10px] text-slate-400 font-mono">AWS, GitHub, Private Keys, JWTs, JDBC</span>
            </div>

            {secrets_and_ctf.secrets.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                No high-confidence hardcoded secrets or API tokens identified in bytecode or constant pool.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {secrets_and_ctf.secrets.map((sec, idx) => (
                  <div key={idx} className="p-4 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Key className="w-4 h-4 text-slate-500" />
                        <span className="font-bold text-slate-900 font-sans">{sec.type}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${getSeverityBadge(sec.severity)}`}>
                          {sec.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-sans">{sec.description}</p>
                      <div className="text-slate-800 font-bold text-xs pt-1 select-all break-all">
                        {sec.masked}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 font-sans shrink-0">
                      <button
                        onClick={() => handleCopySecret(sec.masked, idx)}
                        className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        {copiedSecretIdx === idx ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedSecretIdx === idx ? 'Copied' : 'Copy Masked'}</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Base64 Decoded Blocks & Payloads */}
      {/* ========================================================================= */}
      {activeSubTab === 'base64' && (
        <div className="space-y-4">
          {b64_blocks.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No continuous Base64-encoded payload blocks detected in archive constant pools or resource streams.
            </div>
          ) : (
            <div className="space-y-3 font-mono text-xs">
              {b64_blocks.map((block: JarBase64Block, idx: number) => {
                const isShowingRaw = Boolean(showRawB64[idx]);
                return (
                  <div
                    key={idx}
                    className="p-4 rounded-2xl border border-slate-200 bg-slate-50 space-y-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900 font-sans">
                          Base64 Payload #{idx + 1}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-purple-100 text-purple-800 font-bold font-sans">
                          {block.threat || 'Decoded Payload'}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono">
                          {block.length} bytes encoded
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-mono">
                          {block.encoding}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 font-sans">
                        <button
                          onClick={() =>
                            setShowRawB64((prev) => ({ ...prev, [idx]: !prev[idx] }))
                          }
                          className="px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-lg text-xs font-semibold cursor-pointer"
                        >
                          {isShowingRaw ? 'View Decoded' : 'View Raw Encoded'}
                        </button>
                        <button
                          onClick={() =>
                            handleCopyB64(
                              isShowingRaw ? block.encoded_full || block.encoded : block.decoded_preview,
                              idx
                            )
                          }
                          className="px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                        >
                          {copiedB64Idx === idx ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                          <span>{copiedB64Idx === idx ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Secondary IOCs in Payload */}
                    {block.iocs && block.iocs.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 font-sans text-xs">
                        <span className="font-semibold text-rose-700">Embedded IOCs:</span>
                        {block.iocs.map((ioc, iocIdx) => (
                          <span
                            key={iocIdx}
                            className="px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-200 font-mono text-[11px]"
                          >
                            {ioc}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Payload Content Viewer */}
                    <div className="bg-white p-3 rounded-xl border border-slate-200 max-h-48 overflow-y-auto whitespace-pre-wrap break-all text-slate-800 font-mono leading-relaxed">
                      {isShowingRaw ? block.encoded_full || block.encoded : block.decoded_preview}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: LOLBins & Host Commands */}
      {/* ========================================================================= */}
      {activeSubTab === 'lolbins' && (
        <div className="space-y-4">
          {/* Detected Shell Commands */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
              <span>Detected Host Shell Commands ({detected_commands.length})</span>
              <span className="text-[10px] text-slate-400 font-mono">
                Extracted from bytecode &amp; constant strings
              </span>
            </div>
            <div className="p-3 divide-y divide-slate-100 font-mono text-xs">
              {detected_commands.length === 0 ? (
                <div className="p-4 text-center text-slate-400">
                  No OS command-line patterns discovered in bytecode constants.
                </div>
              ) : (
                detected_commands.map((cmd, i) => (
                  <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                    <span className="text-rose-700 font-bold break-all">{cmd}</span>
                    <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-sans text-[10px] font-bold shrink-0">
                      Shell Command
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Matched LOLBins */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
              <span>Living-off-the-Land Binaries (LOLBins) Invocations ({lolbin_matches.length})</span>
              <span className="text-[10px] text-slate-400 font-mono">MITRE ATT&amp;CK T1218</span>
            </div>
            <div className="divide-y divide-slate-100 font-mono text-xs">
              {lolbin_matches.length === 0 ? (
                <div className="p-6 text-center text-slate-400">
                  No LOLBins (certutil, powershell, bitsadmin, mshta, schtasks) identified.
                </div>
              ) : (
                lolbin_matches.map((item: JarLolbinMatch, i: number) => (
                  <div key={i} className="p-3.5 hover:bg-slate-50/80 space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <strong className="text-slate-900 font-bold font-sans">{item.name}</strong>
                        <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-sans text-[10px] font-bold">
                          {item.category}
                        </span>
                      </div>
                      <span className="text-slate-500 font-mono text-[11px]">
                        Matched in: {item.matched_in}
                      </span>
                    </div>
                    <p className="text-slate-600 font-sans text-xs">{item.description}</p>
                    <div className="p-2 bg-slate-50 rounded-lg border border-slate-200 text-rose-700 break-all text-[11px]">
                      {item.matched_text}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: MANIFEST.MF & Policy */}
      {/* ========================================================================= */}
      {activeSubTab === 'manifest' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                Main-Class Standalone Entry Point
              </span>
              <div className="font-mono text-xs font-bold text-indigo-700 bg-white p-2.5 rounded-xl border border-slate-200 break-all">
                {main_class || '<None declared in manifest>'}
              </div>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                Permissions Security Policy
              </span>
              <div
                className={`font-mono text-xs font-bold p-2.5 rounded-xl border break-all ${
                  isAllPermissions
                    ? 'bg-rose-50 border-rose-200 text-rose-700'
                    : 'bg-white border-slate-200 text-slate-700'
                }`}
              >
                {permissions || 'sandbox (default restricted)'}
              </div>
            </div>
          </div>

          {/* Raw Manifest Viewer */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 text-slate-800 font-mono text-xs">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
              <span className="font-bold text-slate-800">META-INF/MANIFEST.MF</span>
              <button
                onClick={handleCopyManifest}
                className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedManifest ? (
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>{copiedManifest ? 'Copied' : 'Copy Manifest'}</span>
              </button>
            </div>
            <div className="p-4 max-h-[400px] overflow-y-auto space-y-1 bg-white">
              {(manifest_content || 'Manifest empty or absent.').split('\n').map((line, i) => (
                <div key={i} className="flex hover:bg-slate-50 leading-5">
                  <span className="w-8 select-none text-slate-400 text-right pr-3 shrink-0">
                    {i + 1}
                  </span>
                  <span className="whitespace-pre text-slate-800">{line || ' '}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Packages */}
          {packages.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Package className="w-3.5 h-3.5 text-amber-600" />
                  <span>Discovered Package Namespaces ({packages.length})</span>
                </span>
              </div>
              <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 font-mono text-xs max-h-48 overflow-y-auto">
                {packages.map((pkg, i) => (
                  <div key={i} className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-slate-700 truncate">
                    {pkg}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Digital Signature & X.509 Trust */}
      {/* ========================================================================= */}
      {activeSubTab === 'signature' && (
        <div className="space-y-4">
          <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div>
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                  JAR Archive Code-Signing &amp; X.509 Trust Chain
                </span>
                <div className="flex flex-wrap items-center gap-2 mt-1">
                  <span
                    className={`text-xs px-3 py-1 rounded-full font-bold uppercase ${
                      signatureStatus === 'VALID'
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                        : signatureStatus === 'SELF_SIGNED' || signatureStatus === 'DEBUG_KEY'
                        ? 'bg-rose-100 text-rose-800 border border-rose-300'
                        : signatureStatus === 'EXPIRED'
                        ? 'bg-amber-100 text-amber-800 border border-amber-300'
                        : 'bg-slate-200 text-slate-700'
                    }`}
                  >
                    {signatureStatus}
                  </span>

                  {signing_info?.certificate?.is_self_signed && (
                    <span className="text-xs px-2.5 py-1 rounded-lg font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                      Self-Signed Untrusted Certificate
                    </span>
                  )}

                  {signing_info?.certificate?.is_debug_key && (
                    <span className="text-xs px-2.5 py-1 rounded-lg font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                      Android / Java Debug Signing Key
                    </span>
                  )}
                </div>
              </div>

              {signing_info?.signature_files && (
                <div className="text-right text-[11px] font-mono text-slate-400">
                  <span>Signatures: {signing_info.signature_files.join(', ')}</span>
                </div>
              )}
            </div>

            {/* Partially Signed Warning */}
            {signing_info?.is_partially_signed && (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-rose-900">
                    Partially Signed JAR: {signing_info.unsigned_classes_count} Unsigned Executable Classes
                  </h4>
                  <p className="text-xs text-rose-700 leading-relaxed">
                    While the archive contains digital signature files, the signature manifest (.SF) does not cover all compiled bytecode classes. Unsigned classes can be modified or injected to bypass signature validation.
                  </p>
                  {signing_info.unsigned_classes && (
                    <div className="pt-2 font-mono text-[11px] text-rose-800 space-y-0.5">
                      {signing_info.unsigned_classes.slice(0, 5).map((uc, i) => (
                        <div key={i}>• {uc}</div>
                      ))}
                      {signing_info.unsigned_classes.length > 5 && (
                        <div className="text-rose-500 italic">...and {signing_info.unsigned_classes.length - 5} more unsigned classes</div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Certificate Details */}
            {signing_info?.certificate ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[10px] font-sans uppercase font-bold text-slate-400 block">
                    Certificate Subject
                  </span>
                  <div className="text-slate-800 break-all">
                    {signing_info.certificate.subject || 'N/A'}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[10px] font-sans uppercase font-bold text-slate-400 block">
                    Issuer Authority
                  </span>
                  <div className="text-slate-800 break-all">
                    {signing_info.certificate.issuer || 'N/A'}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[10px] font-sans uppercase font-bold text-slate-400 block">
                    Validity Range
                  </span>
                  <div className="text-slate-700 text-[11px]">
                    From: {signing_info.certificate.valid_from || 'N/A'}
                    <br />
                    To: {signing_info.certificate.valid_to || 'N/A'}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[10px] font-sans uppercase font-bold text-slate-400 block">
                    SHA-256 Fingerprint
                  </span>
                  <div className="text-indigo-600 font-bold break-all text-[11px]">
                    {signing_info.certificate.fingerprint_sha256 || 'N/A'}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-6 bg-white rounded-xl border border-slate-200 text-center text-xs text-slate-400">
                This JAR archive has not been digitally signed with jarsigner or apksigner. No PKCS#7 certificate blocks found in META-INF.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Embedded Resources & Native Droppers */}
      {/* ========================================================================= */}
      {activeSubTab === 'resources' && (
        <div className="space-y-4">
          {embedded_resources.length === 0 && embedded_binaries.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No embedded non-class resources or native libraries bundled in this JAR.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>
                  Embedded Resources &amp; Payloads ({embedded_resources.length + embedded_binaries.length})
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  Inspect native DLLs, SOs, executables, scripts, and configs
                </span>
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {embedded_resources.map((res: JarEmbeddedResource, i: number) => (
                  <div
                    key={i}
                    className="p-3 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-bold text-slate-800 break-all">{res.name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-sans">
                        {res.type}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 font-sans">
                      <span className="text-slate-500 text-xs font-mono">{formatBytes(res.size)}</span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          res.threat_level === 'DANGEROUS'
                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                            : res.threat_level === 'SUSPICIOUS'
                            ? 'bg-amber-100 text-amber-800 border border-amber-300'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {res.threat_level}
                      </span>
                    </div>
                  </div>
                ))}

                {/* Legacy embedded binaries if not in resources */}
                {embedded_binaries
                  .filter((b) => !embedded_resources.some((r) => r.name === b))
                  .map((b, i) => (
                    <div
                      key={`bin-${i}`}
                      className="p-3 flex items-center justify-between gap-3 hover:bg-slate-50"
                    >
                      <span className="text-purple-700 font-bold">{b}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 font-sans">
                        Native Dropper
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Network IOCs & Endpoints */}
      {/* ========================================================================= */}
      {activeSubTab === 'urls' && allUrls.length > 0 && (
        <div className="space-y-4">
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
              <span>Extracted Network Endpoints &amp; C2 Infrastructure ({allUrls.length})</span>
              <span className="text-[10px] text-slate-400 font-mono">VirusTotal &amp; URL Intel</span>
            </div>
            <div className="divide-y divide-slate-100 font-mono text-xs">
              {allUrls.map((url, idx) => (
                <div
                  key={idx}
                  className="p-3 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50 group"
                >
                  <span className="text-indigo-700 font-semibold break-all select-all">{url}</span>
                  <div className="flex items-center gap-2 font-sans shrink-0">
                    <button
                      onClick={() => handleCopyUrl(url, idx)}
                      className="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-xs flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      {copiedUrlIdx === idx ? (
                        <Check className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>{copiedUrlIdx === idx ? 'Copied' : 'Copy'}</span>
                    </button>
                    <a
                      href={`https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded text-xs flex items-center gap-1 transition-colors font-semibold"
                    >
                      <ExternalLink className="w-3 h-3" />
                      <span>VT</span>
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Anti-Analysis & Evasion Inspector */}
      {/* ========================================================================= */}
      {activeSubTab === 'anti_analysis' && antiAnalysis && (
        <AntiAnalysisInspectorCard antiAnalysis={antiAnalysis} filename={filename} />
      )}
    </div>
  );
};
