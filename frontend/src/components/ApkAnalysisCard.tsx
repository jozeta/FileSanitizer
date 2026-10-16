import React, { useState, useMemo } from 'react';
import {
  Smartphone,
  ShieldAlert,
  AlertTriangle,
  Key,
  Layers,
  Radio,
  Globe,
  Cpu,
  Package,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Copy,
  Check,
  Search,
  FileCode,
  Code2,
  Binary,
  FileText,
  Hash
} from 'lucide-react';
import { ApkAnalysisData, Finding, ApkClassDetail, ApkEmbeddedSourceFile } from '../types';
import { formatBytes } from '../utils/formatters';

interface ApkAnalysisCardProps {
  apkInfo?: ApkAnalysisData;
  filename?: string;
  findings?: Finding[];
}

export const ApkAnalysisCard: React.FC<ApkAnalysisCardProps> = ({
  apkInfo,
  filename = 'application.apk'
}) => {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'decompiler' | 'embedded_sources' | 'native_so' | 'permissions' | 'components' | 'dex' | 'strings' | 'certificate' | 'manifest' | 'mitre'
  >('overview');

  const [permSearch, setPermSearch] = useState('');
  const [permFilter, setPermFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Decompiler Tab State
  const [classSearch, setClassSearch] = useState('');
  const [selectedClassIndex, setSelectedClassIndex] = useState<number>(0);
  const [decompilerMode, setDecompilerMode] = useState<'java' | 'smali'>('java');
  const [selectedMethodIndex, setSelectedMethodIndex] = useState<number>(0);

  // Embedded Sources Tab State
  const [selectedSourceIndex, setSelectedSourceIndex] = useState<number>(0);
  const [sourceSearch, setSourceSearch] = useState('');

  // Strings Tab State
  const [stringSearch, setStringSearch] = useState('');
  const [selectedStringCategory, setSelectedStringCategory] = useState<
    'all' | 'secrets' | 'urls' | 'ips' | 'commands' | 'crypto' | 'paths' | 'apis'
  >('all');

  // Manifest Tab State
  const [manifestSearch, setManifestSearch] = useState('');

  // Sensitive APIs Tab State
  const [apiSearch, setApiSearch] = useState('');
  const [selectedApiCategory, setSelectedApiCategory] = useState<string>('all');
  const [selectedApiSeverity, setSelectedApiSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [expandedApiIndex, setExpandedApiIndex] = useState<number | null>(null);

  if (!apkInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Smartphone className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No Android APK / Dalvik DEX analysis data available for this file.</p>
      </div>
    );
  }

  const {
    is_standalone_dex = false,
    package_name = 'Unknown',
    version_code = '1',
    version_name = '1.0',
    min_sdk = 'N/A',
    target_sdk = 'N/A',
    compile_sdk,
    app_name,
    manifest_xml,
    security_flags = {},
    permissions = [],
    dangerous_permissions = [],
    components = {},
    signing_info = {},
    dex_info = { dex_count: 1, classes_count: 0, total_strings_count: 0, detected_apis: [] },
    classes = [],
    embedded_source_files = [],
    native_architectures = [],
    native_libraries = [],
    native_so_details = [],
    categorized_strings,
    online_intel,
    packer_info,
    malware_signatures = [],
    keystore_audit,
    security_audit = [],
    embedded_assets = [],
    iocs = { urls: [], ips: [] },
    mitre_mobile_techniques = [],
    risk_score = 0,
    risk_level = 'LOW'
  } = apkInfo;

  const activities = components.activities || [];
  const services = components.services || [];
  const receivers = components.receivers || [];
  const providers = components.providers || [];
  const totalComponents = activities.length + services.length + receivers.length + providers.length;

  const exportedActivities = activities.filter(a => a.exported);
  const exportedServices = services.filter(s => s.exported);
  const exportedReceivers = receivers.filter(r => r.exported);
  const exportedProviders = providers.filter(p => p.exported);
  const totalExported = exportedActivities.length + exportedServices.length + exportedReceivers.length + exportedProviders.length;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredPerms = dangerous_permissions.filter(p => {
    const matchesSearch =
      p.permission.toLowerCase().includes(permSearch.toLowerCase()) ||
      p.title.toLowerCase().includes(permSearch.toLowerCase()) ||
      p.description.toLowerCase().includes(permSearch.toLowerCase());
    const matchesFilter = permFilter === 'all' || p.severity === permFilter;
    return matchesSearch && matchesFilter;
  });

  const filteredClasses = useMemo(() => {
    if (!classes || classes.length === 0) return [];
    if (!classSearch.trim()) return classes;
    const q = classSearch.toLowerCase();
    return classes.filter(
      c => c.name.toLowerCase().includes(q) || (c.package && c.package.toLowerCase().includes(q))
    );
  }, [classes, classSearch]);

  const selectedClass: ApkClassDetail | undefined = filteredClasses[selectedClassIndex] || filteredClasses[0] || classes[0];

  const filteredSourceFiles = useMemo(() => {
    if (!embedded_source_files || embedded_source_files.length === 0) return [];
    if (!sourceSearch.trim()) return embedded_source_files;
    const q = sourceSearch.toLowerCase();
    return embedded_source_files.filter(
      f => f.filename.toLowerCase().includes(q) || f.file_type.toLowerCase().includes(q)
    );
  }, [embedded_source_files, sourceSearch]);

  const selectedSource: ApkEmbeddedSourceFile | undefined =
    filteredSourceFiles[selectedSourceIndex] || filteredSourceFiles[0] || embedded_source_files[0];

  const filteredApis = useMemo(() => {
    const apis = dex_info.detected_apis || [];
    return apis.filter(api => {
      const q = apiSearch.toLowerCase().trim();
      const matchesSearch = !q ||
        api.title.toLowerCase().includes(q) ||
        api.api.toLowerCase().includes(q) ||
        (api.description && api.description.toLowerCase().includes(q)) ||
        (api.risk_explanation && api.risk_explanation.toLowerCase().includes(q)) ||
        (api.remediation && api.remediation.toLowerCase().includes(q)) ||
        (api.cwe && api.cwe.toLowerCase().includes(q)) ||
        (api.owasp_mobile && api.owasp_mobile.toLowerCase().includes(q)) ||
        (api.mitre && api.mitre.toLowerCase().includes(q)) ||
        (api.mitre_name && api.mitre_name.toLowerCase().includes(q));

      const matchesCat = selectedApiCategory === 'all' || api.category === selectedApiCategory;
      const matchesSev = selectedApiSeverity === 'all' || api.severity === selectedApiSeverity;
      return matchesSearch && matchesCat && matchesSev;
    });
  }, [dex_info.detected_apis, apiSearch, selectedApiCategory, selectedApiSeverity]);

  const getRiskBadgeColor = (lvl: string) => {
    switch (lvl.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 border-rose-200';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'high':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'medium':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      default:
        return 'bg-slate-50 text-slate-700 border-slate-200';
    }
  };

  const getAuditStatusBadge = (status: 'PASS' | 'WARN' | 'FAIL') => {
    switch (status) {
      case 'FAIL':
        return {
          icon: <XCircle className="w-4 h-4 text-rose-600 shrink-0" />,
          badge: 'bg-rose-100 text-rose-800 border-rose-200',
          border: 'border-rose-200 bg-rose-50/30'
        };
      case 'WARN':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />,
          badge: 'bg-amber-100 text-amber-800 border-amber-200',
          border: 'border-amber-200 bg-amber-50/30'
        };
      case 'PASS':
      default:
        return {
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />,
          badge: 'bg-emerald-100 text-emerald-800 border-emerald-200',
          border: 'border-slate-200 bg-white'
        };
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-emerald-50 text-emerald-600 rounded-2xl shrink-0">
            <Smartphone className="w-8 h-8" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-xl font-bold text-slate-900">
                {is_standalone_dex ? 'Dalvik Executable (.dex) Forensic Triage' : 'Android Application Package (APK) Forensic Analysis'}
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                {filename}
              </span>
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${getRiskBadgeColor(risk_level)}`}>
                Risk: {risk_level} ({risk_score}/100)
              </span>
              {security_flags.debuggable && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  ⚠️ Debuggable Enabled
                </span>
              )}
              {signing_info.is_debug_key && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-500 text-white">
                  Debug Keystore
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              {is_standalone_dex
                ? 'Bytecode instruction disassembly, sensitive Dalvik API detection, hardcoded URLs, and reflection patterns.'
                : 'Dalvik bytecode decompiler, multi-DEX disassembly, embedded Java/Kotlin source scanner, native ELF libraries, and security compliance audit.'}
            </p>
          </div>
        </div>

        {/* Quick Stats Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Permissions</span>
            <strong className="text-slate-900">{permissions.length}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Dangerous</span>
            <strong className={dangerous_permissions.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {dangerous_permissions.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Classes</span>
            <strong className="text-slate-900">{classes.length || dex_info.classes_count || 0}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Embedded Src</span>
            <strong className={embedded_source_files.length > 0 ? 'text-indigo-600' : 'text-slate-900'}>
              {embedded_source_files.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Native .so</span>
            <strong className={native_libraries.length > 0 ? 'text-amber-600' : 'text-slate-900'}>
              {native_libraries.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Exported</span>
            <strong className={totalExported > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {totalExported} / {totalComponents}
            </strong>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-100 pb-3">
        <button
          onClick={() => setActiveTab('overview')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'overview'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          Overview &amp; Audit
        </button>

        <button
          onClick={() => setActiveTab('decompiler')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'decompiler'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          Decompiler &amp; Bytecode ({classes.length || dex_info.classes_count || 0})
        </button>

        {embedded_source_files.length > 0 && (
          <button
            onClick={() => setActiveTab('embedded_sources')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'embedded_sources'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            Embedded Sources ({embedded_source_files.length})
          </button>
        )}

        {(native_so_details.length > 0 || native_libraries.length > 0) && (
          <button
            onClick={() => setActiveTab('native_so')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'native_so'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Binary className="w-3.5 h-3.5" />
            Native ELF (.so) ({native_libraries.length})
          </button>
        )}

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('permissions')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'permissions'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Permissions ({dangerous_permissions.length})
          </button>
        )}

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('components')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'components'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Components ({totalExported} Exported)
          </button>
        )}

        <button
          onClick={() => setActiveTab('dex')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'dex'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          Sensitive APIs ({(dex_info.detected_apis || []).length})
        </button>

        {categorized_strings && (
          <button
            onClick={() => setActiveTab('strings')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'strings'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            Strings &amp; Secrets
          </button>
        )}

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('certificate')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'certificate'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Signing Cert
          </button>
        )}

        {manifest_xml && (
          <button
            onClick={() => setActiveTab('manifest')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'manifest'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            AndroidManifest.xml
          </button>
        )}

        {mitre_mobile_techniques.length > 0 && (
          <button
            onClick={() => setActiveTab('mitre')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'mitre'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            MITRE Mobile ({mitre_mobile_techniques.length})
          </button>
        )}
      </div>

      {/* Tab: Overview & Audit */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Package Name
              </span>
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-slate-800 truncate" title={package_name}>
                  {package_name}
                </span>
                <button
                  onClick={() => handleCopy(package_name, 'pkg')}
                  className="p-1 text-slate-400 hover:text-slate-600"
                  title="Copy package name"
                >
                  {copiedKey === 'pkg' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Version Details
              </span>
              <span className="font-mono text-sm font-semibold text-slate-800">
                v{version_name} <span className="text-slate-400 text-xs">(Code {version_code})</span>
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                SDK Level
              </span>
              <span className="font-mono text-sm font-semibold text-slate-800">
                Min: {min_sdk} / Target: {target_sdk} {compile_sdk ? `/ Compile: ${compile_sdk}` : ''}
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Application Name
              </span>
              <span className="text-sm font-semibold text-slate-800 truncate block">
                {app_name || package_name.split('.').pop() || 'Android App'}
              </span>
            </div>
          </div>

          {/* Online Threat Intelligence & External Hashes */}
          {online_intel && (
            <div className="p-5 bg-gradient-to-br from-slate-900 to-slate-800 text-white rounded-2xl shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-700/60 pb-3">
                <div className="flex items-center gap-2">
                  <Globe className="w-5 h-5 text-emerald-400" />
                  <h4 className="text-sm font-bold tracking-wide">
                    Online Mobile Threat Intelligence &amp; Hash Lookups
                  </h4>
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  Multi-Engine Lookup &amp; Intel Hub
                </span>
              </div>

              {/* Google Play Store Verification Status */}
              {online_intel.play_store_status && (
                <div className={`p-3 rounded-xl border flex items-center justify-between text-xs ${
                  online_intel.play_store_status === 'verified'
                    ? 'bg-emerald-950/70 border-emerald-500/50 text-emerald-200'
                    : 'bg-amber-950/70 border-amber-500/50 text-amber-200'
                }`}>
                  <div className="flex items-center gap-2.5">
                    {online_intel.play_store_status === 'verified' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                    <div>
                      <strong className="font-semibold block">
                        {online_intel.play_store_status === 'verified'
                          ? 'Official Google Play Store Application'
                          : 'Sideloaded / Unlisted Application (Not on Google Play)'}
                      </strong>
                      <span className="text-[11px] opacity-80 block">
                        {online_intel.play_store_title
                          ? `Official Title: "${online_intel.play_store_title}"`
                          : (online_intel.play_store_details || 'Package identity not found in the Google Play index.')}
                      </span>
                    </div>
                  </div>
                  {online_intel.google_play_url && (
                    <a
                      href={online_intel.google_play_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-[11px] font-medium shrink-0 flex items-center gap-1 transition-all"
                    >
                      <span>View Store</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              )}

              {/* Multi-Feed Threat Intelligence Consensus Verdict */}
              {online_intel.overall_verdict && online_intel.overall_verdict !== 'unknown' && (
                <div className={`p-3.5 rounded-xl border text-xs space-y-2 ${
                  online_intel.overall_verdict === 'malicious'
                    ? 'bg-rose-950/80 border-rose-500/60 text-rose-200'
                    : online_intel.overall_verdict === 'suspicious'
                    ? 'bg-amber-950/70 border-amber-500/50 text-amber-200'
                    : 'bg-emerald-950/70 border-emerald-500/50 text-emerald-200'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className={`w-4 h-4 ${online_intel.overall_verdict === 'malicious' ? 'text-rose-400' : 'text-amber-400'}`} />
                      <span className="font-bold uppercase tracking-wider text-[11px]">
                        CTI Consensus: {online_intel.overall_verdict} Android Binary
                      </span>
                    </div>
                    {online_intel.feeds?.virustotal?.detections > 0 && (
                      <span className="font-mono text-[11px] bg-rose-900/80 px-2 py-0.5 rounded text-rose-200 border border-rose-700/60">
                        VT: {online_intel.feeds?.virustotal?.detections}/{online_intel.feeds?.virustotal?.total} Engines
                      </span>
                    )}
                  </div>
                  {online_intel.malware_families && online_intel.malware_families.length > 0 && (
                    <div className="text-[11px] flex flex-wrap items-center gap-1.5 pt-0.5">
                      <span className="opacity-80 font-semibold">Detected Families:</span>
                      {online_intel.malware_families.map((fam, fIdx) => (
                        <span key={fIdx} className="bg-rose-900/90 text-rose-100 px-2 py-0.5 rounded-md font-mono text-[10px] border border-rose-700/70">
                          {fam}
                        </span>
                      ))}
                    </div>
                  )}
                  {online_intel.threat_tags && online_intel.threat_tags.length > 0 && (
                    <div className="text-[11px] flex flex-wrap items-center gap-1 pt-0.5">
                      <span className="opacity-80 font-semibold">Threat Tags:</span>
                      {online_intel.threat_tags.slice(0, 8).map((tag, tIdx) => (
                        <span key={tIdx} className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded text-[10px] font-mono border border-slate-700">
                          #{tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Hash Pills with Copy */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-800/80 rounded-xl border border-slate-700/80">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1 font-mono uppercase text-[10px]">
                      <Hash className="w-3 h-3 text-emerald-400" /> SHA-256
                    </span>
                    <button
                      onClick={() => handleCopy(online_intel.sha256, 'intel_sha256')}
                      className="text-slate-400 hover:text-white"
                      title="Copy SHA-256"
                    >
                      {copiedKey === 'intel_sha256' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 truncate" title={online_intel.sha256}>
                    {online_intel.sha256}
                  </div>
                </div>

                <div className="p-3 bg-slate-800/80 rounded-xl border border-slate-700/80">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1 font-mono uppercase text-[10px]">
                      <Hash className="w-3 h-3 text-indigo-400" /> SHA-1
                    </span>
                    <button
                      onClick={() => handleCopy(online_intel.sha1, 'intel_sha1')}
                      className="text-slate-400 hover:text-white"
                      title="Copy SHA-1"
                    >
                      {copiedKey === 'intel_sha1' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 truncate" title={online_intel.sha1}>
                    {online_intel.sha1}
                  </div>
                </div>

                <div className="p-3 bg-slate-800/80 rounded-xl border border-slate-700/80">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1 font-mono uppercase text-[10px]">
                      <Hash className="w-3 h-3 text-amber-400" /> MD5
                    </span>
                    <button
                      onClick={() => handleCopy(online_intel.md5, 'intel_md5')}
                      className="text-slate-400 hover:text-white"
                      title="Copy MD5"
                    >
                      {copiedKey === 'intel_md5' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="font-mono text-xs text-slate-200 truncate" title={online_intel.md5}>
                    {online_intel.md5}
                  </div>
                </div>
              </div>

              {/* External Lookup Action Buttons */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                {online_intel.koodous_url && (
                  <a
                    href={online_intel.koodous_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 border border-emerald-500/40 rounded-xl text-xs font-semibold transition-all"
                  >
                    <span>Koodous Mobile Intel</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}

                {online_intel.virustotal_url && (
                  <a
                    href={online_intel.virustotal_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/40 rounded-xl text-xs font-semibold transition-all"
                  >
                    <span>VirusTotal Hash Check</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}

                {online_intel.malwarebazaar_url && (
                  <a
                    href={online_intel.malwarebazaar_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600/30 hover:bg-purple-600/50 text-purple-300 border border-purple-500/40 rounded-xl text-xs font-semibold transition-all"
                  >
                    <span>MalwareBazaar Sample</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}

                {online_intel.google_play_url && package_name !== 'Unknown' && (
                  <a
                    href={online_intel.google_play_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-600/30 hover:bg-teal-600/50 text-teal-300 border border-teal-500/40 rounded-xl text-xs font-semibold transition-all"
                  >
                    <span>Google Play Store</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}

                {online_intel.apkpure_url && package_name !== 'Unknown' && (
                  <a
                    href={online_intel.apkpure_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600 rounded-xl text-xs font-semibold transition-all"
                  >
                    <span>APKPure Archive</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          )}

          {/* Code Protector / Packer Detection */}
          {packer_info?.is_packed && (
            <div className="p-4 bg-amber-50 rounded-2xl border border-amber-200 text-amber-900 flex items-start gap-3">
              <div className="p-2 bg-amber-100 text-amber-700 rounded-xl shrink-0">
                <Package className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <h4 className="text-xs font-bold uppercase tracking-wider text-amber-800">
                  Packer / Code Protector Detected: {packer_info.packer_name}
                </h4>
                <p className="text-xs text-amber-700">
                  {packer_info.description}
                </p>
                {packer_info.matched_markers && packer_info.matched_markers.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {packer_info.matched_markers.map((m, mIdx) => (
                      <span key={mIdx} className="px-2 py-0.5 bg-amber-200/80 text-amber-900 rounded font-mono text-[10px]">
                        {m}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Specialized Android Malware Signatures */}
          {malware_signatures && malware_signatures.length > 0 && (
            <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 space-y-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-600 shrink-0" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-rose-900">
                  High-Confidence Android Malware Behavior Signatures ({malware_signatures.length})
                </h4>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {malware_signatures.map((sig, sIdx) => (
                  <div key={sIdx} className="p-3 bg-white rounded-xl border border-rose-100 shadow-2xs space-y-1">
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-bold text-slate-800">{sig.title}</span>
                      <span className="px-2 py-0.5 bg-rose-100 text-rose-700 font-mono text-[10px] font-bold rounded uppercase">
                        {sig.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{sig.description}</p>
                    <span className="text-[10px] text-slate-400 font-mono block">Family: {sig.family}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Network Security Configuration Audit */}
          {apkInfo.network_security_config?.found && (
            <div className="p-5 bg-white rounded-2xl border border-slate-200 shadow-xs space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900">
                      Network Security Configuration Audit
                    </h4>
                    <p className="text-xs text-slate-500 font-mono">
                      {apkInfo.network_security_config.config_file || 'res/xml/network_security_config.xml'}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {apkInfo.network_security_config.trusts_user_certs ? (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1">
                      <XCircle className="w-3 h-3 text-rose-600" /> User CAs Trusted (MitM Risk)
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-600" /> System CAs Only
                    </span>
                  )}
                  {apkInfo.network_security_config.cleartext_permitted ? (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-amber-50 text-amber-700 border border-amber-200 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-amber-600" /> Cleartext Traffic Allowed
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-600" /> HTTPS Enforced
                    </span>
                  )}
                  {apkInfo.network_security_config.has_pinning ? (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-purple-600" /> Certificate Pinning
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-md bg-slate-100 text-slate-600 border border-slate-200">
                      No Pinning
                    </span>
                  )}
                </div>
              </div>

              {apkInfo.network_security_config.details && apkInfo.network_security_config.details.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  {apkInfo.network_security_config.details.map((detail, dIdx) => (
                    <div key={dIdx} className="flex items-start gap-2 text-xs text-slate-700">
                      <span className="text-slate-400 mt-0.5">•</span>
                      <span>{detail}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Security Compliance Audit Checklist */}
          {security_audit.length > 0 && (
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                    Automated Android Security Compliance Audit
                  </h4>
                  <p className="text-xs text-slate-500">
                    OWASP Mobile Application Security Verification Standard (MASVS) &amp; Android Best Practices.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
                    {security_audit.filter(a => a.status === 'PASS').length} Pass
                  </span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200">
                    {security_audit.filter(a => a.status === 'WARN').length} Warn
                  </span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200">
                    {security_audit.filter(a => a.status === 'FAIL').length} Fail
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {security_audit.map((item, idx) => {
                  const style = getAuditStatusBadge(item.status);
                  return (
                    <div
                      key={idx}
                      className={`p-3.5 rounded-xl border transition-all ${style.border} space-y-1.5`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {style.icon}
                          <span className="text-xs font-bold text-slate-900">{item.title}</span>
                        </div>
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${style.badge}`}>
                          {item.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">{item.description}</p>
                      {item.recommendation && (
                        <div className="text-[11px] text-slate-500 bg-white/70 p-2 rounded-lg border border-slate-100">
                          <strong className="text-slate-700">Remediation: </strong>
                          {item.recommendation}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Security Flags Grid */}
          {!is_standalone_dex && (
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100 space-y-3">
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Application Manifest Security Attributes
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="flex items-center gap-2.5 p-3 bg-white rounded-xl border border-slate-200">
                  {security_flags.debuggable ? (
                    <XCircle className="w-4 h-4 text-rose-600 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  )}
                  <div>
                    <span className="text-xs font-semibold block text-slate-800">android:debuggable</span>
                    <span className="text-[11px] text-slate-500">
                      {security_flags.debuggable ? 'Enabled (High Risk)' : 'Disabled (Secure)'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 p-3 bg-white rounded-xl border border-slate-200">
                  {security_flags.allow_backup ? (
                    <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  )}
                  <div>
                    <span className="text-xs font-semibold block text-slate-800">android:allowBackup</span>
                    <span className="text-[11px] text-slate-500">
                      {security_flags.allow_backup ? 'Enabled (ADB Backup Risk)' : 'Disabled'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 p-3 bg-white rounded-xl border border-slate-200">
                  {security_flags.uses_cleartext_traffic ? (
                    <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  )}
                  <div>
                    <span className="text-xs font-semibold block text-slate-800">Cleartext Traffic</span>
                    <span className="text-[11px] text-slate-500">
                      {security_flags.uses_cleartext_traffic ? 'Permitted (Insecure HTTP)' : 'Enforces TLS'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 p-3 bg-white rounded-xl border border-slate-200">
                  {signing_info.is_debug_key ? (
                    <XCircle className="w-4 h-4 text-rose-600 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  )}
                  <div>
                    <span className="text-xs font-semibold block text-slate-800">Signing Keystore</span>
                    <span className="text-[11px] text-slate-500">
                      {signing_info.is_debug_key ? 'Public Debug Cert' : 'Production Signer'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {embedded_assets.length > 0 && (
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Suspicious Embedded Secondary Assets &amp; Payloads
                </span>
                <span className="text-xs font-mono px-2 py-0.5 bg-rose-100 text-rose-700 rounded-md">
                  {embedded_assets.length} items
                </span>
              </div>
              <div className="max-h-36 overflow-y-auto font-mono text-[11px] text-slate-700 space-y-1">
                {embedded_assets.map((asset, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-rose-700">
                    <AlertTriangle className="w-3 h-3 shrink-0" />
                    <span className="truncate">{asset}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Decompiler & Dalvik Bytecode */}
      {activeTab === 'decompiler' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Code2 className="w-4 h-4 text-emerald-600" />
                Dalvik Bytecode Decompiler &amp; Smali Disassembler
              </h4>
              <p className="text-xs text-slate-500">
                Multi-DEX class browser with high-level Java decompilation and Dalvik opcode instruction disassembly.
              </p>
            </div>

            {/* Toggle Mode: Java Decompiler vs Smali Disassembly */}
            <div className="flex items-center gap-1 bg-white p-1 rounded-xl border border-slate-200 shadow-sm shrink-0">
              <button
                onClick={() => setDecompilerMode('java')}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  decompilerMode === 'java'
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Java Decompiler
              </button>
              <button
                onClick={() => setDecompilerMode('smali')}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  decompilerMode === 'smali'
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Dalvik / Smali Bytecode
              </button>
            </div>
          </div>

          {classes.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Left Column: Class Selector */}
              <div className="lg:col-span-4 bg-slate-50 rounded-2xl border border-slate-200 p-3 space-y-2 flex flex-col h-[560px]">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={classSearch}
                    onChange={e => {
                      setClassSearch(e.target.value);
                      setSelectedClassIndex(0);
                    }}
                    placeholder="Search classes..."
                    className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                  />
                </div>

                <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                  {filteredClasses.map((cls, idx) => {
                    const isSelected = cls.name === selectedClass?.name;
                    return (
                      <button
                        key={idx}
                        onClick={() => {
                          setSelectedClassIndex(idx);
                          setSelectedMethodIndex(0);
                        }}
                        className={`w-full text-left p-2.5 rounded-xl text-xs transition-all border ${
                          isSelected
                            ? 'bg-white border-slate-300 shadow-sm text-slate-900 font-semibold'
                            : 'border-transparent hover:bg-white/60 text-slate-600'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-0.5">
                          <span className="font-mono text-xs truncate font-bold text-slate-800">
                            {cls.name.split('/').pop() || cls.name}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-100 rounded text-slate-500 shrink-0">
                            {cls.methods_count} m
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 truncate font-mono">
                          {cls.package || cls.name}
                        </div>
                      </button>
                    );
                  })}
                  {filteredClasses.length === 0 && (
                    <div className="p-6 text-center text-xs text-slate-400">
                      No classes found matching search.
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column: Code Viewer / Disassembly */}
              <div className="lg:col-span-8 bg-slate-900 rounded-2xl border border-slate-800 p-4 flex flex-col h-[560px]">
                {selectedClass ? (
                  <>
                    {/* Class Details Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b border-slate-800 text-xs">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-emerald-400 font-bold text-sm">
                            {selectedClass.name}
                          </span>
                          {selectedClass.access_flags && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded">
                              {selectedClass.access_flags}
                            </span>
                          )}
                        </div>
                        {selectedClass.superclass && (
                          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                            extends {selectedClass.superclass}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => {
                            const codeToCopy =
                              decompilerMode === 'java'
                                ? selectedClass.source_code || '// No decompiled source available'
                                : (selectedClass.methods || [])
                                    .map(m => `// Method: ${m.name}${m.descriptor}\n` + (m.instructions || []).join('\n'))
                                    .join('\n\n');
                            handleCopy(codeToCopy, 'class_code');
                          }}
                          className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-all"
                        >
                          {copiedKey === 'class_code' ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy Code</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* View Mode: Java Source */}
                    {decompilerMode === 'java' && (
                      <div className="flex-1 overflow-auto bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-200">
                        {selectedClass.source_code ? (
                          <pre className="whitespace-pre leading-relaxed">{selectedClass.source_code}</pre>
                        ) : (
                          <div className="text-slate-500 italic p-6 text-center">
                            No high-level decompiled Java source available for this class. Switch to Dalvik / Smali Bytecode mode to inspect instructions.
                          </div>
                        )}
                      </div>
                    )}

                    {/* View Mode: Dalvik / Smali Bytecode Disassembly */}
                    {decompilerMode === 'smali' && (
                      <div className="flex-1 flex flex-col space-y-3 overflow-hidden">
                        {/* Method Selector */}
                        {selectedClass.methods && selectedClass.methods.length > 0 && (
                          <div className="flex items-center gap-2 overflow-x-auto pb-1 shrink-0">
                            {selectedClass.methods.map((method, mIdx) => (
                              <button
                                key={mIdx}
                                onClick={() => setSelectedMethodIndex(mIdx)}
                                className={`px-2.5 py-1 rounded-lg text-xs font-mono shrink-0 transition-all ${
                                  selectedMethodIndex === mIdx
                                    ? 'bg-emerald-600 text-white font-bold'
                                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                                }`}
                              >
                                {method.name} ({method.instructions_count || (method.instructions || []).length} ins)
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Instructions Disassembly Stream */}
                        <div className="flex-1 overflow-auto bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-200 space-y-1">
                          {selectedClass.methods && selectedClass.methods[selectedMethodIndex] ? (
                            <>
                              <div className="text-slate-500 pb-2 border-b border-slate-800 mb-2">
                                .method {selectedClass.methods[selectedMethodIndex].access_flags || 'public'}{' '}
                                {selectedClass.methods[selectedMethodIndex].name}
                                {selectedClass.methods[selectedMethodIndex].descriptor}
                              </div>
                              {selectedClass.methods[selectedMethodIndex].instructions &&
                              selectedClass.methods[selectedMethodIndex].instructions!.length > 0 ? (
                                selectedClass.methods[selectedMethodIndex].instructions!.map((ins, iIdx) => (
                                  <div key={iIdx} className="flex items-start gap-3 hover:bg-slate-900/60 px-1 rounded">
                                    <span className="text-slate-600 text-[10px] w-6 shrink-0 select-none text-right">
                                      {iIdx + 1}
                                    </span>
                                    <span className="text-emerald-300">{ins}</span>
                                  </div>
                                ))
                              ) : (
                                <div className="text-slate-500 italic p-4 text-center">
                                  No Dalvik bytecode instructions recorded for this method.
                                </div>
                              )}
                            </>
                          ) : (
                            <div className="text-slate-500 italic p-4 text-center">
                              No methods found on this class.
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="m-auto text-slate-500 text-xs">Select a class from the list to view code.</div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center bg-slate-50 rounded-2xl border border-slate-200 text-slate-400 text-xs">
              No DEX classes extracted from this package.
            </div>
          )}
        </div>
      )}

      {/* Tab: Embedded Source Code Files */}
      {activeTab === 'embedded_sources' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-indigo-600" />
                Embedded Source Code Files &amp; Framework Bundles ({embedded_source_files.length})
              </h4>
              <p className="text-xs text-slate-500">
                Extracted Java/Kotlin source, React Native/JavaScript bundles, shell scripts, and configuration files.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left Column: File List */}
            <div className="lg:col-span-4 bg-slate-50 rounded-2xl border border-slate-200 p-3 space-y-2 flex flex-col h-[560px]">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={sourceSearch}
                  onChange={e => {
                    setSourceSearch(e.target.value);
                    setSelectedSourceIndex(0);
                  }}
                  placeholder="Search files..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                {filteredSourceFiles.map((file, idx) => {
                  const isSelected = file.filename === selectedSource?.filename;
                  const dangerColor =
                    file.danger_level === 'malicious'
                      ? 'bg-rose-100 text-rose-800'
                      : file.danger_level === 'suspicious'
                      ? 'bg-amber-100 text-amber-800'
                      : 'bg-emerald-100 text-emerald-800';

                  return (
                    <button
                      key={idx}
                      onClick={() => setSelectedSourceIndex(idx)}
                      className={`w-full text-left p-2.5 rounded-xl text-xs transition-all border ${
                        isSelected
                          ? 'bg-white border-slate-300 shadow-sm text-slate-900 font-semibold'
                          : 'border-transparent hover:bg-white/60 text-slate-600'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-mono text-xs truncate font-bold text-slate-800">
                          {file.filename.split('/').pop() || file.filename}
                        </span>
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.2 rounded ${dangerColor}`}>
                          {file.danger_level}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                        <span className="truncate">{file.filename}</span>
                        <span className="shrink-0">{formatBytes(file.size)}</span>
                      </div>
                    </button>
                  );
                })}
                {filteredSourceFiles.length === 0 && (
                  <div className="p-6 text-center text-xs text-slate-400">No embedded files match search.</div>
                )}
              </div>
            </div>

            {/* Right Column: File Content & Findings */}
            <div className="lg:col-span-8 bg-slate-900 rounded-2xl border border-slate-800 p-4 flex flex-col h-[560px]">
              {selectedSource ? (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b border-slate-800 text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-indigo-300 font-bold text-sm">
                          {selectedSource.filename}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-800 text-slate-300 rounded uppercase">
                          {selectedSource.file_type}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                        Size: {formatBytes(selectedSource.size)}
                      </div>
                    </div>

                    <button
                      onClick={() => handleCopy(selectedSource.content_preview, 'src_content')}
                      className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-all"
                    >
                      {copiedKey === 'src_content' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Preview</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Suspicious Findings Warnings */}
                  {selectedSource.suspicious_findings && selectedSource.suspicious_findings.length > 0 && (
                    <div className="mb-3 p-3 bg-rose-950/60 border border-rose-800/80 rounded-xl space-y-1 shrink-0">
                      <div className="flex items-center gap-1.5 text-rose-300 font-bold text-xs">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Suspicious Code Patterns Detected in this File:
                      </div>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {selectedSource.suspicious_findings.map((f, i) => (
                          <span
                            key={i}
                            className="text-[11px] font-mono px-2 py-0.5 bg-rose-900/60 text-rose-200 border border-rose-700 rounded-md"
                          >
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Content Preview */}
                  <div className="flex-1 overflow-auto bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-200">
                    <pre className="whitespace-pre leading-relaxed">{selectedSource.content_preview}</pre>
                  </div>
                </>
              ) : (
                <div className="m-auto text-slate-500 text-xs">Select a source file to preview.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab: Native ELF (.so) Libraries */}
      {activeTab === 'native_so' && (
        <div className="space-y-6">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Binary className="w-4 h-4 text-amber-600" />
                Native Shared Libraries (.so) &amp; Checksec Mitigations
              </h4>
              <p className="text-xs text-slate-500">
                Bundled ELF binaries compiled for Android ABIs (JNI exports, imported libc/system calls, and exploit mitigations).
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {native_architectures.map((arch, idx) => (
                <span key={idx} className="text-xs font-mono px-2.5 py-1 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-lg font-bold">
                  {arch}
                </span>
              ))}
            </div>
          </div>

          {native_so_details.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {native_so_details.map((so, idx) => (
                <div key={idx} className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-3">
                  <div className="flex items-center justify-between gap-2 border-b border-slate-200 pb-2">
                    <div>
                      <span className="font-mono text-xs font-bold text-slate-900 block truncate" title={so.filename}>
                        {so.filename}
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        {so.architecture} • {formatBytes(so.file_size)}
                      </span>
                    </div>
                  </div>

                  {/* Checksec Mitigations */}
                  {so.checksec && (
                    <div className="space-y-1.5">
                      <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
                        Binary Exploit Mitigations (Checksec)
                      </span>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <div className="p-2 bg-white rounded-lg border border-slate-200 text-center">
                          <span className="text-[10px] text-slate-400 block font-semibold">NX</span>
                          <span className={`text-xs font-bold ${so.checksec.nx ? 'text-emerald-600' : 'text-rose-600'}`}>
                            {so.checksec.nx ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                        <div className="p-2 bg-white rounded-lg border border-slate-200 text-center">
                          <span className="text-[10px] text-slate-400 block font-semibold">PIE</span>
                          <span className={`text-xs font-bold ${so.checksec.pie ? 'text-emerald-600' : 'text-rose-600'}`}>
                            {so.checksec.pie ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                        <div className="p-2 bg-white rounded-lg border border-slate-200 text-center">
                          <span className="text-[10px] text-slate-400 block font-semibold">Canary</span>
                          <span className={`text-xs font-bold ${so.checksec.canary ? 'text-emerald-600' : 'text-rose-600'}`}>
                            {so.checksec.canary ? 'Present' : 'None'}
                          </span>
                        </div>
                        <div className="p-2 bg-white rounded-lg border border-slate-200 text-center">
                          <span className="text-[10px] text-slate-400 block font-semibold">RELRO</span>
                          <span className={`text-xs font-bold ${
                            so.checksec.relro === 'Full' ? 'text-emerald-600' : so.checksec.relro === 'Partial' ? 'text-amber-600' : 'text-rose-600'
                          }`}>
                            {so.checksec.relro || 'None'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* JNI Exports */}
                  {so.jni_exports && so.jni_exports.length > 0 && (
                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
                        JNI Exported Interfaces ({so.jni_exports.length})
                      </span>
                      <div className="bg-slate-900 text-emerald-300 p-2.5 rounded-xl font-mono text-[11px] max-h-28 overflow-y-auto space-y-0.5">
                        {so.jni_exports.map((exp, eIdx) => (
                          <div key={eIdx} className="truncate">• {exp}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suspicious Imports */}
                  {so.suspicious_calls && so.suspicious_calls.length > 0 && (
                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-bold text-rose-500 tracking-wider block">
                        Suspicious Imported Calls ({so.suspicious_calls.length})
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {so.suspicious_calls.map((call, cIdx) => (
                          <span key={cIdx} className="text-[10px] font-mono px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded">
                            {call}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 bg-slate-50 rounded-2xl border border-slate-200 text-xs text-slate-500">
              <span className="font-semibold block mb-2">Native libraries detected:</span>
              <div className="font-mono space-y-1">
                {native_libraries.map((lib, i) => (
                  <div key={i}>• {lib}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Permissions Matrix */}
      {activeTab === 'permissions' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="relative w-full sm:w-72">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={permSearch}
                onChange={e => setPermSearch(e.target.value)}
                placeholder="Search dangerous permissions..."
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
              />
            </div>
            <div className="flex items-center gap-1.5">
              {(['all', 'critical', 'high', 'medium'] as const).map(sev => (
                <button
                  key={sev}
                  onClick={() => setPermFilter(sev)}
                  className={`text-xs px-2.5 py-1 rounded-lg capitalize transition-all ${
                    permFilter === sev
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {filteredPerms.length > 0 ? (
            <div className="space-y-2.5">
              {filteredPerms.map((dp, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-slate-50 hover:bg-slate-100/80 transition-all rounded-2xl border border-slate-200 space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(dp.severity)}`}>
                        {dp.severity}
                      </span>
                      <strong className="text-xs font-bold text-slate-900">{dp.title}</strong>
                    </div>
                    {dp.mitre && (
                      <span className="text-[11px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md">
                        MITRE {dp.mitre} ({dp.mitre_name})
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-xs text-slate-600 font-semibold">{dp.permission}</div>
                  <p className="text-xs text-slate-500 leading-relaxed">{dp.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              No dangerous permissions match current filters. Total package permissions: {permissions.length}.
            </div>
          )}
        </div>
      )}

      {/* Tab: Components & Attack Surface */}
      {activeTab === 'components' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Activities</span>
              <strong className="text-slate-900 text-sm">{activities.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedActivities.length} Exported)</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Services</span>
              <strong className="text-slate-900 text-sm">{services.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedServices.length} Exported)</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Receivers</span>
              <strong className="text-slate-900 text-sm">{receivers.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedReceivers.length} Exported)</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Content Providers</span>
              <strong className="text-slate-900 text-sm">{providers.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedProviders.length} Exported)</span>
            </div>
          </div>

          {/* Exported Components Warning */}
          {totalExported > 0 && (
            <div className="p-4 bg-amber-50 rounded-2xl border border-amber-200 space-y-2">
              <div className="flex items-center gap-2 text-amber-800 font-bold text-xs">
                <AlertTriangle className="w-4 h-4" />
                Inter-Process Communication (IPC) Attack Surface ({totalExported} Exported Components)
              </div>
              <p className="text-xs text-amber-700">
                Exported components can be invoked by any third-party app installed on the device without permissions,
                presenting potential vectors for intent spoofing, privilege escalation, or unintended background activity launches.
              </p>
            </div>
          )}

          {/* Detailed Component List */}
          <div className="space-y-4">
            {receivers.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Broadcast Receivers (Persistence &amp; Boot Triggers)
                </h5>
                <div className="space-y-1.5">
                  {receivers.map((rec, i) => (
                    <div key={i} className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
                      <div className="font-mono text-slate-800 truncate mr-2">
                        {rec.name}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {rec.exported && (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-amber-100 text-amber-800 rounded">
                            EXPORTED
                          </span>
                        )}
                        {rec.actions && rec.actions.some(a => a.includes('BOOT_COMPLETED')) && (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-rose-100 text-rose-800 rounded">
                            BOOT_COMPLETED
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {services.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Background Services ({services.length})
                </h5>
                <div className="space-y-1.5">
                  {services.slice(0, 10).map((srv, i) => (
                    <div key={i} className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
                      <div className="font-mono text-slate-800 truncate mr-2">
                        {srv.name}
                      </div>
                      {srv.exported && (
                        <span className="text-[10px] font-bold px-2 py-0.5 bg-amber-100 text-amber-800 rounded shrink-0">
                          EXPORTED
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: DEX Bytecode & APIs */}
      {activeTab === 'dex' && (
        <div className="space-y-6">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h4 className="text-sm font-bold text-slate-900">Dalvik Bytecode Analysis Engine &amp; Malicious API Catalog</h4>
              <p className="text-xs text-slate-500">
                Dissected DEX string table ({dex_info.total_strings_count.toLocaleString()} strings across {dex_info.classes_count.toLocaleString()} classes). Mapped to OWASP Mobile Top 10, CWE, and MITRE ATT&CK for Mobile.
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs font-bold text-rose-600 block">
                {(dex_info.detected_apis || []).length} Sensitive APIs Detected
              </span>
            </div>
          </div>

          {/* Search & Filter Controls */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={apiSearch}
                  onChange={e => setApiSearch(e.target.value)}
                  placeholder="Search APIs, CWE, OWASP, threats..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* Severity Pills */}
              <div className="flex items-center gap-1.5 self-start sm:self-auto">
                <span className="text-[11px] font-semibold text-slate-400 mr-1">Severity:</span>
                {(['all', 'critical', 'high', 'medium'] as const).map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSelectedApiSeverity(sev)}
                    className={`px-2.5 py-1 text-[11px] font-semibold rounded-lg capitalize transition-all cursor-pointer ${
                      selectedApiSeverity === sev
                        ? 'bg-slate-900 text-white shadow-sm'
                        : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
              {[
                { id: 'all', label: 'All Categories' },
                { id: 'crypto', label: 'Cryptography (ECB/Hashes)' },
                { id: 'network_tls', label: 'Network & TLS MitM' },
                { id: 'webview', label: 'WebView & Bridges' },
                { id: 'telephony_sms', label: 'SMS & Toll Fraud' },
                { id: 'surveillance', label: 'Surveillance & Wiretap' },
                { id: 'accessibility', label: 'Accessibility Abuse' },
                { id: 'overlay', label: 'Overlay & Tapjacking' },
                { id: 'device_admin', label: 'Device Admin Ransomware' },
                { id: 'code_loading', label: 'Dynamic Code / Droppers' },
                { id: 'root_privilege', label: 'Root Escalation' },
                { id: 'anti_analysis', label: 'Anti-Analysis & Evasion' },
                { id: 'app_enumeration', label: 'App Enumeration' },
                { id: 'clipboard', label: 'Clipboard Hijacking' }
              ].map(cat => {
                const catCount = (dex_info.detected_apis || []).filter(a => cat.id === 'all' || a.category === cat.id).length;
                if (cat.id !== 'all' && catCount === 0) return null;
                return (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedApiCategory(cat.id)}
                    className={`px-2.5 py-1 text-[11px] rounded-lg font-medium transition-all cursor-pointer ${
                      selectedApiCategory === cat.id
                        ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                        : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
                    }`}
                  >
                    {cat.label} ({catCount})
                  </button>
                );
              })}
            </div>
          </div>

          {/* Detected APIs */}
          {filteredApis.length > 0 ? (
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Flagged API Calls &amp; Detailed Threat Explanations ({filteredApis.length})
              </h5>
              <div className="space-y-3">
                {filteredApis.map((api, idx) => {
                  const isExpanded = expandedApiIndex === idx;
                  return (
                    <div
                      key={idx}
                      className="p-4 bg-white rounded-2xl border border-slate-200 shadow-xs hover:border-slate-300 transition-all space-y-3"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(api.severity)}`}>
                              {api.severity}
                            </span>
                            <span className="text-[10px] font-semibold uppercase px-2 py-0.5 bg-slate-100 text-slate-600 rounded-md border border-slate-200">
                              {api.category || 'General'}
                            </span>
                            <strong className="text-sm font-bold text-slate-900">{api.title}</strong>
                            <span className="text-[11px] font-mono text-slate-400 font-medium">
                              ({api.count} reference{api.count > 1 ? 's' : ''})
                            </span>
                          </div>
                          <div className="font-mono text-xs text-indigo-700 font-semibold">{api.api}</div>
                        </div>

                        {/* Badges: MITRE, CWE, OWASP */}
                        <div className="flex flex-wrap items-center gap-1.5 self-start">
                          {api.mitre && (
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md" title={api.mitre_name}>
                              MITRE {api.mitre}
                            </span>
                          )}
                          {api.cwe && (
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded-md" title={api.cwe}>
                              {api.cwe.split(':')[0]}
                            </span>
                          )}
                          {api.owasp_mobile && (
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-sky-50 text-sky-800 border border-sky-200 rounded-md" title={api.owasp_mobile}>
                              {api.owasp_mobile.split(':')[0]}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Summary Description */}
                      <p className="text-xs text-slate-600 leading-relaxed">{api.description}</p>

                      {/* Threat Explanation Box (Why This Is Dangerous / How Malware Abuses It) */}
                      {api.risk_explanation && (
                        <div className="p-3 bg-rose-50/70 border border-rose-200/80 rounded-xl space-y-1">
                          <div className="flex items-center gap-1.5 text-xs font-bold text-rose-900">
                            <ShieldAlert className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                            <span>Why This API Call Is Dangerous (Threat Model &amp; Malware Abuse)</span>
                          </div>
                          <p className="text-xs text-rose-800 leading-relaxed pl-5">
                            {api.risk_explanation}
                          </p>
                        </div>
                      )}

                      {/* Remediation & Safe Alternative */}
                      {api.remediation && (
                        <div className="p-3 bg-emerald-50/70 border border-emerald-200/80 rounded-xl space-y-1">
                          <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-900">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                            <span>Remediation &amp; Secure Implementation Alternative</span>
                          </div>
                          <p className="text-xs text-emerald-800 leading-relaxed pl-5">
                            {api.remediation}
                          </p>
                        </div>
                      )}

                      {/* Evidence / Code References */}
                      {api.evidence && api.evidence.length > 0 && (
                        <div className="space-y-1.5">
                          <button
                            onClick={() => setExpandedApiIndex(isExpanded ? null : idx)}
                            className="text-[11px] font-semibold text-slate-500 hover:text-slate-800 flex items-center gap-1 cursor-pointer"
                          >
                            <span>{isExpanded ? 'Hide' : 'Show'} Bytecode Evidence ({api.evidence.length})</span>
                          </button>
                          {isExpanded && (
                            <div className="bg-slate-900 text-slate-200 p-2.5 rounded-xl font-mono text-[11px] overflow-x-auto space-y-1">
                              {api.evidence.map((ev, i) => (
                                <div key={i} className="truncate">{ev}</div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs bg-slate-50 rounded-2xl border border-slate-200">
              No sensitive Dalvik API signatures matched your filter criteria.
            </div>
          )}

          {/* IOCs / URLs in DEX */}
          {iocs.urls && iocs.urls.length > 0 && (
            <div className="space-y-2">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-slate-500" />
                Hardcoded Network Endpoints &amp; URLs in DEX ({iocs.urls.length})
              </h5>
              <div className="bg-slate-50 border border-slate-200 rounded-2xl p-3 max-h-48 overflow-y-auto space-y-1 font-mono text-xs text-slate-700">
                {iocs.urls.map((u, i) => (
                  <div key={i} className="truncate hover:text-indigo-600">• {u}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Categorized Strings & Hardcoded Secrets */}
      {activeTab === 'strings' && categorized_strings && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Search className="w-4 h-4 text-emerald-600" />
                DEX &amp; Asset Categorized Strings ({categorized_strings.total_count})
              </h4>
              <p className="text-xs text-slate-500">
                Extracted API keys, credentials, remote endpoints, shell binaries, and cryptographic algorithms.
              </p>
            </div>
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={stringSearch}
                onChange={e => setStringSearch(e.target.value)}
                placeholder="Filter strings..."
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
              />
            </div>
          </div>

          {/* Sub-Category Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            {[
              { id: 'all', label: 'All Categories' },
              { id: 'secrets', label: `API Keys & Secrets (${categorized_strings.secrets_and_keys?.length || 0})` },
              { id: 'urls', label: `URLs (${categorized_strings.urls?.length || 0})` },
              { id: 'ips', label: `IP Addresses (${categorized_strings.ips?.length || 0})` },
              { id: 'commands', label: `Shell Commands (${categorized_strings.shell_commands?.length || 0})` },
              { id: 'crypto', label: `Crypto Ciphers (${categorized_strings.crypto_algorithms?.length || 0})` },
              { id: 'paths', label: `Sensitive Paths (${categorized_strings.sensitive_paths?.length || 0})` },
              { id: 'apis', label: `Suspicious APIs (${categorized_strings.suspicious_apis?.length || 0})` }
            ].map(cat => (
              <button
                key={cat.id}
                onClick={() => setSelectedStringCategory(cat.id as any)}
                className={`text-xs px-3 py-1.5 rounded-xl font-medium transition-all ${
                  selectedStringCategory === cat.id
                    ? 'bg-slate-900 text-white font-semibold shadow-sm'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>

          {/* Secrets Highlight Section */}
          {(selectedStringCategory === 'all' || selectedStringCategory === 'secrets') &&
            categorized_strings.secrets_and_keys &&
            categorized_strings.secrets_and_keys.length > 0 && (
              <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 space-y-2">
                <div className="flex items-center gap-2 text-rose-800 font-bold text-xs">
                  <Key className="w-4 h-4 text-rose-600" />
                  Hardcoded API Keys, Tokens &amp; Credentials ({categorized_strings.secrets_and_keys.length})
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {categorized_strings.secrets_and_keys.map((sec, i) => (
                    <div
                      key={i}
                      className="p-3 bg-white rounded-xl border border-rose-200 flex items-center justify-between text-xs font-mono"
                    >
                      <div className="truncate mr-2">
                        <span className="text-[10px] font-bold px-1.5 py-0.5 bg-rose-100 text-rose-800 rounded mr-2 uppercase">
                          {sec.type}
                        </span>
                        <span className="text-slate-800">{sec.value}</span>
                      </div>
                      <button
                        onClick={() => handleCopy(sec.value, `sec_${i}`)}
                        className="p-1 text-slate-400 hover:text-slate-700"
                        title="Copy Secret"
                      >
                        {copiedKey === `sec_${i}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Strings Stream */}
          <div className="bg-slate-900 text-slate-200 p-4 rounded-2xl font-mono text-xs max-h-96 overflow-y-auto space-y-1">
            {(() => {
              let items: string[] = [];
              const q = stringSearch.toLowerCase();
              if (selectedStringCategory === 'all' || selectedStringCategory === 'urls') {
                items.push(...(categorized_strings.urls || []).map(u => `[URL] ${u}`));
              }
              if (selectedStringCategory === 'all' || selectedStringCategory === 'ips') {
                items.push(...(categorized_strings.ips || []).map(ip => `[IP] ${ip}`));
              }
              if (selectedStringCategory === 'all' || selectedStringCategory === 'commands') {
                items.push(...(categorized_strings.shell_commands || []).map(c => `[SHELL] ${c}`));
              }
              if (selectedStringCategory === 'all' || selectedStringCategory === 'crypto') {
                items.push(...(categorized_strings.crypto_algorithms || []).map(cr => `[CRYPTO] ${cr}`));
              }
              if (selectedStringCategory === 'all' || selectedStringCategory === 'paths') {
                items.push(...(categorized_strings.sensitive_paths || []).map(p => `[PATH] ${p}`));
              }
              if (selectedStringCategory === 'all' || selectedStringCategory === 'apis') {
                items.push(...(categorized_strings.suspicious_apis || []).map(a => `[API] ${a}`));
              }

              if (q) {
                items = items.filter(it => it.toLowerCase().includes(q));
              }

              if (items.length === 0) {
                return <div className="text-slate-500 italic p-4 text-center">No strings match category and filter.</div>;
              }

              return items.map((str, sIdx) => (
                <div key={sIdx} className="flex items-center justify-between hover:bg-slate-800/80 px-2 py-1 rounded">
                  <span className="truncate mr-2">{str}</span>
                  <button
                    onClick={() => handleCopy(str.replace(/^\[.*?\]\s*/, ''), `str_${sIdx}`)}
                    className="text-slate-500 hover:text-slate-300 shrink-0 p-0.5"
                    title="Copy string"
                  >
                    {copiedKey === `str_${sIdx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ));
            })()}
          </div>
        </div>
      )}

      {/* Tab: Certificate */}
      {activeTab === 'certificate' && (
        <div className="space-y-6">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex items-start gap-4">
            <div className="p-3 bg-indigo-50 text-indigo-600 rounded-xl shrink-0">
              <Key className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900">APK Code Signing &amp; Integrity Verification</h4>
              <p className="text-xs text-slate-500">
                Parsed cryptographic X.509 certificate signatures from META-INF container.
              </p>
            </div>
          </div>

          {signing_info.is_debug_key && (
            <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 flex items-start gap-3 text-rose-800">
              <ShieldAlert className="w-5 h-5 shrink-0 text-rose-600" />
              <div>
                <strong className="text-xs font-bold block">Android Debug Keystore Signature Detected</strong>
                <p className="text-xs text-rose-700 mt-0.5">
                  This APK is signed with the public development Android Debug certificate (CN=Android Debug). Debug builds
                  bypass Google Play release standards and should never be deployed or trusted in production environments.
                </p>
              </div>
            </div>
          )}

          {keystore_audit?.is_masquerading_identity && (
            <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 flex items-start gap-3 text-rose-800">
              <ShieldAlert className="w-5 h-5 shrink-0 text-rose-600" />
              <div>
                <strong className="text-xs font-bold block">Certificate Identity Masquerading / Brand Spoofing</strong>
                <p className="text-xs text-rose-700 mt-0.5">
                  {keystore_audit.masquerade_details}
                </p>
              </div>
            </div>
          )}

          {keystore_audit?.janus_vulnerability && (
            <div className="p-4 bg-amber-50 rounded-2xl border border-amber-200 flex items-start gap-3 text-amber-800">
              <AlertTriangle className="w-5 h-5 shrink-0 text-amber-600" />
              <div>
                <strong className="text-xs font-bold block">Janus Vulnerability Susceptibility (CVE-2017-13156)</strong>
                <p className="text-xs text-amber-700 mt-0.5">
                  {keystore_audit.janus_details}
                </p>
              </div>
            </div>
          )}

          {/* Signature Schemes Support */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-700">Scheme v1 (JAR Signature)</span>
              <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                signing_info.has_v1_signature ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-600'
              }`}>
                {signing_info.has_v1_signature ? 'PRESENT' : 'NOT PRESENT'}
              </span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-700">Scheme v2/v3 (APK Signing Block)</span>
              <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                signing_info.has_v2_or_v3_signature ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
              }`}>
                {signing_info.has_v2_or_v3_signature ? 'PRESENT (PROTECTED)' : 'MISSING (VULNERABLE)'}
              </span>
            </div>
          </div>

          {/* Certificate Attributes Table */}
          <div className="bg-slate-50 rounded-2xl border border-slate-200 overflow-hidden divide-y divide-slate-100 text-xs">
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Certificate Subject</span>
              <span className="font-mono text-slate-800">{signing_info.subject || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Issuer</span>
              <span className="font-mono text-slate-800">{signing_info.issuer || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Serial Number</span>
              <span className="font-mono text-slate-800">{signing_info.serial_number || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Validity Window</span>
              <span className="font-mono text-slate-800">
                {signing_info.valid_from ? `${signing_info.valid_from} to ${signing_info.valid_until}` : 'N/A'}
              </span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">SHA-256 Fingerprint</span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-slate-800 text-[11px] truncate max-w-xs">
                  {signing_info.sha256_fingerprint || 'N/A'}
                </span>
                {signing_info.sha256_fingerprint && (
                  <button
                    onClick={() => handleCopy(signing_info.sha256_fingerprint!, 'fp')}
                    className="p-1 text-slate-400 hover:text-slate-600"
                  >
                    {copiedKey === 'fp' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Self-Signed Status</span>
              <span className={`font-semibold ${signing_info.is_self_signed ? 'text-amber-600' : 'text-slate-800'}`}>
                {signing_info.is_self_signed ? 'Yes (Self-Signed Key)' : 'No (CA Issued)'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tab: AndroidManifest.xml Viewer */}
      {activeTab === 'manifest' && manifest_xml && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <FileText className="w-4 h-4 text-emerald-600" />
                Decoded AndroidManifest.xml
              </h4>
              <p className="text-xs text-slate-500">
                Full parsed application manifest specification, intent filters, receiver definitions, and permission grants.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="relative w-48 sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={manifestSearch}
                  onChange={e => setManifestSearch(e.target.value)}
                  placeholder="Find in manifest..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>
              <button
                onClick={() => handleCopy(manifest_xml, 'manifest')}
                className="flex items-center gap-1 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-semibold transition-all shrink-0"
              >
                {copiedKey === 'manifest' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied XML</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy XML</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="bg-slate-950 p-4 rounded-2xl font-mono text-xs text-emerald-300 max-h-[600px] overflow-auto border border-slate-800">
            <pre className="whitespace-pre leading-relaxed">{manifest_xml}</pre>
          </div>
        </div>
      )}

      {/* Tab: MITRE Mobile ATT&CK */}
      {activeTab === 'mitre' && (
        <div className="space-y-4">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <h4 className="text-sm font-bold text-slate-900">MITRE ATT&amp;CK for Mobile Mapping</h4>
            <p className="text-xs text-slate-500">
              Adversary techniques and capability mapping based on dangerous permissions and bytecode API invocations.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {mitre_mobile_techniques.map((tech, i) => (
              <div
                key={i}
                className="p-3.5 bg-slate-50 rounded-2xl border border-slate-200 flex items-center justify-between"
              >
                <div>
                  <span className="font-mono text-xs font-bold text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-200">
                    {tech.id}
                  </span>
                  <div className="text-xs font-bold text-slate-800 mt-1">{tech.name}</div>
                </div>
                <a
                  href={`https://attack.mitre.org/techniques/${tech.id}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 text-slate-400 hover:text-purple-600 transition-colors"
                  title="View on MITRE ATT&CK Mobile Matrix"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
