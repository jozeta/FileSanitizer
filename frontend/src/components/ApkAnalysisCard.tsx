import React, { useState } from 'react';
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
  Search
} from 'lucide-react';
import { ApkAnalysisData, Finding } from '../types';

interface ApkAnalysisCardProps {
  apkInfo?: ApkAnalysisData;
  filename?: string;
  findings?: Finding[];
}

export const ApkAnalysisCard: React.FC<ApkAnalysisCardProps> = ({
  apkInfo,
  filename = 'application.apk'
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'permissions' | 'components' | 'dex' | 'certificate' | 'mitre'>('overview');
  const [permSearch, setPermSearch] = useState('');
  const [permFilter, setPermFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

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
    app_name,
    security_flags = {},
    permissions = [],
    dangerous_permissions = [],
    components = {},
    signing_info = {},
    dex_info = { dex_count: 1, classes_count: 0, total_strings_count: 0, detected_apis: [] },
    native_architectures = [],
    native_libraries = [],
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
    const matchesSearch = p.permission.toLowerCase().includes(permSearch.toLowerCase()) ||
      p.title.toLowerCase().includes(permSearch.toLowerCase()) ||
      p.description.toLowerCase().includes(permSearch.toLowerCase());
    const matchesFilter = permFilter === 'all' || p.severity === permFilter;
    return matchesSearch && matchesFilter;
  });

  const getRiskBadgeColor = (lvl: string) => {
    switch (lvl.toUpperCase()) {
      case 'CRITICAL': return 'bg-rose-100 text-rose-800 border-rose-200';
      case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM': return 'bg-amber-100 text-amber-800 border-amber-200';
      default: return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'high': return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'medium': return 'bg-amber-50 text-amber-700 border-amber-200';
      default: return 'bg-slate-50 text-slate-700 border-slate-200';
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
                : 'AXML binary manifest parsing, dangerous permissions matrix, component attack surface, code signing certs, and DEX APIs.'}
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
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Components</span>
            <strong className="text-slate-900">{totalComponents}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Exported</span>
            <strong className={totalExported > 0 ? 'text-amber-600' : 'text-slate-900'}>
              {totalExported}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">DEX Classes</span>
            <strong className="text-slate-900">{dex_info.classes_count || 0}</strong>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 pb-3">
        <button
          onClick={() => setActiveTab('overview')}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'overview'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          Overview &amp; Metadata
        </button>

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('permissions')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'permissions'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Dangerous Permissions ({dangerous_permissions.length})
          </button>
        )}

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('components')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'components'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Attack Surface ({totalExported} Exported)
          </button>
        )}

        <button
          onClick={() => setActiveTab('dex')}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'dex'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          DEX Bytecode &amp; APIs ({(dex_info.detected_apis || []).length})
        </button>

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('certificate')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'certificate'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Code Signing Certificate
          </button>
        )}

        {mitre_mobile_techniques.length > 0 && (
          <button
            onClick={() => setActiveTab('mitre')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'mitre'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            MITRE Mobile ATT&amp;CK ({mitre_mobile_techniques.length})
          </button>
        )}
      </div>

      {/* Tab: Overview */}
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
                v{version_name} <span className="text-slate-400 text-xs">(Build {version_code})</span>
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                SDK Compatibility
              </span>
              <span className="font-mono text-sm font-semibold text-slate-800">
                Min: {min_sdk} / Target: {target_sdk}
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                App Label / Name
              </span>
              <span className="text-sm font-semibold text-slate-800">
                {app_name || package_name.split('.').pop() || 'Android App'}
              </span>
            </div>
          </div>

          {/* Security Flags Grid */}
          {!is_standalone_dex && (
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100 space-y-3">
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Application Security Configuration &amp; Manifest Flags
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
                    <span className="text-xs font-semibold block text-slate-800">Cleartext HTTP Traffic</span>
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
                    <span className="text-xs font-semibold block text-slate-800">Release Keystore</span>
                    <span className="text-[11px] text-slate-500">
                      {signing_info.is_debug_key ? 'Public Debug Cert' : 'Production Signer'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Native Binaries & Embedded Assets */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Native Architectures &amp; Libraries (.so)
                </span>
                <span className="text-xs font-mono px-2 py-0.5 bg-slate-200 rounded-md text-slate-700">
                  {native_libraries.length} libs
                </span>
              </div>
              {native_architectures.length > 0 ? (
                <div className="space-y-2">
                  <div className="flex flex-wrap gap-1.5">
                    {native_architectures.map((arch, i) => (
                      <span key={i} className="text-xs px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-lg font-mono">
                        {arch}
                      </span>
                    ))}
                  </div>
                  <div className="max-h-36 overflow-y-auto font-mono text-[11px] text-slate-600 space-y-1">
                    {native_libraries.slice(0, 10).map((lib, i) => (
                      <div key={i} className="truncate">• {lib}</div>
                    ))}
                    {native_libraries.length > 10 && (
                      <div className="text-slate-400 italic">+ {native_libraries.length - 10} more native libraries</div>
                    )}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400">Pure bytecode package; no native ELF libraries bundled.</p>
              )}
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Suspicious Embedded Assets &amp; Payloads
                </span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded-md ${
                  embedded_assets.length > 0 ? 'bg-rose-100 text-rose-700' : 'bg-slate-200 text-slate-700'
                }`}>
                  {embedded_assets.length} items
                </span>
              </div>
              {embedded_assets.length > 0 ? (
                <div className="max-h-44 overflow-y-auto font-mono text-[11px] text-slate-700 space-y-1">
                  {embedded_assets.map((asset, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-rose-700">
                      <AlertTriangle className="w-3 h-3 shrink-0" />
                      <span className="truncate">{asset}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400">No secondary executables or suspicious payloads in assets.</p>
              )}
            </div>
          </div>
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
                Exported components can be invoked by any third-party app installed on the user device without permissions,
                presenting potential vectors for intent spoofing, privilege escalation, or unintended component launching.
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
              <h4 className="text-sm font-bold text-slate-900">Dalvik Bytecode Analysis Engine</h4>
              <p className="text-xs text-slate-500">
                Dissected DEX string table ({dex_info.total_strings_count.toLocaleString()} strings across {dex_info.classes_count.toLocaleString()} classes).
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs font-bold text-rose-600 block">
                {(dex_info.detected_apis || []).length} Sensitive APIs Detected
              </span>
            </div>
          </div>

          {/* Detected APIs */}
          {(dex_info.detected_apis || []).length > 0 ? (
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Sensitive &amp; Potentially Malicious Dalvik API Invocations
              </h5>
              <div className="space-y-2">
                {(dex_info.detected_apis || []).map((api, idx) => (
                  <div
                    key={idx}
                    className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(api.severity)}`}>
                          {api.severity}
                        </span>
                        <strong className="text-xs font-bold text-slate-900">{api.title}</strong>
                        <span className="text-[11px] font-mono text-slate-500">({api.count} references)</span>
                      </div>
                      {api.mitre && (
                        <span className="text-[11px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md">
                          MITRE {api.mitre} ({api.mitre_name})
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">{api.description}</p>
                    {api.evidence && api.evidence.length > 0 && (
                      <div className="bg-slate-900 text-slate-200 p-2.5 rounded-xl font-mono text-[11px] overflow-x-auto space-y-1">
                        {api.evidence.map((ev, i) => (
                          <div key={i} className="truncate">{ev}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              No sensitive Dalvik API signatures detected in bytecode string pools.
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
