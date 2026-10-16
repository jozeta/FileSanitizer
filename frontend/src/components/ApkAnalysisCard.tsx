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
  Hash,
  ChevronDown,
  ChevronRight,
  Archive,
  Flag,
  Download,
  Link2,
  ShieldCheck,
  Lock,
  AlertOctagon
} from 'lucide-react';
import {
  ApkAnalysisData,
  Finding,
  ApkClassDetail,
  ApkEmbeddedSourceFile,
  ApkComponent,
  ApkCertificate
} from '../types';
import { formatBytes } from '../utils/formatters';

const getStandardPermDescription = (perm: string): string => {
  const descriptions: Record<string, string> = {
    'android.permission.INTERNET': 'Allows the application to create network sockets and use custom network protocols (Full Internet access).',
    'android.permission.ACCESS_NETWORK_STATE': 'Allows the application to view the status of network connections (e.g. Wi-Fi vs Mobile data).',
    'android.permission.ACCESS_WIFI_STATE': 'Allows the application to view information about Wi-Fi networking status.',
    'android.permission.CHANGE_WIFI_STATE': 'Allows the application to connect/disconnect from Wi-Fi and alter network configurations.',
    'android.permission.WAKE_LOCK': 'Allows the application to prevent the processor from sleeping or screen from dimming.',
    'android.permission.VIBRATE': 'Allows the application to control the device vibrator for haptics and alerts.',
    'android.permission.FOREGROUND_SERVICE': 'Allows the application to run background tasks with a persistent user notification.',
    'android.permission.FOREGROUND_SERVICE_SPECIAL_USE': 'Allows the application to run foreground services for special purposes.',
    'android.permission.FOREGROUND_SERVICE_DATA_SYNC': 'Allows the application to run foreground services to sync data in the background.',
    'android.permission.POST_NOTIFICATIONS': 'Allows the application to post status bar notifications (Android 13+).',
    'android.permission.RECEIVE_BOOT_COMPLETED': 'Allows the application to launch or trigger a receiver immediately after device boot finishes.',
    'android.permission.REQUEST_INSTALL_PACKAGES': 'Allows the application to request installation of secondary package files (potential dropper capability).',
    'android.permission.QUERY_ALL_PACKAGES': 'Allows the application to query the list of all installed packages on the device.',
    'android.permission.BLUETOOTH': 'Allows the application to connect to paired Bluetooth devices.',
    'android.permission.BLUETOOTH_ADMIN': 'Allows the application to discover and pair with Bluetooth devices.',
    'android.permission.BLUETOOTH_CONNECT': 'Allows the application to communicate with paired Bluetooth devices (Android 12+).',
    'android.permission.BLUETOOTH_SCAN': 'Allows the application to scan for nearby Bluetooth peripherals (Android 12+).',
    'android.permission.NFC': 'Allows the application to perform Near-Field Communication (NFC) transactions.',
    'android.permission.MODIFY_AUDIO_SETTINGS': 'Allows the application to modify global audio settings like volume and output routing.',
    'android.permission.KILL_BACKGROUND_PROCESSES': 'Allows the application to call ActivityManager.killBackgroundProcesses to terminate other apps.',
    'android.permission.REORDER_TASKS': 'Allows the application to move tasks to the foreground and background.',
    'android.permission.SYSTEM_ALERT_WINDOW': 'Allows an app to create windows shown on top of all other apps (Draw over apps / Overlay capability).',
    'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': 'Allows an application to request permission to bypass battery optimization restrictions.'
  };

  if (descriptions[perm]) return descriptions[perm];
  const short = perm.split('.').pop() || perm;
  return `Standard Android platform permission (${short}). Allows application component execution without runtime prompt.`;
};

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
    | 'overview'
    | 'decompiler'
    | 'embedded_sources'
    | 'native_so'
    | 'permissions'
    | 'components'
    | 'dex'
    | 'strings'
    | 'certificate'
    | 'manifest'
    | 'mitre'
    | 'archive_sec'
    | 'dependencies'
    | 'secrets_ctf'
  >('overview');

  // Permissions Tab State
  const [permSearch, setPermSearch] = useState('');
  const [permTypeFilter, setPermTypeFilter] = useState<'all' | 'dangerous' | 'standard'>('all');
  const [permFilter, setPermFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Components Tab State
  const [componentTypeFilter, setComponentTypeFilter] = useState<'all' | 'activities' | 'services' | 'receivers' | 'providers'>('all');
  const [componentSearch, setComponentSearch] = useState('');
  const [componentExportedOnly, setComponentExportedOnly] = useState(false);
  const [expandedComponentIndex, setExpandedComponentIndex] = useState<number | null>(null);

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

  // Certificate Tab State
  const [selectedCertIndex, setSelectedCertIndex] = useState<number>(0);

  // Manifest Tab State
  const [manifestSearch, setManifestSearch] = useState('');
  const [manifestFilterOnly, setManifestFilterOnly] = useState(false);

  // Sensitive APIs Tab State
  const [apiSearch, setApiSearch] = useState('');
  const [selectedApiCategory, setSelectedApiCategory] = useState<string>('all');
  const [selectedApiSeverity, setSelectedApiSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [expandedApiIndex, setExpandedApiIndex] = useState<number | null>(null);

  // Archive Security, SBOM & CTF State
  const [sbomViewMode, setSbomViewMode] = useState<'table' | 'json'>('table');
  const [copiedSbom, setCopiedSbom] = useState<boolean>(false);
  const [copiedFlagIdx, setCopiedFlagIdx] = useState<number | null>(null);
  const [copiedSecretIdx, setCopiedSecretIdx] = useState<number | null>(null);
  const [secretSearch, setSecretSearch] = useState<string>('');
  const [depSearch, setDepSearch] = useState<string>('');

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
    archive_security,
    dependencies = [],
    cyclonedx_sbom,
    secrets_and_ctf,
    deep_links = [],
    sensitive_permission_combos = [],
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

  const handleCopySbom = () => {
    if (!cyclonedx_sbom) return;
    navigator.clipboard.writeText(JSON.stringify(cyclonedx_sbom, null, 2));
    setCopiedSbom(true);
    setTimeout(() => setCopiedSbom(false), 2000);
  };

  const handleDownloadSbom = () => {
    if (!cyclonedx_sbom) return;
    const blob = new Blob([JSON.stringify(cyclonedx_sbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(package_name || 'android-app').replace(/[^a-zA-Z0-9_-]/g, '_')}_cyclonedx_sbom.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Unified Permission List (Dangerous + Standard Android permissions)
  const unifiedPermissions = useMemo(() => {
    const dangMap = new Map<string, (typeof dangerous_permissions)[0]>();
    dangerous_permissions.forEach(dp => {
      dangMap.set(dp.permission, dp);
    });

    const list: Array<{
      permission: string;
      is_dangerous: boolean;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'normal';
      title: string;
      description: string;
      mitre?: string;
      mitre_name?: string;
    }> = [];

    const seen = new Set<string>();

    (permissions || []).forEach(perm => {
      seen.add(perm);
      const dp = dangMap.get(perm);
      if (dp) {
        list.push({
          permission: dp.permission,
          is_dangerous: true,
          severity: dp.severity,
          title: dp.title,
          description: dp.description,
          mitre: dp.mitre,
          mitre_name: dp.mitre_name
        });
      } else {
        const shortName = perm.split('.').pop() || perm;
        list.push({
          permission: perm,
          is_dangerous: false,
          severity: 'normal',
          title: shortName.replace(/_/g, ' '),
          description: getStandardPermDescription(perm)
        });
      }
    });

    dangerous_permissions.forEach(dp => {
      if (!seen.has(dp.permission)) {
        seen.add(dp.permission);
        list.push({
          permission: dp.permission,
          is_dangerous: true,
          severity: dp.severity,
          title: dp.title,
          description: dp.description,
          mitre: dp.mitre,
          mitre_name: dp.mitre_name
        });
      }
    });

    return list;
  }, [permissions, dangerous_permissions]);

  const filteredUnifiedPerms = useMemo(() => {
    return unifiedPermissions.filter(p => {
      const q = permSearch.toLowerCase().trim();
      const matchesSearch =
        !q ||
        p.permission.toLowerCase().includes(q) ||
        p.title.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q);

      if (permTypeFilter === 'dangerous' && !p.is_dangerous) return false;
      if (permTypeFilter === 'standard' && p.is_dangerous) return false;

      if (permFilter !== 'all') {
        if (!p.is_dangerous || p.severity !== permFilter) return false;
      }

      return matchesSearch;
    });
  }, [unifiedPermissions, permSearch, permTypeFilter, permFilter]);

  // Unified Components List (Activities, Services, Receivers, Content Providers)
  const allComponentsList = useMemo(() => {
    const list: Array<ApkComponent & { componentType: 'activity' | 'service' | 'receiver' | 'provider' }> = [];
    activities.forEach(a => list.push({ ...a, componentType: 'activity' }));
    services.forEach(s => list.push({ ...s, componentType: 'service' }));
    receivers.forEach(r => list.push({ ...r, componentType: 'receiver' }));
    providers.forEach(p => list.push({ ...p, componentType: 'provider' }));
    return list;
  }, [activities, services, receivers, providers]);

  const filteredComponentsList = useMemo(() => {
    return allComponentsList.filter(comp => {
      if (componentTypeFilter === 'activities' && comp.componentType !== 'activity') return false;
      if (componentTypeFilter === 'services' && comp.componentType !== 'service') return false;
      if (componentTypeFilter === 'receivers' && comp.componentType !== 'receiver') return false;
      if (componentTypeFilter === 'providers' && comp.componentType !== 'provider') return false;

      if (componentExportedOnly && !comp.exported) return false;

      if (componentSearch.trim()) {
        const q = componentSearch.toLowerCase().trim();
        const matchesName = comp.name.toLowerCase().includes(q);
        const matchesLabel = !!comp.label && comp.label.toLowerCase().includes(q);
        const matchesAuth = !!comp.authorities && comp.authorities.toLowerCase().includes(q);
        const matchesPerm = !!comp.permission && comp.permission.toLowerCase().includes(q);

        let matchesIntent = false;
        if (comp.intent_filters && Array.isArray(comp.intent_filters)) {
          matchesIntent = comp.intent_filters.some(f => {
            if (typeof f === 'string') return f.toLowerCase().includes(q);
            const acts = f.actions || [];
            const cats = f.categories || [];
            return acts.some(a => a.toLowerCase().includes(q)) || cats.some(c => c.toLowerCase().includes(q));
          });
        }
        if (comp.actions && Array.isArray(comp.actions)) {
          matchesIntent = matchesIntent || comp.actions.some(a => a.toLowerCase().includes(q));
        }

        return matchesName || matchesLabel || matchesAuth || matchesPerm || matchesIntent;
      }

      return true;
    });
  }, [allComponentsList, componentTypeFilter, componentExportedOnly, componentSearch]);

  // Filtered Secrets (Strings Tab)
  const filteredSecrets = useMemo(() => {
    const list = categorized_strings?.secrets_and_keys || [];
    if (!stringSearch.trim()) return list;
    const q = stringSearch.toLowerCase();
    return list.filter(
      s => s.type.toLowerCase().includes(q) || s.value.toLowerCase().includes(q) || (s.location && s.location.toLowerCase().includes(q))
    );
  }, [categorized_strings?.secrets_and_keys, stringSearch]);

  // Decoded AndroidManifest Lines & Highlighting
  const manifestLines = useMemo(() => {
    if (!manifest_xml) return [];
    return manifest_xml.split('\n');
  }, [manifest_xml]);

  const manifestMatchLines = useMemo(() => {
    if (!manifestSearch.trim()) {
      return manifestLines.map((line, idx) => ({ lineNum: idx + 1, text: line, isMatch: false }));
    }
    const q = manifestSearch.toLowerCase();
    return manifestLines.map((line, idx) => ({
      lineNum: idx + 1,
      text: line,
      isMatch: line.toLowerCase().includes(q)
    }));
  }, [manifestLines, manifestSearch]);

  const manifestMatchesCount = useMemo(() => {
    if (!manifestSearch.trim()) return 0;
    return manifestMatchLines.filter(l => l.isMatch).length;
  }, [manifestMatchLines, manifestSearch]);

  const displayedManifestLines = useMemo(() => {
    if (manifestFilterOnly && manifestSearch.trim()) {
      return manifestMatchLines.filter(l => l.isMatch);
    }
    return manifestMatchLines;
  }, [manifestMatchLines, manifestFilterOnly, manifestSearch]);

  // Certificate Chain (multi-cert support)
  const certChain: ApkCertificate[] = useMemo(() => {
    if (signing_info?.certificates && signing_info.certificates.length > 0) {
      return signing_info.certificates;
    }
    if (signing_info?.subject || signing_info?.sha256_fingerprint) {
      return [{
        subject: signing_info.subject,
        issuer: signing_info.issuer,
        serial_number: signing_info.serial_number,
        valid_from: signing_info.valid_from,
        valid_until: signing_info.valid_until,
        sha256_fingerprint: signing_info.sha256_fingerprint,
        is_debug_key: signing_info.is_debug_key,
        is_self_signed: signing_info.is_self_signed
      }];
    }
    return [];
  }, [signing_info]);

  const activeCert = certChain[selectedCertIndex] || certChain[0] || signing_info;

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
      case 'low':
        return 'bg-blue-50 text-blue-700 border-blue-200';
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
          {archive_security && (
            <div className={`p-2 rounded-xl border text-center min-w-[70px] ${
              archive_security.verdict === 'VULNERABLE'
                ? 'bg-rose-50 border-rose-200'
                : archive_security.verdict === 'SUSPICIOUS'
                ? 'bg-amber-50 border-amber-200'
                : 'bg-slate-50 border-slate-200'
            }`}>
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Archive</span>
              <strong className={
                archive_security.verdict === 'VULNERABLE'
                  ? 'text-rose-600'
                  : archive_security.verdict === 'SUSPICIOUS'
                  ? 'text-amber-600'
                  : 'text-emerald-600'
              }>
                {archive_security.verdict}
              </strong>
            </div>
          )}
          {dependencies.length > 0 && (
            <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">SDKs</span>
              <strong className="text-indigo-600">{dependencies.length}</strong>
            </div>
          )}
          {secrets_and_ctf && (secrets_and_ctf.total_count > 0 || (secrets_and_ctf.ctf_flags && secrets_and_ctf.ctf_flags.length > 0)) && (
            <div className={`p-2 rounded-xl border text-center min-w-[70px] ${
              (secrets_and_ctf.ctf_flags && secrets_and_ctf.ctf_flags.length > 0)
                ? 'bg-purple-50 border-purple-200'
                : 'bg-rose-50 border-rose-200'
            }`}>
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Secrets/CTF</span>
              <strong className={(secrets_and_ctf.ctf_flags && secrets_and_ctf.ctf_flags.length > 0) ? 'text-purple-700' : 'text-rose-600'}>
                {((secrets_and_ctf.ctf_flags || []).length) + ((secrets_and_ctf.secrets || []).length)}
              </strong>
            </div>
          )}
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-100 pb-3">
        <button
          onClick={() => setActiveTab('overview')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
            activeTab === 'overview'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          Overview &amp; Audit
        </button>

        {archive_security && (
          <button
            onClick={() => setActiveTab('archive_sec')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              activeTab === 'archive_sec'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Archive className={`w-3.5 h-3.5 ${
              archive_security.verdict === 'VULNERABLE'
                ? 'text-rose-500'
                : archive_security.verdict === 'SUSPICIOUS'
                ? 'text-amber-500'
                : 'text-slate-400'
            }`} />
            <span>Archive Security</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold uppercase ${
              archive_security.verdict === 'VULNERABLE'
                ? 'bg-rose-100 text-rose-800'
                : archive_security.verdict === 'SUSPICIOUS'
                ? 'bg-amber-100 text-amber-800'
                : 'bg-emerald-100 text-emerald-800'
            }`}>
              {archive_security.verdict}
            </span>
          </button>
        )}

        {(dependencies.length > 0 || cyclonedx_sbom) && (
          <button
            onClick={() => setActiveTab('dependencies')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              activeTab === 'dependencies'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Package className="w-3.5 h-3.5 text-indigo-500" />
            <span>Dependencies &amp; SBOM ({dependencies.length})</span>
            {dependencies.some(d => d.known_vulnerabilities && d.known_vulnerabilities.length > 0) && (
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>
        )}

        {secrets_and_ctf && (secrets_and_ctf.total_count > 0 || (secrets_and_ctf.ctf_flags && secrets_and_ctf.ctf_flags.length > 0) || (secrets_and_ctf.secrets && secrets_and_ctf.secrets.length > 0)) && (
          <button
            onClick={() => setActiveTab('secrets_ctf')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              activeTab === 'secrets_ctf'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Flag className={`w-3.5 h-3.5 ${(secrets_and_ctf.ctf_flags || []).length > 0 ? 'text-purple-500' : 'text-rose-500'}`} />
            <span>Secrets &amp; CTF ({((secrets_and_ctf.ctf_flags || []).length) + ((secrets_and_ctf.secrets || []).length)})</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab('decompiler')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              activeTab === 'permissions'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Permissions ({unifiedPermissions.length})
          </button>
        )}

        {!is_standalone_dex && (
          <button
            onClick={() => setActiveTab('components')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
              activeTab === 'components'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Components ({totalExported > 0 ? `${totalExported} Exp / ${totalComponents}` : totalComponents})
          </button>
        )}

        <button
          onClick={() => setActiveTab('dex')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
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

          {/* Sensitive Permission Combinations (Checklist Sec 2 & 10) */}
          {sensitive_permission_combos.length > 0 && (
            <div className="p-5 bg-rose-50/50 rounded-2xl border border-rose-200 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-rose-600" />
                  <h4 className="text-xs font-bold text-rose-900 uppercase tracking-wider">
                    High-Risk Permission Combinations ({sensitive_permission_combos.length} Detected)
                  </h4>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-rose-600 text-white rounded-md font-bold uppercase">
                  Malware Attack Vectors
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {sensitive_permission_combos.map((combo, idx) => (
                  <div key={idx} className="p-3.5 bg-white rounded-xl border border-rose-200/80 shadow-xs space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <strong className="text-xs font-bold text-rose-900">{combo.title}</strong>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                        combo.severity === 'critical' ? 'bg-rose-100 text-rose-800' : 'bg-orange-100 text-orange-800'
                      }`}>
                        {combo.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 leading-relaxed">{combo.description}</p>
                    <div className="flex flex-wrap gap-1 pt-1 font-mono text-[10px]">
                      {combo.permissions.map((p, pIdx) => (
                        <span key={pIdx} className="px-1.5 py-0.5 bg-slate-100 text-slate-700 rounded border border-slate-200">
                          {p.split('.').pop()}
                        </span>
                      ))}
                    </div>
                    {combo.mitre && (
                      <div className="text-[10px] text-slate-400 font-mono pt-1">
                        MITRE Mobile: <span className="text-indigo-600 font-bold">{combo.mitre} ({combo.mitre_name})</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Deep Links & Custom Schemes (Checklist Sec 2 & 3) */}
          {deep_links.length > 0 && (
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-indigo-600" />
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                    Deep Links &amp; Custom URL Schemes ({deep_links.length})
                  </h4>
                </div>
                {deep_links.some(dl => dl.is_custom_scheme && dl.exported) && (
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-100 text-amber-800 border border-amber-300 rounded-md font-bold">
                    ⚠️ Custom Schemes Exported
                  </span>
                )}
              </div>
              <div className="divide-y divide-slate-200 bg-white rounded-xl border border-slate-200 overflow-hidden font-mono text-xs">
                {deep_links.map((dl, idx) => (
                  <div key={idx} className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-slate-50">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold text-xs ${dl.is_custom_scheme ? 'text-amber-700' : 'text-indigo-700'}`}>
                          {dl.scheme}://{dl.host || '*'}{dl.path_prefix || dl.path_pattern || ''}
                        </span>
                        {dl.is_custom_scheme && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded font-sans font-bold bg-amber-50 text-amber-700 border border-amber-200">
                            Custom Scheme
                          </span>
                        )}
                        {dl.exported && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded font-sans font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            Exported
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] text-slate-500 font-sans block">
                        Handler: <code className="font-mono text-slate-700">{dl.activity}</code>
                      </span>
                    </div>
                    {dl.is_custom_scheme && dl.exported && (
                      <span className="text-[10px] font-sans text-amber-700 bg-amber-50/70 p-1.5 rounded border border-amber-200 max-w-xs">
                        Subject to scheme hijacking and malicious parameter injection.
                      </span>
                    )}
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
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-600" />
                Declared Android Permissions &amp; Privileges ({unifiedPermissions.length})
              </h4>
              <p className="text-xs text-slate-500">
                Audited against Android framework dangerous permissions, privileged system capabilities, and MITRE Mobile techniques.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs px-2.5 py-1 bg-rose-50 text-rose-700 border border-rose-200 rounded-lg font-bold">
                {unifiedPermissions.filter(p => p.is_dangerous).length} Dangerous
              </span>
              <span className="text-xs px-2.5 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-lg font-medium">
                {unifiedPermissions.filter(p => !p.is_dangerous).length} Standard
              </span>
            </div>
          </div>

          {/* Filter and Search Bar */}
          <div className="space-y-2.5">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={permSearch}
                  onChange={e => setPermSearch(e.target.value)}
                  placeholder="Search permission string, title, or threat..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* Type Filter: All / Dangerous / Standard */}
              <div className="flex items-center gap-1.5 self-start sm:self-auto">
                <span className="text-[11px] font-semibold text-slate-400 mr-1">Type:</span>
                {[
                  { id: 'all', label: `All (${unifiedPermissions.length})` },
                  { id: 'dangerous', label: `Dangerous (${unifiedPermissions.filter(p => p.is_dangerous).length})` },
                  { id: 'standard', label: `Standard (${unifiedPermissions.filter(p => !p.is_dangerous).length})` }
                ].map(typeTab => (
                  <button
                    key={typeTab.id}
                    onClick={() => setPermTypeFilter(typeTab.id as any)}
                    className={`text-xs px-2.5 py-1 rounded-lg capitalize transition-all cursor-pointer ${
                      permTypeFilter === typeTab.id
                        ? 'bg-slate-900 text-white font-semibold shadow-xs'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {typeTab.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Severity Filter Pills (if viewing all or dangerous) */}
            {permTypeFilter !== 'standard' && (
              <div className="flex items-center gap-1.5 pt-0.5">
                <span className="text-[11px] font-semibold text-slate-400 mr-1">Severity:</span>
                {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => {
                  const count = sev === 'all'
                    ? unifiedPermissions.filter(p => p.is_dangerous).length
                    : unifiedPermissions.filter(p => p.is_dangerous && p.severity === sev).length;
                  return (
                    <button
                      key={sev}
                      onClick={() => setPermFilter(sev)}
                      className={`text-[11px] px-2.5 py-0.5 rounded-lg capitalize transition-all cursor-pointer ${
                        permFilter === sev
                          ? 'bg-rose-600 text-white font-semibold'
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                      }`}
                    >
                      {sev} {sev !== 'all' && `(${count})`}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {filteredUnifiedPerms.length > 0 ? (
            <div className="space-y-2.5">
              {filteredUnifiedPerms.map((dp, idx) => (
                <div
                  key={idx}
                  className={`p-4 transition-all rounded-2xl border space-y-1.5 ${
                    dp.is_dangerous
                      ? 'bg-slate-50 hover:bg-slate-100/90 border-slate-200'
                      : 'bg-white hover:bg-slate-50 border-slate-200/80'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${
                        dp.is_dangerous ? getSeverityBadge(dp.severity) : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {dp.is_dangerous ? dp.severity : 'Standard'}
                      </span>
                      <strong className="text-xs font-bold text-slate-900">{dp.title}</strong>
                    </div>
                    {dp.mitre && (
                      <span className="text-[11px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md">
                        MITRE {dp.mitre} ({dp.mitre_name})
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-xs text-slate-700 font-semibold truncate">{dp.permission}</div>
                    <button
                      onClick={() => handleCopy(dp.permission, `perm_${idx}`)}
                      className="text-slate-400 hover:text-slate-600 p-0.5 shrink-0"
                      title="Copy permission name"
                    >
                      {copiedKey === `perm_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <p className="text-xs text-slate-500 leading-relaxed">{dp.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs bg-slate-50 rounded-2xl border border-slate-200">
              No permissions match current filters. Total package permissions: {unifiedPermissions.length}.
            </div>
          )}
        </div>
      )}

      {/* Tab: Components & Attack Surface */}
      {activeTab === 'components' && (
        <div className="space-y-6">
          {/* Top Component Architecture Breakdown */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div
              onClick={() => setComponentTypeFilter('activities')}
              className={`p-3 rounded-xl border text-center cursor-pointer transition-all ${
                componentTypeFilter === 'activities' ? 'bg-sky-50 border-sky-300 shadow-xs' : 'bg-slate-50 hover:bg-slate-100 border-slate-200'
              }`}
            >
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Activities</span>
              <strong className="text-slate-900 text-sm">{activities.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedActivities.length} Exported)</span>
            </div>
            <div
              onClick={() => setComponentTypeFilter('services')}
              className={`p-3 rounded-xl border text-center cursor-pointer transition-all ${
                componentTypeFilter === 'services' ? 'bg-indigo-50 border-indigo-300 shadow-xs' : 'bg-slate-50 hover:bg-slate-100 border-slate-200'
              }`}
            >
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Services</span>
              <strong className="text-slate-900 text-sm">{services.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedServices.length} Exported)</span>
            </div>
            <div
              onClick={() => setComponentTypeFilter('receivers')}
              className={`p-3 rounded-xl border text-center cursor-pointer transition-all ${
                componentTypeFilter === 'receivers' ? 'bg-purple-50 border-purple-300 shadow-xs' : 'bg-slate-50 hover:bg-slate-100 border-slate-200'
              }`}
            >
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Receivers</span>
              <strong className="text-slate-900 text-sm">{receivers.length}</strong>
              <span className="text-[10px] text-amber-600 block">({exportedReceivers.length} Exported)</span>
            </div>
            <div
              onClick={() => setComponentTypeFilter('providers')}
              className={`p-3 rounded-xl border text-center cursor-pointer transition-all ${
                componentTypeFilter === 'providers' ? 'bg-emerald-50 border-emerald-300 shadow-xs' : 'bg-slate-50 hover:bg-slate-100 border-slate-200'
              }`}
            >
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

          {/* Search & Category Filter Controls */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={componentSearch}
                  onChange={e => setComponentSearch(e.target.value)}
                  placeholder="Filter components by name, action, or authority..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-slate-900"
                />
              </div>

              {/* Exported Only Toggle */}
              <div className="flex items-center gap-2 self-start sm:self-auto">
                <label className="flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={componentExportedOnly}
                    onChange={e => setComponentExportedOnly(e.target.checked)}
                    className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                  />
                  <span>Exported Only ({totalExported})</span>
                </label>
              </div>
            </div>

            {/* Category Selector Pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                { id: 'all', label: `All Components (${allComponentsList.length})` },
                { id: 'activities', label: `Activities (${activities.length})` },
                { id: 'services', label: `Services (${services.length})` },
                { id: 'receivers', label: `Broadcast Receivers (${receivers.length})` },
                { id: 'providers', label: `Content Providers (${providers.length})` }
              ].map(cat => (
                <button
                  key={cat.id}
                  onClick={() => setComponentTypeFilter(cat.id as any)}
                  className={`text-xs px-3 py-1.5 rounded-xl font-medium transition-all cursor-pointer ${
                    componentTypeFilter === cat.id
                      ? 'bg-slate-900 text-white font-semibold shadow-sm'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>

          {/* Component List */}
          {filteredComponentsList.length > 0 ? (
            <div className="space-y-3">
              {filteredComponentsList.map((comp, idx) => {
                const isExpanded = expandedComponentIndex === idx;
                const typeColors = {
                  activity: 'bg-sky-50 text-sky-700 border-sky-200',
                  service: 'bg-indigo-50 text-indigo-700 border-indigo-200',
                  receiver: 'bg-purple-50 text-purple-700 border-purple-200',
                  provider: 'bg-emerald-50 text-emerald-700 border-emerald-200'
                };

                return (
                  <div
                    key={idx}
                    className="p-4 bg-white hover:bg-slate-50/80 transition-all rounded-2xl border border-slate-200 space-y-2.5 shadow-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${typeColors[comp.componentType]}`}>
                          {comp.componentType}
                        </span>

                        {comp.exported ? (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-amber-100 text-amber-800 border border-amber-200 rounded-md">
                            EXPORTED
                          </span>
                        ) : (
                          <span className="text-[10px] font-medium px-2 py-0.5 bg-slate-100 text-slate-500 rounded-md">
                            PRIVATE
                          </span>
                        )}

                        {comp.is_launcher && (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-emerald-100 text-emerald-800 border border-emerald-200 rounded-md">
                            MAIN / LAUNCHER
                          </span>
                        )}

                        {comp.is_boot && (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-rose-100 text-rose-800 border border-rose-200 rounded-md">
                            BOOT TRIGGER
                          </span>
                        )}

                        {comp.is_sms && (
                          <span className="text-[10px] font-bold px-2 py-0.5 bg-rose-100 text-rose-800 border border-rose-200 rounded-md">
                            SMS LISTENER
                          </span>
                        )}

                        {comp.authorities && (
                          <span className="text-[10px] font-mono px-2 py-0.5 bg-teal-50 text-teal-800 border border-teal-200 rounded-md">
                            AUTHORITY: {comp.authorities}
                          </span>
                        )}
                      </div>

                      {comp.permission && (
                        <span className="text-[11px] font-mono px-2 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 rounded-md">
                          Requires: {comp.permission.split('.').pop()}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center justify-between gap-2">
                      <div className="font-mono text-xs font-semibold text-slate-800 truncate" title={comp.name}>
                        {comp.name}
                      </div>
                      <button
                        onClick={() => handleCopy(comp.name, `comp_${idx}`)}
                        className="text-slate-400 hover:text-slate-600 p-0.5 shrink-0"
                        title="Copy component class name"
                      >
                        {copiedKey === `comp_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>

                    {comp.label && (
                      <div className="text-xs text-slate-500">
                        <span className="font-medium text-slate-600">Label:</span> {comp.label}
                      </div>
                    )}

                    {/* Intent Filters (Actions & Categories) */}
                    {comp.intent_filters && Array.isArray(comp.intent_filters) && comp.intent_filters.length > 0 && (
                      <div className="pt-1 border-t border-slate-100 space-y-1">
                        <button
                          onClick={() => setExpandedComponentIndex(isExpanded ? null : idx)}
                          className="flex items-center gap-1 text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 cursor-pointer"
                        >
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          <span>Intent Filters ({comp.intent_filters.length})</span>
                        </button>

                        {isExpanded && (
                          <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200 space-y-2 text-xs">
                            {comp.intent_filters.map((flt, fIdx) => {
                              if (typeof flt === 'string') {
                                return (
                                  <div key={fIdx} className="font-mono text-[11px] text-slate-700">
                                    • {flt}
                                  </div>
                                );
                              }
                              const actions = flt.actions || [];
                              const categories = flt.categories || [];
                              return (
                                <div key={fIdx} className="space-y-1">
                                  {actions.length > 0 && (
                                    <div className="flex flex-wrap items-center gap-1 font-mono text-[10px]">
                                      <span className="text-slate-400 font-sans">Actions:</span>
                                      {actions.map((act, aIdx) => (
                                        <span key={aIdx} className="px-1.5 py-0.2 bg-white border border-slate-200 rounded text-slate-800">
                                          {act}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                  {categories.length > 0 && (
                                    <div className="flex flex-wrap items-center gap-1 font-mono text-[10px]">
                                      <span className="text-slate-400 font-sans">Categories:</span>
                                      {categories.map((cat, cIdx) => (
                                        <span key={cIdx} className="px-1.5 py-0.2 bg-white border border-slate-200 rounded text-slate-600">
                                          {cat}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs bg-slate-50 rounded-2xl border border-slate-200">
              No components match the selected category and filter. Total package components: {allComponentsList.length}.
            </div>
          )}
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
              <span className={`text-xs font-bold block ${
                (dex_info.detected_apis || []).length > 0 ? 'text-rose-600' : 'text-emerald-600'
              }`}>
                {(dex_info.detected_apis || []).length} Sensitive APIs Detected
              </span>
            </div>
          </div>

          {/* DEX Architecture Breakdown */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">DEX Files</span>
              <strong className="text-slate-900 text-sm">{dex_info.dex_count || 1}</strong>
            </div>
            <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Classes Audited</span>
              <strong className="text-slate-900 text-sm">{(classes.length || dex_info.classes_count || 0).toLocaleString()}</strong>
            </div>
            <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">String Table</span>
              <strong className="text-slate-900 text-sm">{(dex_info.total_strings_count || 0).toLocaleString()}</strong>
            </div>
            <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Flagged APIs</span>
              <strong className={(dex_info.detected_apis || []).length > 0 ? 'text-rose-600 text-sm' : 'text-emerald-600 text-sm'}>
                {(dex_info.detected_apis || []).length}
              </strong>
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
          ) : (dex_info.detected_apis || []).length === 0 ? (
            <div className="p-6 bg-emerald-50/70 border border-emerald-200/80 rounded-2xl flex items-start gap-3.5">
              <div className="p-2 bg-emerald-100 text-emerald-700 rounded-xl shrink-0">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <strong className="text-sm font-bold text-emerald-950 block">Clean Dalvik API Triage</strong>
                <p className="text-xs text-emerald-800 leading-relaxed">
                  No malicious or high-risk Dalvik API signatures were identified across {(classes.length || dex_info.classes_count || 0).toLocaleString()} classes and {(dex_info.total_strings_count || 0).toLocaleString()} strings audited. The Dalvik bytecode analysis engine scanned for dynamic code execution (DexClassLoader), unencrypted TLS MitM, SMS toll fraud, accessibility service abuse, root privilege escalation, and anti-analysis evasion techniques.
                </p>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs bg-slate-50 rounded-2xl border border-slate-200">
              No sensitive Dalvik API signatures matched your filter criteria ({(dex_info.detected_apis || []).length} detected across other categories).
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
            filteredSecrets.length > 0 && (
              <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 space-y-2">
                <div className="flex items-center gap-2 text-rose-800 font-bold text-xs">
                  <Key className="w-4 h-4 text-rose-600" />
                  Hardcoded API Keys, Tokens &amp; Credentials ({filteredSecrets.length})
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {filteredSecrets.map((sec, i) => (
                    <div
                      key={i}
                      className="p-3 bg-white rounded-xl border border-rose-200 flex items-center justify-between text-xs font-mono"
                    >
                      <div className="truncate mr-2">
                        <span className="text-[10px] font-bold px-1.5 py-0.5 bg-rose-100 text-rose-800 rounded mr-2 uppercase">
                          {sec.type}
                        </span>
                        <span className="text-slate-800">{sec.value}</span>
                        {sec.location && (
                          <span className="text-[10px] text-slate-400 block truncate mt-0.5">
                            Loc: {sec.location}
                          </span>
                        )}
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

          {selectedStringCategory === 'secrets' && filteredSecrets.length === 0 && (
            <div className="p-6 bg-slate-50 rounded-2xl border border-slate-200 text-center text-slate-400 text-xs">
              No hardcoded API keys or high-entropy credentials match current criteria.
            </div>
          )}

          {/* Strings Stream */}
          <div className="bg-slate-900 text-slate-200 p-4 rounded-2xl font-mono text-xs max-h-96 overflow-y-auto space-y-1">
            {(() => {
              let items: string[] = [];
              const q = stringSearch.toLowerCase();
              if (selectedStringCategory === 'all' || selectedStringCategory === 'secrets') {
                items.push(
                  ...(categorized_strings.secrets_and_keys || []).map(
                    s => `[KEY: ${s.type.toUpperCase()}] ${s.value}${s.location ? ` (${s.location})` : ''}`
                  )
                );
              }
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

          {/* Multi-Certificate Chain Selector */}
          {certChain.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-100 pb-3">
              <span className="text-xs font-semibold text-slate-400 mr-2">Certificates ({certChain.length}):</span>
              {certChain.map((_, idx) => (
                <button
                  key={idx}
                  onClick={() => setSelectedCertIndex(idx)}
                  className={`text-xs px-3 py-1.5 rounded-xl font-medium transition-all cursor-pointer ${
                    selectedCertIndex === idx
                      ? 'bg-slate-900 text-white font-semibold shadow-xs'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  Certificate #{idx + 1} {idx === 0 ? '(Signer)' : '(Chain)'}
                </button>
              ))}
            </div>
          )}

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
              <span className="font-mono text-slate-800 break-all">{activeCert.subject || signing_info.subject || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Issuer</span>
              <span className="font-mono text-slate-800 break-all">{activeCert.issuer || signing_info.issuer || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Serial Number</span>
              <span className="font-mono text-slate-800">{activeCert.serial_number || signing_info.serial_number || 'N/A'}</span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Validity Window</span>
              <span className="font-mono text-slate-800">
                {activeCert.valid_from ? `${activeCert.valid_from} to ${activeCert.valid_until}` : (signing_info.valid_from ? `${signing_info.valid_from} to ${signing_info.valid_until}` : 'N/A')}
              </span>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">SHA-256 Fingerprint</span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-slate-800 text-[11px] truncate max-w-xs">
                  {activeCert.sha256_fingerprint || signing_info.sha256_fingerprint || 'N/A'}
                </span>
                {(activeCert.sha256_fingerprint || signing_info.sha256_fingerprint) && (
                  <button
                    onClick={() => handleCopy((activeCert.sha256_fingerprint || signing_info.sha256_fingerprint)!, 'fp')}
                    className="p-1 text-slate-400 hover:text-slate-600 cursor-pointer"
                  >
                    {copiedKey === 'fp' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>
            <div className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-500">Self-Signed Status</span>
              <span className={`font-semibold ${
                (activeCert.is_self_signed ?? signing_info.is_self_signed) ? 'text-amber-600' : 'text-slate-800'
              }`}>
                {(activeCert.is_self_signed ?? signing_info.is_self_signed) ? 'Yes (Self-Signed Key)' : 'No (CA Issued)'}
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
            <div className="flex flex-wrap items-center gap-2">
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
              {manifestSearch.trim() && (
                <button
                  onClick={() => setManifestFilterOnly(!manifestFilterOnly)}
                  className={`px-2.5 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                    manifestFilterOnly ? 'bg-indigo-600 text-white shadow-xs' : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
                  }`}
                  title={manifestFilterOnly ? 'Show all lines' : 'Show only matching lines'}
                >
                  {manifestFilterOnly ? 'Matches Only' : 'Highlight All'}
                </button>
              )}
              <button
                onClick={() => handleCopy(manifest_xml, 'manifest')}
                className="flex items-center gap-1 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-semibold transition-all shrink-0 cursor-pointer"
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

          {manifestSearch.trim() && (
            <div className="text-xs px-2 text-slate-500 font-mono flex items-center justify-between">
              <span>Found {manifestMatchesCount} matching lines across {manifestLines.length} lines</span>
              <button
                onClick={() => setManifestSearch('')}
                className="text-indigo-600 hover:underline cursor-pointer"
              >
                Clear search
              </button>
            </div>
          )}

          <div className="bg-slate-950 p-4 rounded-2xl font-mono text-xs text-emerald-300 max-h-[600px] overflow-auto border border-slate-800 space-y-0.5">
            {displayedManifestLines.map((line, idx) => (
              <div
                key={idx}
                className={`flex items-start gap-3 py-0.5 px-2 rounded font-mono ${
                  line.isMatch
                    ? 'bg-amber-950/80 text-amber-200 border-l-2 border-amber-400 font-semibold'
                    : 'hover:bg-slate-900/60 text-emerald-300/90'
                }`}
              >
                <span className="w-10 text-right text-slate-600 select-none text-[11px] shrink-0 font-sans">
                  {line.lineNum}
                </span>
                <span className="whitespace-pre flex-1 overflow-x-auto leading-relaxed">
                  {line.text}
                </span>
              </div>
            ))}
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

      {/* ========================================================================= */}
      {/* Tab: Archive Security & Structural Integrity (Checklist Sec 1)            */}
      {/* ========================================================================= */}
      {activeTab === 'archive_sec' && archive_security && (
        <div className="space-y-6">
          {/* Top Verdict Banner */}
          <div
            className={`p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
              archive_security.verdict === 'VULNERABLE'
                ? 'bg-rose-50 border-rose-300'
                : archive_security.verdict === 'SUSPICIOUS'
                ? 'bg-amber-50 border-amber-300'
                : 'bg-emerald-50 border-emerald-300'
            }`}
          >
            <div className="flex items-center gap-3">
              {archive_security.verdict === 'VULNERABLE' ? (
                <AlertOctagon className="w-8 h-8 text-rose-600 shrink-0" />
              ) : archive_security.verdict === 'SUSPICIOUS' ? (
                <AlertTriangle className="w-8 h-8 text-amber-600 shrink-0" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-600 shrink-0" />
              )}
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-base font-bold text-slate-900">
                    APK Archive Structural Security
                  </h4>
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${
                      archive_security.verdict === 'VULNERABLE'
                        ? 'bg-rose-200 text-rose-800'
                        : archive_security.verdict === 'SUSPICIOUS'
                        ? 'bg-amber-200 text-amber-800'
                        : 'bg-emerald-200 text-emerald-800'
                    }`}
                  >
                    {archive_security.verdict}
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-0.5">
                  {archive_security.verdict === 'VULNERABLE'
                    ? 'Critical archive structure anomalies detected (Zip Slip traversal, concealed executables, or polyglot header injection).'
                    : archive_security.verdict === 'SUSPICIOUS'
                    ? 'Archive contains suspicious duplicate central-directory entries, nested archives, or extraneous trailing data.'
                    : 'Clean archive structure: no path traversal sequences, compression bomb ratios, or disguised executables.'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-500 shrink-0">
              <span>Uncompressed: {formatBytes(archive_security.total_uncompressed_bytes)}</span>
              <span>•</span>
              <span>Ratio: {archive_security.decompression_ratio}:1</span>
            </div>
          </div>

          {/* 4 Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Zip Slip */}
            <div className={`p-4 rounded-2xl border ${archive_security.zip_slip.detected ? 'bg-rose-50 border-rose-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Zip Slip Traversal
              </span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.zip_slip.detected ? 'text-rose-700' : 'text-slate-700'}`}>
                  {archive_security.zip_slip.detected ? `${archive_security.zip_slip.paths.length} Paths` : 'Clean (0)'}
                </span>
                {archive_security.zip_slip.detected ? (
                  <AlertOctagon className="w-5 h-5 text-rose-600" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                )}
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">
                {archive_security.zip_slip.detected ? 'Path traversal escape sequences' : 'No directory traversal paths'}
              </span>
            </div>

            {/* 2. Decompression Ratio */}
            <div className={`p-4 rounded-2xl border ${archive_security.zip_bomb_risk ? 'bg-rose-50 border-rose-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Decompression Ratio
              </span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.zip_bomb_risk ? 'text-rose-700' : 'text-slate-700'}`}>
                  {archive_security.decompression_ratio}:1
                </span>
                {archive_security.zip_bomb_risk ? (
                  <AlertTriangle className="w-5 h-5 text-rose-600" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                )}
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">
                {archive_security.zip_bomb_risk ? 'Zip Bomb DoS Risk (>50:1)' : 'Normal compression ratio'}
              </span>
            </div>

            {/* 3. Duplicate Entries */}
            <div className={`p-4 rounded-2xl border ${archive_security.duplicate_entries.detected ? 'bg-amber-50 border-amber-300' : 'bg-slate-50 border-slate-200'}`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Duplicate Entries
              </span>
              <div className="flex items-center justify-between">
                <span className={`text-base font-bold font-mono ${archive_security.duplicate_entries.detected ? 'text-amber-700' : 'text-slate-700'}`}>
                  {archive_security.duplicate_entries.entries.length} Duplicates
                </span>
                {archive_security.duplicate_entries.detected ? (
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                )}
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">
                {archive_security.duplicate_entries.detected ? 'Central directory collision' : 'Unique archive entry names'}
              </span>
            </div>

            {/* 4. Polyglot & Trailing */}
            <div className={`p-4 rounded-2xl border ${
              archive_security.polyglot_and_trailing.has_prepended_header || archive_security.polyglot_and_trailing.has_trailing_data
                ? 'bg-rose-50 border-rose-300'
                : 'bg-slate-50 border-slate-200'
            }`}>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Polyglot &amp; Trailing
              </span>
              <div className="flex items-center justify-between">
                <span className={`text-sm font-bold font-mono truncate max-w-[140px] ${
                  archive_security.polyglot_and_trailing.has_prepended_header || archive_security.polyglot_and_trailing.has_trailing_data
                    ? 'text-rose-700'
                    : 'text-slate-700'
                }`}>
                  {archive_security.polyglot_and_trailing.has_prepended_header
                    ? 'Janus Polyglot'
                    : (archive_security.polyglot_and_trailing.has_trailing_data
                    ? `+${archive_security.polyglot_and_trailing.trailing_bytes_count}B Past EOCD`
                    : 'Standard ZIP')}
                </span>
                {archive_security.polyglot_and_trailing.has_prepended_header ? (
                  <AlertOctagon className="w-5 h-5 text-rose-600" />
                ) : archive_security.polyglot_and_trailing.has_trailing_data ? (
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                )}
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">
                {archive_security.polyglot_and_trailing.has_prepended_header
                  ? 'Prepended DEX (CVE-2017-13156)'
                  : (archive_security.polyglot_and_trailing.has_trailing_data
                  ? 'Extraneous payload after EOCD'
                  : 'Clean boundary verification')}
              </span>
            </div>
          </div>

          {/* Zip Slip Path Traversal Warning */}
          {archive_security.zip_slip.detected && (
            <div className="border border-rose-300 bg-rose-50/50 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-rose-900 font-bold text-sm">
                <AlertOctagon className="w-5 h-5 text-rose-600 shrink-0" />
                <span>Zip Slip Path Traversal Entries ({archive_security.zip_slip.paths.length})</span>
              </div>
              <p className="text-xs text-rose-700 leading-relaxed font-sans">
                The archive contains relative or absolute file paths with directory traversal sequences (<code>../</code>). Unpackers that do not sanitize destination paths will write files outside the target extraction root, leading to arbitrary code execution or system file overwrites.
              </p>
              <div className="divide-y divide-rose-200 bg-white rounded-xl border border-rose-200 overflow-hidden font-mono text-xs">
                {archive_security.zip_slip.paths.map((p, idx) => (
                  <div key={idx} className="p-3 text-rose-700 break-all flex items-center gap-2">
                    <span className="text-slate-400 select-none">{idx + 1}.</span>
                    <span>{p}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Concealed Executables & Extension Mismatches */}
          {archive_security.extension_mismatches && archive_security.extension_mismatches.length > 0 && (
            <div className="border border-rose-300 bg-rose-50/40 rounded-2xl p-5 space-y-4">
              <div className="flex items-center gap-2 text-rose-900 font-bold text-sm">
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
                <span>Concealed Executables &amp; Extension Mismatches ({archive_security.extension_mismatches.length})</span>
              </div>
              <p className="text-xs text-rose-700 font-sans">
                Native ELF libraries, Dalvik DEX files, shell scripts, or Windows binaries disguised with non-executable extensions (e.g., <code>.png</code>, <code>.dat</code>, <code>.xml</code>, <code>.txt</code>). Classic stealth dropper technique.
              </p>
              <div className="divide-y divide-rose-200 bg-white rounded-xl border border-rose-200 overflow-hidden font-mono text-xs">
                {archive_security.extension_mismatches.map((item, idx) => (
                  <div key={idx} className="p-3.5 space-y-1.5 hover:bg-rose-50/40">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-bold text-slate-900 break-all">{item.filename}</span>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-sans text-[10px]">
                          Declared: {item.declared_ext}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-sans text-[10px] font-bold">
                          Actual: {item.actual_type}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-600 font-sans">{item.reason}</p>
                    <div className="text-[10px] text-slate-400 font-mono">Magic bytes: <code>0x{item.magic_hex}</code></div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Polyglot & Trailing Data Details */}
          {(archive_security.polyglot_and_trailing.has_prepended_header || archive_security.polyglot_and_trailing.has_trailing_data) && (
            <div className="border border-amber-300 bg-amber-50/50 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-amber-900 font-bold text-sm">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
                <span>Polyglot / Trailing Data Analysis</span>
              </div>
              <p className="text-xs text-amber-800 font-sans leading-relaxed">
                {archive_security.polyglot_and_trailing.details}
              </p>
            </div>
          )}

          {/* Multi-DEX Structural Header Inventory Table */}
          {archive_security.multi_dex_inventory && archive_security.multi_dex_inventory.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-600" />
                  <span>Multi-DEX Structural Header Inventory ({archive_security.multi_dex_inventory.length} DEX Files)</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono">DEX Version &amp; Symbol Table Counts</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-50 border-b border-slate-200 text-[10px] text-slate-400 uppercase font-sans">
                    <tr>
                      <th className="py-2.5 px-4">DEX File</th>
                      <th className="py-2.5 px-3">Version</th>
                      <th className="py-2.5 px-3">Size</th>
                      <th className="py-2.5 px-3">Classes</th>
                      <th className="py-2.5 px-3">Strings</th>
                      <th className="py-2.5 px-3">Methods</th>
                      <th className="py-2.5 px-3">Checksum</th>
                      <th className="py-2.5 px-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {archive_security.multi_dex_inventory.map((dex, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/70">
                        <td className="py-2.5 px-4 font-bold text-slate-800">{dex.name}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded font-bold text-[11px]">
                            {dex.dex_version}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-600">{formatBytes(dex.size)}</td>
                        <td className="py-2.5 px-3 text-slate-700 font-semibold">{dex.classes_count.toLocaleString()}</td>
                        <td className="py-2.5 px-3 text-slate-700">{dex.strings_count.toLocaleString()}</td>
                        <td className="py-2.5 px-3 text-slate-700">{dex.methods_count.toLocaleString()}</td>
                        <td className="py-2.5 px-3 text-[11px] text-slate-400 truncate max-w-[100px]" title={dex.checksum}>
                          {dex.checksum || 'N/A'}
                        </td>
                        <td className="py-2.5 px-4">
                          {dex.is_stub ? (
                            <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 font-sans text-[10px] font-bold">
                              Parser Bomb Stub
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 font-sans text-[10px] font-bold">
                              Valid Bytecode
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Duplicate Archive Entries List */}
          {archive_security.duplicate_entries.detected && (
            <div className="border border-amber-300 bg-amber-50/40 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-amber-900 font-bold text-sm">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
                <span>Duplicate Central Directory Entries ({archive_security.duplicate_entries.entries.length})</span>
              </div>
              <div className="divide-y divide-amber-200 bg-white rounded-xl border border-amber-200 overflow-hidden font-mono text-xs">
                {archive_security.duplicate_entries.entries.map((d, idx) => (
                  <div key={idx} className="p-2.5 text-amber-800 break-all">
                    {d}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Nested Archives */}
          {archive_security.nested_archives && archive_security.nested_archives.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Nested Embedded Archives ({archive_security.nested_archives.length})</span>
                <span className="text-[10px] text-slate-400 font-mono">Secondary Container Payloads</span>
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {archive_security.nested_archives.map((na, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between gap-3 hover:bg-slate-50">
                    <span className="font-bold text-purple-700 break-all">{na.filename}</span>
                    <div className="flex items-center gap-2 font-sans">
                      <span className="text-slate-500 text-xs font-mono">{formatBytes(na.size)}</span>
                      <span className="px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-[10px] font-bold">
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
      {/* Tab: Third-Party Android SDK Inventory & CycloneDX v1.4 SBOM (Sec 8 & 11) */}
      {/* ========================================================================= */}
      {activeTab === 'dependencies' && (
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
                SDKs &amp; Dependencies ({dependencies.length})
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

          {/* Vulnerable SDK Alerts */}
          {dependencies.some(d => d.known_vulnerabilities && d.known_vulnerabilities.length > 0) && (
            <div className="border border-rose-300 bg-rose-50/40 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-rose-900 font-bold text-sm">
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
                <span>Known Vulnerable Android SDKs Detected</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {dependencies
                  .filter(d => d.known_vulnerabilities && d.known_vulnerabilities.length > 0)
                  .map((dep, idx) => (
                    <div key={idx} className="bg-white border border-rose-200 rounded-xl p-3.5 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <strong className="text-xs font-bold text-slate-900">{dep.name}</strong>
                        <span className="text-[10px] px-2 py-0.5 bg-rose-600 text-white rounded font-bold uppercase">
                          Vulnerable
                        </span>
                      </div>
                      <div className="text-[11px] text-rose-700 font-mono">
                        {dep.known_vulnerabilities?.map((v, vIdx) => (
                          <div key={vIdx}>• {v}</div>
                        ))}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* View Mode: Table */}
          {sbomViewMode === 'table' && (
            <div className="space-y-4">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={depSearch}
                  onChange={(e) => setDepSearch(e.target.value)}
                  placeholder="Filter detected SDKs & dependencies..."
                  className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
                <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                  <span>Detected Third-Party Android Libraries &amp; Frameworks ({dependencies.length})</span>
                  <span className="text-[10px] text-slate-400 font-mono">Dalvik Package &amp; Namespace Matching</span>
                </div>
                {dependencies.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-400">
                    No third-party Android SDKs or framework signatures detected.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 font-mono text-xs">
                    {dependencies
                      .filter(d => !depSearch.trim() || d.name.toLowerCase().includes(depSearch.toLowerCase()) || d.group.toLowerCase().includes(depSearch.toLowerCase()))
                      .map((dep, idx) => (
                        <div key={idx} className="p-3.5 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50">
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <Package className="w-4 h-4 text-indigo-600 shrink-0" />
                              <strong className="text-slate-900 text-xs">{dep.name}</strong>
                              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-[10px] font-sans font-bold">
                                {dep.category}
                              </span>
                            </div>
                            <span className="text-[11px] text-slate-500 font-sans block">{dep.description}</span>
                            <span className="text-[10px] text-slate-400 font-mono block">PURL: {dep.purl}</span>
                          </div>
                          <div className="text-right">
                            <span className="px-2 py-0.5 bg-slate-100 rounded text-slate-700 text-[11px] font-bold">
                              {dep.group}:{dep.artifact}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* View Mode: CycloneDX v1.4 JSON */}
          {sbomViewMode === 'json' && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-900 text-emerald-400 font-mono text-xs">
              <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex items-center justify-between text-slate-300">
                <span className="font-bold flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-emerald-400" />
                  CycloneDX v1.4 JSON Software Bill of Materials (SBOM)
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  Standard format for dependency supply chain compliance
                </span>
              </div>
              <div className="p-4 max-h-[500px] overflow-y-auto space-y-0.5">
                {JSON.stringify(cyclonedx_sbom, null, 2).split('\n').map((line, i) => (
                  <div key={i} className="flex hover:bg-slate-800/60 leading-5">
                    <span className="w-10 select-none text-slate-600 text-right pr-3 shrink-0 font-sans">
                      {i + 1}
                    </span>
                    <span className="whitespace-pre overflow-x-auto">{line}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Secrets & CTF Flags (Checklist Sec 9 & 12)                           */}
      {/* ========================================================================= */}
      {activeTab === 'secrets_ctf' && secrets_and_ctf && (
        <div className="space-y-6">
          {/* Search Filter */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={secretSearch}
              onChange={(e) => setSecretSearch(e.target.value)}
              placeholder="Filter captured CTF flags or credentials..."
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
          </div>

          {/* Captured CTF Flags Banner */}
          {secrets_and_ctf.ctf_flags && secrets_and_ctf.ctf_flags.length > 0 && (
            <div className="bg-gradient-to-r from-purple-900 via-indigo-900 to-slate-900 text-white p-6 rounded-3xl shadow-sm space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-purple-700/50">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-purple-500/20 rounded-xl">
                    <Flag className="w-6 h-6 text-purple-300" />
                  </div>
                  <div>
                    <h4 className="text-base font-bold tracking-wide">
                      Capture The Flag (CTF) Flags Captured ({secrets_and_ctf.ctf_flags.length})
                    </h4>
                    <p className="text-xs text-purple-200">
                      Discovered embedded CTF flags matching mobile security challenge formats.
                    </p>
                  </div>
                </div>
                <span className="px-3 py-1 rounded-full font-mono text-xs font-bold bg-purple-500/30 text-purple-200 border border-purple-400/30">
                  FLAG CAPTURED
                </span>
              </div>

              <div className="divide-y divide-purple-800/40">
                {secrets_and_ctf.ctf_flags
                  .filter(flagItem => !secretSearch.trim() || flagItem.flag.toLowerCase().includes(secretSearch.toLowerCase()) || flagItem.type.toLowerCase().includes(secretSearch.toLowerCase()))
                  .map((flagItem, idx) => (
                  <div key={idx} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-sm text-yellow-300 break-all select-all">
                          {flagItem.flag}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-purple-800/60 text-purple-200 font-sans">
                          {flagItem.type}
                        </span>
                      </div>
                      <span className="text-[11px] text-purple-300 font-mono block">
                        Source: {flagItem.source}
                      </span>
                    </div>

                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(flagItem.flag);
                        setCopiedFlagIdx(idx);
                        setTimeout(() => setCopiedFlagIdx(null), 2000);
                      }}
                      className="px-3 py-1.5 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/30 rounded-xl text-xs font-semibold text-purple-200 flex items-center gap-1.5 transition-colors cursor-pointer shrink-0 self-start sm:self-auto"
                    >
                      {copiedFlagIdx === idx ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      <span>{copiedFlagIdx === idx ? 'Copied Flag' : 'Copy Flag'}</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Hardcoded Secrets Table */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white space-y-0">
            <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
              <span>Hardcoded Cloud API Keys &amp; Sensitive Credentials ({secrets_and_ctf.secrets?.length || 0})</span>
              <span className="text-[10px] text-slate-400 font-mono">AWS, Google Cloud, Slack, Discord, Telegram, Private Keys</span>
            </div>

            {(!secrets_and_ctf.secrets || secrets_and_ctf.secrets.length === 0) ? (
              <div className="p-8 text-center text-xs text-slate-400">
                No high-confidence hardcoded cloud tokens, API keys, or private key headers found.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {secrets_and_ctf.secrets
                  .filter(sec => !secretSearch.trim() || sec.type.toLowerCase().includes(secretSearch.toLowerCase()) || sec.value.toLowerCase().includes(secretSearch.toLowerCase()))
                  .map((sec, idx) => (
                  <div key={idx} className="p-3.5 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-50">
                    <div className="space-y-1 max-w-xl">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-rose-600 shrink-0" />
                        <strong className="text-xs font-bold text-slate-900 font-sans">{sec.type}</strong>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase font-sans ${
                          sec.severity === 'critical' ? 'bg-rose-100 text-rose-800' : 'bg-orange-100 text-orange-800'
                        }`}>
                          {sec.severity}
                        </span>
                      </div>
                      <div className="text-rose-700 font-bold break-all select-all text-xs bg-rose-50/60 p-1.5 rounded border border-rose-100">
                        {sec.value}
                      </div>
                      <span className="text-[10px] text-slate-400 font-sans block">
                        Location: {sec.source}
                      </span>
                    </div>

                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(sec.value);
                        setCopiedSecretIdx(idx);
                        setTimeout(() => setCopiedSecretIdx(null), 2000);
                      }}
                      className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
                    >
                      {copiedSecretIdx === idx ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      <span>{copiedSecretIdx === idx ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
